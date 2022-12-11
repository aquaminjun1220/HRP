import socket
import nftables
import os

IP_ORIGDSTADDR = 20
IP_RECVORIGDSTADDR = IP_ORIGDSTADDR


# Target: make a socket based server that intercepts Linphone SIP messages, modifies it (optional), and relays it.#
# Features:
# intercepts every UDP datagram send from sport 5060, modifies it, and sends it out as if nothing happened.
# appropriately intercepts RTP packets too, modifies it, and sends it out as if nothing happened.
# after RTP session ends, stops intercepting RTP packet of that port.
# must run in following conditions:
# 1. when local invites remote.
# 2. when remote invites local.
# 3. when local byebyes remote.
# 4. when remote byebyes local.
# 5. when connection is simply lost? #

# decodes byte message sent from local sipphone, check whether it is SIP or RTP. add new port to proxy if needed, and process byte message.

def find_method(msg):
    i = msg.find(" ")
    j = msg.find("\n")
    word1 = msg[:i]
    if word1 != "SIP/2.0":
        return word1
    response = msg[i+1:j]
    i = msg.find("CSeq:")
    method = msg[i:].split(3)
    return response+" ("+method+")"

def process_msg(bmsg, sport):
    if sport == 5060:
        msg = bmsg.decode()
        method = find_method(msg)
        if (method == "INVITE") or (method == "200 OK (INVITE)"):
            sdp = msg.split("\r\n\r\n")[1]
            idx = sdp.find("m=audio")
            idk = sdp.find(" ", idx+8)
            rtp_sport = int(sdp[idx+8:idk])
            nft_include(nft, odict, rtp_sport)
        
        return sip_mod(bmsg)
    else:
        return rtp_mod(bmsg)

def sip_mod(bmsg):
    return bmsg

def rtp_mod(bmsg):
    return bmsg

def isock_set(iport):
    isock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # create listening socket
    isock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1) 
    # nftables tproxy rule will be sending packets not destinied for this socket
    # set socket option IP_TRANSPARENT to receive those packets
    isock.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
    while True:
        try:
            # proxy must have information about the original destination addr:port
            # set socket option IP_RECVORIGDSTADDR to receive ancillary data for destination addr:port
            isock.bind(("0.0.0.0", iport))
            print("ISOCK binded at 0.0.0.0:{}".format(iport))
            break
        except:
            iport += 1
            continue
    return isock, iport

def osock_set(oport):
    osock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # create output socket
    while True:
        try:
            osock.bind(("0.0.0.0", oport))
            print("OSOCK binded at 0.0.0.0:{}".format(oport))
            break
        except:
            oport += 1
            continue
    # bind to data original source port
    return osock, oport

def recv(isock, verbose=0, bufsize=4096, ancbufsize=4096):
    # receives data from isock with specified data buffer size and ancillary data buffer size
    # returns received bytes, source address, port tuple, destination address, port tuple
    (bmsg, ancdata, _, saddr) = isock.recvmsg(bufsize, ancbufsize, 0)
    cdata = ancdata[0][2]
    dport = int.from_bytes(cdata[2:4], 'big')
    daddr = socket.inet_ntoa(cdata[4:8])
    if verbose:
        print("Packet received from {}".format(saddr))
        print("Original destination was {}:{}".format(daddr, dport))
    return bmsg, saddr, (daddr, dport)

def init_nft(iport):
    global nft 
    nft = nftables.Nftables()
    nft.cmd("delete table HRP")
    nft.cmd("add table ip HRP")
    nft.cmd("add set HRP inc_port { type inet_service ; }")
    nft.cmd("add chain HRP prerouting { type filter hook prerouting priority -150 ; }")
    nft.cmd("add chain HRP output { type route hook output priority 0 ; }")
    nft.cmd("add chain HRP postrouting { type filter hook postrouting priority -300 ; }")
    # if this packet is redirected to loopback by output chain for the proxy, tproxy it into the proxy.
    # mark set 1 is needed, because the routing decision will hand it over to forward chain otherwise. (at least for remote destinied)
    nft.cmd("add rule HRP prerouting meta iif 1 udp sport @inc_port tproxy to :{} meta mark set 1 accept".format(iport))
    # if this packet must be redirected to loopback for the proxy, mark with 1 to use loopback routing table.
    nft.cmd("add rule HRP output udp sport @inc_port meta mark set 1")
    print("NFT initialized")

def init_iproute():
    os.sys("ip rule add fwmark 1 lookup 100")
    os.sys("ip route add local 0.0.0.0/0 dev lo:1 table 100")

def init_proxy(iport):
    init_nft(iport)
    init_iproute()

def nft_include(sport):
    # include sport to 'must be redirected'
    nft.cmd("add element HRP inc_port { " + str(sport) + " }")
    print("port {} is now routed to proxy".format(sport))
    oport = 10000 + sport
    osock, oport = osock_set(oport)
    odict[sport] = osock
    # if this packet came from proxy output, statelessly SNAT to original sport.
    nft.cmd("add rule HRP postrouting udp sport {} udp sport set {} notrack".format(oport, sport))
    print("oport {} is now statelessly snat to {}".format(oport, sport))

def main():
    iport = 7777 # listening port of the proxy
    global odict
    odict  = dict() # dict mapping port number to socket

    input("Press any key to start")
    # initialize listening port
    isock, iport = isock_set(iport)
    # initialize nft table / chain / rules / interaces / routing table
    init_proxy(iport)
    # include 5060 to proxy
    nft_include(5060)

    while True:
        # recieves data from isock
        bmsg, saddr, daddr = recv(isock, 1)

        # find appropriate osock
        osock = odict[saddr[1]]
        bmsg = process_msg(bmsg, saddr[1])
        osock.sendto(bmsg, daddr)

if __name__ == "__main__":
    main()


