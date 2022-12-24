import socket
import nftables
import os


IP_RECVORIGDSTADDR = 20

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

valid = ["REGISTER", "INVITE", "ACK", "BYE", "CANCEL", "UPDATE", "REFER", "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH", "MESSAGE", "INFO", "OPTIONS"]

def find_method(msg):
    i = msg.find(" ")
    j = msg.find("\r\n")
    word1 = msg[:i].upper()
    if word1 in valid:
        return word1
    if word1 != "SIP/2.0":
        return "INVALID"
    response = msg[i+1:j].upper()
    i = msg.find("CSeq:")
    method = msg[i:].split(None, 3)[2].upper()
    return response+" ("+method+")"

def process_msg(bmsg, sport):
    if sport == 5060:
        msg = bmsg.decode(errors="ignore")
        method = find_method(msg)
        print("SIP packet delivered: ", method)
        if (method == "INVITE") or (method == "200 OK (INVITE)"):
            sdp = msg.split("\r\n\r\n")[1]
            idx = sdp.find("m=audio")
            idk = sdp.find(" ", idx+8)
            rtp_sport = int(sdp[idx+8:idk])
            nft_includeRTP(rtp_sport)
        elif (method == "BYE") or (method == "200 OK (BYE)"):
            nft_flushRTP()
        elif method=="INVALID":
            return None
        return sip_mod(bmsg)
    else:
        print("RTP packet delivered: ")
        return rtp_mod(bmsg)

def foo(bmsg):
    return bmsg.decode().lower().encode()


def sip_mod(bmsg):
    return bmsg

def rtp_mod(bmsg):
    return bmsg

def isock_set(iport):
    # create listening socket
    isock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # nftables tproxy rule will be sending packets not destinied for this socket
    # set socket option IP_TRANSPARENT to receive those packets
    isock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
    # set socket option IP_RECVORIGDSTADDR to... recover original destination address.
    isock.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
    while True:
        try:
            # proxy must have information about the original destination addr:port
            # set socket option IP_RECVORIGDSTADDR to receive ancillary data for destination addr:port
            isock.bind(("0.0.0.0", iport))
            print("INFO: ISOCK binded at 0.0.0.0:{}".format(iport))
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
            print("INFO: OSOCK binded at 0.0.0.0:{}".format(oport))
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
        print()
        print("RECV: Packet received from {}".format(saddr))
        print("RECV: Original destination was {}:{}".format(daddr, dport))
    return bmsg, saddr, (daddr, dport)

def init_nft(iport):
    global nft 
    nft = nftables.Nftables()
    nft.cmd("delete table HRP")
    nft.cmd("add table ip HRP")
    nft.cmd("add set HRP inc_portSIP { type inet_service ; }")
    nft.cmd("add set HRP inc_portRTP { type inet_service ; }")
    nft.cmd("add chain HRP prerouting { type filter hook prerouting priority -150 ; }")
    nft.cmd("add chain HRP output { type route hook output priority 0 ; }")
    nft.cmd("add chain HRP postroutingSIP { type filter hook postrouting priority -300 ; }")
    nft.cmd("add chain HRP postroutingRTP { type filter hook postrouting priority -301 ; }")
    # if this packet is redirected to loopback by output chain for the proxy, tproxy it into the proxy.
    # mark set 1 is needed, because the routing decision will hand it over to forward chain otherwise. (at least for remote destinied)
    nft.cmd("add rule HRP prerouting meta iif 1 udp sport @inc_portSIP tproxy to :{} meta mark set 1 accept".format(iport))
    nft.cmd("add rule HRP prerouting meta iif 1 udp sport @inc_portRTP tproxy to :{} meta mark set 1 accept".format(iport))
    # if this packet must be redirected to loopback for the proxy, mark with 1 to use loopback routing table.
    nft.cmd("add rule HRP output udp sport @inc_portSIP meta mark set 1")
    nft.cmd("add rule HRP output udp sport @inc_portRTP meta mark set 1")
    print("INFO: NFT initialized")

def init_ip():
    os.system("ip rule del fwmark 1 lookup 100")
    print("CMD: ip rule del fwmark 1 lookup 100")
    os.system("ip route del local 0.0.0.0/0 dev lo table 100")
    print("CMD: ip route del local 0.0.0.0/0 dev lo table 100")
    print("INFO: reset routing table")

    os.system("ip rule add fwmark 1 lookup 100")
    print("CMD: ip rule add fwmark 1 lookup 100")
    os.system("ip route add local 0.0.0.0/0 dev lo table 100")
    print("CMD: ip route add local 0.0.0.0/0 dev lo table 100")
    print("INFO: routing table initialized")

def init_proxy(iport):
    init_ip()
    init_nft(iport)

def nft_includeSIP(sport):
    # include sport to 'must be redirected'
    nft.cmd("add element HRP inc_portSIP { " + str(sport) + " }")
    print("INFO: port {} is now routed to proxy".format(sport))
    oport = 10000 + sport
    if not(sport in odict):
        osock, oport = osock_set(oport)
        odict[sport] = (osock, oport)
    # if this packet came from proxy output, statelessly SNAT to original sport.
    nft.cmd("add rule HRP postroutingSIP udp sport {} udp sport set {} notrack".format(oport, sport))
    print("INFO: oport {} is now statelessly snat to {}".format(oport, sport))

def nft_includeRTP(sport):
    # include sport to 'must be redirected'
    nft.cmd("add element HRP inc_portRTP { " + str(sport) + " }")
    print("INFO: port {} is now routed to proxy".format(sport))
    oport = 10000 + sport
    if not(sport in odict):
        osock, oport = osock_set(oport)
        odict[sport] = (osock, oport)
    # if this packet came from proxy output, statelessly SNAT to original sport.
    nft.cmd("add rule HRP postroutingRTP udp sport {} udp sport set {} notrack".format(oport, sport))
    print("INFO: oport {} is now statelessly snat to {}".format(oport, sport))

def nft_flushRTP():
    nft.cmd("flush set HRP inc_portRTP")
    print("INFO: all RTP ports are no longer routed to proxy")

    nft.cmd("flush chain HRP postroutingRTP")
    print("INFO: all RTP ports are no longer SNAT")


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
    nft_includeSIP(5060)

    while True:
        # recieves data from isock
        bmsg, saddr, daddr = recv(isock, 1)
        if saddr[0] == daddr[0]:
            print("WARNING: possible loop detected")
            continue

        # find appropriate osock
        osock = odict[saddr[1]][0]
        bmsg = process_msg(bmsg, saddr[1])
        if bmsg:
            osock.sendto(bmsg, daddr)

if __name__ == "__main__":
    main()


