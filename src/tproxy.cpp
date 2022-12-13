#include <stdio.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/udp.h>
#include <bits/stdc++.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <map>
#include <signal.h>
#include "tproxy.hpp"

typedef void handler_t(int);
static std::map<uint16_t, uint16_t> omapSIP;
static std::map<uint16_t, uint16_t> omapRTP;
static std::map<std::string, int8_t> valid;


/**
 * What does this code need to do?
 * create tun0
 * bind to it
 * modify routing table
 * modify nftables
 * create raw socket
 * send out packets
 * modify packets (with audiowmark)
*/

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
static int open_tun(char *dev) 
{
  struct ifreq ifr;
  int fd;
  int sfd;
  int i = 1;
  struct sockaddr_in sai;

  // open tun
  if( (fd = open("/dev/net/tun" , O_RDWR)) < 0 ) {
    perror("Failed to open /dev/net/tun");
    exit(-1);
  }
  std::cout << "INFO: opened tun" << std::endl;

  // setup ifr for first ioctl call (initialize tun)
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (*dev)
  {
    strncpy(ifr.ifr_name, "tun10", IFNAMSIZ);
  }

  if( (ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("Failed ioctl(TUNSETIFF)");
    close(fd);
    exit(-1);
  }
  strcpy(dev, ifr.ifr_name);
  std::cout << "INFO: initialized tun" << std::endl;

  // using socket, set tun
  sfd = socket(AF_INET, SOCK_DGRAM, 0);
  memset(&sai, 0, sizeof(struct sockaddr));
  sai.sin_family = AF_INET;
  sai.sin_port   = 0;
  sai.sin_addr.s_addr = inet_addr("10.20.20.20");
  memcpy(&(ifr.ifr_addr), &sai, sizeof(struct sockaddr));
  if( (ioctl(sfd, SIOCSIFADDR, (void *)&ifr)) < 0 ) {
    perror("Failed ioctl(SIOCSIFADDR)");
    close(fd);
    exit(-1);
  }

  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  if( (ioctl(sfd, SIOCSIFFLAGS, (void *)&ifr)) < 0 ) {
    perror("Failed ioctl(SIOCSIFFLAGS)");
    close(fd);
    exit(-1);
  } 
  close(sfd);
  std::cout << "INFO: setted tun" << std::endl;

  return fd;
}

static void init_rules(char *dev)
{
  system("ip rule add fwmark 1 lookup 100");
  char buffer[64];
  sprintf(buffer, "ip route add 0.0.0.0/0 dev %s table 100", dev);
  system(buffer);
  std::cout << "INFO: routing table initialized" << std::endl;

  system("nft add table ip HRP");
  system("nft add set HRP inc_portSIP \" { type inet_service ; } \"");
  system("nft add set HRP inc_portRTP \" { type inet_service ; } \"");
  system("nft add chain HRP output \" { type route hook output priority 0 ; } \"");
  system("nft add chain HRP postroutingSIP \" { type filter hook postrouting priority -300 ; } \"");
  system("nft add chain HRP postroutingRTP \" { type filter hook postrouting priority -301 ; } \"");
  system("nft add rule HRP output udp sport @inc_portSIP meta mark set 1");
  system("nft add rule HRP output udp sport @inc_portRTP meta mark set 1");
  std::cout << "INFO: nftable initialized" << std::endl;
}


static int occupy_port(int oport)
{
  int osock;
  struct sockaddr_in osock_addr;
  if ((osock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
      perror("Failed to create osock");
      exit(-1);
  }

  memset(&osock_addr, 0, sizeof(osock_addr));
  osock_addr.sin_family = AF_INET;
  osock_addr.sin_addr.s_addr = INADDR_ANY;
  osock_addr.sin_port = htons(oport);
  while (bind(osock, (const sockaddr *)(&osock_addr), sizeof(osock_addr)) < 0)
  {
      oport++;
      osock_addr.sin_port = htons(oport);
  }
  return oport;
}

static int rawsock_set()
{
  int rsock;
  if ((rsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
  {
      perror("Failed to create raw socket");
      exit(-1);
  }

  return rsock;
}

static void nft_includeSIP(int sport)
{
  if (omapSIP.contains(sport))
      return;
  char buffer[96];
  sprintf(buffer, "nft add element HRP inc_portSIP { %d }", sport);
  system(buffer);
  std::cout << "INFO: port " << sport << " is now routed to proxy" << std::endl;
  int oport;
  oport = 10000 + sport;
  oport = occupy_port(oport);
  omapSIP[sport] = oport;

  sprintf(buffer, "nft add rule HRP postroutingSIP udp sport %d udp sport set %d notrack", oport, sport);
  system(buffer);
  std::cout << "INFO: oport " << oport << " is now statelessly snat to " << sport << std::endl;
}

static void nft_includeRTP(int sport)
{
  if (omapRTP.contains(sport))
      return;
  char buffer[96];
  sprintf(buffer, "nft add element HRP inc_portRTP { %d }", sport);
  system(buffer);
  std::cout << "INFO: port " << sport << " is now routed to proxy" << std::endl;
  int oport;
  oport = 10000 + sport;
  oport = occupy_port(oport);
  omapRTP[sport] = oport;

  sprintf(buffer, "nft add rule HRP postroutingRTP udp sport %d udp sport set %d notrack", oport, sport);
  system(buffer);
  std::cout << "INFO: oport " << oport << " is now statelessly snat to " << sport << std::endl;
}

static void nft_flushRTP()
{
  omapRTP.clear();
  system("nft flush set HRP inc_portRTP");
  std::cout << "INFO: all RTP ports are no longer routed to proxy" << std::endl;

  system("nft flush chain HRP postroutingRTP");
  std::cout << "INFO: all RTP ports are no longer SNAT" << std::endl;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
static int cread(int fd, uint8_t *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

void sigINThandler(int sig)
{
    int olderrno = errno;
    sigset_t mask_all, prev_mask;
    pid_t pid;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
    system("ip rule del fwmark 1 lookup 100");
    system("ip route flush table 100");
    std::cout << "INFO: routing table cleaned" << std::endl;

    system("nft delete table HRP");
    std::cout << "INFO: nftable cleaned" << std::endl;
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    errno = olderrno;
    exit(0);
}

/*
 * Signal - wrapper for the sigaction function
 */
handler_t *Signal(int signum, handler_t *handler)
{
    struct sigaction action, old_action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask); /* block sigs of type being handled */
    action.sa_flags = SA_RESTART; /* restart syscalls if possible */

    if (sigaction(signum, &action, &old_action) < 0)
        perror("Failed to install signal handler");
    return (old_action.sa_handler);
}

static std::string find_method(std::string& payload)
{
  std::string method;
  int wordend = payload.find(' ');
  method = payload.substr(0, wordend);
  transform(method.begin(), method.end(), method.begin(), ::toupper);
  if (valid.contains(method))
    return method;
  if (method != "SIP/2.0")
    return "INVALID";
  int lineend = payload.find('\r');
  std::string response = payload.substr(wordend+1, lineend-(wordend+1));
  transform(response.begin(), response.end(), response.begin(), ::toupper);
  int C = payload.find("CSeq:");
  C = payload.find(' ', C);
  C = payload.find(' ', C+1);
  C = C+1;
  lineend = payload.find('\r', C);
  method = payload.substr(C, lineend-C);
  transform(method.begin(), method.end(), method.begin(), ::toupper);
  return response + " (" + method + ")";
}

static int process_bmsg(uint8_t *in_buffer, uint8_t *out_buffer, int in_len)
{
  uint8_t *iptr = in_buffer;
  uint8_t *optr = out_buffer;
  uint16_t *ip_len;
  uint16_t *udp_len;
  uint8_t version;
  version = (*in_buffer) & 0xF0;
  // network protocol is IPV4, copy IPV4 header to out_buffer
  if (version == 4<<4)
  {
    struct iphdr ip;
    memcpy(&ip, iptr, sizeof(struct iphdr));
    ip.check = 0;
    ip_len = &(reinterpret_cast<struct iphdr *>(iptr)->tot_len);
    iptr += sizeof(struct iphdr);
    in_len -= sizeof(struct iphdr);
    memcpy(optr, &ip, sizeof(struct iphdr));
    optr += sizeof(struct iphdr);
    std::cout << "IPV4 Packet Header:" << std::endl;
    char addr[64];
    inet_ntop(AF_INET, &(ip.saddr), addr, sizeof(addr));
    std::cout << "Source Address: " << addr << std::endl;
    inet_ntop(AF_INET, &(ip.daddr), addr, sizeof(addr));
    std::cout << "Destination Address: " << addr << std::endl;
    if (ip.protocol != IPPROTO_UDP)
    {
      std::cout << "Discarded Invalid Packet" << std::endl;
      return 0;
    }
  }

  // network protocol is IPV6, copy IPV6 header to out_buffer
  else if (version == 6<<4)
  {
    struct ip6_hdr ip6;
    memcpy(&ip6, iptr, sizeof(struct ip6_hdr));
    ip_len = &(reinterpret_cast<struct ip6_hdr *>(iptr)->ip6_plen);
    iptr += sizeof(struct ip6_hdr);
    in_len -= sizeof(struct ip6_hdr);
    memcpy(optr, &ip6, sizeof(struct ip6_hdr));
    optr += sizeof(struct ip6_hdr);
    std::cout << "IPV6 Packet Header:" << std::endl;
    char addr[64];
    inet_ntop(AF_INET6, &(ip6.ip6_src), addr, sizeof(addr));
    std::cout << "Source Address: " << addr << std::endl;
    inet_ntop(AF_INET6, &(ip6.ip6_dst), addr, sizeof(addr));
    std::cout << "Destination Address: " << addr << std::endl;
    if (ip6.ip6_nxt != IPPROTO_UDP)
    {
      std::cout << "Discarded Invalid Packet" << std::endl;
      return 0;
    }
  }

  // transport protocol is UDP
  struct udphdr udp;
  memcpy(&udp, iptr, sizeof(struct udphdr));
  udp_len = &(reinterpret_cast<struct udphdr *>(iptr)->len);
  iptr += sizeof(struct udphdr);
  in_len -= sizeof(struct udphdr);
  std::cout << "UDP Packet Header:" << std::endl;
  std::cout << "Source Port: " << ntohs(udp.source) << std::endl;
  std::cout << "Destination Port: " << ntohs(udp.dest) << std::endl;

  // application is SIP, copy udp header and payload to out_buffer, modify source port.
  // do some SIP specific stuff
  if (omapSIP.contains(ntohs(udp.source)))
  {
    std::cout << "SIP packet recieved:" << std::endl;
    udp.source = htons(omapSIP[ntohs(udp.source)]);
    memcpy(optr, &udp, sizeof(struct udphdr));
    optr += sizeof(struct udphdr);
    memcpy(optr, iptr, in_len);
    optr += in_len;

    std::string payload ((char *)iptr, in_len);
    std::string method = find_method(payload);
    std::cout << "SIP Method: " << method << std::endl;

    if ((method == "INVITE") || (method == "200 OK (INVITE)"))
    {
      int sdp = payload.find("\r\n\r\n");
      int idx = payload.find("m=audio", sdp);
      int idk = payload.find(' ', idx+8);
      uint16_t rtpport = std::stoi(payload.substr(idx+8, idk-(idx+8)));
      nft_includeRTP(rtpport);
      return optr - out_buffer;
    }
    else if ((method == "BYE") || (method == "200 OK (BYE)"))
    {
      nft_flushRTP();
      return optr - out_buffer;
    }
    else if (method == "INVALID")
    {
      //return 0;
      return optr - out_buffer;
    }
    return optr - out_buffer;
  }

  else if (omapRTP.contains(ntohs(udp.source)))
  {
    return 0;
  }
  return 0;
}

int main()
{
  char dev[IF_NAMESIZE] = "tun10";
  int tun, rsock;
  uint8_t in_buffer[2000];
  int in_len;
  uint8_t out_buffer[2000];
  int out_len;
  sockaddr_in sai;
  sai.sin_family = AF_INET;
  sai.sin_addr.s_addr = INADDR_ANY;
  sai.sin_port = 0;

  std::cout << "Press any key to start" << std::endl;
  std::cin.get();

  valid["REGISTER"] = 1;
  valid["INVITE"] = 1;
  valid["ACK"] = 1;
  valid["BYE"] = 1;
  valid["CANCEL"] = 1;
  valid["UPDATE"] = 1;
  valid["REFER"] = 1;
  valid["PRACK"] = 1;
  valid["SUBSCRIBE"] = 1;
  valid["NOTIFY"] = 1;
  valid["PUBLISH"] = 1;
  valid["MESSAGE"] = 1;
  valid["INFO"] = 1;
  valid["OPTIONS"] = 1;

  tun = open_tun(dev);
  rsock = rawsock_set();

  init_rules(dev);
  Signal(SIGINT, sigINThandler);

  nft_includeSIP(5060);

  while (1)
  {
    std::cout << "Trying to read..." << std::endl;
    in_len = cread(tun, in_buffer, 2000);
    std::cout << "Packet recieved:" << std::endl;
    out_len = process_bmsg(in_buffer, out_buffer, in_len);
    sendto(rsock, out_buffer, out_len, 0, (sockaddr *)(&sai), sizeof(sockaddr_in));
    memset(in_buffer, 0, sizeof(in_buffer));
    in_len = 0;
    memset(out_buffer, 0, sizeof(out_buffer));
    out_len = 0;
    std::cout << std::endl;
  }
}