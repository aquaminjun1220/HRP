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

typedef void handler_t(int);
static char buffer[128];
static std::map<std::string, int> valid_methods = {
  {"REGISTER", 1},
  {"INVITE", 1},
  {"ACK", 1},
  {"BYE", 1},
  {"CANCEL", 1},
  {"UPDATE", 1},
  {"REFER", 1},
  {"PRACK", 1},
  {"SUBSCRIBE", 1},
  {"NOTIFY", 1},
  {"PUBLISH", 1},
  {"MESSAGE", 1},
  {"INFO", 1},
  {"OPTIONS", 1}
};
static int open_tun(char *);
static void init_rules(char *);
static int rawsock_set();
static int cread(int, uint8_t *, int);
handler_t sigINThandler;
handler_t *Signal(int, handler_t *);
pid_t Fork();
static std::string find_method(std::string&);
static int process_bmsg(uint8_t *, uint8_t *, int);



static int open_tun(char *dev) 
{
  struct ifreq ifr;
  int fd;
  int sfd;
  int i = 1;
  struct sockaddr_in sai;

  // open tun
  if( (fd = open("/dev/net/tun" , O_RDWR)) < 0 ) {
    perror("ERROR: Failed to open /dev/net/tun");
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
    perror("ERROR: Failed ioctl(TUNSETIFF)");
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
    perror("ERROR: Failed ioctl(SIOCSIFADDR)");
    close(fd);
    exit(-1);
  }

  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  if( (ioctl(sfd, SIOCSIFFLAGS, (void *)&ifr)) < 0 ) {
    perror("ERROR: Failed ioctl(SIOCSIFFLAGS)");
    close(fd);
    exit(-1);
  } 
  close(sfd);
  std::cout << "INFO: setted tun" << std::endl;
  return fd;
}

static void init_rules(char *dev)
{
  system("ip rule add fwmark 77 table 77");
  sprintf(buffer, "ip route add default dev %s table 77", dev);
  system(buffer);
  system("nft add table ip HRP");
  system("nft add set HRP inc_portSIP \"{ type inet_service ; }\"");
  system("nft add element HRP inc_portSIP \"{ 5060 }\" ");
  system("nft add set HRP inc_portRTP \"{ type inet_service ; }\"");
  system("nft add chain HRP output \"{ type route hook output priority 0 ; }\"");
  system("nft add rule HRP output meta mark != 10 udp sport @inc_portSIP meta mark set 77");
  system("nft add rule HRP output meta mark != 10 udp sport @inc_portRTP meta mark set 77");
  std::cout << "INFO: advanced routing initialized" << std::endl;
  std::cout << "INFO: sniffing on port 5060 for SIP packets" << std::endl;
}

static int rawsock_set()
{
  int rsock;
  int mark = 10;
  if ((rsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
  {
      perror("ERROR: Failed to create raw socket");
      kill(0, SIGINT);
  }
  if (setsockopt(rsock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
  {
      perror("ERROR: Failed to set SO_MARK");
      kill(0, SIGINT);
  }
  return rsock;
}

static int cread(int fd, uint8_t *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("ERROR: Reading data");
    kill(0, SIGINT);
  }
  return nread;
}

void sigINThandler(int sig)
{
  int olderrno = errno;
  sigset_t mask_all, prev_mask;
  sigfillset(&mask_all);
  sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
  system("ip rule delete fwmark 77 table 77");
  system("ip route flush table 77");
  system("nft delete table HRP");
  std::cout << "INFO: advanced routing terminated" << std::endl;
  sigprocmask(SIG_SETMASK, &prev_mask, NULL);
  errno = olderrno;
  exit(0);
}

handler_t *Signal(int signum, handler_t *handler)
{
  struct sigaction action, old_action;
  std::cout << "INFO: installing SIGINT handler" << std::endl;
  action.sa_handler = handler;
  sigemptyset(&action.sa_mask); /* block sigs of type being handled */
  action.sa_flags = SA_RESTART; /* restart syscalls if possible */

  if (sigaction(signum, &action, &old_action) < 0)
  {
    perror("ERROR: Failed to install signal handler");
    exit(-1);
  }
  return (old_action.sa_handler);
}

pid_t Fork()
{
  int pid;
  if ((pid = fork()) < 0)
  {
    perror("ERROR: Failed to fork");
    kill(0, SIGINT);
  }
  return pid;
}

static std::string find_method(std::string& sipmsg)
{
  int i = sipmsg.find(" ", 0);
  std::string method = sipmsg.substr(0, i-0);
  std::transform(method.begin(), method.end(), method.begin(), ::toupper);
  if (valid_methods.contains(method))
    return method;
  else if(method != "SIP/2.0")
    return "INVALID";
  int j = sipmsg.find("\r\n", 0);
  std::string response = sipmsg.substr(i+1, j-(i+1));
  std::transform(response.begin(), response.end(), response.begin(), ::toupper);
  i = sipmsg.find("CSeq:", 0);
  i = sipmsg.find(" ", i+1);
  i = sipmsg.find(" ", i+1);
  j = sipmsg.find("\r\n", i);
  std::string request = sipmsg.substr(i+1, j-(i+1));
  return response + " " + request;
}

static int process_bmsg(uint8_t *in_buffer, struct sockaddr_in *sai, int in_len)
{
  uint8_t *iptr = in_buffer;
  uint8_t version;
  version = (*in_buffer) & 0xF0;
  // network protocol is IPV4, copy IPV4 header to out_buffer
  if (version == 4<<4)
  {
    struct iphdr *ip = reinterpret_cast<struct iphdr *>(iptr);
    iptr += sizeof(struct iphdr);
    std::cout << "--------    IPV4 Header Info    --------" << std::endl;
    char addr[64];
    inet_ntop(AF_INET, &(ip->saddr), addr, sizeof(addr));
    std::cout << "Source Address: " << addr << std::endl;
    inet_ntop(AF_INET, &(ip->daddr), addr, sizeof(addr));
    std::cout << "Destination Address: " << addr << std::endl;
    sai->sin_family = AF_INET;
    sai->sin_addr.s_addr = ip->daddr;
    sai->sin_port = 0;
    if (ip->protocol != IPPROTO_UDP)
    {
      std::cout << "--------     non-UDP Packet     --------" << std::endl;
      return 0;
    }
  }

  // network protocol is IPV6, copy IPV6 header to out_buffer
  else if (version == 6<<4)
  {
    struct ip6_hdr *ip6 = reinterpret_cast<struct ip6_hdr *>(iptr);
    iptr += sizeof(struct ip6_hdr);
    std::cout << "--------    IPV6 Header Info    --------" << std::endl;
    char addr[64];
    inet_ntop(AF_INET6, &(ip6->ip6_src), addr, sizeof(addr));
    std::cout << "Source Address: " << addr << std::endl;
    inet_ntop(AF_INET6, &(ip6->ip6_dst), addr, sizeof(addr));
    std::cout << "Destination Address: " << addr << std::endl;
    std::cout << "--------   IPV6 not supported   --------" << std::endl;
    return 0;
  }

  else
  {
    std::cout << "--------     non-IP Packet      --------" << std::endl;
    return 0;
  }

  // transport protocol is UDP
  struct udphdr *udp = reinterpret_cast<struct udphdr *>(iptr);
  iptr += sizeof(struct udphdr);
  udp->check = 0;
  std::cout << "--------    UDP Header Info     --------" << std::endl;
  std::cout << "Source Port: " << ntohs(udp->source) << std::endl;
  std::cout << "Destination Port: " << ntohs(udp->dest) << std::endl;

  // application is SIP, copy udp header and payload to out_buffer, modify source port.
  // do some SIP specific stuff
  if (ntohs(udp->source) == 5060)
  {
    std::cout << "--------       SIP Packet       --------" << std::endl;
    std::string sipmsg((char *)(iptr), in_len);
    std::string method = find_method(sipmsg);
    std::cout << "SIP Method: " << method << std::endl;
    if ((method == "INVITE") || (method == "200 OK INVITE"))
    {
      int i = sipmsg.find("\r\n\r\n", 0);
      i = sipmsg.find("m=audio", i+1);
      i = sipmsg.find(" ", i+1);
      int j = sipmsg.find(" ", i+1);
      std::string rtpport = sipmsg.substr(i+1, j-(i+1));
      sprintf(buffer, "nft add element HRP inc_portRTP \"{ %s }\" ", rtpport.c_str());
      system(buffer);
      std::cout << "INFO: Detected INVITE. Adding port " << rtpport << " to rtp port set." << std::endl;
    }
    else if ((method == "BYE") || (method == "CANCEL") || (method == "200 OK BYE") || (method == "200 OK CANCEL"))
    {
      system("nft flush set HRP inc_portRTP");
      std::cout << "INFO: Detected BYE-ish. Flushing rtp port set." << std::endl;
    }
    return in_len;
  }
  else
  {
    std::cout << "--------    maybe-RTP Packet    --------" << std::endl;
    return in_len;
  }
}

int main()
{
  char dev[IF_NAMESIZE] = "tun10";
  int tun, rsock;
  sockaddr_in sai;
  uint8_t in_buffer[2000];
  int in_len;
  int out_len;
  int pipes[10];
  sai.sin_family = AF_INET;
  sai.sin_addr.s_addr = 0;
  sai.sin_port = 0;

  std::cout << "-------- Press any key to start --------" << std::endl;
  std::cin.get();

  tun = open_tun(dev);
  rsock = rawsock_set();

  init_rules(dev);
  Signal(SIGINT, sigINThandler);

  while (1)
  {
    in_len = cread(tun, in_buffer, 2000);
    std::cout << "!!------    Received packet     ------!!" << std::endl;
    std::cout << std::endl << std::endl;
    out_len = process_bmsg(in_buffer, &sai, in_len);
    sendto(rsock, in_buffer, out_len, 0, (sockaddr *)(&sai), sizeof(sockaddr_in));
    memset(in_buffer, 0, sizeof(in_buffer));
    in_len = 0;
    out_len = 0;
    std::cout << std::endl << std::endl;
  }
}