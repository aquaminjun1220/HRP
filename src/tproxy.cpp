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

#define verbose 1
#define filelog 1

#if verbose >= 1
#define LOG(str) std::cout << str << std::endl; logfd << str << std::endl
#else
#define LOG(str) logfd << str << std::endl
#endif

#if verbose >= 2
#define LOG2(str) std::cout << str << std::endl
#else
#define LOG2(str)
#endif

#if filelog
#define FLOG(str) logfd << str << std::endl
#else
#define FLOG(str)
#endif


typedef void handler_t(int);
static char sprintf_buf[128];
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
static std::fstream logfd("./log/log.txt", std::ios::out | std::ios::trunc);

static int rtpport;
static int open_tun(char *);
static void init_rules(char *);
static int rawsock_set();
static int cread(int, void *, int);
static int nread(int, void *, int);
static int cwrite(int, void *, int);
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
  LOG("INFO: opened tun");

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
  LOG("INFO: intialized tun");

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
  LOG("INFO: setted tun");
  return fd;
}

static void init_rules(char *dev)
{
  system("ip rule add fwmark 77 table 77");
  sprintf(sprintf_buf, "ip route add default dev %s table 77", dev);
  system(sprintf_buf);
  system("nft add table ip HRP");
  system("nft add set HRP inc_portSIP \"{ type inet_service ; }\"");
  system("nft add element HRP inc_portSIP \"{ 5060 }\" ");
  system("nft add set HRP inc_portRTP \"{ type inet_service ; }\"");
  system("nft add chain HRP output \"{ type route hook output priority 0 ; }\"");
  system("nft add rule HRP output meta mark != 10 udp sport @inc_portSIP meta mark set 77");
  system("nft add rule HRP output meta mark != 10 udp sport @inc_portRTP meta mark set 77");
  LOG("INFO: advanced routing initialized");
  LOG("INFO: sniffing on port 5060 for SIP packets");
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
  LOG("INFO: setted raw socket");
  if (setsockopt(rsock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
  {
      perror("ERROR: Failed to set SO_MARK");
      kill(0, SIGINT);
  }
  LOG("INFO: starting to mark raw sockets");
  return rsock;
}

static int cread(int fd, void *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("ERROR: Reading data");
    kill(0, SIGINT);
  }
  return nread;
}

static int nread(int fd, void *buf, int n)
{
  int ret = n;
  uint8_t *ptr = (uint8_t *)buf;
  int len = 0;
  while (n > 0)
  {
    len = cread(fd, ptr, n);
    ptr += len;
    n -= len;
  }
  return ret;
}

static int cwrite(int fd, void *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    perror("ERROR: Writing data");
    kill(0, SIGINT);
  }
  return nwrite;
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
  LOG("INFO: advanced routing terminated");
  sigprocmask(SIG_SETMASK, &prev_mask, NULL);
  errno = olderrno;
  exit(0);
}

handler_t *Signal(int signum, handler_t *handler)
{
  struct sigaction action, old_action;
  LOG("INFO: installing SIGINT handler");
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

/**
 * static int process_bmsg(uint8_t *in_buffer, struct sockaddr_in *sai, int in_len)
 * 
 * args:
 * uint8_t *in_buffer - received bytes
 * struct sockaddr_in *sai - destination of the packet (process_bmsg modifies the struct pointed by sai according to the packet headers)
 * int in_len - length of received bytes\
 * 
 * returns:
 * if packet is a rtp packet, returns the offset to RTP payload
 * else if packet is a sip invite-like, returns -1
 * else if packet is a sip bye-like, returns -2
 * else if packet should be sent to its destination whatever it is, returns 0
 * else packet should be ignored, returns -3
*/
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
    LOG2("--------    IPV4 Header Info    --------");
    char addr[64];
    inet_ntop(AF_INET, &(ip->saddr), addr, sizeof(addr));
    LOG2("Source Address: " << addr);
    inet_ntop(AF_INET, &(ip->daddr), addr, sizeof(addr));
    LOG2("Destination Address: " << addr);
    sai->sin_family = AF_INET;
    sai->sin_addr.s_addr = ip->daddr;
    sai->sin_port = 0;
    if (ip->protocol != IPPROTO_UDP)
    {
      LOG2("--------     non-UDP Packet     --------");
      return -3;
    }
  }

  // network protocol is IPV6, copy IPV6 header to out_buffer
  else if (version == 6<<4)
  {
    struct ip6_hdr *ip6 = reinterpret_cast<struct ip6_hdr *>(iptr);
    iptr += sizeof(struct ip6_hdr);
    LOG2("--------    IPV6 Header Info    --------");
    char addr[64];
    inet_ntop(AF_INET6, &(ip6->ip6_src), addr, sizeof(addr));
    LOG2("Source Address: " << addr);
    inet_ntop(AF_INET6, &(ip6->ip6_dst), addr, sizeof(addr));
    LOG2("Destination Address: " << addr);
    LOG2("--------   IPV6 not supported   --------");
    return -3;
  }

  else
  {
    LOG2("--------     non-IP Packet      --------");
    return -3;
  }

  // transport protocol is UDP
  struct udphdr *udp = reinterpret_cast<struct udphdr *>(iptr);
  iptr += sizeof(struct udphdr);
  udp->check = 0;
  LOG2("--------    UDP Header Info     --------");
  LOG2("Source Port: " << ntohs(udp->source));
  LOG2("Destination Port: " << ntohs(udp->dest));

  // application is SIP, copy udp header and payload to out_buffer, modify source port.
  // do some SIP specific stuff
  if (ntohs(udp->source) == 5060)
  {
    LOG("--------       SIP Packet       --------");
    std::string sipmsg((char *)(iptr), in_len);
    std::string method = find_method(sipmsg);
    LOG2("SIP Method: " << method);
    if ((method == "INVITE") || (method == "200 OK INVITE"))
    {
      int i = sipmsg.find("\r\n\r\n", 0);
      i = sipmsg.find("m=audio", i+1);
      i = sipmsg.find(" ", i+1);
      int j = sipmsg.find(" ", i+1);
      std::string new_rtpport = sipmsg.substr(i+1, j-(i+1));
      sprintf(sprintf_buf, "nft add element HRP inc_portRTP \"{ %s }\" ", new_rtpport.c_str());
      system(sprintf_buf);
      rtpport = stoi(new_rtpport);
      LOG2("INFO: Detected INVITE-like. Adding port " << new_rtpport << " to rtp port set.");
      return -1;
    }
    else if ((method == "BYE") || (method == "CANCEL") || (method == "200 OK BYE") || (method == "200 OK CANCEL"))
    {
      system("nft flush set HRP inc_portRTP");
      rtpport = 0;
      LOG2("INFO: Detected BYE-like. Flushing rtp port set.");
      return -2;
    }
    return 0;
  }
  else if (ntohs(udp->source) == rtpport)
  {
    if (*(reinterpret_cast<uint16_t *>(iptr)) != 0x0080)
    {
      LOG("--------   Invalid RTP Packet   --------");
      return 0;
    }
    LOG("--------       RTP Packet       --------");
    return iptr + 12 - in_buffer;
  }
  else
    return 0;
}

int main()
{
  std::cout << "-------- Press any key to start --------" << std::endl;
  std::cin.get();

  int pipes[5][2];
  pipe(pipes[0]);
  pipe(pipes[1]);
  pipe(pipes[2]);
  pipe(pipes[3]);
  pipe(pipes[4]);


  if (!Fork())
  {
    LOG("CHILD1: Starting child 1 - RTP PCMU -> PCM");
    dup2(pipes[0][0], 0);
    dup2(pipes[1][1], 1);
    int devnull = open("/dev/null", O_RDWR);
    dup2(devnull, 2);
    close(devnull);

    close(pipes[0][0]);
    close(pipes[0][1]);
    close(pipes[1][0]);
    close(pipes[1][1]);
    close(pipes[2][0]);
    close(pipes[2][1]);
    close(pipes[3][0]);
    close(pipes[3][1]);
    close(pipes[4][0]);
    close(pipes[4][1]);

    char *args[] = {"ffmpeg", "-f", "mulaw", "-c:a", "pcm_mulaw", "-ar", "8000", "-ac", "1", "-probesize", "32", "-analyzeduration", "0", \
    "-i", "pipe:", "-f", "s16le", "-c:a", "pcm_s16le", "-ar", "8000", "-ac", "1", "-packetsize", "160", "-fflags", "flush_packets", \
    "-flush_packets", "1", "pipe:", NULL};

    if (execvp(*args, args) < 0)
    {
      perror("ERROR: Failed to start child 1 - RTP PCMU -> PCM");
      exit(-1);
    }
  }
  if (!Fork())
  {
    LOG("CHILD2: Starting child 2 - PCM -> wt PCM");
    dup2(pipes[1][0], 0);
    dup2(pipes[2][1], 1);

    close(pipes[0][0]);
    close(pipes[0][1]);
    close(pipes[1][0]);
    close(pipes[1][1]);
    close(pipes[2][0]);
    close(pipes[2][1]);
    close(pipes[3][0]);
    close(pipes[3][1]);
    close(pipes[4][0]);
    close(pipes[4][1]);

    char *args[] = {"audiowmark", "add", "-", "-", "0123456789abcdef0011223344556677", "--format", "raw", "--raw-rate", "8000", "--raw-bits", "16",\
     "--raw-endian", "little", "--raw-encoding", "signed", "--raw-channels", "1", NULL};
    if (execvp(*args, args) < 0)
    {
      perror("ERROR: Failed to start child 2 - PCM -> wt PCM");
      exit(-1);
    }
  }
  if (!Fork())
  {
    LOG("CHILD3: Starting child 3 - wt PCM -> wt RTP PCMU");
    dup2(pipes[2][0], 0);
    dup2(pipes[3][1], 1);
    int devnull = open("/dev/null", O_RDWR);
    dup2(devnull, 2);

    close(pipes[0][0]);
    close(pipes[0][1]);
    close(pipes[1][0]);
    close(pipes[1][1]);
    close(pipes[2][0]);
    close(pipes[2][1]);
    close(pipes[3][0]);
    close(pipes[3][1]);
    close(pipes[4][0]);
    close(pipes[4][1]);

    char *args[] = {"ffmpeg", "-f", "s16le", "-c:a", "pcm_s16le", "-ar", "8000", "-ac", "1", "-probesize", "32", "-analyzeduration", "0", \
    "-i", "pipe:", "-f", "mulaw", "-c:a", "pcm_mulaw", "-ar", "8000", "-ac", "1", "-packetsize", "160", "-fflags", "flush_packets", \
    "-flush_packets", "1", "pipe:", NULL};
    if (execvp(*args, args) < 0)
    {
      perror("ERROR: Failed to start child 3 - wt PCM -> wt RTP PCMU");
      exit(-1);
    }
  }
  
  int rsock;
  rsock = rawsock_set();
  
  if (!Fork())
  {
    LOG("CHILD4: Starting child 4 - wt RTP PCMU -> network");
    dup2(pipes[3][0], 0);
    int metafd = pipes[4][0];

    close(pipes[0][0]);
    close(pipes[0][1]);
    close(pipes[1][0]);
    close(pipes[1][1]);
    close(pipes[2][0]);
    close(pipes[2][1]);
    close(pipes[3][0]);
    close(pipes[3][1]);
    
    close(pipes[4][1]);

    uint8_t out_buffer[2048];

    while (1)
    {
      int rtp_len, hdr_len;
      sockaddr_in sai;
      uint8_t *optr = out_buffer;
      nread(metafd, &rtp_len, sizeof(int));
      if (rtp_len < 0)
      {
        rtp_len = -rtp_len;
        FLOG("CHILD4: detected buffer flusher from pipe4");
        optr += nread(0, optr, rtp_len);
        memset(out_buffer, 0, sizeof(out_buffer));
        FLOG("CHILD4: flushed decoder buffer");
        continue;
      }

      nread(metafd, &sai, sizeof(sai));
      nread(metafd, &hdr_len, sizeof(int));
      optr += nread(metafd, optr, hdr_len);
      optr += nread(0, optr, rtp_len);
      sendto(rsock, out_buffer, optr - out_buffer, 0, (sockaddr *)(&sai), sizeof(sockaddr_in));
      FLOG("CHILD4: sent " << optr - out_buffer << " bytes of RTP packet to raw sock");
      memset(out_buffer, 0, sizeof(out_buffer));
    }
    exit(0);
  }

  char dev[IF_NAMESIZE] = "tun10";
  int tun;
  tun = open_tun(dev);

  init_rules(dev);
  Signal(SIGINT, sigINThandler);

  sockaddr_in sai;
  uint8_t in_buffer[2048];
  int in_len, offset;

  sai.sin_family = AF_INET;
  sai.sin_addr.s_addr = 0;
  sai.sin_port = 0;

  int tmpfd = open("./audio/ntrd.mu", O_CREAT|O_RDWR|O_TRUNC, S_IRWXU);

  while (1)
  {
    in_len = cread(tun, in_buffer, 2000);
    LOG2("!!------    Received packet     ------!!");
    LOG2(std::endl);
    offset = process_bmsg(in_buffer, &sai, in_len);

    if (offset == 0)
    {
      sendto(rsock, in_buffer, in_len, 0, (sockaddr *)(&sai), sizeof(sockaddr_in));
      FLOG("MAIN: sent " << in_len << " bytes of normal packet to raw sock");
    }

    else if (offset == -1)
    {
      sendto(rsock, in_buffer, in_len, 0, (sockaddr *)(&sai), sizeof(sockaddr_in));
      FLOG("MAIN: sent " << in_len << " bytes of INVITE-like packet to raw sock");
    }

    else if (offset == -2)
    {
      int flush_len = -1024;
      cwrite(pipes[0][1], in_buffer, -flush_len);
      FLOG("MAIN: sent " << -flush_len << " bytes of buffer flusher to pipe0");
      cwrite(pipes[4][1], (void *)&flush_len, sizeof(int));
      FLOG("MAIN: sent buffer flusher metadata to pipe4");
      sendto(rsock, in_buffer, in_len, 0, (sockaddr *)(&sai), sizeof(sockaddr_in));
      FLOG("MAIN: sent " << in_len << " bytes of BYE-like packet to raw sock");
    }

    else if (offset > 0)
    {
      int rtp_len = in_len - offset;
      cwrite(pipes[0][1], in_buffer+offset, rtp_len);
      FLOG("MAIN: sent " << rtp_len << " bytes of rtp payload to pipe0");
      cwrite(pipes[4][1], (void *)&rtp_len, sizeof(int));
      cwrite(pipes[4][1], &sai, sizeof(sai));
      cwrite(pipes[4][1], (void *)&offset, sizeof(int));
      cwrite(pipes[4][1], in_buffer, offset);
      FLOG("MAIN: sent rtp payload metadata to pipe4");
      cwrite(tmpfd, in_buffer+offset, rtp_len);
    }
    memset(in_buffer, 0, sizeof(in_buffer));
    in_len = 0;
    offset = 0;
    LOG2(std::endl);
  }
}