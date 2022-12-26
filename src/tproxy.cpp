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

#define verbose 0

#if verbose
#define LOG(str) std::cout << str << std::endl
#endif

#if !verbose
#define LOG(str)
#endif


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
static int rtpport;
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
  sprintf(buffer, "ip route add default dev %s table 77", dev);
  system(buffer);
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
    LOG("--------    IPV4 Header Info    --------");
    char addr[64];
    inet_ntop(AF_INET, &(ip->saddr), addr, sizeof(addr));
    LOG("Source Address: " << addr);
    inet_ntop(AF_INET, &(ip->daddr), addr, sizeof(addr));
    LOG("Destination Address: " << addr);
    sai->sin_family = AF_INET;
    sai->sin_addr.s_addr = ip->daddr;
    sai->sin_port = 0;
    if (ip->protocol != IPPROTO_UDP)
    {
      LOG("--------     non-UDP Packet     --------");
      return -1;
    }
  }

  // network protocol is IPV6, copy IPV6 header to out_buffer
  else if (version == 6<<4)
  {
    struct ip6_hdr *ip6 = reinterpret_cast<struct ip6_hdr *>(iptr);
    iptr += sizeof(struct ip6_hdr);
    LOG("--------    IPV6 Header Info    --------");
    char addr[64];
    inet_ntop(AF_INET6, &(ip6->ip6_src), addr, sizeof(addr));
    LOG("Source Address: " << addr);
    inet_ntop(AF_INET6, &(ip6->ip6_dst), addr, sizeof(addr));
    LOG("Destination Address: " << addr);
    LOG("--------   IPV6 not supported   --------");
    return -1;
  }

  else
  {
    LOG("--------     non-IP Packet      --------");
    return -1;
  }

  // transport protocol is UDP
  struct udphdr *udp = reinterpret_cast<struct udphdr *>(iptr);
  iptr += sizeof(struct udphdr);
  udp->check = 0;
  LOG("--------    UDP Header Info     --------");
  LOG("Source Port: " << ntohs(udp->source));
  LOG("Destination Port: " << ntohs(udp->dest));

  // application is SIP, copy udp header and payload to out_buffer, modify source port.
  // do some SIP specific stuff
  if (ntohs(udp->source) == 5060)
  {
    LOG("--------       SIP Packet       --------");
    std::string sipmsg((char *)(iptr), in_len);
    std::string method = find_method(sipmsg);
    LOG("SIP Method: " << method);
    if ((method == "INVITE") || (method == "200 OK INVITE"))
    {
      int i = sipmsg.find("\r\n\r\n", 0);
      i = sipmsg.find("m=audio", i+1);
      i = sipmsg.find(" ", i+1);
      int j = sipmsg.find(" ", i+1);
      std::string new_rtpport = sipmsg.substr(i+1, j-(i+1));
      sprintf(buffer, "nft add element HRP inc_portRTP \"{ %s }\" ", new_rtpport.c_str());
      system(buffer);
      rtpport = stoi(new_rtpport);
      LOG("INFO: Detected INVITE. Adding port " << new_rtpport << " to rtp port set.");
    }
    else if ((method == "BYE") || (method == "CANCEL") || (method == "200 OK BYE") || (method == "200 OK CANCEL"))
    {
      system("nft flush set HRP inc_portRTP");
      rtpport = 0;
      LOG("INFO: Detected BYE-ish. Flushing rtp port set.");
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
    LOG("--------    RTP Packet    --------");
    return iptr + 12 - in_buffer;
  }
  else
    return 0;
}

int main()
{
  std::cout << "-------- Press any key to start --------" << std::endl;
  std::cin.get();

  int pipes[10];
  pipe(pipes);
  pipe(pipes+2);
  pipe(pipes+4);
  pipe(pipes+6);
  pipe(pipes+8);

  if (!Fork())
  {
    LOG("INFO: Starting child 1 - RTP PCMU -> PCM");
    int devnull = open("/dev/null", O_RDWR);
    dup2(pipes[0], 0);
    dup2(pipes[3], 1);
    dup2(devnull, 2);

    close(pipes[0]);
    close(pipes[1]);
    close(pipes[2]);
    close(pipes[3]);
    close(pipes[4]);
    close(pipes[5]);
    close(pipes[6]);
    close(pipes[7]);
    close(pipes[8]);
    close(pipes[9]);

    char *args[] = {"ffmpeg", "-f", "mulaw", "-c:a", "pcm_mulaw", "-ar", "8000", "-ac", "1", "-probesize", "32", "-analyzeduration", "0", "-fflags", "nobuffer",  "-i", "pipe:0", "-f", "s16le", "-c:a", "pcm_s16le", "-ar", "8000", "-ac", "1", "-packetsize", "160", "-fflags", "flush_packets", "-flush_packets", "1", "pipe:", NULL};
    if (execvp(*args, args) < 0)
    {
      perror("ERROR: Failed to start child 1 - RTP PCMU -> PCM");
      exit(-1);
    }
  }

  if (0)
  {
    LOG("INFO: Starting child 2 - PCM -> play");
    dup2(pipes[2], 0);
    //dup2(pipes[5], 1);

    close(pipes[0]);
    close(pipes[1]);
    close(pipes[2]);
    close(pipes[3]);
    close(pipes[4]);
    close(pipes[5]);
    close(pipes[6]);
    close(pipes[7]);
    close(pipes[8]);
    close(pipes[9]);

    char *args[] = {"aplay", "-f", "S16_LE", "-c", "1", "-r", "8000", NULL};
    if (execvp(*args, args) < 0)
    {
      perror("ERROR: Failed to start child 1 - PCM -> play");
      exit(-1);
    }
  }

  if (!Fork())
  {
    LOG("INFO: Starting child 2 - PCM -> count");
    dup2(pipes[2], 0);
    //dup2(pipes[5], 1);

    close(pipes[0]);
    close(pipes[1]);
    close(pipes[2]);
    close(pipes[3]);
    close(pipes[4]);
    close(pipes[5]);
    close(pipes[6]);
    close(pipes[7]);
    close(pipes[8]);
    close(pipes[9]);

    char *args[] = {"./build/BB", NULL};
    if (execvp(*args, args) < 0)
    {
      perror("ERROR: Failed to start child 1 - PCM -> count");
      exit(-1);
    }
  }

  char dev[IF_NAMESIZE] = "tun10";
  int tun, rsock;
  tun = open_tun(dev);
  rsock = rawsock_set();

  init_rules(dev);
  Signal(SIGINT, sigINThandler);

  sockaddr_in sai;
  uint8_t in_buffer[2000];
  int in_len, offset;

  sai.sin_family = AF_INET;
  sai.sin_addr.s_addr = 0;
  sai.sin_port = 0;

  int tmpfd = open("./audio/ntrd.mu", O_CREAT|O_RDWR, S_IRWXU);

  while (1)
  {
    in_len = cread(tun, in_buffer, 2000);
    LOG("!!------    Received packet     ------!!");
    LOG(std::endl);
    offset = process_bmsg(in_buffer, &sai, in_len);
    if (offset == 0)
    {
      sendto(rsock, in_buffer, in_len, 0, (sockaddr *)(&sai), sizeof(sockaddr_in));
    }
    else if (offset > 0)
    {
      if (write(pipes[1], in_buffer+offset, in_len-offset) < 0)
        perror("ERROR: Something went wrong with write to pipe");
      if (write(tmpfd, in_buffer+offset, in_len-offset) < 0)
        perror("ERROR: Something went wrong with write to pipe");
      sendto(rsock, in_buffer, in_len, 0, (sockaddr *)(&sai), sizeof(sockaddr_in));
    }
    memset(in_buffer, 0, sizeof(in_buffer));
    in_len = 0;
    offset = 0;
    LOG(std::endl);
  }
}