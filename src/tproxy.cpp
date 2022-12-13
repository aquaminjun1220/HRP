#include <stdio.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <map>
#include <signal.h>
#include "tproxy.hpp"


typedef void handler_t(int);
static std::map<int, int> omap;

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

static void init_proxy(char *dev)
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

static int osock_set(int oport)
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
    return osock;
}

static int rawsock_set(int oport)
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
    return osock;
}

static int get_sock_port(int sock)
{
    struct sockaddr_in sock_addr;
    socklen_t addrlen = sizeof(sock_addr);
    getsockname(sock, (sockaddr *)(&sock_addr), &addrlen);
    return ntohs(sock_addr.sin_port);
}

static void nft_includeSIP(int sport)
{
    if (omap.contains(sport))
        return;
    char buffer[96];
    sprintf(buffer, "nft add element HRP inc_portSIP { %d }", sport);
    system(buffer);
    std::cout << "INFO: port " << sport << " is now routed to proxy" << std::endl;
    int oport, osock;
    oport = 10000 + sport;
    osock = osock_set(oport);
    omap[sport] = osock;

    sprintf(buffer, "nft add rule HRP postroutingSIP udp sport %d udp sport set %d notrack", oport, sport);
    system(buffer);
    std::cout << "INFO: oport " << oport << " is now statelessly snat to " << sport << std::endl;
}

static void nft_includeRTP(int sport)
{
    if (omap.contains(sport))
        return;
    char buffer[96];
    sprintf(buffer, "nft add element HRP inc_portRTP { %d }", sport);
    system(buffer);
    std::cout << "INFO: port " << sport << " is now routed to proxy" << std::endl;
    int oport, osock;
    oport = 10000 + sport;
    osock = osock_set(oport);
    omap[sport] = osock;

    sprintf(buffer, "nft add rule HRP postroutingRTP udp sport %d udp sport set %d notrack", oport, sport);
    system(buffer);
    std::cout << "INFO: oport " << oport << " is now statelessly snat to " << sport << std::endl;
}

static void nft_flushRTP()
{
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

static void process_bmsg(uint8_t *in_buffer, uint8_t *out_buffer, int in_len)
{
  //struct iphdr ip;
  //struct udphdr udp;

  //memcpy(in_buffer, &ip, sizeof(struct iphdr));
  //memcpy(in_buffer + sizeof(struct udphdr), &udp, sizeof(struct udphdr));

  std::cout << std::hex << std::setfill('0');
  for (int i = 0; i < in_len; ++i)
  {
    if (i % 4 == 0)
    {
      std::cout << std::endl;
    }
    std::cout << std::setw(2) << static_cast<unsigned>(static_cast<uint8_t>(in_buffer[i])) << " ";
  }
  std::cout << std::endl;

}

/**
 * 60 00 00 00 
 * 00 08 3a ff 
 * 
 * fe 80 00 00 
 * 00 00 00 00
 * f7 60 dd e8 
 * 47 d6 5d 11 
 * 
 * ff 02 00 00 
 * 00 00 00 00
 * 00 00 00 00 
 * 00 00 00 02 
 * 
 * 85 00 03 06 
 * 00 00 00 00

*/

int main()
{
  char dev[IF_NAMESIZE] = "tun10";
  int tun;
  uint8_t in_buffer[2000];
  int in_len;
  uint8_t out_buffer[2000];
  int out_len;

  std::cout << "Press any key to start" << std::endl;
  std::cin.get();


  tun = open_tun(dev);
  init_proxy(dev);
  Signal(SIGINT, sigINThandler);

  nft_includeSIP(5060);

  while (1)
  {
    std::cout << "Trying to read..." << std::endl;
    in_len = cread(tun, in_buffer, 2000);
    process_bmsg(in_buffer, out_buffer, in_len); 
    memset(in_buffer, 0, sizeof(in_buffer));
  }
}