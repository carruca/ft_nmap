#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <sys/types.h>
# include <sys/time.h>
# include <sys/select.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <stdio.h>
# include <errno.h>
# include <string.h>
# include <unistd.h>
# include <netinet/ether.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>
# include <netdb.h>
# include <error.h>
# include <math.h>
# include <signal.h>
# include <stdlib.h>

# define MAXSCANS   1

# define SCAN_SYN   0x0001
# define SCAN_NULL  0x0002
# define SCAN_FIN   0x0004
# define SCAN_XMAS  0x0008
# define SCAN_ACK   0x0010
# define SCAN_UDP   0x0020
# define SCAN_ALL   0x003F

# define MAXSTATES          5

# define PORT_CLOSED        0x0001
# define PORT_OPEN          0x0002
# define PORT_FILTERED      0x0004
# define PORT_UNFILTERED    0x0008
# define PORT_OPENFILTERED  0x0010

struct nmap_data
{
	struct sockaddr_in dst_sockaddr;
	struct sockaddr_in src_sockaddr;
	pid_t id;
};

struct scan_mode
{
  const char *name;
  short option;
  int (*encode_and_send)(
    char *, size_t,
    struct sockaddr_in *, struct sockaddr_in *,
    short, int);
};

struct s_port_state
{
  const char *name;
  short option;
};

typedef struct s_port_state t_port_state;

struct s_port
{
  unsigned short portno;
  unsigned char proto;
  short state;
  char *service_name;
};

typedef struct s_port t_port;

struct s_scan_config
{
  struct in_addr target_addr;
  unsigned int number_of_ports;
  short scan_type;
};

typedef struct s_scan_config t_scan_config;

#endif
