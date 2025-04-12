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
# include <stdlib.h>
# include <unistd.h>
# include <netinet/ether.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>
# include <netdb.h>
# include <argp.h>
# include <error.h>
# include <math.h>
# include <signal.h>
# include <stdlib.h>

# define MAXSCANS   6

# define SCAN_SYN   0x0001
# define SCAN_NULL  0x0002
# define SCAN_FIN   0x0004
# define SCAN_XMAS  0x0008
# define SCAN_ACK   0x0010
# define SCAN_UDP   0x0020
# define SCAN_ALL   0x003F

struct scan_mode
{
  const char *name;
  short flag;
};

enum e_port_state
{
  PORT_UNKNOWN,
  PORT_CLOSED,
  PORT_OPEN,
  PORT_FILTERED,
  PORT_OPENFILTERED,
  PORT_CLOSEDFILTERED
};

typedef enum e_port_state t_port_state;

struct s_port
{
  unsigned short port_number;
  unsigned char port_protocol;
  unsigned char *port_owner;
  struct s_port *next;
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
