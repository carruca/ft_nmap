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

enum e_scan_type
{
  SCAN_ALL = 0,
  SCAN_SYN,
  SCAN_NULL,
  SCAN_ACK,
  SCAN_FIN,
  SCAN_XMAS,
  SCAN_UDP
};

typedef enum e_scan_type t_scan_type;

struct s_port_scan
{
  t_scan_type type;
  t_port_state state;
};

typedef struct s_port_scan t_port_scan;

struct s_port
{
  unsigned short portno;
  unsigned char proto;
  unsigned char *owner;
};

typedef struct s_port t_port;

#endif
