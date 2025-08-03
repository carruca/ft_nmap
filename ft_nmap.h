#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "libft.h"
# include <pcap.h>
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
/*
# define MAXSTATES          5

# define PORT_CLOSED        0x0001
# define PORT_OPEN          0x0002
# define PORT_FILTERED      0x0004
# define PORT_UNFILTERED    0x0008
# define PORT_OPENFILTERED  0x0010

# define MAX_OUTSTANDING_PROBES  100
# define MAX_PORTS               1024
# define INITIAL_TIMEOUT_MS      1000
# define MAX_RETRIES             3
*/

# define PCAP_BUFSIZ USHRT_MAX // 65535
# define MAX_RETRIES 3
# define MAX_PORTSTATES 7

struct nmap_data
{
	struct sockaddr_in dst_sockaddr;
	struct sockaddr_in src_sockaddr;
	pid_t id;
};

struct scan_mode
{
  const char *name;
  short flag;
  int (*encode_and_send)(
    char *, size_t,
    struct sockaddr_in *, struct sockaddr_in *,
    short, int);
};
/*
struct s_port_state
{
  const char *name;
  short option;
};

typedef struct s_port_state t_port_state;
*/
enum e_port_state
{
  PORT_UNKNOWN = 0,
  PORT_TESTING,
  PORT_OPEN,
  PORT_CLOSED,
  PORT_FILTERED,
  PORT_UNFILTERED,
  PORT_OPENFILTERED
};

typedef enum e_port_state t_port_state;

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

struct s_timing_info
{
  double srtt;
  double rrtvar;
  double timeout;
  int num_responses;
};

typedef struct s_timing_info t_timing_info;

struct s_probe
{
  unsigned short port;
  t_port_state state;
  struct timeval sent_time;
  struct timeval recv_time;
  int retries;
  int outstanding;
  t_timing_info timing;
};

typedef struct s_probe t_probe;

struct s_scan_options
{
  char *target;
  char *filename;
  char *portlist;
  short scan_flag;
  int verbose;
  int debugging;
};

typedef struct s_scan_options t_scan_options;

struct s_scan_engine
{
  t_list *probe_list;
  unsigned int total_probes;
  unsigned int outstanding_probes;
  unsigned int max_outstanding;
  unsigned int completed_probes;
  pcap_t *pcap_handle;
  int raw_socket;
  struct sockaddr_in source;
  struct sockaddr_in target;
  t_timing_info global_timing;
};

typedef struct s_scan_engine t_scan_engine;
#endif
