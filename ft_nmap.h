#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "libft.h"
# include <pcap.h>
# include <pthread.h>
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

# define PCAP_BUFSIZ USHRT_MAX // 65535
# define MAX_RETRIES 3
# define MAX_PORTSTATES 7
# define MAX_PKTQUEUE 1024

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

struct s_packet
{
  u_char *data;
  size_t size;
  struct timeval ts;
};

typedef struct s_packet t_packet;

struct s_packet_queue
{
  int count;
  int shutdown;
  t_list *head;
  t_list *tail;
  pthread_mutex_t mutex;
  pthread_cond_t not_empty;
  pthread_cond_t not_full;
};

typedef struct s_packet_queue t_packet_queue;

struct s_scan_options
{
  unsigned short num_threads;
  short scan_flag;
  int verbose;
  int debugging;
  char *target;
  char *filename;
  char *portlist;
};

typedef struct s_scan_options t_scan_options;

struct s_scan_engine
{
  int raw_socket;
  unsigned int total_probes;
  unsigned int outstanding_probes;
  unsigned int max_outstanding;
  unsigned int completed_probes;
  t_scan_options *opts;
  t_list *probe_list;
  pcap_t *pcap_handle;
  struct sockaddr_in source;
  struct sockaddr_in target;
  t_timing_info global_timing;

  int capture_active;
  t_packet_queue *capture_queue;
  pthread_t capture_thread;
  pthread_t *worker_threads;
  pthread_mutex_t engine_mutex;
};

typedef struct s_scan_engine t_scan_engine;

#endif
