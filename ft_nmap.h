#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "libft.h"
# include <arpa/inet.h>
# include <error.h>
# include <netdb.h>
# include <netinet/ether.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>
# include <pcap.h>
# include <pthread.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <sys/select.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <unistd.h>
# include <sys/types.h>

# define MAXSCANS 1

# define SCAN_SYN 0x0001
# define SCAN_NULL 0x0002
# define SCAN_FIN 0x0004
# define SCAN_XMAS 0x0008
# define SCAN_ACK 0x0010
# define SCAN_UDP 0x0020
# define SCAN_ALL 0x003F

# define PCAP_BUFSIZ USHRT_MAX // 65535
# define MAX_RETRIES 3
# define MAX_PORTSTATES 7
# define MAX_PKTQUEUE 1024
# define PROBE_BATCH_MAXSIZE 10

# define FILTER_STRLEN 512

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
  int (*encode_and_send)(char *, size_t, struct sockaddr_in *,
                         struct sockaddr_in *, short, int);
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
  uint8_t *data;
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

typedef struct s_scan_worker t_scan_worker;

struct s_scan_engine
{
  int raw_socket;
  uint32_t total_probes;
  uint32_t outstanding_probes;
  unsigned int max_outstanding;
  unsigned int completed_probes;
  t_scan_options *opts;
  t_list *probe_list;
  t_list *pending_probe_list;
  pcap_t *pcap_handle;
  struct sockaddr_in source;
  struct sockaddr_in target;
  t_timing_info global_timing;

  int capture_active;
  t_packet_queue *capture_queue;
  pthread_t capture_thread;
  pthread_t *worker_threads;

  t_scan_worker *send_workers;

  pthread_mutex_t engine_mutex;
  pthread_mutex_t probe_mutex;
};

typedef struct s_scan_engine t_scan_engine;

struct s_scan_worker
{
  int thread_id;
  int tcp_socket;
  pthread_t thread;

  t_probe *probe_batch[PROBE_BATCH_MAXSIZE];
  /*
  char packet_tcp_template[sizeof(struct tcphdr)];
  size_t template_size;
*/
  int active;

  t_scan_engine *engine;
};

struct s_scan_config
{
  int use_threads;
  int max_threads;
  int verbose;
  int packet_delay_us;
  int capture_timeout_ms;
};

typedef struct s_scan_config t_scan_config;

struct s_port_scan
{
  int scan_id;

  int tcp_raw_socket;
  int udp_raw_socket;

  char *interface;
  pcap_t *pcap_handle;
  struct bpf_program bpf_filter;
  char filter_str[FILTER_STRLEN];

  int source_port_base;
  int source_port_range;
  int current_source_port;

  char **target_ips;
  int num_targets;
  int *target_ports;
  int num_ports;

  int packets_sent;
  int packets_received;
  int ports_open;
  int ports_closed;
  int ports_filtered;
  int ports_unfiltered;
  int ports_openfiltered;
  int scan_complete;

  t_scan_config *config;
};

typedef struct s_port_scan t_port_scan;

#endif
