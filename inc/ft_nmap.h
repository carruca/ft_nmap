#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "libft.h"
# include <pcap.h>
# include <pthread.h>
#include <stdint.h>
# include <sys/types.h>
# include <sys/time.h>
# include <sys/select.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <stdio.h>
# include <string.h>
# include <unistd.h>
# include <netinet/ether.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netdb.h>
# include <stdlib.h>
# include <limits.h>

# define MAXPORTS 1024

# define MAXTHREADS 250

# define DEFAULT_PORT_RANGE "1-1024"

# define PCAP_BUFSIZ USHRT_MAX
# define MAX_RETRIES 3
# define WINDOW_SIZE 20

# define TCP_HLEN (sizeof(struct tcphdr) >> 2)

# define IP_STRLEN 16

# define PROMISC_TRUE	1

# define FILTER_STRLEN 512
# define NULL_HDR_LEN  4

# define MAX_PORTS_PER_SCAN 1024

# define TCP_WINDOW_SIZE    1024
# define SPORT_MIN          1024
# define SPORT_RAND_PRIME   7919
# define SELECT_TIMEOUT_US  10000

typedef enum e_scan_type
{
    SCAN_UNDEFINED = 0x0000,
    SCAN_SYN = 0x0001,
    SCAN_NULL = 0x0002,
    SCAN_FIN = 0x0004,
    SCAN_XMAS = 0x0008,
    SCAN_ACK = 0x0010,
    SCAN_UDP = 0x0020,
    SCAN_ALL = 0x003f,
} t_scan_type;

typedef enum e_scan_proto
{
    PROTO_TCP = 0,
    PROTO_UDP = 1,
} t_scan_proto;

enum e_port_state
{
  PORT_OPEN = 0,
  PORT_CLOSED,
  PORT_FILTERED,
  PORT_UNFILTERED,
  PORT_OPENFILTERED
};

typedef enum e_port_state t_port_state;

typedef struct s_scan_def
{
    const char    *name;
    t_scan_type    flag;
    t_scan_proto   proto;
    uint8_t        tcp_flags;
    t_port_state (*classify)(uint8_t tcp_flags);
} t_scan_def;

enum e_probe_status
{
  PROBE_PENDING = 0,
  PROBE_SENT,
  PROBE_REPLIED,
  PROBE_TIMEOUT
};

typedef enum e_probe_status t_probe_status;

struct s_probe
{
  char dst_ip[IP_STRLEN];
  uint16_t dst_port;
  uint16_t src_port;
  t_probe_status status;
  t_scan_type scan_type;

  struct timeval time_sent;
  struct timeval time_recv;
  double timeout;
  int retries;

  t_port_state result;
};

typedef struct s_probe t_probe;

typedef struct s_scan_thread t_scan_thread;

struct s_scan_opts
{
  unsigned short num_threads;
  t_scan_type scan_flag;
  int verbose;
  char *filename;
  char *portlist;
  char *program_name;
  struct sockaddr_in source_addr;
  char *target;
  char **targets;
  int num_targets;
};

typedef struct s_scan_opts t_scan_opts;

struct s_scan_ctx
{
  unsigned int probes_total;
  t_list *probes;
  struct sockaddr_in dst;
  double timeout;
  unsigned short *ports;
  unsigned short num_ports;
};

typedef struct s_scan_ctx t_scan_ctx;

struct s_scan_thread
{
  pthread_t thread;
  int thread_id;

  int tcp_sock;
  int udp_sock;

  pcap_t *pcap_handle;
  int     datalink;
  char filter_expr[FILTER_STRLEN];

  int sport_base;

  t_probe **probes;

  struct sockaddr_in dst;

  t_scan_opts *opts;
};

pcap_t *get_pcap_handle(t_scan_opts *opts, int *datalink);
t_list *probe_list_create(uint16_t *ports, uint16_t num_ports, char *target_ip, double timeout, t_scan_type scan_flag);
void probe_list_destroy(t_scan_ctx *ctx);
void scan_opts_destroy(t_scan_opts *opts);
int set_pcap_filter(pcap_t *pcap_handle, char *filter_exp);
void scan_opts_parse(t_scan_opts *opts, int *arg_index, int argc, char **argv);
t_scan_type get_scan_type_by_name(char *expr);
void ip_file_parse(t_scan_opts *opts, const char *filename);
void print_usage(char *name);
void scan_destroy(t_scan_ctx *ctx);
int get_raw_socket_by_protocol(const char *protocol_name);
int probe_send(t_scan_thread *thread, t_probe *probe, t_scan_opts *opts, uint16_t sport);
void probe_mark_sent(t_probe *probe, uint16_t sport);
int probe_send_tcp(t_scan_thread *thread, t_probe *probe, t_scan_opts *opts, uint16_t sport);
int probe_send_udp(t_scan_thread *thread, t_probe *probe, t_scan_opts *opts, uint16_t sport);
int probe_match(t_probe *probe, struct timeval ts, const u_char *pkt_data, uint32_t caplen, int datalink);
int scan_detect_source(struct sockaddr_in *sockaddr, const struct sockaddr_in *dst);
int scan_resolve_target(struct sockaddr_in *sockaddr, const char *hostname);
void scan_config_print(const t_scan_ctx *ctx, const t_scan_opts *opts, int num_ports);
void scan_results_print(t_scan_thread *threads, int num_threads, const char *target, double scan_duration);
unsigned short tcp_checksum(const struct sockaddr_in *src_sockaddr, const struct sockaddr_in *dst_sockaddr, const struct tcphdr *th);
unsigned short checksum(char *buffer, size_t bufsize);
unsigned short *get_ports(char *expr, unsigned short *number_of_ports);

void error(int status, int errnum, const char *format, ...);
int  fqdn_is_valid(const char *str);
const t_scan_def *scan_def_by_flag(t_scan_type flag);
const t_scan_def *scan_def_by_index(int index);
void scan_run(t_scan_ctx *ctx, t_scan_opts *opts);
t_scan_ctx *scan_create();

t_probe *probe_new(char *target_ip, uint16_t target_port, double timeout);
int count_probes(t_probe **probes);
void scan_thread_destroy(t_scan_thread *thread);
int scan_thread_init(t_scan_thread *thread, int thread_id, t_scan_opts *config);
int scan_thread_run(t_scan_thread *thread, t_scan_opts *opts);
void *scan_thread_entry(void *data);
int scan_thread_dispatch(t_scan_thread *threads, t_list **pending_list, t_scan_ctx *ctx, t_scan_opts *config);
t_probe **probe_dequeue(t_list **pending_node, int num_probes);

#endif
