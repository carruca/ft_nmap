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
# include <netdb.h>
# include <stdlib.h>
# include <limits.h>

# define MAXSCANS 5

# define MAXPORTS 1024
# define MINPORTS 1

# define MAXTHREADS 250

# define DEFAULT_PORT_RANGE "1-1024"

# define PCAP_BUFSIZ USHRT_MAX // 65535
# define MAX_RETRIES 3
# define MAX_PORTSTATES 7
# define WINDOW_SIZE 20

# define IP_HLEN (sizeof(struct ip) >> 2)
# define TCP_HLEN (sizeof(struct tcphdr) >> 2)

# define IP_STRLEN 16

# define PROMISC_TRUE	1
# define PROMISC_FALSE 0
# define ETH0 1

# define FILTER_STRLEN 512
# define NULL_HDR_LEN  4

# define MAX_PORTS_PER_SCAN 1024

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

// Result codes for scan functions
typedef enum e_scan_result
{
    SCAN_RESULT_SUCCESS = 0,
    SCAN_RESULT_FAILURE = 1,
    SCAN_RESULT_CTX_NULL = 2,
} t_scan_result;

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

struct s_rtt
{
  double srtt;
  double rrtvar;
  double timeout;
  int num_responses;
};

typedef struct s_rtt t_rtt;

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

  struct timeval time_sent;
  struct timeval time_recv;
  double timeout;
  int retries;

  char *service_name;
  t_port_state result;
};

typedef struct s_probe t_probe;

typedef struct s_scan_thread t_scan_thread;

struct s_opts
{
  unsigned short num_threads;
  t_scan_type scan_flag;
  int verbose;
  int debugging;
  char *target;
  char *filename;
  char *portlist;
  char *program_name;
  struct sockaddr_in source_addr;
  char **file_targets;
  int num_file_targets;
};

typedef struct s_opts t_opts;

// Scan context structure
struct s_engine
{
  unsigned int probes_total;
  t_opts *opts;
  t_list *probes;
  t_list *probes_pending;
  struct sockaddr_in dst;
  t_rtt timing;
};

typedef struct s_engine t_engine;

struct s_scan_thread
{
  pthread_t thread;
  int thread_id;

  int tcp_sock;
  int udp_sock;

  pcap_t *pcap_handle;
  int     datalink;
  struct bpf_program bpf_filter;
  char filter_expr[FILTER_STRLEN];

  int sport_base;
  int sport_range;

  t_probe **probes;

  struct sockaddr_in dst;

  t_opts *opts;
};

// Function prototypes
pcap_t *get_pcap_handle(t_opts *opts, int *datalink);
t_list *probes_create(uint16_t *ports, uint16_t num_ports, char *target_ip, double timeout);
void scan_probe_list_destroy(t_engine *scan_eng);
void scan_options_destroy(t_opts *opts);
void scan_init(t_engine *scan_eng);
int set_pcap_filter(pcap_t *pcap_handle, char *filter_exp);
void scan_options_parse(t_opts *scan_options, int *arg_index, int argc, char **argv);
t_scan_type get_scan_type_by_name(char *expr);
void ip_file_parse(t_opts *opts, const char *filename);
void print_usage(char *name);
void scan_destroy(t_engine *scan_eng);
int get_raw_socket_by_protocol(const char *protocol_name);
int probe_send_syn(t_scan_thread *info, t_probe *probe, t_opts *opts, uint16_t sport);
int packet_match_probe(t_scan_thread *info, struct timeval ts, const u_char *pkt_data);
int scan_source_sockaddr_set(struct sockaddr_in *sockaddr);
int scan_target_sockaddr_set(struct sockaddr_in *sockaddr, const char *hostname);
void scan_config_print(const t_engine *scan_eng, int num_ports);
unsigned short tcp_checksum(const struct sockaddr_in *src_sockaddr, const struct sockaddr_in *dst_sockaddr, const struct tcphdr *th);
unsigned short checksum(char *buffer, size_t bufsize);
unsigned short *get_ports(char *expr, unsigned short *number_of_ports);

void error(int status, int errnum, const char *format, ...);
int  fqdn_is_valid(const char *str);
const struct scan_mode *get_scan_mode(int index);
void scan_run(t_engine *scan_eng, t_opts *scan_options);
void scan_options_program_name_set(t_opts *scan_options, const char *program_name);
t_engine *scan_create();

// Probe management functions
t_probe *probe_new(char *target_ip, uint16_t target_port, double timeout);
int scan_thread_init(t_scan_thread *info, int thread_id, t_opts *config);
int scan_thread_run(t_scan_thread *info, t_opts *opts);
void *scan_thread_entry(void *data);
int scan_threads_dispatch(t_scan_thread *infos, t_list **pending_list, t_engine *ctx, t_opts *config);
t_probe **probes_dequeue(t_list **pending_node, int num_probes);

#endif /* FT_NMAP_H */
