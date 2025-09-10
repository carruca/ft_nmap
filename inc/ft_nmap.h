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
# include <string.h>
# include <unistd.h>
# include <netinet/ether.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>
# include <netdb.h>
# include <error.h>
# include <stdlib.h>
# include <limits.h>

# define MAXSCANS   1

# define MAXPORTS 	1024
# define MINPORTS 						1

# define MAXTHREADS 					250

# define DEFAULT_PORT_RANGE 	"1-1024"

# define PCAP_BUFSIZ USHRT_MAX // 65535
# define MAX_RETRIES 3
# define MAX_PORTSTATES 7
# define MAX_PKTQUEUE 1024
# define PROBE_BATCH_MAXSIZE 10

# define IP_HLEN 						sizeof(struct ip) >> 2
# define TCP_HLEN 						sizeof(struct tcphdr) >> 2

# define PROMISC_TRUE				1
# define PROMISC_FALSE 			0
# define ETH0 								1

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
  t_scan_type scan_flag;
  int verbose;
  int debugging;
  char *target;
  char *filename;
  char *portlist;
  char *program_name;
};

typedef struct s_scan_options t_scan_options;

typedef struct s_scan_worker t_scan_worker;

struct s_scan_ctx
{
  int raw_socket;
  unsigned int total_probes;
  unsigned int outstanding_probes;
  unsigned int max_outstanding;
  unsigned int completed_probes;
  t_scan_options opts;
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

typedef struct s_scan_ctx t_scan_ctx;

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

  t_scan_ctx *engine;
};

typedef struct s_scan_worker t_scan_worker;

pcap_t *get_pcap_handle();
void scan_probe_list_create(t_scan_ctx *scan_ctx, unsigned short *ports, unsigned short num_ports);
void scan_probe_list_destroy(t_scan_ctx *scan_ctx);
void scan_options_destroy(t_scan_options *opts);
void scan_init(t_scan_ctx *scan_ctx, const char *path);
int set_pcap_filter(pcap_t *pcap_handle, char *filter_exp);
int scan_options_parse(t_scan_ctx *scan_ctx, int *arg_index, int argc, char **argv);
t_scan_type get_scan_type_by_name(char *expr);
char *get_program_name(char *arg);
void nmap_ip_file_parse(const char *filename);
void print_usage_and_exit(char *name);
void scan_ports_parallel(t_scan_ctx *scan_ctx, int num_ports);
int send_worker_create(t_scan_worker *worker, int id, t_scan_ctx *scan_ctx);
void *send_worker_thread(void *arg);
int send_probe_batch(t_scan_worker *worker, t_scan_ctx *scan_ctx, int batch_count);
int get_probe_batch(t_scan_worker *worker, t_scan_ctx *scan_ctx);
void scan_destroy(t_scan_ctx *scan_ctx);
void *packet_worker_thread(void *arg);
void *packet_capture_thread(void *arg);
t_packet_queue *packet_queue_create();
void packet_queue_destroy(t_packet_queue *queue);
void packet_queue_handler(t_packet_queue *queue, const u_char *data, size_t size, struct timeval tv);
t_packet *packet_create(const u_char *data, size_t size, struct timeval tv);
void packet_destroy(t_packet *packet);
t_packet *packet_dequeue(t_packet_queue *queue);
int packet_enqueue(t_packet_queue *queue, t_packet *pkt);
void scan_ports(t_scan_ctx *scan_ctx, int num_ports);
void probe_list_timeout(t_scan_ctx *scan_ctx);
void scan_results_print(t_scan_ctx *scan_ctx);
void print_probe_list_if(t_port_state state, t_list *probe_list);
int cmp_probe_state(t_port_state *state, t_probe *probe);
void print_probe(void *content);
void send_probe_list(t_scan_ctx *scan_ctx);
int get_raw_socket_by_protocol(const char *protocol_name);
int send_syn_probe(int raw_socket, t_scan_ctx *scan_ctx, t_probe *probe);
int nmap_xmit(struct nmap_data *nmap, short scan_type, unsigned short port);
int nmap_set_source_sockaddr(struct nmap_data *nmap);
int scan_local_sockaddr_set(struct sockaddr_in *sockaddr);
int nmap_set_dst_sockaddr(struct nmap_data *nmap, const char *hostname);
int set_sockaddr_by_hostname(struct sockaddr_in *sockaddr, const char *hostname);
void scan_config_print(const t_scan_ctx *scan_ctx, int num_ports);
void scan_run(t_scan_ctx *scan_ctx);
int syn_encode_and_send(char *buffer, size_t bufsize, struct sockaddr_in *src_sockaddr, struct sockaddr_in *dst_sockaddr, short port, int sockfd);
unsigned short tcp_checksum(const struct sockaddr_in *src_sockaddr, const struct sockaddr_in *dst_sockaddr, const struct tcphdr *th);
unsigned short checksum(char *buffer, size_t bufsize);
void packet_response(t_scan_ctx *scan_ctx, struct timeval ts, const u_char *pkt_data);
int probe_update(t_scan_ctx *scan_ctx, t_probe *probe, unsigned short sport, struct timeval ts, struct tcphdr *th);
int recv_packet(pcap_t *handle, short scan_type, t_list **port_lst);
void port_destroy(void *port);
t_port *init_port(unsigned short s_port, unsigned char protocol, short state, struct servent *serv);
int print_pkt_header(struct pcap_pkthdr *pkt_header);
unsigned short *get_ports(char *expr, unsigned int *number_of_ports);
void print_error(char *program_name, char *error);
void print_error_and_exit(char *program_name, char *error);
void print_packet_info(const struct pcap_pkthdr *header, const u_char *bytes);
uint16_t handle_ethernet(const u_char *bytes);
void tvsub(struct timeval *out, struct timeval *in);

const struct scan_mode *get_scan_mode(int index);
void scan_program_name_set(t_scan_ctx *scan_ctx, const char *program_name);
t_scan_ctx *scan_create();

#endif
