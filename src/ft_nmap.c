#include "ft_nmap.h"
#include "libft.h"
#include <pcap.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <ifaddrs.h>


#define MAXIPHDRLEN					20
#define PROMISC_TRUE				1
#define PROMISC_FALSE 			0
#define TIMESTRLEN 					100
#define MAXPORTS 						1024
#define MINPORTS 						1
#define MAXTHREADS 					250
#define DEFAULT_PORT_RANGE 	"1-1024"

#define NMAP_IP_OPTARG 			0x01
#define NMAP_FILE_OPTARG 		0x02
#define NMAP_PORTS_OPTARG 	0x04

#define ETH0 								1
#define IPV4 								4
#define IP_HLEN 						sizeof(struct ip) >> 2
#define TCP_HLEN 						sizeof(struct tcphdr) >> 2
#define DATALEN 						4

int number_of_packets = 0;
unsigned int number_of_ports = 0;
unsigned short number_of_threads = 0;
short scan_technique = 0;
int debugging = 0;
extern char *optarg;
extern int optind;
extern int errno;
char *program_name = NULL;
unsigned short *ports = NULL;
char *source = NULL;
char *filename = NULL;
int print_all_packet_info = 0;
int stop = 0;

void
tvsub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0)
	{
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

uint16_t
handle_ethernet(const u_char *bytes)
{
	const struct ether_header *eth;
	uint16_t type;

	eth = (struct ether_header *)bytes;
	type = ntohs(eth->ether_type);

	if (type == ETHERTYPE_IP)
		printf("   Type                 : IP (hex) 0x%x (dec) %d\n", type, type);
	else if (type == ETHERTYPE_ARP)
		printf("   Type                 : ARP (hex) 0x%x (dec) %d\n", type, type);
	else if (type == ETHERTYPE_REVARP)
		printf("   Type                 : REVARP (hex) 0x%x (dec) %d\n", type, type);
	else
		printf("   Type                 : not IP (hex) 0x%x (dec) %d\n", type, type);

	printf("   Destination Mac      : %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));
  printf("   Source Mac           : %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));

	return type;
}

void
print_packet_info(const struct pcap_pkthdr *header, const u_char *bytes)
{
	struct iphdr *ip;
	struct tcphdr *th;
	struct icmp *icmp;
  struct sockaddr_in ip_source, ip_dest;
  unsigned short ip_hlen;
	uint16_t ether_type;

	++number_of_packets;
	printf("\n################### PACKET n%d ###################", number_of_packets);
	printf("\nETH header\n");
	printf("   Packet lenght        : %d Bytes\n", header->len);
	printf("   Recv time            : %s", ctime((const time_t*)&header->ts.tv_sec));

  memset(&ip_source, 0, sizeof(ip_source));
  memset(&ip_dest, 0, sizeof(ip_dest));

	ether_type = handle_ethernet(bytes);
	if (ether_type == ETHERTYPE_IP)
	{
		bytes += ETH_HLEN;
		ip = (struct iphdr*)bytes;
		ip_source.sin_addr.s_addr = ip->saddr;
		ip_dest.sin_addr.s_addr = ip->daddr;
		ip_hlen = ip->ihl << 2;

		printf("\nIP header\n");
		printf("   Version              : %d\n", (unsigned int)ip->version);
		printf("   Header Lenght        : %d bytes\n", ((unsigned int)ip_hlen));
		printf("   Type of Service      : %d\n", (unsigned int)ip->tos);
		printf("   Total length         : %d bytes\n", ntohs(ip->tot_len));
		printf("   Identification       : %d\n", ntohs(ip->id));
		printf("   Time-To-Live         : %d\n", (unsigned int)(ip->ttl));
		printf("   Protocol             : %d\n", (unsigned int)(ip->protocol));
		printf("   Checksum             : %d\n", (unsigned int)(ip->check));
		printf("   Source IP            : %s\n", inet_ntoa(ip_source.sin_addr));
		printf("   Destination IP       : %s\n", inet_ntoa(ip_dest.sin_addr));

		bytes += ip_hlen;
		switch(ip->protocol)
		{
			case IPPROTO_ICMP:
				icmp = (struct icmp *)bytes;
				printf("\nICMP header\n");
				printf("   Type                 : %d\n", icmp->icmp_type);
				printf("   Code                 : %d\n", icmp->icmp_code);
				printf("   Seq                  : %d\n", icmp->icmp_seq);
				break;

			case IPPROTO_TCP:
				ip_hlen = ip->ihl << 2;
				th = (struct tcphdr*)(bytes);

				printf("\nTCP header\n");
				printf("   Source port          : %u\n", ntohs(th->source));
				printf("   Destination port     : %u\n", ntohs(th->dest));
				printf("   Sequence number      : %u\n", ntohl(th->seq));
				printf("   Ack number           : %u\n", ntohl(th->ack_seq));
				printf("   Header length        : %u bytes\n", (unsigned int)th->doff*4);
				printf("   URG                  : %u\n", (unsigned int)th->urg);
				printf("   ACK                  : %u\n", (unsigned int)th->ack);
				printf("   PSH                  : %u\n", (unsigned int)th->psh);
				printf("   RST                  : %u\n", (unsigned int)th->rst);
				printf("   SYN                  : %u\n", (unsigned int)th->syn);
				printf("   FIN                  : %u\n", (unsigned int)th->fin);
				printf("   Window               : %u\n", htons(th->window));
				printf("   Checksum             : %u\n", htons(th->check));
				printf("   urgent Pointer       : %u\n", htons(th->urg_ptr));
				break;

			default:
				printf("   Protocol             : %d\n", ip->protocol);
		}
	}
  printf("\n");
}

void
nmap_print_error_and_exit(char *error)
{
	fprintf(stderr, "%s: %s\n", program_name, error);
	exit(EXIT_FAILURE);
}

unsigned short *
//nmap_get_ports(char *expr, unsigned int *number_of_ports)
get_ports(char *expr, unsigned int *number_of_ports)
{
	unsigned short *ports;
	int count, start, end;
	char *next, *dash;
	char checks[MAXPORTS + 1];

	ports = malloc(MAXPORTS * sizeof(unsigned short));
	if (ports == NULL)
		return NULL;

	memset(checks, 0, MAXPORTS + 1);
	count = 0;
	next = expr;
	while (next != NULL)
	{
		next = strchr(expr, ',');
		if (next)
			*next = '\0';
		if (*expr == '-')
		{
			start = 1;
			end = atoi(expr + 1);
		}
		else
		{
			start = atoi(expr);
			end = start;
			dash = strchr(expr, '-');
			if (dash && *(dash + 1))
				end = atoi(dash + 1);
			else if (dash && !*(dash + 1))
				end = MAXPORTS;
		}

		if (start < MINPORTS || start > end || end > MAXPORTS)
			nmap_print_error_and_exit("port range is invalid.");

		for (int i = start; i <= end; ++i)
		{
			if (checks[i] == 0)
			{
				ports[count++] = i;
				checks[i] = 1;
			}
		}
		expr = next + 1;
	}
	*number_of_ports = count;
	return ports;
}

int
print_pkt_header(struct pcap_pkthdr *pkt_header)
{
	struct tm *ltime;
	char timestr[TIMESTRLEN];
	time_t local_tv_sec;

	local_tv_sec = pkt_header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	if (ltime == NULL)
	{
		perror("localtime");
		return 1;
	}

	if (strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime) == 0)
		return 1;

	printf("%s cnt:%d cap:%d len:%d\n",
		timestr,
		number_of_packets,
		pkt_header->caplen,
		pkt_header->len);
	++number_of_packets;
	return 0;
}
/*
const t_port_state port_states[] =
{
	{"closed", PORT_CLOSED},
	{"open", PORT_OPEN},
	{"filtered", PORT_FILTERED},
	{"unfiltered", PORT_UNFILTERED},
	{"openfiltered", PORT_OPENFILTERED}
};

void
print_port_result(void *port)
{
	int i;
	t_port *tmp;

	tmp = port;
	for (i = 0; i < MAXSTATES; ++i)
	{
		if (port_states[i].option & tmp->state)
			break ;
	}
	printf("%-9d %-9s %-s\n", tmp->portno, port_states[i].name, tmp->service_name);
}

void
nmap_print_result(struct nmap_data *nmap, t_list *port_lst, double scantime)
{
	printf("Scan took %.2f secs\n", scantime);
	printf("IP address: %s\n",
		inet_ntoa(nmap->dst_sockaddr.sin_addr));
	printf("%-9s %-9s %-s\n", "PORT", "STATE", "SERVICE");
//	ft_lstiter(port_lst, print_port_result);
}
*/
t_port *
init_port(
	unsigned short s_port, unsigned char protocol,
	short state, struct servent *serv)
{
	t_port *port;

	port = malloc(sizeof(*port));
	if (port == NULL)
		return NULL;

	memset(port, 0, sizeof(*port));
	port->portno = s_port;
	port->proto = protocol;
	port->state = state;
	port->service_name = strdup((serv) ? serv->s_name : "unknown");
	if (port->service_name == NULL)
	{
		free(port);
		return NULL;
	}
	return port;
}

void
free_port(void *port)
{
	t_port *tmp;

	if (port)
	{
		tmp = port;
		free(tmp->service_name);
		free(tmp);
	}
}

int
//recv_packet(pcap_t *handle, short scan_type, unsigned short port, t_list **port_lst)
recv_packet(pcap_t *handle, short scan_type, t_list **port_lst)
{
	(void)scan_type;
	struct pcap_pkthdr *pkt_header;
//	struct pcap_pkthdr *cpy_pkt_header;
	const u_char *pkt_data;
//	const u_char *cpy_pkt_data;
	unsigned ip_hlen;
	struct iphdr *ih;
	struct tcphdr *th;
	struct servent *serv;
	t_port *new_port;
	int res;
	unsigned short port;

	fd_set fdset;
	int fdmax, nfds;
	int pcap_fd;
	struct timeval timeout;

//	serv = getservbyport(htons(port), "tcp");
	serv = NULL;

	pcap_fd = pcap_get_selectable_fd(handle);
	fdmax = pcap_fd + 1;
	FD_ZERO(&fdset);
	FD_SET(pcap_fd, &fdset);

	timeout.tv_sec = 2;
	timeout.tv_usec = 0;

	nfds = select(fdmax, &fdset, NULL, NULL, &timeout);
	if (nfds == -1)
		error(EXIT_FAILURE, errno, "select");
	else if (nfds == 0)
	{
/*		new_port = init_port(port, IPPROTO_TCP, PORT_FILTERED, serv);
		if (new_port)
			ft_lstadd_back(port_lst, ft_lstnew(new_port));
	*/	return 0;
	}

	//TODO: we need to make a copy of pkt_header and pkt_data when using multithreads
	res = pcap_next_ex(handle, &pkt_header, &pkt_data);
	if (res == PCAP_ERROR)
	{
		fprintf(stderr, "Couldn't read next packet: %s\n",
			pcap_geterr(handle));
		return 1;
	}
	else if (res != 0)
	{
		if (debugging)
			printf("captured %u bytes...\n", pkt_header->caplen);
		if (print_all_packet_info)
			print_packet_info(pkt_header, pkt_data);

		pkt_data += ETH_HLEN;
		ih = (struct iphdr*)pkt_data;
		ip_hlen = ih->ihl << 2;

		switch(ih->protocol)
		{
			case IPPROTO_TCP:
				th = (struct tcphdr *)(pkt_data + ip_hlen);
				port = ntohs(th->th_sport);
				serv = getservbyport(th->th_sport, "tcp");

				if (port == ntohs(th->th_sport))
				{
					if (th->th_flags & TH_SYN && th->th_flags & TH_ACK)
					{
						new_port = init_port(port, IPPROTO_TCP, PORT_OPEN, serv);
						if (new_port)
							ft_lstadd_back(port_lst, ft_lstnew(new_port));
					}
					else if (th->th_flags & TH_RST)
					{
						new_port = init_port(port, IPPROTO_TCP, PORT_CLOSED, serv);
						if (new_port)
							ft_lstadd_back(port_lst, ft_lstnew(new_port));
					}
				}
		}
	}
	else
	{/*
		new_port = init_port(port, IPPROTO_TCP, PORT_FILTERED, serv);
		if (new_port)
			ft_lstadd_back(port_lst, ft_lstnew(new_port));
*/	}
	return 0;
}

int
update_probe(t_scan_engine *engine, t_probe *probe, unsigned short sport,
	struct timeval ts, struct tcphdr *th)
{
	if (probe->port == sport && probe->outstanding)
	{
		if (th->th_flags & TH_SYN)
			probe->state = PORT_OPEN;
		else if (th->th_flags & TH_RST)
			probe->state = PORT_CLOSED;

		probe->outstanding = 0;
		probe->recv_time = ts;
		--engine->outstanding_probes;
		++engine->completed_probes;
		return 1;
	}
	return 0;
}

void
process_response(t_scan_engine *engine,
	struct timeval ts, const u_char *pkt_data)
{
	unsigned short sport;
	unsigned int ip_hlen;
	struct iphdr *ih;
	struct tcphdr *th;
	t_list *current_node;

	pkt_data += ETH_HLEN;
	ih = (struct iphdr*)pkt_data;
	ip_hlen = ih->ihl << 2;

	switch(ih->protocol)
	{
		case IPPROTO_TCP:
			th = (struct tcphdr *)(pkt_data + ip_hlen);
			sport = ntohs(th->th_sport);
	}

	current_node = engine->probe_list;
	while (current_node)
	{
		if (update_probe(engine, current_node->content, sport, ts, th))
			break;
		current_node = current_node->next;
	}
}

unsigned short
cksum(char *buffer, size_t bufsize)
{
	register int sum = 0;
	unsigned short *wp;

	for (wp = (unsigned short *)buffer; bufsize > 1; wp++, bufsize -= 2)
		sum += *wp;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

struct pseudo_header
{
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t zero;
	uint8_t proto;
	uint16_t th_len;
	struct tcphdr th;
};

unsigned short
tcp_cksum(
	const struct sockaddr_in *src_sockaddr,
	const struct sockaddr_in *dst_sockaddr,
	const struct tcphdr *th)
{
  struct pseudo_header psh;
  size_t th_len;

  th_len = sizeof(struct tcphdr);
	psh.src_addr = src_sockaddr->sin_addr.s_addr;
  psh.dst_addr = dst_sockaddr->sin_addr.s_addr;
  psh.zero = 0;
	psh.proto = IPPROTO_TCP;
	psh.th_len = htons(th_len);
	memcpy(&psh.th, th, th_len);

	return cksum((char *)&psh, sizeof(struct pseudo_header));
}

int
syn_encode_and_send(
	char *buffer, size_t bufsize,
	struct sockaddr_in *src_sockaddr,
	struct sockaddr_in *dst_sockaddr,
	short port, int sockfd)
{
	struct tcphdr *th;
	ssize_t number_of_bytes_sent;
	pid_t pid = getpid();

	memset(buffer, 0, bufsize);
	th = (struct tcphdr *)buffer;
	th->th_sport = htons(rand() % 65535);
	th->th_dport = htons(port);
	th->th_seq = htons(rand() % pid);
	th->th_off = TCP_HLEN;
	th->th_flags = TH_SYN;
	th->th_win = 4;
	th->th_sum = tcp_cksum(src_sockaddr, dst_sockaddr, th);

	number_of_bytes_sent = sendto(sockfd, buffer, bufsize, 0,
		(struct sockaddr *)dst_sockaddr, sizeof(struct sockaddr_in));
	if (number_of_bytes_sent < 0)
		return 1;
	if (debugging)
		printf("sent %lu bytes...\n", number_of_bytes_sent);
	return 0;
}

const struct scan_mode scan_modes[] =
{
/*	{"NULL", SCAN_NULL},
	{"FIN", SCAN_FIN},
	{"XMAS", SCAN_XMAS},
	{"ACK", SCAN_ACK},
	{"UDP", SCAN_UDP}
*/	{"SYN", SCAN_SYN, syn_encode_and_send}
};
/*
void
nmap_print_scan_config(struct nmap_data *nmap, int ports, short scan_mode, int threads)
{
	printf("Scan configurations\n");
	printf("Target IP-Address : %s\n",
		inet_ntoa(nmap->dst_sockaddr.sin_addr));
	printf("No of ports to scan : %d\n", ports);
	printf("Scans to be performed :");
	for (int i = 0; i < MAXSCANS; ++i)
	{
		if (scan_modes[i].flag & scan_mode)
			printf(" %s", scan_modes[i].name);
	}
	printf("\n");
	printf("No of threads : %d\n", threads);
	printf("Scanning...\n");
	printf("\n");
}
*/
void
print_scan_config(const t_scan_engine *engine, const t_scan_options *opts, int num_ports)
{
	printf("Scan configurations\n");
	printf("Target IP-Address : %s\n",
		inet_ntoa(engine->target.sin_addr));
	printf("No of ports to scan : %d\n", num_ports);
	printf("Scans to be performed :");
	for (int pos = 0; pos < MAXSCANS; ++pos)
	{
		if (scan_modes[pos].flag & opts->scan_flag)
			printf(" %s", scan_modes[pos].name);
	}
	printf("\n");
	printf("No of threads : %d\n", opts->num_threads);
	printf("Scanning...\n");
	printf("\n");
}

int
set_sockaddr_by_hostname(struct sockaddr_in *sockaddr, const char *hostname)
{
	struct addrinfo hints, *res;
	int s;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;

	s = getaddrinfo(hostname, NULL, &hints, &res);
	if (s != 0)
	{
		fprintf(stderr, "ft_nmap: failed to resolve \"%s\": %s\n", hostname, gai_strerror(s));
		return 1;
	}
	memcpy(sockaddr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return 0;
}

int
nmap_set_dst_sockaddr(struct nmap_data *nmap, const char *hostname)
{
	return set_sockaddr_by_hostname(&nmap->dst_sockaddr, hostname);
}

int
set_local_sockaddr(struct sockaddr_in *sockaddr)
{
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
		return 1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr != NULL
			&& ifa->ifa_addr->sa_family == AF_INET
			&& !strcmp(ifa->ifa_name,"eth0"))
		{
			memcpy(sockaddr, ifa->ifa_addr, sizeof(struct sockaddr));
			break;
		}
	}
	freeifaddrs(ifaddr);
	return 0;
}

int
nmap_set_source_sockaddr(struct nmap_data *nmap)
{
	return set_local_sockaddr(&nmap->src_sockaddr);
}

int
nmap_xmit(struct nmap_data *nmap, short scan_type, unsigned short port)
{
	char *buffer;
	size_t bufsize;
	int sockfd;
	struct protoent *proto;

	bufsize = sizeof(struct tcphdr);
	buffer = malloc(bufsize);
	if (buffer == NULL)
		nmap_print_error_and_exit("buffer malloc failed.");

	proto = getprotobyname("tcp");
	if (proto == NULL)
	{
		perror("getprotobyname");
		return 1;
	}
	sockfd = socket(AF_INET, SOCK_RAW, proto->p_proto);
	if (sockfd < 0)
	{
		perror("socket");
		return 1;
	}

	for (int i = 0; i < MAXSCANS; ++i)
	{
		if (scan_modes[i].flag & scan_type)
			scan_modes[i].encode_and_send(
				buffer, bufsize,
				&nmap->src_sockaddr, &nmap->dst_sockaddr,
				port, sockfd);
	}
	close(sockfd);
	free(buffer);
	return 0;
}

int
send_syn_probe(int raw_socket, t_scan_engine *engine, t_scan_options *opts, t_probe *probe)
{
	ssize_t bytes_sent;
	struct tcphdr *th;
	char packet[sizeof(struct tcphdr)];
	pid_t pid = getpid();

	memset(packet, 0, sizeof(packet));
	th = (struct tcphdr *)packet;

	th->th_sport = htons(rand() % 65535);
	th->th_dport = htons(probe->port);
	th->th_seq = htonl(rand() % pid);
	th->th_off = TCP_HLEN;
	th->th_flags = TH_SYN;
	th->th_win = htons(1024);
	th->th_sum = tcp_cksum(&engine->source, &engine->target, th);

	bytes_sent = sendto(raw_socket, packet, sizeof(packet), 0,
		(struct sockaddr *)&engine->target, sizeof(struct sockaddr_in));
	if (bytes_sent > 0)
	{
		if (gettimeofday(&probe->sent_time, NULL) < 0)
			error(EXIT_FAILURE, errno, "gettimeofday");

		probe->outstanding = 1;
		probe->state = PORT_TESTING;
		++engine->outstanding_probes;

		if (opts->debugging)
			printf("probe of %lu bytes sent to port %u (outstanding: %u)\n",
				bytes_sent, probe->port, engine->outstanding_probes);

		return 0;
	}
	return 1;
}
/*
void
nmap_run(struct nmap_data *nmap, pcap_t *pcap_handle, const char *hostname)
{
	t_list *port_lst;
	struct timeval tv_in, tv_out;
	double scantime;

	port_lst = NULL;
	memset(&tv_in, 0, sizeof(struct timeval));

	if (nmap_set_dst_sockaddr(nmap, hostname))
		exit(EXIT_FAILURE);
	nmap_print_scan_config(nmap, number_of_ports, scan_technique, number_of_threads);

	if (gettimeofday(&tv_in, NULL) < 0)
		error(EXIT_FAILURE, errno, "gettimeofday");

	for (unsigned short i = 0; i < number_of_ports; ++i)
	{
		if (nmap_xmit(nmap, scan_technique, ports[i]))
			exit(EXIT_FAILURE);
	}
	//recv_packet(pcap_handle, scan_technique, ports[i], &port_lst);
	recv_packet(pcap_handle, scan_technique, &port_lst);

	if (gettimeofday(&tv_out, NULL) < 0)
		error(EXIT_FAILURE, errno, "gettimeofday");
	tvsub(&tv_out, &tv_in);
	scantime = ((double)tv_out.tv_sec) +
		((double)tv_out.tv_usec) / 1000000.0;

//	nmap_print_result(nmap, port_lst, scantime);
	if (port_lst)
		ft_lstclear(&port_lst, free_port);
}
*/
int
get_raw_socket_by_protocol(const char *protocol_name)
{
	int raw_socket;
	struct protoent *proto;

	proto = getprotobyname(protocol_name);
	if (proto == NULL)
		error(EXIT_FAILURE, errno, "getprotobyname");

	raw_socket = socket(AF_INET, SOCK_RAW, proto->p_proto);
	if (raw_socket < 0)
		error(EXIT_FAILURE, errno, "socket");
	return raw_socket;
}

void
send_probe_list(t_scan_engine *engine, t_scan_options *opts)
{
	t_list *current_node;
	t_probe *probe;
	int raw_socket;

	raw_socket = get_raw_socket_by_protocol("tcp");
	current_node = engine->probe_list;

	while (current_node
		&& engine->outstanding_probes < engine->max_outstanding)
	{
		probe = current_node->content;
		if (probe->state == PORT_UNKNOWN)
		{
			if (send_syn_probe(raw_socket, engine, opts, probe) == 0)
				current_node = current_node->next;
			else
				break;
		}
		else
			current_node = current_node->next;
	}
	close(raw_socket);
}

static const char *
get_port_state_string(t_port_state state)
{
	static const char *strings[] =
	{
		"unknown",
		"testing",
		"open",
		"closed",
		"filtered",
		"unfiltered",
		"open|filtered"
	};

	return strings[state];
}

void
print_probe(void *content)
{
	struct servent *serv;
	t_probe *probe;


	probe = content;
	serv = getservbyport(htons(probe->port), NULL);

	printf("%-9u %-9s %-s\n",
		probe->port,
		get_port_state_string(probe->state),
		(serv) ? serv->s_name : "unknown");
}

int
cmp_probe_state(t_port_state *state, t_probe *probe)
{
	return probe->state != *state;
}

void
print_probe_list_if(t_port_state state, t_list *probe_list)
{
	ft_lstiter_if(probe_list, &state, cmp_probe_state, print_probe);
}

void
print_scan_results(t_scan_engine *engine)
{
	printf("IP address: %s\n",
		inet_ntoa(engine->target.sin_addr));
	printf("\n");
	printf("%-9s %-9s %-s\n", "PORT", "STATE", "SERVICE");
	print_probe_list_if(PORT_OPEN, engine->probe_list);
	print_probe_list_if(PORT_CLOSED, engine->probe_list);
	print_probe_list_if(PORT_FILTERED, engine->probe_list);
	print_probe_list_if(PORT_UNFILTERED, engine->probe_list);
	print_probe_list_if(PORT_OPENFILTERED, engine->probe_list);
}

void
cktimeout_probe_list(t_scan_engine *engine)
{
	t_list *current_node;
	t_probe *probe;
	double elapsed_time;
	struct timeval current_time;


	current_node = engine->probe_list;
	while (current_node)
	{
		probe = current_node->content;
		if (probe->outstanding)
		{
			if (gettimeofday(&current_time, NULL) < 0)
				error(EXIT_FAILURE, errno, "gettimeofday");
			tvsub(&current_time, &probe->sent_time);	
			elapsed_time = (double)current_time.tv_sec
				+ (double)current_time.tv_usec / 1000000.0;

			if (elapsed_time > probe->timing.timeout)
			{
				if (debugging)
					printf("port %u timeout after %.2fs\n", probe->port, elapsed_time);
	/*			if (probe->retries < MAX_RETRIES)
				{
					++probe->retries;
					probe->outstanding = 0;
					--engine->outstanding_probes;
				}
				else
	*/			{
					probe->state = PORT_FILTERED;
					probe->outstanding = 0;
					--engine->outstanding_probes;
					++engine->completed_probes;
				}
			}
		}
		current_node = current_node->next;
	}
}

void
scan_ports(t_scan_engine *engine, t_scan_options *opts, int num_ports)
{
	struct timeval scan_start, scan_end, timeout;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	double total_time;
	int pcap_fd, pcap_res;
	fd_set fdset;

	if (gettimeofday(&scan_start, NULL) < 0)
		error(EXIT_FAILURE, errno, "gettimeofday");

	if (set_sockaddr_by_hostname(&engine->target, opts->target))
		exit(EXIT_FAILURE);

	print_scan_config(engine, opts, num_ports);

	while (engine->completed_probes < engine->total_probes)
	{
		send_probe_list(engine, opts);

		pcap_fd = pcap_get_selectable_fd(engine->pcap_handle);

		FD_ZERO(&fdset);
		FD_SET(pcap_fd, &fdset);

		timeout.tv_sec = 0;
		timeout.tv_usec = 1000;

		if (select(pcap_fd + 1, &fdset, NULL, NULL, &timeout) > 0)
		{
			while ((pcap_res = pcap_next_ex(engine->pcap_handle, &pkt_header, &pkt_data)) == 1)
			{
				if (opts->debugging)
					printf("probe of %u bytes captured\n", pkt_header->caplen);
				process_response(engine, pkt_header->ts, pkt_data);
			}
		}

		cktimeout_probe_list(engine);
		usleep(1000);
	}

	if (gettimeofday(&scan_end, NULL) < 0)
		error(EXIT_FAILURE, errno, "gettimeofday");
	tvsub(&scan_end, &scan_start);
	total_time = (double)scan_end.tv_sec
		+ (double)scan_end.tv_usec / 1000000.0;

	printf("Scan took %.2f secs\n", total_time);
	print_scan_results(engine);
}

int
packet_enqueue(t_packet_queue *queue, t_packet *pkt)
{
	t_list *node;

	pthread_mutex_lock(&queue->mutex);

	while (queue->count >= MAX_PKTQUEUE
		&& !queue->shutdown)
		pthread_cond_wait(&queue->not_full, &queue->mutex);

	if (queue->shutdown)
	{
		pthread_mutex_unlock(&queue->mutex);
		return 0;
	}

	node = ft_lstnew(pkt);
	if (node == NULL)
	{
		pthread_mutex_unlock(&queue->mutex);
		return 0;
	}

	ft_lstadd_back(&queue->head, node);
	queue->tail = node;
	++queue->count;

	pthread_cond_signal(&queue->not_empty);

	pthread_mutex_unlock(&queue->mutex);
	return 1;
}

t_packet *
packet_dequeue(t_packet_queue *queue)
{
	t_packet *pkt;
	t_list *node;

	pthread_mutex_lock(&queue->mutex);

	while (queue->count == 0
		&& !queue->shutdown)
		pthread_cond_wait(&queue->not_empty, &queue->mutex);

	if ((queue->shutdown && queue->count == 0)
		|| queue->head ==  NULL)
	{
		pthread_mutex_unlock(&queue->mutex);
		return NULL;
	}

	node = queue->head;
	pkt = (t_packet *)node->content;
	queue->head = queue->head->next;
	if (!queue->head)
		queue->tail = NULL;
	--queue->count;

	free(node);
	pthread_cond_signal(&queue->not_full);

	pthread_mutex_unlock(&queue->mutex);
	return pkt;
}

void
packet_destroy(t_packet *packet)
{
	if (packet != NULL)
	{
		free(packet->data);
		free(packet);
	}
}

t_packet *
packet_create(const u_char *data, size_t size, struct timeval tv)
{
	t_packet *packet;

	packet = malloc(sizeof(t_packet));
	if (packet == NULL)
		return NULL;

	packet->data = malloc(size);
	if (packet->data == NULL)
	{
		free(packet);
		return NULL;
	}

	memcpy(packet->data, data, size);
	packet->size = size;
	packet->ts = tv;
	return packet;
}

void
packet_queue_handler(t_packet_queue *queue,
	const u_char *data, size_t size, struct timeval tv)
{
	t_packet *packet;

	packet = packet_create(data, size, tv);
	if (packet == NULL)
		return ;

	if (!packet_enqueue(queue, packet))
		packet_destroy(packet);
}

void
packet_queue_destroy(t_packet_queue *queue)
{
	if (queue)
	{
		pthread_cond_destroy(&queue->not_empty);
		pthread_cond_destroy(&queue->not_full);
		pthread_mutex_destroy(&queue->mutex);
		free(queue);
	}
}

t_packet_queue *
packet_queue_create()
{
	t_packet_queue *queue;

	queue = calloc(1, sizeof(t_packet_queue));
	if (queue == NULL) return NULL;

	pthread_mutex_init(&queue->mutex, NULL);
	pthread_cond_init(&queue->not_empty, NULL);
	pthread_cond_init(&queue->not_full, NULL);
	return queue;
}

void *
packet_capture_thread(void *arg)
{
	int pcap_fd, pcap_res;
	fd_set fdset;
	t_scan_engine *engine;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	struct timeval timeout;

	engine = (t_scan_engine *)arg;
	while (!engine->capture_queue->shutdown)
	{
		pcap_fd = pcap_get_selectable_fd(engine->pcap_handle);

		FD_ZERO(&fdset);
		FD_SET(pcap_fd, &fdset);

		timeout.tv_sec = 0;
		timeout.tv_usec = 10000;

		if (select(pcap_fd + 1, &fdset, NULL, NULL, &timeout) > 0)
		{
			while ((pcap_res = pcap_next_ex(engine->pcap_handle, &pkt_header, &pkt_data)) == 1)
			{
				if (engine->opts->debugging)
					printf("probe of %u bytes captured\n", pkt_header->caplen);
				packet_queue_handler(engine->capture_queue,
					pkt_data, pkt_header->caplen, pkt_header->ts);
			}
		}
	}
	return NULL;
}


void *
packet_worker_thread(void *arg)
{
	t_scan_engine *engine;
	t_packet *packet;

	engine = (t_scan_engine *)arg;
	while ((packet = packet_dequeue(engine->capture_queue)) != NULL)
	{
		pthread_mutex_lock(&engine->engine_mutex);
		process_response(engine, packet->ts, packet->data);
		pthread_mutex_unlock(&engine->engine_mutex);

		packet_destroy(packet);
	}
	return NULL;
}

void
scan_ports_parallel(t_scan_engine *engine, t_scan_options *opts, int num_ports)
{
	struct timeval scan_start, scan_end;
	double total_time;

	if (gettimeofday(&scan_start, NULL) < 0)
		error(EXIT_FAILURE, errno, "gettimeofday");

	if (set_sockaddr_by_hostname(&engine->target, opts->target))
		exit(EXIT_FAILURE);

	print_scan_config(engine, opts, num_ports);

	pthread_mutex_init(&engine->engine_mutex, NULL);

	engine->capture_queue = packet_queue_create();
	if (engine->capture_queue == NULL)
		error(EXIT_FAILURE, errno, "capture_queue_create");

	engine->worker_threads = calloc(engine->opts->num_threads, sizeof(pthread_t));
	if (engine->worker_threads == NULL)
		error(EXIT_FAILURE, errno, "worker_threads_create");

	engine->capture_active = 1;

	if (pthread_create(&engine->capture_thread, NULL, packet_capture_thread, engine) != 0)
		error(EXIT_FAILURE, errno, "pthread_create");

	for (unsigned short pos = 0; pos < engine->opts->num_threads; ++pos)
	{
		if (pthread_create(&engine->worker_threads[pos], NULL, packet_worker_thread, engine) != 0)
			error(EXIT_FAILURE, errno, "pthread_create");
	}

	while (engine->completed_probes < engine->total_probes)
	{
		send_probe_list(engine, opts);

		cktimeout_probe_list(engine);
		usleep(1000);
	}

// TODO: check all callocs to destroy
	engine->capture_active = 0;
	engine->capture_queue->shutdown = 1;

	pthread_cond_broadcast(&engine->capture_queue->not_empty);
	pthread_cond_broadcast(&engine->capture_queue->not_full);

	pthread_join(engine->capture_thread, NULL);
	for (unsigned short pos = 0; pos < engine->opts->num_threads; ++pos)
		pthread_join(engine->worker_threads[pos], NULL);

	if (engine->worker_threads)
	{
		free(engine->worker_threads);
		engine->worker_threads = NULL;
	}
	if (engine->capture_queue)
	{
		packet_queue_destroy(engine->capture_queue);
		engine->capture_queue = NULL;
	}
	pthread_mutex_destroy(&engine->engine_mutex);

	if (gettimeofday(&scan_end, NULL) < 0)
		error(EXIT_FAILURE, errno, "gettimeofday");
	tvsub(&scan_end, &scan_start);
	total_time = (double)scan_end.tv_sec
		+ (double)scan_end.tv_usec / 1000000.0;

	printf("Scan took %.2f secs\n", total_time);
	print_scan_results(engine);
}

void
print_usage_and_exit(char *name)
{
	printf("%s [OPTIONS]\n"
    "--help        Print this help screen\n"
		"--ports       Ports to scan (ex: '-p 1-10' or '-p 1,2,3' or '-p 1,5-15')\n"
    "--ip          IP addresses to scan in dot format\n"
    "--file        File name containing IP addresses to scan\n"
    "--speedup     [max 250] number of parallel threads to use\n"
    "--scan        Scan type: SYN/NULL/FIN/XMAS/ACK/UDP\n",
    name);
	exit(EXIT_FAILURE);
}

void
nmap_ip_file_parse(const char *filename)
{
	FILE *stream;
	char nextline[HOST_NAME_MAX];

/*
 * TODO: stores ip address/hostname somewhere
 */
	stream = fopen(filename, "r");
	if (stream == NULL)
		nmap_print_error_and_exit("fopen: not able to open the file.");

	while (fgets(nextline, sizeof(nextline), stream))
	fclose(stream);
}

char *
get_program_name(char *arg)
{
	char *pos;

	pos = strchr(arg, '/');
	if (pos == NULL)
		return arg;
	return pos + 1;
}

short
nmap_get_scan_technique_by_name(char *expr)
{
	for (int i = 0; i < MAXSCANS; ++i)
	{
		if (strcmp(scan_modes[i].name, expr) == 0)
			return scan_modes[i].flag;
	}
	return 0;
}

int
parse_args(int argc, char **argv, t_scan_options *opts, int *arg_index)
{
	int opt;
	struct option long_options[] =
	{
		{"help", no_argument, 0, 'h'},
		{"ports", required_argument, 0, 'p'},
		{"ip", required_argument, 0, 'i'},
		{"file", required_argument, 0, 'f'},
		{"speedup", required_argument, 0, 's'},
		{"scan", required_argument, 0, 'S'},
		{"debug", no_argument, 0, 'd'},
		{0}
	};

	program_name = get_program_name(argv[0]);

	if (argc < 2)
		print_usage_and_exit(program_name);

	while ((opt = getopt_long(argc, argv, "hdp:i:f:", long_options, NULL)) != -1)
	{
		switch (opt)
		{
			case 'p':
				if (opts->portlist)
		//		if (ports)
					nmap_print_error_and_exit("only one --ports option allowed, separate multiples ranges with commas.");
		//		ports = nmap_get_ports(optarg, &number_of_ports);
				opts->portlist = strdup(optarg);
				break;
			case 'i':
		//		if (source)
				if (opts->target)
					nmap_print_error_and_exit("you can only use --ip option once.");
		//		source = optarg;
				opts->target = strdup(optarg);
				break;
			case 'f':
		//		filename = optarg;
				opts->filename = strdup(optarg);
				break;
			case 's':
				opts->num_threads = atoi(optarg);
		//		number_of_threads = atoi(optarg);
				if (number_of_threads > MAXTHREADS)
					nmap_print_error_and_exit("speedup exceeded.");
				break;
			case 'S':
		//		scan_technique = nmap_get_scan_technique_by_name(optarg);
				opts->scan_flag = nmap_get_scan_technique_by_name(optarg);
		//		if (scan_technique == 0)
				if (opts->scan_flag == 0)
					nmap_print_error_and_exit("scan flag is invalid.");
				break;
			case 'd':
				print_all_packet_info = 1;
				debugging = 1;
				opts->debugging = 1;
				break;
			case 'h':
			default:
				print_usage_and_exit(program_name);
		}
	}

//	if (filename && source)
	if (opts->target && opts->filename)
		nmap_print_error_and_exit("--ip and --file options cannot be used at the same time.");

//	if (filename)
	if (opts->filename)
		nmap_ip_file_parse(filename);

	*arg_index = optind;
	return 0;
}

pcap_t *
get_pcap_handle()
{
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	size_t number_of_devs;
	size_t iface;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle;

	if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "Couldn't find any devide: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
/*
	number_of_devices = 0;
	for (dev = alldevs; dev != NULL; dev = dev->next)
	{
		printf("%lu. %s", ++number_of_devices, dev->name);
		if (dev->description != NULL)
			printf(" (%s)\n", dev->description);
		else
			printf(" (No description available)\n");
	}

	printf("Enter the interface number (1-%lu) range.\n", number_of_devices);
	if (scanf("%lu", &num) == 0)
	{
		fprintf(stderr, "Interface number out of range.\n");
		exit(EXIT_FAILURE);
	}
*/
	iface = ETH0;
	for (dev = alldevs, number_of_devs = 0; number_of_devs < iface - 1; dev = dev->next, ++number_of_devs);
	printf("%s interface opening...\n", dev->name);

	pcap_handle = pcap_create(dev->name, errbuf);
	if (pcap_handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n",
			dev->name,
			errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_set_buffer_size(pcap_handle, PCAP_BUFSIZ) != 0)
	{
		fprintf(stderr, "Couldn't set buffer size: %s\n",
			pcap_geterr(pcap_handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_set_promisc(pcap_handle, PROMISC_TRUE) != 0)
	{
		fprintf(stderr, "Couldn't set promiscuous mode: %s\n",
			pcap_geterr(pcap_handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_set_timeout(pcap_handle, 1000) != 0)
	{
		fprintf(stderr, "Couldn't set packet buffer timeout: %s\n",
			pcap_geterr(pcap_handle));
		exit(EXIT_FAILURE);
	}
/*
	if (pcap_set_immediate_mode(pcap_handle, 1) != 0)
	{
		fprintf(stderr, "Couldn't set immediate mode: %s\n",
			pcap_geterr(pcap_handle));
		exit(EXIT_FAILURE);
	}
*/
	if (pcap_setnonblock(pcap_handle, 1, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "Couldn't set non-blocking mode: %s\n",
			errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_activate(pcap_handle) != 0)
	{
		fprintf(stderr, "Couldn't activate handle: %s\n",
			pcap_geterr(pcap_handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(pcap_handle) != DLT_EN10MB)
	{
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n",
			dev->name);
		exit(EXIT_FAILURE);
	}

	pcap_freealldevs(alldevs);
	return pcap_handle;
}

int
set_pcap_filter(pcap_t *pcap_handle, char *filter_exp)
{
	struct bpf_program fp;

	if (pcap_compile(pcap_handle, &fp, filter_exp, 0, 0) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
			filter_exp,
			pcap_geterr(pcap_handle));
		return 1;
	}
	if (pcap_setfilter(pcap_handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n",
			filter_exp,
			pcap_geterr(pcap_handle));
		return 1;
	}
	pcap_freecode(&fp);
	return 0;
}

void
init_scan_engine(t_scan_engine *e, t_scan_options *opts)
{
	memset(e, 0, sizeof(t_scan_engine));

	e->max_outstanding = 100;
	e->global_timing.timeout = 2.0;
	e->opts = opts;
}

void
free_scan_options(t_scan_options *opts)
{
	if (opts->target) free(opts->target);
	if (opts->filename) free(opts->filename);
	if (opts->portlist) free(opts->portlist);
}

void
init_probe_list(t_scan_engine *engine, unsigned short *ports, unsigned int num_ports)
{
	for (unsigned int pos = 0; pos < num_ports; ++pos)
	{
		t_probe *probe;
		t_list *node;

		probe = malloc(sizeof(t_probe));
		if (probe == NULL)
			continue ;

		memset(probe, 0, sizeof(t_probe));
		probe->port = ports[pos];
		probe->state = PORT_UNKNOWN;
		probe->timing.timeout = engine->global_timing.timeout;

		node = ft_lstnew(probe);
		if (node == NULL)
		{
			free(probe);
			continue ;
		}

		ft_lstadd_back(&engine->probe_list, node);
		++engine->total_probes;
	}
}

int
main(int argc, char **argv)
{
	int arg_index;
	t_scan_options opts;
	t_scan_engine engine;
	unsigned short *ports;
	unsigned int num_ports;

	memset(&opts, 0, sizeof(t_scan_options));
	opts.scan_flag = SCAN_ALL;

	if (parse_args(argc, argv, &opts, &arg_index))
		nmap_print_error_and_exit("arg_parse failed.");

	init_scan_engine(&engine, &opts);

	engine.pcap_handle = get_pcap_handle();
	if (engine.pcap_handle == NULL)
		nmap_print_error_and_exit("pcap_handle failed.");

	if (set_pcap_filter(engine.pcap_handle, "src google.com")) //TODO: eliminate this and scanf the filter str
		nmap_print_error_and_exit("pcap_filter failed.");

	ports = get_ports( opts.portlist ? opts.portlist : DEFAULT_PORT_RANGE, &num_ports);

	init_probe_list(&engine, ports, num_ports);

	set_local_sockaddr(&engine.source);

	if (!opts.num_threads)
		scan_ports(&engine, &opts, num_ports);
	else
		scan_ports_parallel(&engine, &opts, num_ports);

	free(ports);
	ft_lstclear(&engine.probe_list, free);
	pcap_close(engine.pcap_handle);
	free_scan_options(&opts);
	return 0;
}
