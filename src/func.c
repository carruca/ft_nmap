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
#define TIMESTRLEN 					100

#define NMAP_IP_OPTARG 			0x01
#define NMAP_FILE_OPTARG 		0x02
#define NMAP_PORTS_OPTARG 	0x04

#define IPV4 								4
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
port_destroy(void *port)
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
recv_packet(pcap_t *handle, short scan_type, t_list **port_lst)
{
	(void)scan_type;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
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
		return 0;
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
	th->th_sum = tcp_checksum(src_sockaddr, dst_sockaddr, th);

	number_of_bytes_sent = sendto(sockfd, buffer, bufsize, 0,
		(struct sockaddr *)dst_sockaddr, sizeof(struct sockaddr_in));
	if (number_of_bytes_sent < 0)
		return 1;
	if (debugging)
		printf("sent %lu bytes...\n", number_of_bytes_sent);
	return 0;
}

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

int
nmap_set_dst_sockaddr(struct nmap_data *nmap, const char *hostname)
{
	return set_sockaddr_by_hostname(&nmap->dst_sockaddr, hostname);
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
cmp_probe_state(t_port_state *state, t_probe *probe)
{
	return probe->state != *state;
}

int
equal_probe_state(t_port_state *state, t_probe *probe)
{
	return probe->state == *state;
}

void
print_probe_list_if(t_port_state state, t_list *probe_list)
{
	ft_lstiter_if(probe_list, &state, cmp_probe_state, print_probe);
}

void
scan_probe_list_create(t_scan_ctx *engine, unsigned short *ports, unsigned int num_ports)
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
