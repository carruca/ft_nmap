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
short scan_type = 0;
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

unsigned short *
nmap_get_ports(char *expr, unsigned int *number_of_ports)
{
	unsigned short *ports;
	int count, start, end;
	char *next, *dash;
	char checks[MAXPORTS + 1];

	ports = malloc(MAXPORTS * sizeof(unsigned short));
	if (ports == NULL)
		nmap_print_error_and_exit("get_ports: malloc failed.");

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

void
print_port_result(unsigned int port, char *state, char *service)
{
	printf("%-9d %-9s %-s\n", port, state, service);
}

void
print_result()
{}

int
recv_packet(pcap_t *handle, short scan_type)
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
	t_list *openports;

	(void)openports;

	//TODO: we need to make a copy of pkt_header and pkt_data when using multithreads
	if (pcap_next_ex(handle, &pkt_header, &pkt_data) == PCAP_ERROR)
	{
		fprintf(stderr, "Couldn't read next packet: %s\n",
			pcap_geterr(handle));
		return 1;
	}
	//TODO:
	// que queremos del paquete
	//  port
	//  scan flags
	//
	if (print_all_packet_info)
		print_packet_info(pkt_header, pkt_data);

	pkt_data += ETH_HLEN;
	ih = (struct iphdr*)pkt_data;
	ip_hlen = ih->ihl << 2;

	switch(ih->protocol)
	{
		case IPPROTO_TCP:
			th = (struct tcphdr *)(pkt_data + ip_hlen);
			serv = getservbyport(th->th_sport, "tcp");

			printf("%-9s %-9s %-s\n", "PORT", "STATE", "SERVICE");
			for (unsigned int i = 0; i < number_of_ports; ++i)
			{
				if (ports[i] == ntohs(th->th_sport))
					print_port_result(ports[i], "open", (serv) ? serv->s_name : "unknown");
			}
			stop = 1;
	}
	return 0;
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
	unsigned long src_addr;
	unsigned long dst_addr;
	char zero;
	unsigned char proto;
	unsigned long th_len;
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
		printf("successfully sent %lu bytes.\n", number_of_bytes_sent);
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
	int ret;

	ret = 1;
	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
		return ret;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr != NULL
			&& ifa->ifa_addr->sa_family == AF_INET
			&& !strcmp(ifa->ifa_name,"eth0"))
		{
			memcpy(sockaddr, ifa->ifa_addr, sizeof(struct sockaddr));
			ret = 0;
			break;
		}
	}
	freeifaddrs(ifaddr);
	return ret;
}

int
nmap_set_src_sockaddr(struct nmap_data *nmap)
{
	return set_local_sockaddr(&nmap->src_sockaddr);
}

int
nmap_xmit(struct nmap_data *nmap, short scan_type)
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
				ports[0], sockfd);
	}
	close(sockfd);
	free(buffer);
	return 0;
}

void
nmap_run(struct nmap_data *nmap, pcap_t *pcap_handle, const char *hostname)
{
	if (nmap_set_dst_sockaddr(nmap, hostname))
		exit(EXIT_FAILURE);
	nmap_print_scan_config(nmap, number_of_ports, scan_type, number_of_threads);

	// TODO: run
	// xmit
	// 	bucle de puertos
	// 	bucle de tipos de escaneo
	// recv
	// 	pcap_next_ex
	// 	analizar mensaje recibido y guardar estadisticas
	// print
	// 	estadisticas
	if (nmap_xmit(nmap, scan_type))
		exit(EXIT_FAILURE);

	recv_packet(pcap_handle, scan_type);
}

struct nmap_data *
nmap_init()
{
	struct nmap_data *nmap;

	nmap = malloc(sizeof(struct nmap_data));
	if (nmap == NULL)
		return NULL;

	memset(nmap, 0, sizeof(*nmap));
	nmap->id = getpid();
	return nmap;
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
nmap_get_scan_type_by_name(char *expr)
{
	for (int i = 0; i < MAXSCANS; ++i)
	{
		if (strcmp(scan_modes[i].name, expr) == 0)
			return scan_modes[i].flag;
	}
	return 0;
}

int
nmap_arg_parse(int argc, char **argv, int *arg_index)
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
		{"print", no_argument, 0, 'x'},
		{0}
	};

	program_name = get_program_name(argv[0]);

	if (argc < 2)
		print_usage_and_exit(program_name);

	while ((opt = getopt_long(argc, argv, "hp:i:f:", long_options, NULL)) != -1)
	{
		switch (opt)
		{
			case 'p':
				if (ports)
					nmap_print_error_and_exit("only one --ports option allowed, separate multiples ranges with commas.");
				ports = nmap_get_ports(optarg, &number_of_ports);
				break;
			case 'i':
				if (source)
					nmap_print_error_and_exit("you can only use --ip option once.");
				source = optarg;
				break;
			case 'f':
				filename = optarg;
				break;
			case 's':
				number_of_threads = atoi(optarg);
				if (number_of_threads > MAXTHREADS)
					nmap_print_error_and_exit("speedup exceeded.");
				break;
			case 'S':
				scan_type = nmap_get_scan_type_by_name(optarg);
				if (scan_type == 0)
					nmap_print_error_and_exit("scan type is invalid.");
				break;
			case 'x':
				print_all_packet_info = 0;
				break;
			case 'h':
			default:
				print_usage_and_exit(program_name);
		}
	}

	if (filename && source)
		nmap_print_error_and_exit("--ip and --file options cannot be used at the same time.");

	if (filename)
		nmap_ip_file_parse(filename);

	*arg_index = optind;
	return 0;
}

pcap_t *
nmap_pcap_get_handle()
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

	pcap_handle = pcap_open_live(dev->name, BUFSIZ, PROMISC_TRUE, 1000, errbuf);
	if (pcap_handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n",
			dev->name,
			errbuf);
		return NULL;
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
nmap_pcap_set_filter(pcap_t *pcap_handle, char *filter_exp)
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
	return 0;
}

int
main(int argc, char **argv)
{
	pcap_t *pcap_handle;
	struct nmap_data *nmap;
	int arg_index;

	if (nmap_arg_parse(argc, argv, &arg_index))
		nmap_print_error_and_exit("arg_parse failed.");

	pcap_handle = nmap_pcap_get_handle();
	if (pcap_handle == NULL)
		nmap_print_error_and_exit("pcap_handle failed.");

	nmap = nmap_init();
	if (nmap == NULL)
		nmap_print_error_and_exit("initialisation failed.");

	if (nmap_pcap_set_filter(pcap_handle, "src port 80"))
		nmap_print_error_and_exit("pcap_filter failed.");

	if (!number_of_ports)
		ports = nmap_get_ports(DEFAULT_PORT_RANGE, &number_of_ports);

	if (!scan_type)
		scan_type = SCAN_ALL;

	if (nmap_set_src_sockaddr(nmap))
		exit(EXIT_FAILURE);

	nmap_run(nmap, pcap_handle, source);

	free(nmap);
	free(ports);
	pcap_close(pcap_handle);

	return 0;
}
