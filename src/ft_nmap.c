#include "ft_nmap.h"
#include <pcap.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <getopt.h>


#define MAXIPHDRLEN		20
#define PROMISC_TRUE	1 
#define PROMISC_FALSE 0
#define TIMESTRLEN 		100
#define MAXPORTS 			1024
#define MINPORTS 			1

int number_of_packets = 0;
int number_of_ports = 0;
int number_of_threads = 0;
short scan_mode = 0;
int debugging = 1;

void
print_host(const u_char *host, char *origin)
{
	printf("%s MAC Address: %s\n", origin, ether_ntoa((struct ether_addr *)host));
}

uint16_t
handle_ethernet(const u_char *bytes)
{
	const struct ether_header *ether;
	uint16_t type;

	ether = (struct ether_header *)bytes;
	type = ntohs(ether->ether_type);

	if (type == ETHERTYPE_IP)
	{
		printf("Ethernet type hex:0x%x dec:%d is a IP packet\n",
				type,
				type);
	}
	else if (type == ETHERTYPE_ARP)
	{
		printf("Ethernet type hex:0x%x dec:%d is a ARP packet\n",
				type,
				type);
	}
	else if (type == ETHERTYPE_REVARP)
	{
		printf("Ethernet type hex:0x%x dec:%d is a REVARP packet\n",
				type,
				type);
	}
	else
	{
		printf("Ethernet type hex:0x%x dec:%d not IP\n",
				type,
				type);
	}

	print_host(ether->ether_dhost, "Destination");
	print_host(ether->ether_shost, "Source");
	return type;
}

void
print_packet_info(const struct pcap_pkthdr *header, const u_char *bytes)
{
	uint16_t ether_type;
	struct ip *ip;
	unsigned int ip_hlen;
	struct icmp *icmp;
	struct tcphdr *tcphdr;

	++number_of_packets;
	printf("Grabbed packet of lenght: %d\n", header->len);
	printf("Total number of packets: %d\n", number_of_packets);
	printf("Recieved at .... %s", ctime((const time_t*)&header->ts.tv_sec));
	printf("Ethernet address lenght is %d\n", ETH_HLEN);

	ether_type = handle_ethernet(bytes);
	if (ether_type == ETHERTYPE_IP)
	{
		bytes += ETH_HLEN;
		ip = (struct ip *)bytes;
		
		printf("Time To Live: %d\n", ip->ip_ttl);
		printf("IP src: %s\n", inet_ntoa(ip->ip_src));
		printf("IP dst: %s\n", inet_ntoa(ip->ip_dst));

		ip_hlen = ip->ip_hl << 2;
		bytes += ip_hlen;
		switch(ip->ip_p)
		{
			case IPPROTO_ICMP:
				icmp = (struct icmp *)bytes;
				printf("Protocol: ICMP\n");
				printf("Type:%d Code:%d Seq:%d\n",
					icmp->icmp_type, icmp->icmp_code, ntohs(icmp->icmp_seq));
				break;

			case IPPROTO_TCP:
				tcphdr = (struct tcphdr *)bytes;
				printf("Protocol: TCP\n");
				printf("Ports: %d -> %d\n",
					ntohs(tcphdr->th_sport),
					ntohs(tcphdr->th_dport));
				printf("Flags:%s%s%s%s%s Seq:0x%x Ack:0x%x\n",
					(tcphdr->th_flags & TH_URG ? "URG" : "*"),
					(tcphdr->th_flags & TH_ACK ? "ACK" : "*"),
					(tcphdr->th_flags & TH_PUSH ? "PUSH" : "*"),
					(tcphdr->th_flags & TH_RST ? "RST" : "*"),
					(tcphdr->th_flags & TH_SYN ? "SYN" : "*"),
					ntohs(tcphdr->th_seq), ntohs(tcphdr->th_ack));
				break;

			case IPPROTO_UDP:
				printf("Protocol: UDP\n");
				break;

			default:
				printf("Protocol: Unknown\n");
				break;
		}
	}
	else printf("Not IP Adrress\n");
	printf("\n");
}
/*
static error_t
parse_opt(int key, char *arg,
	struct argp_state *state)
{
	(void)arg;
	switch(key)
	{
		case ARGP_KEY_NO_ARGS:
			argp_error(state, "missing host operand");

		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
*/

unsigned short *
getpts(char *expr, int *number_of_ports)
{
	unsigned short *ports;
	int count, start, end;
	char *next, *dash;

	ports = malloc(MAXPORTS * sizeof(unsigned short));
	if (ports == NULL)
	{
		fprintf(stderr, "getpts: malloc failed\n");
		exit(EXIT_FAILURE);
	}

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
		{
			fprintf(stderr, "Your port range is invalid.\n");
			exit(EXIT_FAILURE);
		}

		for (int i = start; i <= end; ++i)
			ports[count++] = i;
		expr = next + 1;
	}
	*number_of_ports = count;
	return ports;
}


void
print_packet_data(const u_char *pkt_data)
{
	(void)pkt_data;

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
print_ip_header(struct ip *ip)
{
	(void)ip;
	return ;
}

void
print_pkt_data(const u_char *pkt_data)
{
	print_ip_header((struct ip *)pkt_data + ETH_HLEN);
	return ;
}

int
recv_packet(pcap_t *handle)
{
	struct pcap_pkthdr *pkt_header;
//	struct pcap_pkthdr *cpy_pkt_header;
	const u_char *pkt_data;
//	const u_char *cpy_pkt_data;
	

	//TODO: we need to make a copy of pkt_header and pkt_data when using multithreads
	if (pcap_next_ex(handle, &pkt_header, &pkt_data) == PCAP_ERROR)
	{
		fprintf(stderr, "Couldn't read next packet: %s\n",
			pcap_geterr(handle));
		return 1;
	}

	print_packet_info(pkt_header, pkt_data);
	/*
	if (print_pkt_header(pkt_header))
		return 1;
	print_pkt_data(pkt_data);
	*/
	return 0;
}

// scan(sock, )

u_char *
set_buffer(u_char *buffer, size_t size)
{

	if (buffer == NULL)
		buffer = malloc(size);
	return buffer;
}

int
encode_syn()
{
	return 0;
}

struct nmap_data
{
	struct sockaddr_in target_addr;
};

static const struct scan_mode scan_modes[] = {
	{"SYN", SCAN_SYN},
	{"NULL", SCAN_NULL},
	{"FIN", SCAN_FIN},
	{"XMAS", SCAN_XMAS},
	{"ACK", SCAN_ACK},
	{"UDP", SCAN_UDP}
};

void
nmap_print_scan_config(struct nmap_data *nmap, int ports, short scan_mode, int threads)
{
	printf("Scan configurations\n");
	printf("Target IP-Address : %s\n",
		inet_ntoa(nmap->target_addr.sin_addr));
	printf("No of ports to scan : %d\n", ports);
	printf("Scans to be performed :");
	for (int i = 0; i < MAXSCANS; ++i)
	{
		if (scan_modes[i].flag & scan_mode)
			printf(" %s", scan_modes[i].name);
	}
	printf("\n");
	printf("No of threads : %d\n", threads);
}

int
nmap_set_target(struct nmap_data *nmap, const char *hostname)
{
	int rc;
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;

	rc = getaddrinfo(hostname, NULL, &hints, &res);
	if (rc != 0)
		return 1;
	memcpy(&nmap->target_addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return 0;
}

void
nmap_run(struct nmap_data *nmap, const char *hostname)
{
	nmap_set_target(nmap, hostname);
	nmap_print_scan_config(nmap, number_of_ports, scan_mode, number_of_threads);
}

struct nmap_data *
nmap_init()
{
	struct nmap_data *nmap;

	nmap = malloc(sizeof(struct nmap_data));
	if (nmap == NULL)
		return NULL;
	memset(nmap, 0, sizeof(*nmap));
	return nmap;
}

void
printusage(char *name)
{
	printf("%s [options] [hostname ...]\n"
    "--help        Print this help screen\n"
		"--ports       Ports to scan (ex: '-p 1-10' or '-p 1,2,3' or '-p 1,5-15')\n"
    "--ip          IP addresses to scan in dot format\n"
    "--file        File name containing IP addresses to scan\n"
    "--speedup     [max 250] number of parallel threads to use\n"
    "--scan        Scan type: SYN/NULL/FIN/XMAS/ACK/UDP\n",
    name);
}

extern char *optarg;
extern int optind;

int
main(int argc, char **argv)
{
	struct option long_options[] =
	{
		{"help", no_argument, 0, 'h'},
		{"ports", required_argument, 0, 'p'},
		{"ip", required_argument, 0, 'i'},
		{"file", required_argument, 0, 'f'},
		{"speedup", required_argument, 0, 's'},
		{"scan", required_argument, 0, 'S'}
	};
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	size_t number_of_devices;
	size_t num;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle;
	u_char *pkt_buf;
	size_t pkt_size;
	struct nmap_data *nmap;
	unsigned short *ports;
	int opt;
	char *program_name;

	program_name = strchr(argv[0], '/') + 1;

	if (argc < 2)
	{
		printusage(program_name);
		exit(EXIT_FAILURE);
	}

	while ((opt = getopt_long(argc, argv, "hp:", long_options, NULL)) != -1)
	{
		switch (opt)
		{
			case 'p':
				ports = getpts(optarg, &number_of_ports);
				break;
			case 'h':
			default:
				printusage(program_name);
				exit(EXIT_FAILURE);
		}
	}

	(void)ports;
	argv += optind;
	argc -= optind;

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
	num = 1;
	for (dev = alldevs, number_of_devices = 0; number_of_devices < num - 1; dev = dev->next, ++number_of_devices);
	printf("%s interface opening...\n", dev->name);

	pcap_handle = pcap_open_live(dev->name, BUFSIZ, PROMISC_TRUE, 1000, errbuf);
	if (pcap_handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n",
			dev->name,
			errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(pcap_handle) != DLT_EN10MB)
	{
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n",
			dev->name);
		exit(EXIT_FAILURE);
	}

	pcap_freealldevs(alldevs);

	nmap = nmap_init();

	if (!number_of_ports)
		number_of_ports = MAXPORTS;

	if (!scan_mode)
		scan_mode = SCAN_ALL;

	while (argc--)
		nmap_run(nmap, *argv++);


//	if ()
	pkt_size = 100;
	pkt_buf = NULL;
	pkt_buf = set_buffer(pkt_buf, pkt_size);

//	struct ether_header ethhdr;
	int bytes_inject;

	encode_syn();

	bytes_inject = pcap_inject(pcap_handle, pkt_buf, pkt_size);
	if (bytes_inject < 0)
	{
		pcap_perror(pcap_handle, "An error occured sending a packet");
		exit(EXIT_FAILURE);
	}

	while (1)	
	{
		recv_packet(pcap_handle);
	}

	pcap_close(pcap_handle);
	return 0;
}
