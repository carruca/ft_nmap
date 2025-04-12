#include "ft_nmap.h"
#include <pcap.h>
#include <time.h>
#include <netinet/if_ether.h>


#define MAXIPHDRLEN		20
#define PROMISC_TRUE	1 
#define PROMISC_FALSE 0
#define TIMESTRLEN 		100
#define MAXPORTS 			1024

int number_of_packets = 0;
int number_of_ports = 0;
int number_of_threads = 0;

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

static error_t
parse_opt(int key, char *arg,
	struct argp_state *state)
{
	(void)arg;
	switch(key)
	{
		case ARGP_KEY_NO_ARGS:
			argp_error(state, "missing host operand");

		/* fallthrough */
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
/*
unsigned short *
getpts(char *origexpr)
{
	(void)origexpr;
	return ;
}
*/

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

static const struct scan_mode scan_modes[] = {
	{"SYN", SCAN_SYN},
	{"NULL", SCAN_NULL},
	{"FIN", SCAN_FIN},
	{"XMAS", SCAN_XMAS},
	{"ACK", SCAN_ACK},
	{"UDP", SCAN_UDP}
};

void
print_scan_config(int ports, char *target_addr, short scan_mode, int threads)
{
	printf("Scan configurations\n");
	printf("Target IP-Address : %s\n", target_addr);
	printf("No of ports to scan : %d\n", ports);
	printf("Scans to be performed :");
	for (int i= 0; i < MAXSCANS; ++i)
	{
		if (scan_mode & scan_modes[i].flag)
			printf(" %s", scan_modes[i].name);
	}
	printf("\n");
	printf("No of threads : %d\n", threads);

}

int
main(int argc, char **argv)
{
	int index;
	char args_doc[] = "[OPTIONS]";
	char doc[] = "Network exploration tool and security / port scanner";
	struct argp_option argp_options[] = {
		//		{"first-hop", 'f', "NUM", 0, "set initial hop distance, i.e., time-to-live", 0},
		{0}
	};
	struct argp argp =
		{argp_options, parse_opt, args_doc, doc, NULL, NULL, NULL};

	pcap_if_t *alldevs;
	pcap_if_t *dev;
	size_t number_of_devices;
	size_t num;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle;
	u_char *pkt_buf;
	size_t pkt_size;
	short scan_mode = 0;

	if (argp_parse(&argp, argc, argv, 0, &index, NULL) != 0)
		return 0;
	
	argv += index;
	argc += index;

	if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "Couldn't find any devide: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

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

	if (!number_of_ports)
		number_of_ports = MAXPORTS;

	if (!scan_mode)
		scan_mode = SCAN_SYN;

	print_scan_config(number_of_ports, *argv, scan_mode, number_of_threads);

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

int
old_main()
{	
	pcap_t *handle;										/* Session handle */
	pcap_if_t *devs_list;
	char errbuf[PCAP_ERRBUF_SIZE];
//	struct bpf_program fp; 						/* The compiled filter expression */
//	char filter_exp[] = "port 80"; 		/* Filter expression */

	struct in_addr addr;
	bpf_u_int32 mask;
	bpf_u_int32 net;
//	struct pcap_pkthdr header;
//	const u_char *packet;
//	int num_packets = 10;
//	const struct ether_header *ethernet;

	if (pcap_findalldevs(&devs_list, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "Couldn't find any devide: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	for (pcap_if_t *devp = devs_list; devp != NULL; devp = devp->next)
	{
		printf("Device:	%s\n", devp->name);
		if (devp->description != NULL)
			printf("Description:	%s\n", devp->description);
/*		for (struct pcap_addr *addrp = devp->addresses; addrp != NULL; addrp = addrp->next)
		{
			if (addrp->addr != NULL)
			{
				if (addrp->addr->sa_family == AF_INET)
				{
					printf("Address ipv4: %s\n", inet_ntoa(((struct sockaddr_in *)addrp->addr)->sin_addr));
				}
			}
		}
*/
		if (pcap_lookupnet(devp->name, &net, &mask, errbuf) == PCAP_ERROR)
		{
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", devp->name, errbuf);
			net = 0;
			mask = 0;
		}

		addr.s_addr = net;
		printf("Net:	%s\n", inet_ntoa(addr));

		addr.s_addr = mask;
		printf("Mask:	%s\n", inet_ntoa(addr));
		

		handle = pcap_open_live(devp->name, BUFSIZ, PROMISC_TRUE, -1, errbuf);
		if (handle == NULL)
		{
			fprintf(stderr, "Couldn't open device %s: %s\n", devp->name, errbuf);
			exit(EXIT_FAILURE);
		}

		if (pcap_datalink(handle) != DLT_EN10MB)
		{
			fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", devp->name);
			exit(EXIT_FAILURE);
		}
/*
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == PCAP_ERROR)
		{
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}

		if (pcap_setfilter(handle, &fp) == PCAP_ERROR)
		{
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
*/
//		pcap_loop(handle, num_packets, print_packet_info, NULL);

//		pcap_freecode(&fp);
		pcap_close(handle);
		printf("\n");
	}

	pcap_freealldevs(devs_list);
  return 0;
}
