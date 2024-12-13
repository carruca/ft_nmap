#include "ft_nmap.h"
#include <pcap.h>
#include <time.h>

#define MAXIPHDRLEN		20
#define PROMISC_TRUE	1 
#define PROMISC_FALSE 0

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
print_packet_info(u_char *args, const struct pcap_pkthdr *header, const u_char *bytes)
{
	(void)args;
	uint16_t ether_type;
	struct ip *ip;

	printf("Grabbed packet of lenght: %d\n", header->len);
	printf("Recieved at .... %s", ctime((const time_t*)&header->ts.tv_sec));
	printf("Ethernet address lenght is %d\n", ETH_HLEN);

	ether_type = handle_ethernet(bytes);
	if (ether_type == ETHERTYPE_IP)
	{
		ip = (struct ip *)(bytes + ETH_HLEN);
		printf("Time To Live: %d\n", ip->ip_ttl);
		printf("IP src: %s\n", inet_ntoa(ip->ip_src));
		printf("IP dst: %s\n", inet_ntoa(ip->ip_dst));
		switch(ip->ip_p)
		{
			case IPPROTO_ICMP:
				printf("Protocol: ICMP\n");
				break;

			case IPPROTO_TCP:
				printf("Protocol: TCP\n");
				break;

			case IPPROTO_UDP:
				printf("Protocol: UDP\n");
				break;

			default:
				printf("Protocol: Unknown\n");
				break;
		}
	}
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
print_pkthdr(struct pcap_pkthdr *pkt_header)
{
	struct tm *ltime;
	char timestr[11];
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

	printf("%s cap:%d len:%d\n",
		timestr,
		pkt_header->caplen,
		pkt_header->len);
	return 0;
}

int
recv_packet(pcap_t *p_handle)
{
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;

	//TODO: we need to make a copy of pkt_header and pkt_data when using multithreads
	if (pcap_next_ex(p_handle, &pkt_header, &pkt_data) == PCAP_ERROR)
	{
		fprintf(stderr, "Couldn't read next packet: %s\n",
			pcap_geterr(p_handle));
		return 1;
	}

	if (print_pkthdr(pkt_header))
		return 1;
	return 0;
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
	size_t dcount;
	size_t dnum;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pkt_handle;

	if (argp_parse(&argp, argc, argv, 0, &index, NULL) != 0)
		return 0;
	
	argv += index;
	argc += index;

	if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "Couldn't find any devide: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	dcount = 0;
	for (dev = alldevs; dev != NULL; dev = dev->next)
	{
		printf("%lu. %s", ++dcount, dev->name);
		if (dev->description != NULL)
			printf(" (%s)\n", dev->description);
		else
			printf(" (No description available)\n");
	}

	printf("Enter the interface number (1-%lu) range.\n", dcount);
	scanf("%lu", &dnum);

	for (dev = alldevs, dcount = 0; dcount < dnum - 1; dev = dev->next, ++dcount);
	printf("%s interface opening...\n", dev->name);

	pkt_handle = pcap_open_live(dev->name, BUFSIZ, PROMISC_TRUE, 1000, errbuf);
	if (pkt_handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n",
			dev->name,
			errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(pkt_handle) != DLT_EN10MB)
	{
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n",
			dev->name);
		exit(EXIT_FAILURE);
	}

	pcap_freealldevs(alldevs);

	while (1)
		recv_packet(pkt_handle);

	pcap_close(pkt_handle);
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
	int num_packets = 10;
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
		pcap_loop(handle, num_packets, print_packet_info, NULL);

//		pcap_freecode(&fp);
		pcap_close(handle);
		printf("\n");
	}

	pcap_freealldevs(devs_list);
  return 0;
}
