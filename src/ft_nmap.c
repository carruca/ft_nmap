#include "ft_nmap.h"
#include <pcap.h>
#include <time.h>

#define MAXIPHDRLEN		20
#define PROMISC_TRUE	1 
#define PROMISC_FALSE 0

void
print_host(const u_char *host, char *origin)
{
	int i;

	i = ETH_ALEN;
	printf("%s Address: ", origin);
	while (i > 0)
	{
		printf("%s%x", (i == ETH_ALEN) ? " " : ":", *host++);
		--i;
	}
	printf("\n");
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
		printf("Ethernet type hex:%x dec:%d is a IP packet\n",
				type,
				type);
	}
	else if (type == ETHERTYPE_ARP)
	{
		printf("Ethernet type hex:%x dec:%d is a ARP packet\n",
				type,
				type);
	}
	else if (type == ETHERTYPE_REVARP)
	{
		printf("Ethernet type hex:%x dec:%d is a REVARP packet\n",
				type,
				type);
	}
	else
	{
		printf("Ethernet type hex:%x dec:%d not IP\n",
				type,
				type);
	}

	print_host(ether->ether_dhost, "Destination");
	print_host(ether->ether_shost, "Source");
	printf("\n");
	return type;
}

void
print_packet_info(u_char *args, const struct pcap_pkthdr *header, const u_char *bytes)
{
	(void)args;
	uint16_t ether_type;

	printf("Grabbed packet of lenght: %d\n", header->len);
	printf("Recieved at .... %s", ctime((const time_t*)&header->ts.tv_sec));
	printf("Ethernet address lenght is %d\n", ETH_HLEN);

	ether_type = handle_ethernet(bytes);
	if (ether_type == ETHERTYPE_IP)
	{}

}

int
main()
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
		

		handle = pcap_open_live(devp->name, BUFSIZ, PROMISC_FALSE, -1, errbuf);
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
