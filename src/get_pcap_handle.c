#include "ft_nmap.h"

pcap_t *
get_pcap_handle(t_scan_options *opts)
{
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	size_t num_devices;
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
	for (dev = alldevs, num_devices = 0; num_devices < iface - 1; dev = dev->next, ++num_devices);
	if (opts->verbose)
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
