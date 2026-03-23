#include "ft_nmap.h"
#include "logging/log.h"

static pcap_if_t *
pcap_find_iface_for_target(const char *target, pcap_if_t *alldevs)
{
	struct sockaddr_in target_addr;
	pcap_if_t *dev;

	if (inet_pton(AF_INET, target, &target_addr.sin_addr) == 1
		&& (ntohl(target_addr.sin_addr.s_addr) >> 24) == 127)
	{
		for (dev = alldevs; dev != NULL; dev = dev->next)
			if (strcmp(dev->name, "lo") == 0)
				return dev;
	}

	for (dev = alldevs; dev != NULL; dev = dev->next)
		if (!(dev->flags & PCAP_IF_LOOPBACK) && dev->addresses != NULL)
			return dev;

	return alldevs;
}

pcap_t *
get_pcap_handle(t_scan_opts *opts, int *datalink)
{
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle;

	if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "Couldn't find any device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	dev = pcap_find_iface_for_target(opts->target, alldevs);

	pcap_handle = pcap_create(dev->name, errbuf);
	if (pcap_handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_set_buffer_size(pcap_handle, PCAP_BUFSIZ) != 0)
	{
		fprintf(stderr, "Couldn't set buffer size: %s\n", pcap_geterr(pcap_handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_set_promisc(pcap_handle, PROMISC_TRUE) != 0)
	{
		fprintf(stderr, "Couldn't set promiscuous mode: %s\n", pcap_geterr(pcap_handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_set_timeout(pcap_handle, 10) != 0)
	{
		fprintf(stderr, "Couldn't set packet buffer timeout: %s\n", pcap_geterr(pcap_handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_setnonblock(pcap_handle, 1, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "Couldn't set non-blocking mode: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_activate(pcap_handle) != 0)
	{
		fprintf(stderr, "Couldn't activate handle: %s\n", pcap_geterr(pcap_handle));
		exit(EXIT_FAILURE);
	}

	*datalink = pcap_datalink(pcap_handle);
	if (*datalink != DLT_EN10MB && *datalink != DLT_NULL && *datalink != DLT_LOOP)
	{
		fprintf(stderr, "Unsupported datalink type: %d\n", *datalink);
		exit(EXIT_FAILURE);
	}

	log_message(LOG_LEVEL_DEBUG, "Capture ready on interface %s", dev->name);
	pcap_freealldevs(alldevs);
	return pcap_handle;
}
