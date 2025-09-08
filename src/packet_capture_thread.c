#include "ft_nmap.h"

void *
packet_capture_thread(void *arg)
{
	int pcap_fd, pcap_res;
	fd_set fdset;
	t_scan_ctx *engine;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	struct timeval timeout;

	engine = (t_scan_ctx *)arg;
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
				if (engine->opts.debugging)
					printf("probe of %u bytes captured\n", pkt_header->caplen);
				packet_queue_handler(engine->capture_queue,
					pkt_data, pkt_header->caplen, pkt_header->ts);
			}
		}
	}
	return NULL;
}
