#include "ft_nmap.h"
#include "logging/log.h"

#include <errno.h>

extern int errno;

void
scan_ports(t_scan_ctx *scan_ctx, int num_ports)
{
	t_scan_options *opts;
	struct timeval scan_start, scan_end, timeout;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	double total_time;
	int pcap_fd, pcap_res;
	fd_set fdset;

	opts = scan_ctx->opts; 

	if (gettimeofday(&scan_start, NULL) < 0)
	{
		log_message(LOG_LEVEL_FATAL, "gettypeofday failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (set_sockaddr_by_hostname(&scan_ctx->target, opts->target))
	{
		log_message(LOG_LEVEL_FATAL, "set_sockaddr_by_hostname failed");
		exit(EXIT_FAILURE);
	}

	scan_config_print(scan_ctx, num_ports);

	while (scan_ctx->completed_probes < scan_ctx->total_probes)
	{
		send_probe_list(scan_ctx);

		pcap_fd = pcap_get_selectable_fd(scan_ctx->pcap_handle);

		FD_ZERO(&fdset);
		FD_SET(pcap_fd, &fdset);

		timeout.tv_sec = 0;
		timeout.tv_usec = 1000;

		if (select(pcap_fd + 1, &fdset, NULL, NULL, &timeout) > 0)
		{
			while ((pcap_res = pcap_next_ex(scan_ctx->pcap_handle, &pkt_header, &pkt_data)) == 1)
			{
				if (opts->debugging)
					printf("probe of %u bytes captured\n", pkt_header->caplen);
				packet_response(scan_ctx, pkt_header->ts, pkt_data);
			}
		}

		probe_list_timeout(scan_ctx);
		usleep(1000);
	}

	if (gettimeofday(&scan_end, NULL) < 0)
		error(EXIT_FAILURE, errno, "gettimeofday");
	tvsub(&scan_end, &scan_start);
	total_time = (double)scan_end.tv_sec
		+ (double)scan_end.tv_usec / 1000000.0;

	printf("Scan took %.2f secs\n", total_time);
	scan_results_print(scan_ctx);
}
