#include "ft_nmap.h"
#include "logging/log.h"

#include <errno.h>

extern int errno;

int
probe_send_syn(t_scan_thread *info, t_probe *probe, t_opts *opts, uint16_t sport)
{
	ssize_t bytes_sent;
	struct tcphdr *th;
	char packet[sizeof(struct tcphdr)];

	memset(packet, 0, sizeof(packet));
	th = (struct tcphdr *)packet;

	th->th_sport = htons(sport);
	th->th_dport = htons(probe->dst_port);
	th->th_seq = htonl(rand());
	th->th_off = TCP_HLEN;
	th->th_flags = TH_SYN;
	th->th_win = htons(1024);
	th->th_sum = tcp_checksum(&opts->source_addr, &info->dst, th);

	bytes_sent = sendto(info->tcp_sock, packet, sizeof(packet), 0,
		(struct sockaddr *)&info->dst, sizeof(struct sockaddr_in));
	if (bytes_sent > 0)
	{
		if (gettimeofday(&probe->time_sent, NULL) < 0)
			error(EXIT_FAILURE, errno, "gettimeofday");

		probe->src_port = sport;
		probe->status = PROBE_SENT;

		log_message(LOG_LEVEL_DEBUG, "Sending SYN to %s:%u (sport: %u)",
			probe->dst_ip, probe->dst_port, sport);

		return 0;
	}
	log_message(LOG_LEVEL_WARN, "Failed to send SYN to %s:%u", probe->dst_ip, probe->dst_port);
	return 1;
}

