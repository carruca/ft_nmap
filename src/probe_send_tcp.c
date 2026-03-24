#include "ft_nmap.h"
#include "tcp_checksum.h"
#include "logging/log.h"

#include <sys/random.h>


int
probe_send_tcp(t_scan_thread *thread, t_probe *probe, t_scan_opts *opts, uint16_t sport)
{
	ssize_t bytes_sent;
	struct tcphdr *th;
	char packet[sizeof(struct tcphdr)];
	const t_scan_def *def;

	def = scan_def_by_flag(probe->scan_type);
	if (def == NULL)
		return 1;

	memset(packet, 0, sizeof(packet));
	th = (struct tcphdr *)packet;

	th->th_sport = htons(sport);
	th->th_dport = htons(probe->dst_port);
	uint32_t isn;
	if (getrandom(&isn, sizeof(isn), 0) != sizeof(isn))
		isn = (uint32_t)(uintptr_t)probe;
	th->th_seq   = htonl(isn);
	th->th_off   = TCP_HLEN;
	th->th_flags = def->tcp_flags;
	th->th_win   = htons(TCP_WINDOW_SIZE);
	th->th_sum   = tcp_checksum(&opts->source_addr, &thread->dst, th);

	bytes_sent = sendto(thread->tcp_sock, packet, sizeof(packet), 0,
		(struct sockaddr *)&thread->dst, sizeof(struct sockaddr_in));
	if (bytes_sent == (ssize_t)sizeof(packet))
	{
		probe_mark_sent(probe, sport);
		log_message(LOG_LEVEL_DEBUG, "Sending %s to %s:%u (sport: %u)",
			def->name, probe->dst_ip, probe->dst_port, sport);
		return 0;
	}
	log_message(LOG_LEVEL_WARN, "Failed to send %s to %s:%u",
		def->name, probe->dst_ip, probe->dst_port);
	return 1;
}
