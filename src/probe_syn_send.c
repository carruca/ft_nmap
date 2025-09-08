#include "ft_nmap.h"

#include <errno.h>

extern int errno;

int
send_syn_probe(int raw_socket, t_scan_ctx *scan_ctx, t_probe *probe)
{
	ssize_t bytes_sent;
	struct tcphdr *th;
	char packet[sizeof(struct tcphdr)];
	pid_t pid = getpid();

	memset(packet, 0, sizeof(packet));
	th = (struct tcphdr *)packet;

	th->th_sport = htons(rand() % 65535);
	th->th_dport = htons(probe->port);
	th->th_seq = htonl(rand() % pid);
	th->th_off = TCP_HLEN;
	th->th_flags = TH_SYN;
	th->th_win = htons(1024);
	th->th_sum = tcp_checksum(&scan_ctx->source, &scan_ctx->target, th);

	bytes_sent = sendto(raw_socket, packet, sizeof(packet), 0,
		(struct sockaddr *)&scan_ctx->target, sizeof(struct sockaddr_in));
	if (bytes_sent > 0)
	{
		if (gettimeofday(&probe->sent_time, NULL) < 0)
			error(EXIT_FAILURE, errno, "gettimeofday");

		probe->outstanding = 1;
		probe->state = PORT_TESTING;
		++scan_ctx->outstanding_probes;

		if (scan_ctx->opts.debugging)
			printf("probe of %lu bytes sent to port %u (outstanding: %u)\n",
				bytes_sent, probe->port, scan_ctx->outstanding_probes);

		return 0;
	}
	return 1;
}
