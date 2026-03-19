#include "ft_nmap.h"
#include "logging/log.h"

#include <errno.h>

extern int errno;

/*
** probe_send_udp — envía un datagrama UDP mínimo (solo header, sin payload).
**
** El socket es SOCK_RAW con IPPROTO_UDP; el kernel añade el header IP.
** La suma de comprobación a 0 es válida en IPv4 (UDP checksum opcional).
** La respuesta esperada es ICMP port-unreachable (puerto cerrado) o un
** datagrama UDP de respuesta (puerto abierto).
*/
int
probe_send_udp(t_scan_thread *thread, t_probe *probe, t_opts *opts, uint16_t sport)
{
	ssize_t bytes_sent;
	struct udphdr uh;

	(void)opts;

	memset(&uh, 0, sizeof(uh));
	uh.uh_sport = htons(sport);
	uh.uh_dport = htons(probe->dst_port);
	uh.uh_ulen  = htons(sizeof(struct udphdr));
	uh.uh_sum   = 0;

	bytes_sent = sendto(thread->udp_sock, &uh, sizeof(uh), 0,
		(struct sockaddr *)&thread->dst, sizeof(struct sockaddr_in));
	if (bytes_sent > 0)
	{
		if (gettimeofday(&probe->time_sent, NULL) < 0)
			error(EXIT_FAILURE, errno, "gettimeofday");
		probe->src_port = sport;
		probe->status   = PROBE_SENT;
		log_message(LOG_LEVEL_DEBUG, "Sending UDP to %s:%u (sport: %u)",
			probe->dst_ip, probe->dst_port, sport);
		return 0;
	}
	log_message(LOG_LEVEL_WARN, "Failed to send UDP to %s:%u",
		probe->dst_ip, probe->dst_port);
	return 1;
}
