#include "ft_nmap.h"

int
probe_send(t_scan_thread *thread, t_probe *probe, t_opts *opts, uint16_t sport)
{
	const t_scan_def *def;

	def = scan_def_by_flag(probe->scan_type);
	if (def == NULL)
		return 1;
	if (def->proto == PROTO_TCP)
		return probe_send_tcp(thread, probe, opts, sport);
	return probe_send_udp(thread, probe, opts, sport);
}
