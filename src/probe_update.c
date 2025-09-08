#include "ft_nmap.h"

int
probe_update(t_scan_ctx *engine, t_probe *probe, unsigned short sport,
	struct timeval ts, struct tcphdr *th)
{
	if (probe->port == sport && probe->outstanding)
	{
		if (th->th_flags & TH_SYN)
			probe->state = PORT_OPEN;
		else if (th->th_flags & TH_RST)
			probe->state = PORT_CLOSED;

		probe->outstanding = 0;
		probe->recv_time = ts;
		--engine->outstanding_probes;
		++engine->completed_probes;
		return 1;
	}
	return 0;
}
