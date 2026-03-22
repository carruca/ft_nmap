#include "ft_nmap.h"

#include <errno.h>

extern int errno;

void
probe_mark_sent(t_probe *probe, uint16_t sport)
{
	if (gettimeofday(&probe->time_sent, NULL) < 0)
		error(EXIT_FAILURE, errno, "gettimeofday");
	probe->src_port = sport;
	probe->status = PROBE_SENT;
}
