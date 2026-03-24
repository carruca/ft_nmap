#include "ft_nmap.h"
#include "logging/log.h"

#include <errno.h>
#include <string.h>

void
probe_mark_sent(t_probe *probe, uint16_t sport)
{
	if (gettimeofday(&probe->time_sent, NULL) < 0)
	{
		log_message(LOG_LEVEL_FATAL, "probe_mark_sent: gettimeofday failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	probe->src_port = sport;
	probe->status = PROBE_SENT;
}
