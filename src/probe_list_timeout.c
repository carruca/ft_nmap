#include "ft_nmap.h"

#include <errno.h>

extern int errno;

void
probe_list_timeout(t_scan_ctx *engine)
{
	t_list *current_node;
	t_probe *probe;
	double elapsed_time;
	struct timeval current_time;


	current_node = engine->probe_list;
	while (current_node)
	{
		probe = current_node->content;
		if (probe->outstanding)
		{
			if (gettimeofday(&current_time, NULL) < 0)
				error(EXIT_FAILURE, errno, "gettimeofday");
			tvsub(&current_time, &probe->sent_time);	
			elapsed_time = (double)current_time.tv_sec
				+ (double)current_time.tv_usec / 1000000.0;

			if (elapsed_time > probe->timing.timeout)
			{
				if (engine->opts->debugging)
					printf("port %u timeout after %.2fs\n", probe->port, elapsed_time);
/*				if (probe->retries < MAX_RETRIES)
				{
					++probe->retries;
					probe->outstanding = 0;
					--engine->outstanding_probes;
				}
				else
*/				{
					probe->state = PORT_FILTERED;
					probe->outstanding = 0;
					--engine->outstanding_probes;
					++engine->completed_probes;
				}
			}
		}
		current_node = current_node->next;
	}
}
