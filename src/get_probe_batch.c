#include "ft_nmap.h"

int
get_probe_batch(t_scan_worker *worker, t_scan_ctx *engine)
{
	t_list *current_node;
	t_probe *probe;
	int count;

	count = 0;
	current_node = engine->pending_probe_list;
	while (current_node && count < PROBE_BATCH_MAXSIZE
		&& engine->outstanding_probes < engine->max_outstanding)
	{
		probe = (t_probe *)current_node->content;
		if (probe->state == PORT_UNKNOWN)
		{
			worker->probe_batch[count] = probe;
			++count;
			engine->pending_probe_list = current_node->next;
		}
		current_node = current_node->next;
	}

	return count;
}
