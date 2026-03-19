#include "ft_nmap.h"

t_probe **
probe_dequeue(t_list **pending_node, int num_probes)
{
	t_probe **probes;
	t_probe *probe;
	int count;

	probes = calloc(num_probes + 1, sizeof(t_probe *));
	if (probes == NULL)
		return NULL;

	count = 0;
	while (*pending_node && count < num_probes)
	{
		probe = (t_probe *)(*pending_node)->content;
		if (probe->status == PROBE_PENDING)
			probes[count++] = probe;
		*pending_node = (*pending_node)->next;
	}
	probes[count] = NULL;
	return probes;
}
