#include "ft_nmap.h"

void
scan_probe_list_create(t_scan_ctx *engine, unsigned short *ports, unsigned int num_ports)
{
	for (unsigned int pos = 0; pos < num_ports; ++pos)
	{
		t_probe *probe;
		t_list *node;

		probe = malloc(sizeof(t_probe));
		if (probe == NULL)
			continue ;

		memset(probe, 0, sizeof(t_probe));
		probe->port = ports[pos];
		probe->state = PORT_UNKNOWN;
		probe->timing.timeout = engine->global_timing.timeout;

		node = ft_lstnew(probe);
		if (node == NULL)
		{
			free(probe);
			continue ;
		}

		ft_lstadd_back(&engine->probe_list, node);
		++engine->total_probes;
	}
}
