#include "ft_nmap.h"

void
scan_probe_list_create(t_scan_ctx *scan_ctx, unsigned short *ports, unsigned short num_ports)
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
		probe->timing.timeout = scan_ctx->global_timing.timeout;

		node = ft_lstnew(probe);
		if (node == NULL)
		{
			free(probe);
			continue ;
		}

		ft_lstadd_back(&scan_ctx->probe_list, node);
		++scan_ctx->total_probes;
	}
}
