#include "ft_nmap.h"

t_scan_probe *
probe_create(char *target_ip, uint16_t target_port, double timeout)
{
	t_scan_probe * probe;

	probe = malloc(sizeof(t_scan_probe));
	if (probe == NULL)
		return NULL;

	strncpy(probe->target_ip, target_ip, sizeof(probe->target_ip) - 1);
	probe->target_ip[sizeof(probe->target_ip) - 1] = '\0';

	probe->target_port = target_port;
	probe->state = PROBE_PENDING;
	probe->timeout = timeout;
	probe->retries = 0;

	return probe;
}

t_list *
probe_list_create(
	uint16_t *ports, uint16_t num_ports,
	char *target_ip, double timeout)
{
	t_list *probe_list = NULL;

	for (uint16_t pos = 0; pos < num_ports; ++pos)
	{
		t_scan_probe *probe;
		t_list *node;

		probe = probe_create(target_ip, ports[pos], timeout);
		if (probe == NULL)
			continue;


		node = ft_lstnew(probe);
		if (node == NULL)
		{
			free(probe);
			continue ;
		}

		ft_lstadd_back(&probe_list, node);
	}

	return probe_list;
}

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
