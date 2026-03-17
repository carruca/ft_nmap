#include "ft_nmap.h"

t_probe *
probe_new(char *target_ip, uint16_t target_port, double timeout)
{
	t_probe *probe;

	probe = malloc(sizeof(t_probe));
	if (probe == NULL)
		return NULL;

	strncpy(probe->dst_ip, target_ip, sizeof(probe->dst_ip) - 1);
	probe->dst_ip[sizeof(probe->dst_ip) - 1] = '\0';

	probe->dst_port = target_port;
	probe->status = PROBE_PENDING;
	probe->timeout = timeout;
	probe->retries = 0;

	return probe;
}

t_list *
probes_create(
	uint16_t *ports, uint16_t num_ports,
	char *target_ip, double timeout)
{
	t_list *probe_list = NULL;

	for (uint16_t pos = 0; pos < num_ports; ++pos)
	{
		t_probe *probe;
		t_list *node;

		probe = probe_new(target_ip, ports[pos], timeout);
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

