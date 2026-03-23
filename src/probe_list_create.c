#include "ft_nmap.h"
#include "logging/log.h"

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
probe_list_create(
	uint16_t *ports, uint16_t num_ports,
	char *target_ip, double timeout, t_scan_type scan_flag)
{
	t_list *probe_list;
	const t_scan_def *def;
	t_probe *probe;
	t_list *node;

	probe_list = NULL;
	for (uint16_t pos = 0; pos < num_ports; ++pos)
	{
		for (int d = 0; (def = scan_def_by_index(d))->name != NULL; ++d)
		{
			if (!(def->flag & scan_flag))
				continue;

			probe = probe_new(target_ip, ports[pos], timeout);
			if (probe == NULL)
			{
				log_message(LOG_LEVEL_FATAL, "probe_new failed");
				exit(EXIT_FAILURE);
			}
			probe->scan_type = def->flag;

			node = ft_lstnew(probe);
			if (node == NULL)
			{
				free(probe);
				log_message(LOG_LEVEL_FATAL, "ft_lstnew failed");
				exit(EXIT_FAILURE);
			}
			ft_lstadd_back(&probe_list, node);
		}
	}
	return probe_list;
}
