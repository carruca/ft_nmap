#include "ft_nmap.h"

void
send_probe_list(t_scan_ctx *scan_ctx)
{
	t_list *current_node;
	t_probe *probe;
	int raw_socket;

	raw_socket = get_raw_socket_by_protocol("tcp");
	current_node = scan_ctx->probe_list;

	while (current_node
		&& scan_ctx->outstanding_probes < scan_ctx->max_outstanding)
	{
		probe = current_node->content;
		if (probe->state == PORT_UNKNOWN)
		{
			if (send_syn_probe(raw_socket, scan_ctx, probe) == 0)
				current_node = current_node->next;
			else
				break;
		}
		else
			current_node = current_node->next;
	}
	close(raw_socket);
}
