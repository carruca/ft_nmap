#include "ft_nmap.h"

int
send_probe_batch(t_scan_worker *worker, t_scan_ctx *engine, int batch_count)
{
	t_probe *probe;
	int sent_count;

	sent_count = 0;
	for (int pos = 0; pos < batch_count; ++pos)
	{
		probe = worker->probe_batch[pos];

		if (send_syn_probe(worker->tcp_socket, engine, probe) == 0)
			++sent_count;
	}
	return sent_count;
}
