#include "ft_nmap.h"

void *
send_worker_thread(void *arg)
{
	t_scan_worker *worker;
	t_scan_ctx *engine;
	int batch_count, sent_count;

	worker = (t_scan_worker *)arg;
	engine = worker->engine;

	while (worker->active)
	{
		pthread_mutex_lock(&engine->probe_mutex);

		batch_count = get_probe_batch(worker, engine);

		pthread_mutex_unlock(&engine->probe_mutex);

		if (batch_count == 0)
		{
			if (engine->pending_probe_list == NULL
				&& engine->outstanding_probes == 0)
				break ;
			else
			{
				usleep(1000);
				continue;
			}
		}

		sent_count = send_probe_batch(worker, engine, batch_count);

		if (sent_count > 0)
			usleep(1000 * sent_count);
	}

	return NULL;
}
