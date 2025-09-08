#include "ft_nmap.h"

void
scan_engine_destroy(t_scan_ctx *engine)
{
	if (engine->worker_threads)
	{
		free(engine->worker_threads);
		engine->worker_threads = NULL;
	}

	if (engine->capture_queue)
	{
		packet_queue_destroy(engine->capture_queue);
		engine->capture_queue = NULL;
	}

	pthread_mutex_destroy(&engine->probe_mutex);
	pthread_mutex_destroy(&engine->engine_mutex);
}
