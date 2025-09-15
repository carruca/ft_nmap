#include "ft_nmap.h"

void
scan_destroy(t_scan_ctx *scan_ctx)
{
	if (scan_ctx)
	{
		free(scan_ctx->worker_threads);
		packet_queue_destroy(scan_ctx->capture_queue);

		pthread_mutex_destroy(&scan_ctx->probe_mutex);
		pthread_mutex_destroy(&scan_ctx->engine_mutex);

		scan_probe_list_destroy(scan_ctx);
		scan_options_destroy(scan_ctx->opts);

		free(scan_ctx);
	}
}
