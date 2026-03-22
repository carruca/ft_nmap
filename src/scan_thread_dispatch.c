#include "ft_nmap.h"
#include "logging/log.h"

int
scan_thread_dispatch(
	t_scan_thread *threads, t_list **pending_list,
	t_scan_ctx *ctx, t_scan_opts *config)
{
	uint16_t probes_per_thread;
	uint16_t remaining_probes;
	uint16_t probes_assigned_to_thread;
	t_scan_thread *cur;

	probes_per_thread = ctx->probes_total / config->num_threads;
	remaining_probes = ctx->probes_total % config->num_threads;

	for (uint16_t i = 0; i < config->num_threads; ++i)
	{
		probes_assigned_to_thread = probes_per_thread +
			(i < remaining_probes ? 1 : 0);

		cur = &threads[i];
		cur->dst = ctx->dst;

		if (scan_thread_init(cur, i + 1, config))
		{
			log_message(LOG_LEVEL_ERROR, "scan_thread_dispatch: scan_thread_init failed");
			return -1;
		}

		cur->probes = probe_dequeue(pending_list, probes_assigned_to_thread);
		if (cur->probes == NULL)
		{
			log_message(LOG_LEVEL_ERROR, "scan_thread_dispatch: probe_dequeue failed");
			return -1;
		}

		if (pthread_create(&cur->thread, NULL, scan_thread_entry, cur) != 0)
		{
			log_message(LOG_LEVEL_ERROR, "scan_thread_dispatch: pthread_create failed");
			return -1;
		}
	}

	for (uint16_t i = 0; i < config->num_threads; ++i)
		pthread_join(threads[i].thread, NULL);
	return 0;
}
