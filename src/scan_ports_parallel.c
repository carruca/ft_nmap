#include "ft_nmap.h"
#include "logging/log.h"

#include <errno.h>

extern int errno;

void
scan_ports_parallel(t_scan_ctx *scan_ctx, int num_ports)
{
	t_scan_options *opts;
	struct timeval scan_start, scan_end;
	double total_time;

	if (scan_ctx == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_ctx is NULL");
		exit(EXIT_FAILURE);
	}

	opts = scan_ctx->opts;

	if (gettimeofday(&scan_start, NULL) < 0)
	{
		log_message(LOG_LEVEL_ERROR, "gettimeofday failed: %s", strerror(errno));
	  exit(EXIT_FAILURE);
  }

	//init scan
	if (scan_target_sockaddr_set(&scan_ctx->target, opts->target))
	{
		log_message(LOG_LEVEL_ERROR, "set_sockaddr_by_hostname failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	scan_config_print(scan_ctx, num_ports);

	pthread_mutex_init(&scan_ctx->engine_mutex, NULL);
	pthread_mutex_init(&scan_ctx->probe_mutex, NULL);

	scan_ctx->pending_probe_list = scan_ctx->probe_list;

	scan_ctx->capture_queue = packet_queue_create();
	if (scan_ctx->capture_queue == NULL)
		error(EXIT_FAILURE, errno, "capture_queue_create");

	// TODO: unificar las dos cadenas de workers
	scan_ctx->worker_threads = calloc(opts->num_threads, sizeof(pthread_t));
	if (scan_ctx->worker_threads == NULL)
		error(EXIT_FAILURE, errno, "worker_threads_create");

	scan_ctx->capture_active = 1;

	if (pthread_create(&scan_ctx->capture_thread, NULL, packet_capture_thread, scan_ctx) != 0)
		error(EXIT_FAILURE, errno, "pthread_create");

	for (unsigned short pos = 0; pos < opts->num_threads; ++pos)
	{
		if (pthread_create(&scan_ctx->worker_threads[pos], NULL, packet_worker_thread, scan_ctx) != 0)
			error(EXIT_FAILURE, errno, "pthread_create");
	}

	scan_ctx->send_workers = calloc(opts->num_threads, sizeof(t_scan_worker));
	if (scan_ctx->send_workers == NULL)
		error(EXIT_FAILURE, errno, "send_workers_create");

	for (unsigned short pos = 0; pos < opts->num_threads; ++pos)
	{
		if (send_worker_create(&scan_ctx->send_workers[pos], pos, scan_ctx) != 0)
			error(EXIT_FAILURE, errno, "send_worker_create");
	}

	while (scan_ctx->completed_probes < scan_ctx->total_probes)
	{
		pthread_mutex_lock(&scan_ctx->engine_mutex);
		probe_list_timeout(scan_ctx);
		pthread_mutex_unlock(&scan_ctx->engine_mutex);

		usleep(1000);
	}

	for (unsigned short pos = 0; pos < opts->num_threads; ++pos)
		scan_ctx->send_workers[pos].active = 0;

	for (unsigned short pos = 0; pos < opts->num_threads; ++pos)
	{
		pthread_join(scan_ctx->send_workers[pos].thread, NULL);
		close(scan_ctx->send_workers[pos].tcp_socket);
	}

	free(scan_ctx->send_workers);

	scan_ctx->capture_active = 0;
	scan_ctx->capture_queue->shutdown = 1;

	pthread_cond_broadcast(&scan_ctx->capture_queue->not_empty);
	pthread_cond_broadcast(&scan_ctx->capture_queue->not_full);

	pthread_join(scan_ctx->capture_thread, NULL);
	for (unsigned short pos = 0; pos < opts->num_threads; ++pos)
		pthread_join(scan_ctx->worker_threads[pos], NULL);

	scan_destroy(scan_ctx);

	if (gettimeofday(&scan_end, NULL) < 0)
		error(EXIT_FAILURE, errno, "gettimeofday");
	tvsub(&scan_end, &scan_start);
	total_time = (double)scan_end.tv_sec
		+ (double)scan_end.tv_usec / 1000000.0;

	printf("Scan took %.2f secs\n", total_time);
	scan_results_print(scan_ctx);
}
