#include "ft_nmap.h"
#include "logging/log.h"

static void
scan_run_sequential(t_scan_ctx *ctx, t_scan_opts *opts)
{
	t_scan_thread *thread;
	t_list *probes_pending;
	struct timeval scan_start;
	struct timeval scan_end;
	double elapsed;

	thread = calloc(1, sizeof(t_scan_thread));
	if (thread == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_run_sequential: calloc failed");
		exit(EXIT_FAILURE);
	}

	thread->dst = ctx->dst;
	if (scan_thread_init(thread, 0, opts))
	{
		log_message(LOG_LEVEL_ERROR, "scan_run_sequential: scan_thread_init failed");
		free(thread);
		exit(EXIT_FAILURE);
	}

	probes_pending = ctx->probes;
	thread->probes = probe_dequeue(&probes_pending, ctx->probes_total);
	if (thread->probes == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_run_sequential: probe_dequeue failed");
		free(thread);
		exit(EXIT_FAILURE);
	}

	gettimeofday(&scan_start, NULL);
	scan_thread_run(thread, opts);
	gettimeofday(&scan_end, NULL);

	elapsed = (double)(scan_end.tv_sec - scan_start.tv_sec)
		+ (double)(scan_end.tv_usec - scan_start.tv_usec) / 1e6;
	scan_results_print(thread, 1, opts->target, elapsed);

	scan_thread_destroy(thread);
	free(thread);
}

static void
scan_run_parallel(t_scan_ctx *ctx, t_scan_opts *opts)
{
	t_scan_thread *threads;
	t_list *probes_pending;
	struct timeval scan_start;
	struct timeval scan_end;
	double elapsed;

	threads = calloc(opts->num_threads, sizeof(t_scan_thread));
	if (threads == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_run_parallel: calloc failed");
		exit(EXIT_FAILURE);
	}

	probes_pending = ctx->probes;
	gettimeofday(&scan_start, NULL);
	scan_thread_dispatch(threads, &probes_pending, ctx, opts);
	gettimeofday(&scan_end, NULL);

	elapsed = (double)(scan_end.tv_sec - scan_start.tv_sec)
		+ (double)(scan_end.tv_usec - scan_start.tv_usec) / 1e6;
	scan_results_print(threads, opts->num_threads, opts->target, elapsed);

	for (uint16_t i = 0; i < opts->num_threads; ++i)
		scan_thread_destroy(&threads[i]);
	free(threads);
}

void
scan_run(t_scan_ctx *ctx, t_scan_opts *opts)
{
	if (ctx == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_run: ctx is NULL");
		exit(EXIT_FAILURE);
	}

	if (scan_resolve_target(&ctx->dst, opts->target))
	{
		log_message(LOG_LEVEL_ERROR, "scan_run: scan_resolve_target failed");
		exit(EXIT_FAILURE);
	}

	if (scan_detect_source(&opts->source_addr, &ctx->dst))
	{
		log_message(LOG_LEVEL_ERROR, "scan_run: scan_detect_source failed");
		exit(EXIT_FAILURE);
	}

	probe_list_destroy(ctx);
	ctx->probes = probe_list_create(
		(uint16_t *)ctx->ports, ctx->num_ports,
		opts->target, ctx->timeout, opts->scan_flag);
	ctx->probes_total = ft_lstsize(ctx->probes);

	scan_config_print(ctx, opts, ctx->num_ports);

	if (!opts->num_threads)
		scan_run_sequential(ctx, opts);
	else
		scan_run_parallel(ctx, opts);
}
