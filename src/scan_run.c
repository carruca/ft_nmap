#include "ft_nmap.h"
#include "logging/log.h"

static int
scan_thread_open_sockets(t_scan_thread *thread, t_opts *config)
{
	if (config->scan_flag & (SCAN_SYN | SCAN_FIN | SCAN_NULL | SCAN_XMAS | SCAN_ACK))
		thread->tcp_sock = get_raw_socket_by_protocol("tcp");

	if (config->scan_flag & SCAN_UDP)
		thread->udp_sock = get_raw_socket_by_protocol("udp");

	return 0;
}

static int
scan_thread_setup_pcap(t_scan_thread *thread, int thread_id, t_opts *config)
{
	int has_tcp;
	int has_udp;
	const char *src_ip;
	int lo;
	int hi;

	thread->pcap_handle = get_pcap_handle(config, &thread->datalink);
	if (thread->pcap_handle == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_thread_setup_pcap: pcap_handle is NULL (id:%i)", thread_id);
		return -1;
	}

	srand((unsigned int)time(NULL) ^ ((unsigned int)thread_id * 7919));
	thread->sport_base = 1024 + (rand() % (65535 - 1024 - MAX_PORTS_PER_SCAN));

	has_tcp = config->scan_flag & (SCAN_SYN | SCAN_ACK | SCAN_FIN | SCAN_XMAS | SCAN_NULL);
	has_udp = config->scan_flag & SCAN_UDP;
	src_ip = inet_ntoa(thread->dst.sin_addr);
	lo = thread->sport_base;
	hi = thread->sport_base + MAX_PORTS_PER_SCAN - 1;

	if (has_tcp && has_udp)
		snprintf(thread->filter_expr, sizeof(thread->filter_expr),
			"(tcp and src host %s and dst portrange %d-%d) or (icmp and src host %s)",
			src_ip, lo, hi, src_ip);
	else if (has_udp)
		snprintf(thread->filter_expr, sizeof(thread->filter_expr),
			"(icmp or udp) and src host %s", src_ip);
	else
		snprintf(thread->filter_expr, sizeof(thread->filter_expr),
			"tcp and src host %s and dst portrange %d-%d",
			src_ip, lo, hi);

	if (set_pcap_filter(thread->pcap_handle, thread->filter_expr))
	{
		log_message(LOG_LEVEL_ERROR, "scan_thread_setup_pcap: set_pcap_filter failed");
		return -1;
	}

	return 0;
}

int
scan_thread_init(t_scan_thread *thread, int thread_id, t_opts *config)
{
	thread->thread_id = thread_id;
	thread->opts = config;

	if (scan_thread_open_sockets(thread, config))
		return -1;

	if (scan_thread_setup_pcap(thread, thread_id, config))
		return -1;

	return 0;
}

static int
count_probes(t_probe **probes)
{
	int count;

	count = 0;
	while (probes[count] != NULL)
		count++;
	return count;
}

int
scan_thread_run(t_scan_thread *thread, t_opts *opts)
{
	int total;
	int next_to_send;
	int outstanding;
	int completed;
	int pcap_fd;
	int pcap_res;
	fd_set fdset;
	struct timeval select_timeout;
	struct timeval now;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	t_probe *probe;
	uint16_t sport;
	double elapsed;

	total = count_probes(thread->probes);
	pcap_fd = pcap_get_selectable_fd(thread->pcap_handle);
	next_to_send = 0;
	outstanding = 0;
	completed = 0;

	while (completed < total)
	{
		while (outstanding < WINDOW_SIZE && next_to_send < total)
		{
			probe = thread->probes[next_to_send];
			sport = (uint16_t)(thread->sport_base
				+ (next_to_send % MAX_PORTS_PER_SCAN));

			if (probe->status == PROBE_PENDING)
			{
				if (probe_send(thread, probe, opts, sport) == 0)
					outstanding++;
				else
				{
					probe->status = PROBE_TIMEOUT;
					probe->result = PORT_FILTERED;
					completed++;
				}
			}
			next_to_send++;
		}

		FD_ZERO(&fdset);
		FD_SET(pcap_fd, &fdset);
		select_timeout.tv_sec = 0;
		select_timeout.tv_usec = 10000;

		if (select(pcap_fd + 1, &fdset, NULL, NULL, &select_timeout) > 0)
		{
			while ((pcap_res = pcap_next_ex(thread->pcap_handle,
					&pkt_header, &pkt_data)) == 1)
			{
				for (int j = 0; thread->probes[j] != NULL; j++)
				{
					if (probe_match(thread->probes[j],
							pkt_header->ts, pkt_data, thread->datalink))
					{
						outstanding--;
						completed++;
						break;
					}
				}
			}
		}

		gettimeofday(&now, NULL);
		for (int i = 0; i < total; i++)
		{
			probe = thread->probes[i];
			if (probe->status != PROBE_SENT)
				continue;

			elapsed = (double)(now.tv_sec - probe->time_sent.tv_sec)
				+ (double)(now.tv_usec - probe->time_sent.tv_usec) / 1e6;
			if (elapsed < probe->timeout)
				continue;

			if (probe->retries < MAX_RETRIES)
			{
				sport = (uint16_t)(thread->sport_base
					+ (i % MAX_PORTS_PER_SCAN));
				probe->retries++;
				log_message(LOG_LEVEL_DEBUG, "Retrying probe to %s:%u (%d/%d)",
					probe->dst_ip, probe->dst_port, probe->retries, MAX_RETRIES);
				probe_send(thread, probe, opts, sport);
			}
			else
			{
				const t_scan_def *def = scan_def_by_flag(probe->scan_type);
				log_message(LOG_LEVEL_DEBUG, "Timeout waiting for response from %s:%u",
					probe->dst_ip, probe->dst_port);
				probe->status = PROBE_TIMEOUT;
				probe->result = (def && (def->proto == PROTO_UDP
					|| def->flag & (SCAN_NULL | SCAN_FIN | SCAN_XMAS)))
					? PORT_OPENFILTERED
					: PORT_FILTERED;
				outstanding--;
				completed++;
			}
		}
	}

	return 0;
}

void
*scan_thread_entry(void *data)
{
	t_scan_thread *thread;

	thread = (t_scan_thread *)data;
	log_message(LOG_LEVEL_DEBUG, "Initiating parallel scan %d [%d probes]",
		thread->thread_id, count_probes(thread->probes));
	scan_thread_run(thread, thread->opts);
	log_message(LOG_LEVEL_DEBUG, "Completed parallel scan %d", thread->thread_id);
	return NULL;
}

int
scan_thread_dispatch(
	t_scan_thread *threads, t_list **pending_list,
	t_engine *ctx, t_opts *config)
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

static void
scan_thread_cleanup(t_scan_thread *thread)
{
	pcap_close(thread->pcap_handle);
	if (thread->tcp_sock > 0)
		close(thread->tcp_sock);
	if (thread->udp_sock > 0)
		close(thread->udp_sock);
	free(thread->probes);
}

static void
scan_run_sequential(t_engine *scan_eng, t_opts *opts, uint16_t num_ports)
{
	t_scan_thread *thread;
	struct timeval scan_start;
	struct timeval scan_end;
	double elapsed;

	thread = calloc(1, sizeof(t_scan_thread));
	if (thread == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_run_sequential: calloc failed");
		exit(EXIT_FAILURE);
	}

	thread->dst = scan_eng->dst;
	if (scan_thread_init(thread, 0, opts))
	{
		log_message(LOG_LEVEL_ERROR, "scan_run_sequential: scan_thread_init failed");
		free(thread);
		exit(EXIT_FAILURE);
	}

	scan_eng->probes_pending = scan_eng->probes;
	thread->probes = probe_dequeue(&scan_eng->probes_pending, scan_eng->probes_total);
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

	scan_thread_cleanup(thread);
	free(thread);
}

static void
scan_run_parallel(t_engine *scan_eng, t_opts *opts, uint16_t num_ports)
{
	t_scan_thread *threads;
	struct timeval scan_start;
	struct timeval scan_end;
	double elapsed;

	threads = calloc(opts->num_threads, sizeof(t_scan_thread));
	if (threads == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_run_parallel: calloc failed");
		exit(EXIT_FAILURE);
	}

	scan_eng->probes_pending = scan_eng->probes;
	gettimeofday(&scan_start, NULL);
	scan_thread_dispatch(threads, &scan_eng->probes_pending, scan_eng, opts);
	gettimeofday(&scan_end, NULL);

	elapsed = (double)(scan_end.tv_sec - scan_start.tv_sec)
		+ (double)(scan_end.tv_usec - scan_start.tv_usec) / 1e6;
	scan_results_print(threads, opts->num_threads, opts->target, elapsed);

	for (uint16_t i = 0; i < opts->num_threads; i++)
		scan_thread_cleanup(&threads[i]);
	free(threads);
}

void
scan_run(t_engine *scan_eng, t_opts *opts)
{
	unsigned short *ports;
	unsigned short num_ports;
	t_list *node;

	if (scan_eng == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_run: scan_eng is NULL");
		exit(EXIT_FAILURE);
	}

	scan_eng->opts = opts;

	if (scan_source_sockaddr_set(&opts->source_addr))
	{
		log_message(LOG_LEVEL_ERROR, "scan_run: scan_source_sockaddr_set failed");
		exit(EXIT_FAILURE);
	}

	if (scan_target_sockaddr_set(&scan_eng->dst, opts->target))
	{
		log_message(LOG_LEVEL_ERROR, "scan_run: scan_target_sockaddr_set failed");
		exit(EXIT_FAILURE);
	}

	ports = get_ports((opts->portlist) ? opts->portlist : DEFAULT_PORT_RANGE, &num_ports);

	scan_eng->probes = probe_list_create(
		(uint16_t *)ports, num_ports,
		opts->target, scan_eng->timeout, opts->scan_flag);

	scan_eng->probes_total = 0;
	node = scan_eng->probes;
	while (node)
	{
		scan_eng->probes_total++;
		node = node->next;
	}

	scan_config_print(scan_eng, num_ports);

	char *resolved_ip = inet_ntoa(scan_eng->dst.sin_addr);
	if (strcmp(opts->target, resolved_ip) == 0)
		log_message(LOG_LEVEL_INFO, "Scanning %s [%d ports]",
			opts->target, num_ports);
	else
		log_message(LOG_LEVEL_INFO, "Scanning %s (%s) [%d ports]",
			opts->target, resolved_ip, num_ports);

	if (!opts->num_threads)
		scan_run_sequential(scan_eng, opts, num_ports);
	else
		scan_run_parallel(scan_eng, opts, num_ports);

	free(ports);
}
