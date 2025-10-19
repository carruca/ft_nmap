#include "ft_nmap.h"
#include "logging/log.h"

int
scan_info_init(t_scan_info *info, int thread_id, t_scan_options *config)
{
	info->thread_id = thread_id;
	info->config = config;

	if (config->scan_flag
		& (SCAN_SYN | SCAN_FIN | SCAN_NULL | SCAN_XMAS | SCAN_ACK))
		info->raw_tcp_socket = get_raw_socket_by_protocol("tcp");

	if (config->scan_flag
		& SCAN_UDP)
		info->raw_udp_socket = get_raw_socket_by_protocol("udp");

	info->pcap_handle = get_pcap_handle(config);
	if (info->pcap_handle == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_port_init: pcap_handle is NULL (id:%i)", info->thread_id);
		return -1;
	}

	srand(time(NULL));
	info->source_port_base = (unsigned short)(1024 + (rand() % (65535 - 1024)));

	snprintf(info->filter_str, sizeof(info->filter_str), "tcp and udp and src %s and dst portrange %d-%d",
		config->target, info->source_port_base, info->source_port_base + MAX_PORTS_PER_SCAN - 1);
	if (set_pcap_filter(info->pcap_handle, info->filter_str))
	{
		log_message(LOG_LEVEL_ERROR, "scan_port_init: set_pcap_filter failed");
		return -1;
	}

	if (config->verbose)
		log_message(LOG_LEVEL_INFO, "init thread %d: using filter: '%s'", info->thread_id, info->filter_str);

	return 0;
}

t_scan_probe **
get_pending_probes(t_list **pending_node, int num_probes)
{
	t_scan_probe **probes;
	t_scan_probe *probe;
	int count;

	probes = calloc(num_probes, sizeof(t_scan_probe *));
	if (probes == NULL)
		return NULL;

	count = 0;
	while (*pending_node && count < num_probes)
	{
		probe = (t_scan_probe *)(*pending_node)->content;
		if (probe->state == PROBE_PENDING)
			probes[count++] = probe;
		*pending_node = (*pending_node)->next;
	}
	return probes;
}

int
scan_info_execute(t_scan_info *info, t_scan_options *opts)
{
	/*
	scan_target_sockaddr_setruct timeval scan_start, scan_end, timeout;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	double total_time;
	int pcap_fd, pcap_res;
	fd_set fdset;
*/
	(void)info;
	(void)opts;

	return 0;
}

void
*thread_wrapper(void *data)
{
	t_scan_info *info;

	info = (t_scan_info *)data;
	scan_info_execute(info, info->config);
	return NULL;
}

int
scan_info_parallel_execute(
	t_scan_info *infos, t_list **pending_list,
	t_scan_ctx *ctx, t_scan_options *config)
{
	uint16_t probes_per_thread;
	uint16_t remaining_probes;
	uint16_t probes_assigned_to_thread;
	t_scan_info *next_info;

	probes_per_thread = ctx->total_probes / config->num_threads;
	remaining_probes = ctx->total_probes % config->num_threads;

	for (uint16_t current_thread = 0; current_thread < config->num_threads; ++current_thread)
	{
		probes_assigned_to_thread = probes_per_thread +
			(current_thread < remaining_probes ? 1 : 0);

		next_info = &infos[current_thread];

		if (scan_info_init(next_info, current_thread + 1, config))
		{
			log_message(LOG_LEVEL_ERROR, "scan_info_thread_distribute: scan_info_init failed");
			return -1;
		}

		next_info->probes = get_pending_probes(pending_list, probes_assigned_to_thread);
		if (next_info->probes == NULL)
		{
			log_message(LOG_LEVEL_ERROR, "scan_info_thread_distribute: get_pending_probes failed");
			return -1;
		}

		log_message(LOG_LEVEL_DEBUG, "Thread %d assigned %d probes",
			current_thread, probes_assigned_to_thread);


		if (pthread_create(&next_info->thread, NULL, thread_wrapper, next_info) != 0)
		{
			log_message(LOG_LEVEL_ERROR, "scan_info_thread_distribute: pthread_create failed");
			return -1;
		}
	}

	for (uint16_t current_thread = 0; current_thread < config->num_threads; ++current_thread)
	{
		next_info = &infos[current_thread];

		pthread_join(next_info->thread, NULL);
		// TODO: free resources
	}
	return 0;
}

void
scan_run(t_scan_ctx *scan_ctx, t_scan_options *opts)
{
	unsigned short *ports;
	unsigned short num_ports;
//	char filter_str[256];

	if (scan_ctx == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_run: scan_ctx is NULL");
		exit(EXIT_FAILURE);
	}

	scan_ctx->opts = opts;
	if (scan_source_sockaddr_set(&scan_ctx->source))
	{
		log_message(LOG_LEVEL_ERROR, "scan_run: scan_source_sockaddr_set failed");
		exit(EXIT_FAILURE);
	}

	ports = get_ports((opts->portlist) ? opts->portlist : DEFAULT_PORT_RANGE, &num_ports);

	scan_probe_list_create(scan_ctx, ports, num_ports);

	/*
	scan_ctx->pcap_handle = get_pcap_handle(scan_options);
	if (scan_ctx->pcap_handle == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_run: pcap_handle is NULL");
		exit(EXIT_FAILURE);
	}

	snprintf(filter_str, sizeof(filter_str), "src %s and portrange %s",
		scan_options->target, (scan_options->portlist) ? scan_options->portlist : DEFAULT_PORT_RANGE);
	if (set_pcap_filter(scan_ctx->pcap_handle, filter_str))
	{
		log_message(LOG_LEVEL_ERROR, "scan_run: pcap_filter failed");
		exit(EXIT_FAILURE);
	}
	*/
	if (scan_target_sockaddr_set(&scan_ctx->target, opts->target))
	{
		log_message(LOG_LEVEL_ERROR, "scan_run: scan_target_sockaddr_set failed");
		exit(EXIT_FAILURE);
	}

	scan_config_print(scan_ctx, num_ports);
	if (!opts->num_threads)
	{
		log_message(LOG_LEVEL_INFO, "Starting single-threaded scan");

		t_scan_info *info;

		info = calloc(1, sizeof(t_scan_info));
		if (info == NULL)
		{
			log_message(LOG_LEVEL_ERROR, "scan_run: calloc failed");
			exit(EXIT_FAILURE);
		}

		if (scan_info_init(info, 0, opts))
		{
			log_message(LOG_LEVEL_ERROR, "scan_run: scan_info_init failed");
			free(info);
			exit(EXIT_FAILURE);
		}

		// TODO: asignar probes
		scan_ctx->pending_probe_list = scan_ctx->probe_list;
		info->probes = get_pending_probes(&scan_ctx->pending_probe_list, scan_ctx->total_probes);
		if (info->probes == NULL)
		{
			log_message(LOG_LEVEL_ERROR, "scan_run: get_pending_probes failed");
			exit(EXIT_FAILURE);
		}

		scan_info_execute(info, opts);
		scan_ports(scan_ctx, num_ports);
	}
	else
	{
		log_message(LOG_LEVEL_INFO, "Starting multi-threaded scan with %d threads", opts->num_threads);

		pthread_t threads[opts->num_threads];
		t_scan_info infos[opts->num_threads];

		(void)threads;

		//asign probes per thread
		scan_ctx->pending_probe_list = scan_ctx->probe_list;
		scan_info_parallel_execute(infos, &scan_ctx->pending_probe_list, scan_ctx, opts);

		scan_ports_parallel(scan_ctx, num_ports);
	}

//	pcap_close(scan_ctx->pcap_handle);
	free(ports);
}
