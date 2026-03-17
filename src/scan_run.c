#include "ft_nmap.h"
#include "logging/log.h"

#include <time.h>

static void
scan_type_name(int scan_flag, char *buf, size_t size)
{
	int first = 1;

	buf[0] = '\0';
	for (int i = 0; i < MAXSCANS; i++)
	{
		const struct scan_mode *mode = get_scan_mode(i);
		if (mode->flag & scan_flag)
		{
			if (!first)
				strncat(buf, "/", size - strlen(buf) - 1);
			strncat(buf, mode->name, size - strlen(buf) - 1);
			first = 0;
		}
	}
}

static void
current_time_str(char *buf, size_t size)
{
	time_t t = time(NULL);
	struct tm *tm_info = localtime(&t);
	strftime(buf, size, "%H:%M", tm_info);
}

int
scan_thread_init(t_scan_thread *info, int thread_id, t_opts *config)
{
	info->thread_id = thread_id;
	info->opts = config;

	if (config->scan_flag
		& (SCAN_SYN | SCAN_FIN | SCAN_NULL | SCAN_XMAS | SCAN_ACK))
		info->tcp_sock = get_raw_socket_by_protocol("tcp");

	if (config->scan_flag & SCAN_UDP)
		info->udp_sock = get_raw_socket_by_protocol("udp");

	info->pcap_handle = get_pcap_handle(config, &info->datalink);
	if (info->pcap_handle == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_port_init: pcap_handle is NULL (id:%i)", info->thread_id);
		return -1;
	}

	/*
	** Cada hilo usa un rango de source ports único para que su filtro pcap
	** sólo capture sus propias respuestas sin necesidad de mutex.
	** Se asegura que sport_base + MAX_PORTS_PER_SCAN - 1 <= 65535.
	*/
	srand((unsigned int)time(NULL) ^ ((unsigned int)thread_id * 7919));
	info->sport_base = 1024 + (rand() % (65535 - 1024 - MAX_PORTS_PER_SCAN));

	snprintf(info->filter_expr, sizeof(info->filter_expr),
		"tcp and src host %s and dst portrange %d-%d",
		inet_ntoa(info->dst.sin_addr),
		info->sport_base,
		info->sport_base + MAX_PORTS_PER_SCAN - 1);

	if (set_pcap_filter(info->pcap_handle, info->filter_expr))
	{
		log_message(LOG_LEVEL_ERROR, "scan_port_init: set_pcap_filter failed");
		return -1;
	}


	return 0;
}

/*
** probes_dequeue: extrae hasta num_probes probes PENDING de la lista
** enlazada avanzando el puntero *pending_node.
** El array retornado termina en NULL y debe ser liberado por el llamador.
*/
t_probe **
probes_dequeue(t_list **pending_node, int num_probes)
{
	t_probe **probes;
	t_probe *probe;
	int count;

	probes = calloc(num_probes + 1, sizeof(t_probe *));
	if (probes == NULL)
		return NULL;

	count = 0;
	while (*pending_node && count < num_probes)
	{
		probe = (t_probe *)(*pending_node)->content;
		if (probe->status == PROBE_PENDING)
			probes[count++] = probe;
		*pending_node = (*pending_node)->next;
	}
	probes[count] = NULL;
	return probes;
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

/*
** scan_thread_run — sliding window scan loop
**
** En lugar de enviar un probe y esperar su respuesta antes de enviar el
** siguiente, mantiene una ventana de WINDOW_SIZE probes en vuelo de forma
** simultánea. Mientras espera respuestas puede enviar nuevos probes,
** solapando la latencia de red. Esto reduce el tiempo total de O(N*timeout)
** a O((N/WINDOW_SIZE)*timeout).
**
** Cada iteración del loop principal hace tres fases:
**   1. SEND:    llena la ventana con probes PENDING.
**   2. RECEIVE: procesa todos los paquetes disponibles en pcap sin bloquear.
**   3. TIMEOUT: reenvía o descarta probes que superaron su timeout.
*/
int
scan_thread_run(t_scan_thread *info, t_opts *opts)
{
	int					total;
	int					next_to_send;
	int					outstanding;
	int					completed;
	int					pcap_fd;
	int					pcap_res;
	fd_set				fdset;
	struct timeval		select_timeout;
	struct timeval		now;
	struct pcap_pkthdr	*pkt_header;
	const u_char		*pkt_data;
	t_probe				*probe;
	uint16_t			sport;
	double				elapsed;

	total = count_probes(info->probes);
	pcap_fd = pcap_get_selectable_fd(info->pcap_handle);
	next_to_send = 0;
	outstanding = 0;
	completed = 0;

	while (completed < total)
	{
		/* --- FASE 1: SEND ---
		** Llena la ventana hasta WINDOW_SIZE enviando probes PENDING.
		** sport = sport_base + índice del probe en el array del hilo.
		** Así cada probe tiene un sport único y predecible dentro del rango
		** cubierto por el filtro BPF del hilo.
		*/
		while (outstanding < WINDOW_SIZE && next_to_send < total)
		{
			probe = info->probes[next_to_send];
			sport = (uint16_t)(info->sport_base
				+ (next_to_send % MAX_PORTS_PER_SCAN));

			if (probe->status == PROBE_PENDING)
			{
				if (probe_send_syn(info, probe, opts, sport) == 0)
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

		/* --- FASE 2: RECEIVE ---
		** select() con timeout muy corto (10ms) para no bloquear el loop.
		** Drena todos los paquetes disponibles en pcap de una vez.
		*/
		FD_ZERO(&fdset);
		FD_SET(pcap_fd, &fdset);
		select_timeout.tv_sec = 0;
		select_timeout.tv_usec = 10000;

		if (select(pcap_fd + 1, &fdset, NULL, NULL, &select_timeout) > 0)
		{
			while ((pcap_res = pcap_next_ex(info->pcap_handle,
					&pkt_header, &pkt_data)) == 1)
			{
				if (packet_match_probe(info, pkt_header->ts, pkt_data) > 0)
				{
					outstanding--;
					completed++;
				}
			}
		}

		/* --- FASE 3: TIMEOUT ---
		** Recorre todos los probes en estado SENT. Si superaron su timeout:
		**   - Si tiene reintentos disponibles: reenvía (outstanding no cambia).
		**   - Si agotó reintentos: marca como TIMEOUT/FILTERED y lo saca
		**     de la ventana.
		*/
		gettimeofday(&now, NULL);
		for (int i = 0; i < total; i++)
		{
			probe = info->probes[i];
			if (probe->status != PROBE_SENT)
				continue;

			elapsed = (double)(now.tv_sec - probe->time_sent.tv_sec)
				+ (double)(now.tv_usec - probe->time_sent.tv_usec) / 1e6;
			if (elapsed < probe->timeout)
				continue;

			if (probe->retries < MAX_RETRIES)
			{
				sport = (uint16_t)(info->sport_base
					+ (i % MAX_PORTS_PER_SCAN));
				probe->retries++;
				log_message(LOG_LEVEL_DEBUG, "Retrying SYN to %s:%u (%d/%d)",
					probe->dst_ip, probe->dst_port, probe->retries, MAX_RETRIES);
				probe_send_syn(info, probe, opts, sport);
			}
			else
			{
				log_message(LOG_LEVEL_DEBUG, "Timeout waiting for response from %s:%u (filtered)",
					probe->dst_ip, probe->dst_port);
				probe->status = PROBE_TIMEOUT;
				probe->result = PORT_FILTERED;
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
	t_scan_thread *info;

	info = (t_scan_thread *)data;
	log_message(LOG_LEVEL_DEBUG, "Initiating parallel scan %d [%d probes]",
		info->thread_id, count_probes(info->probes));
	scan_thread_run(info, info->opts);
	log_message(LOG_LEVEL_DEBUG, "Completed parallel scan %d", info->thread_id);
	return NULL;
}

int
scan_threads_dispatch(
	t_scan_thread *infos, t_list **pending_list,
	t_engine *ctx, t_opts *config)
{
	uint16_t probes_per_thread;
	uint16_t remaining_probes;
	uint16_t probes_assigned_to_thread;
	t_scan_thread *next_info;

	probes_per_thread = ctx->probes_total / config->num_threads;
	remaining_probes = ctx->probes_total % config->num_threads;

	for (uint16_t current_thread = 0; current_thread < config->num_threads; ++current_thread)
	{
		probes_assigned_to_thread = probes_per_thread +
			(current_thread < remaining_probes ? 1 : 0);

		next_info = &infos[current_thread];

		next_info->dst = ctx->dst;

		if (scan_thread_init(next_info, current_thread + 1, config))
		{
			log_message(LOG_LEVEL_ERROR, "scan_threads_dispatch: scan_thread_init failed");
			return -1;
		}

		next_info->probes = probes_dequeue(pending_list, probes_assigned_to_thread);
		if (next_info->probes == NULL)
		{
			log_message(LOG_LEVEL_ERROR, "scan_threads_dispatch: probes_dequeue failed");
			return -1;
		}



		if (pthread_create(&next_info->thread, NULL, scan_thread_entry, next_info) != 0)
		{
			log_message(LOG_LEVEL_ERROR, "scan_threads_dispatch: pthread_create failed");
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

static const char *
port_state_str(t_port_state state)
{
	static const char *strings[] = {
		"unknown", "testing", "open", "closed",
		"filtered", "unfiltered", "open|filtered"
	};
	return strings[state];
}

static void
print_probe_line(t_probe *probe)
{
	struct servent *serv;

	serv = getservbyport(htons(probe->dst_port), NULL);
	printf("%-9u %-12s %-s\n",
		probe->dst_port,
		port_state_str(probe->result),
		serv ? serv->s_name : "unknown");
}

static void
scan_results_print(t_scan_thread *infos, int num_threads,
	const char *target, double elapsed)
{
	printf("Scan took %.2f sec\n", elapsed);
	char *resolved_ip = inet_ntoa(infos[0].dst.sin_addr);
	if (strcmp(target, resolved_ip) == 0)
		printf("Scan results for %s\n", target);
	else
		printf("Scan results for %s (%s)\n", target, resolved_ip);
	printf("%-9s %-12s %-s\n", "PORT", "STATE", "SERVICE");

	for (int t = 0; t < num_threads; t++)
		for (int i = 0; infos[t].probes[i] != NULL; i++)
			if (infos[t].probes[i]->result == PORT_OPEN)
				print_probe_line(infos[t].probes[i]);

	for (int t = 0; t < num_threads; t++)
		for (int i = 0; infos[t].probes[i] != NULL; i++)
			if (infos[t].probes[i]->result != PORT_OPEN)
				print_probe_line(infos[t].probes[i]);
}

void
scan_run(t_engine *scan_eng, t_opts *opts)
{
	unsigned short	*ports;
	unsigned short	num_ports;
	t_list			*node;
	struct timeval	scan_start;
	struct timeval	scan_end;
	double			elapsed;

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

	/*
	** Crea la lista de probes usando t_probe (sistema nuevo).
	** probes_create() es la función correcta — scan_probe_list_create()
	** creaba t_port_stat (sistema viejo) que es una struct distinta.
	*/
	scan_eng->probes = probes_create(
		(uint16_t *)ports, num_ports,
		opts->target, scan_eng->timing.timeout);

	scan_eng->probes_total = 0;
	node = scan_eng->probes;
	while (node)
	{
		scan_eng->probes_total++;
		node = node->next;
	}

	scan_config_print(scan_eng, num_ports);

	char scan_type_buf[64];
	char time_buf[6];
	scan_type_name(opts->scan_flag, scan_type_buf, sizeof(scan_type_buf));
	current_time_str(time_buf, sizeof(time_buf));
	log_message(LOG_LEVEL_INFO, "Initiating %s Scan at %s", scan_type_buf, time_buf);

	char *resolved_ip = inet_ntoa(scan_eng->dst.sin_addr);
	if (strcmp(opts->target, resolved_ip) == 0)
		log_message(LOG_LEVEL_INFO, "Scanning %s [%d ports]",
			opts->target, num_ports);
	else
		log_message(LOG_LEVEL_INFO, "Scanning %s (%s) [%d ports]",
			opts->target, resolved_ip, num_ports);

	gettimeofday(&scan_start, NULL);

	if (!opts->num_threads)
	{
		t_scan_thread *info;

		info = calloc(1, sizeof(t_scan_thread));
		if (info == NULL)
		{
			log_message(LOG_LEVEL_ERROR, "scan_run: calloc failed");
			exit(EXIT_FAILURE);
		}

		info->dst = scan_eng->dst;

		if (scan_thread_init(info, 0, opts))
		{
			log_message(LOG_LEVEL_ERROR, "scan_run: scan_thread_init failed");
			free(info);
			exit(EXIT_FAILURE);
		}

		scan_eng->probes_pending = scan_eng->probes;
		info->probes = probes_dequeue(&scan_eng->probes_pending, scan_eng->probes_total);
		if (info->probes == NULL)
		{
			log_message(LOG_LEVEL_ERROR, "scan_run: probes_dequeue failed");
			free(info);
			exit(EXIT_FAILURE);
		}

		scan_thread_run(info, opts);
		gettimeofday(&scan_end, NULL);

		elapsed = (double)(scan_end.tv_sec - scan_start.tv_sec)
			+ (double)(scan_end.tv_usec - scan_start.tv_usec) / 1e6;
		current_time_str(time_buf, sizeof(time_buf));
		log_message(LOG_LEVEL_INFO, "Completed %s Scan at %s, %.2fs elapsed (%d total ports)",
			scan_type_buf, time_buf, elapsed, num_ports);
		scan_results_print(info, 1, opts->target, elapsed);

		pcap_close(info->pcap_handle);
		if (info->tcp_sock > 0)
			close(info->tcp_sock);
		if (info->udp_sock > 0)
			close(info->udp_sock);
		free(info->probes);
		free(info);
	}
	else
	{
		t_scan_thread *infos;

		infos = calloc(opts->num_threads, sizeof(t_scan_thread));
		if (infos == NULL)
		{
			log_message(LOG_LEVEL_ERROR, "scan_run: calloc failed");
			exit(EXIT_FAILURE);
		}

		scan_eng->probes_pending = scan_eng->probes;
		scan_threads_dispatch(infos, &scan_eng->probes_pending, scan_eng, opts);
		gettimeofday(&scan_end, NULL);

		elapsed = (double)(scan_end.tv_sec - scan_start.tv_sec)
			+ (double)(scan_end.tv_usec - scan_start.tv_usec) / 1e6;
		current_time_str(time_buf, sizeof(time_buf));
		log_message(LOG_LEVEL_INFO, "Completed %s Scan at %s, %.2fs elapsed (%d total ports)",
			scan_type_buf, time_buf, elapsed, num_ports);
		scan_results_print(infos, opts->num_threads, opts->target, elapsed);

		for (uint16_t i = 0; i < opts->num_threads; i++)
		{
			pcap_close(infos[i].pcap_handle);
			if (infos[i].tcp_sock > 0)
				close(infos[i].tcp_sock);
			if (infos[i].udp_sock > 0)
				close(infos[i].udp_sock);
			free(infos[i].probes);
		}
		free(infos);
	}

	free(ports);
}
