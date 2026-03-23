#include "ft_nmap.h"
#include "logging/log.h"

int
count_probes(t_probe **probes)
{
	int count;

	count = 0;
	while (probes[count] != NULL)
		++count;
	return count;
}

int
scan_thread_run(t_scan_thread *thread, t_scan_opts *opts)
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
					++outstanding;
				else
				{
					probe->status = PROBE_TIMEOUT;
					probe->result = PORT_FILTERED;
					++completed;
				}
			}
			++next_to_send;
		}

		FD_ZERO(&fdset);
		FD_SET(pcap_fd, &fdset);
		select_timeout.tv_sec = 0;
		select_timeout.tv_usec = SELECT_TIMEOUT_US;

		if (select(pcap_fd + 1, &fdset, NULL, NULL, &select_timeout) > 0)
		{
			while ((pcap_res = pcap_next_ex(thread->pcap_handle,
					&pkt_header, &pkt_data)) == 1)
			{
				for (int i = 0; thread->probes[i] != NULL; ++i)
				{
					if (probe_match(thread->probes[i],
							pkt_header->ts, pkt_data, pkt_header->caplen, thread->datalink))
					{
						--outstanding;
						++completed;
						break;
					}
				}
			}
		}

		if (gettimeofday(&now, NULL) < 0)
			continue;
		for (int i = 0; i < total; ++i)
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
				++probe->retries;
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
				--outstanding;
				++completed;
			}
		}
	}

	return 0;
}
