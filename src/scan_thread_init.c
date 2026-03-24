#include "ft_nmap.h"
#include "logging/log.h"

static int
scan_thread_open_sockets(t_scan_thread *thread, t_scan_opts *config)
{
	if (config->scan_flag & (SCAN_SYN | SCAN_FIN | SCAN_NULL | SCAN_XMAS | SCAN_ACK))
	{
		thread->tcp_sock = get_raw_socket_by_protocol("tcp");
		if (thread->tcp_sock < 0)
		{
			log_message(LOG_LEVEL_ERROR, "scan_thread_open_sockets: tcp socket failed");
			return -1;
		}
	}

	if (config->scan_flag & SCAN_UDP)
	{
		thread->udp_sock = get_raw_socket_by_protocol("udp");
		if (thread->udp_sock < 0)
		{
			log_message(LOG_LEVEL_ERROR, "scan_thread_open_sockets: udp socket failed");
			return -1;
		}
	}
	return 0;
}

static int
scan_thread_setup_pcap(t_scan_thread *thread, int thread_id, t_scan_opts *config)
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

	has_tcp = config->scan_flag & (SCAN_SYN | SCAN_ACK | SCAN_FIN | SCAN_XMAS | SCAN_NULL);
	has_udp = config->scan_flag & SCAN_UDP;
	src_ip = inet_ntoa(thread->dst.sin_addr);
	lo = thread->sport_base;
	hi = thread->sport_base + thread->sport_range - 1;

	if (has_tcp && has_udp)
		snprintf(thread->filter_expr, sizeof(thread->filter_expr),
			"(tcp and src host %s and dst portrange %d-%d)"
			" or (icmp and src host %s and icmp[28:2] >= %d and icmp[28:2] <= %d)",
			src_ip, lo, hi, src_ip, lo, hi);
	else if (has_udp)
		snprintf(thread->filter_expr, sizeof(thread->filter_expr),
			"icmp and src host %s and icmp[28:2] >= %d and icmp[28:2] <= %d",
			src_ip, lo, hi);
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
scan_thread_init(t_scan_thread *thread, int thread_id, t_scan_opts *config)
{
	thread->thread_id = thread_id;
	thread->opts = config;

	if (scan_thread_open_sockets(thread, config))
		return -1;

	if (scan_thread_setup_pcap(thread, thread_id, config))
		return -1;

	return 0;
}
