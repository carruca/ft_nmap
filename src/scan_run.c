#include "ft_nmap.h"
#include "logging/log.h"

void *thread_start(void *data)
{
	(void)data;
/*
	char filter_str[256];

	scan_ctx.pcap_handle = get_pcap_handle();
	if (scan_ctx.pcap_handle == NULL)
		nmap_print_error_and_exit("pcap_handle failed.");

	snprintf(filter_str, sizeof(filter_str), "src %s and portrange %s",
		scan_ctx.opts.target, (scan_ctx.opts.portlist) ? scan_ctx.opts.portlist : DEFAULT_PORT_RANGE);
	if (set_pcap_filter(scan_ctx.pcap_handle, filter_str))
		nmap_print_error_and_exit("pcap_filter failed.");
*/
	return NULL;
}

void
scan_run(t_scan_ctx *scan_ctx, t_scan_options *scan_options)
{
	unsigned short *ports;
	unsigned short num_ports;
	char filter_str[256];

	if (scan_ctx == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_run: scan_ctx is NULL");
		exit(EXIT_FAILURE);
	}

	scan_ctx->opts = scan_options;
	scan_local_sockaddr_set(&scan_ctx->source);

	ports = get_ports((scan_options->portlist) ? scan_options->portlist : DEFAULT_PORT_RANGE, &num_ports);

	scan_probe_list_create(scan_ctx, ports, num_ports);

	scan_ctx->pcap_handle = get_pcap_handle();
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

	if (!scan_options->num_threads)
		scan_ports(scan_ctx, num_ports);
	else
		scan_ports_parallel(scan_ctx, num_ports);

	pcap_close(scan_ctx->pcap_handle);
	free(ports);
}
