#include "ft_nmap.h"

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
}

void scan_run(t_scan_ctx *scan_ctx)
{
    unsigned short *ports;
    unsigned short num_ports;

	scan_local_sockaddr_set(&scan_ctx->source);

	ports = get_ports((scan_ctx->opts.portlist) ? scan_ctx->opts.portlist : DEFAULT_PORT_RANGE, &num_ports);

	scan_probe_list_create(&scan_ctx, ports, num_ports);

	if (!scan_ctx->opts.num_threads)
    ;
		//scan_ports(scan_ctx, num_ports);
	else
    ;
		//scan_ports_parallel(scan_ctx, num_ports);
}