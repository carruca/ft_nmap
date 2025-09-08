#include "ft_nmap.h"

int
main(int argc, char **argv)
{
	int arg_index;
	//t_scan_options opts;
	t_scan_ctx scan_ctx;
	unsigned short *ports;
	unsigned int num_ports;
	char filter_str[256];

	memset(&scan_ctx.opts, 0, sizeof(t_scan_options));
	scan_ctx.opts.scan_flag = SCAN_ALL;

	if (scan_options_parse(&scan_ctx.opts, &arg_index, argc, argv))
		nmap_print_error_and_exit("arg_parse failed.");

	scan_init(&scan_ctx);

	scan_ctx.pcap_handle = get_pcap_handle();
	if (scan_ctx.pcap_handle == NULL)
		nmap_print_error_and_exit("pcap_handle failed.");

	snprintf(filter_str, sizeof(filter_str), "src %s and portrange %s",
		scan_ctx.opts.target, (scan_ctx.opts.portlist) ? scan_ctx.opts.portlist : DEFAULT_PORT_RANGE);
	if (set_pcap_filter(scan_ctx.pcap_handle, filter_str))
		nmap_print_error_and_exit("pcap_filter failed.");

	ports = get_ports((scan_ctx.opts.portlist) ? scan_ctx.opts.portlist : DEFAULT_PORT_RANGE, &num_ports);

	scan_probe_list_create(&scan_ctx, ports, num_ports);

	set_local_sockaddr(&scan_ctx.source);

	if (!scan_ctx.opts.num_threads)
		scan_ports(&scan_ctx, num_ports);
	else
		scan_ports_parallel(&scan_ctx, num_ports);

	free(ports);
	scan_probe_list_destroy(&scan_ctx);
	pcap_close(scan_ctx.pcap_handle);
	scan_options_destroy(&scan_ctx.opts);
	return 0;
}
