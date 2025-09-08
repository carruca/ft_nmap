#include "ft_nmap.h"

int
main(int argc, char **argv)
{
	int arg_index;
	t_scan_options opts;
	t_scan_engine engine;
	unsigned short *ports;
	unsigned int num_ports;
	char filter_str[256];

	memset(&opts, 0, sizeof(t_scan_options));
	opts.scan_flag = SCAN_ALL;

	if (parse_args(argc, argv, &opts, &arg_index))
		nmap_print_error_and_exit("arg_parse failed.");

	init_scan_engine(&engine, &opts);

	engine.pcap_handle = get_pcap_handle();
	if (engine.pcap_handle == NULL)
		nmap_print_error_and_exit("pcap_handle failed.");

	snprintf(filter_str, sizeof(filter_str), "src %s and tcp", opts.target);
	if (set_pcap_filter(engine.pcap_handle, filter_str))
		nmap_print_error_and_exit("pcap_filter failed.");

	ports = get_ports((opts.portlist) ? opts.portlist : DEFAULT_PORT_RANGE, &num_ports);

	init_probe_list(&engine, ports, num_ports);

	set_local_sockaddr(&engine.source);

	if (!opts.num_threads)
		scan_ports(&engine, &opts, num_ports);
	else
		scan_ports_parallel(&engine, &opts, num_ports);

	free(ports);
	ft_lstclear(&engine.probe_list, free);
	pcap_close(engine.pcap_handle);
	free_scan_options(&opts);
	return 0;
}
