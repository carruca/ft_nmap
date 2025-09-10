#include "ft_nmap.h"

int
main(int argc, char **argv)
{
	int arg_index;
	t_scan_ctx *scan_ctx;
	t_scan_options scan_options;

	scan_ctx = scan_create();	
	scan_init(scan_ctx);
	scan_options_parse(&scan_options, &arg_index, argc, argv);
	scan_run(scan_ctx, &scan_options);
	//pcap_close(scan_ctx->pcap_handle);
	scan_destroy(scan_ctx);
	return 0;
}
