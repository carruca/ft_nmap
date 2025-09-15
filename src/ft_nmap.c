#include "ft_nmap.h"
#include "logging/log.h"

int
main(int argc, char **argv)
{
	int arg_index;
	t_scan_ctx *scan_ctx;
	t_scan_options scan_options;

	log_level_set(LOG_LEVEL_DEBUG);

	scan_ctx = scan_create();	
	log_message(LOG_LEVEL_DEBUG, "ft_nmap started");
	scan_init(scan_ctx);
	log_message(LOG_LEVEL_DEBUG, "Scan context initialized");
	scan_options_parse(&scan_options, &arg_index, argc, argv);
	log_message(LOG_LEVEL_DEBUG, "Scan options parsed");
	scan_run(scan_ctx, &scan_options);
	log_message(LOG_LEVEL_DEBUG, "Scan run completed");
	scan_destroy(scan_ctx);
	log_message(LOG_LEVEL_DEBUG, "ft_nmap finished");
	return 0;
}
