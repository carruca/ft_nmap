#include "ft_nmap.h"
#include "logging/log.h"

#include <libgen.h>

int
main(int argc, char **argv)
{
	int arg_index;
	t_scan_ctx *ctx;
	t_scan_opts opts;

	log_level_set(LOG_LEVEL_FATAL);
	log_name_set(basename(argv[0]));

	ctx = scan_create();
	scan_opts_parse(&opts, &arg_index, argc, argv);
	ctx->ports = get_ports((opts.portlist) ? opts.portlist : DEFAULT_PORT_RANGE, &ctx->num_ports);
	if (ctx->ports == NULL)
	{
		log_message(LOG_LEVEL_FATAL, "ft_nmap: failed to parse port list");
		scan_opts_destroy(&opts);
		scan_destroy(ctx);
		return 1;
	}

	switch (opts.verbose)
	{
		case 0:  log_level_set(LOG_LEVEL_NONE);  break;
		case 1:  log_level_set(LOG_LEVEL_INFO);  break;
		default: log_level_set(LOG_LEVEL_DEBUG); break;
	}
	log_message(LOG_LEVEL_DEBUG, "verbose level: %d", opts.verbose);

	log_message(LOG_LEVEL_DEBUG, "ft_nmap started");
	log_message(LOG_LEVEL_DEBUG, "scan engine created");
	log_message(LOG_LEVEL_DEBUG, "scan engine initialized");

	for (int i = 0; i < opts.num_targets; ++i)
	{
		opts.target = opts.targets[i];
		scan_run(ctx, &opts);
		if (i < opts.num_targets - 1)
			printf("\n");
	}

	log_message(LOG_LEVEL_DEBUG, "Scan run completed");
	scan_opts_destroy(&opts);
	scan_destroy(ctx);
	log_message(LOG_LEVEL_DEBUG, "ft_nmap finished");
	return 0;
}
