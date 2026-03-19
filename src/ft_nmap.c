#include "ft_nmap.h"
#include "logging/log.h"

#include <libgen.h>

int
main(int argc, char **argv)
{
	int arg_index;
	t_engine *scan_eng;
	t_opts scan_options;

	log_level_set(LOG_LEVEL_FATAL);
	log_name_set(basename(argv[0]));

	scan_eng = scan_create();
	scan_init(scan_eng);
	scan_options_parse(&scan_options, &arg_index, argc, argv);

	switch (scan_options.verbose)
	{
		case 0:  log_level_set(LOG_LEVEL_NONE);  break;
		case 1:  log_level_set(LOG_LEVEL_INFO);  break;
		default: log_level_set(LOG_LEVEL_DEBUG); break;
	}
	log_message(LOG_LEVEL_DEBUG, "verbose level: %d", scan_options.verbose);

	log_message(LOG_LEVEL_DEBUG, "ft_nmap started");
	log_message(LOG_LEVEL_DEBUG, "scan engine created");
	log_message(LOG_LEVEL_DEBUG, "scan engine initialized");

	for (int i = 0; i < scan_options.num_targets; i++)
	{
		scan_options.target = scan_options.targets[i];
		probe_list_destroy(scan_eng);
		scan_eng->probes_total = 0;
		scan_eng->probes_pending = NULL;
		scan_run(scan_eng, &scan_options);
		if (i < scan_options.num_targets - 1)
			printf("\n");
	}

	log_message(LOG_LEVEL_DEBUG, "Scan run completed");
	scan_destroy(scan_eng);
	log_message(LOG_LEVEL_DEBUG, "ft_nmap finished");
	return 0;
}
