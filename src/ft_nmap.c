#include "ft_nmap.h"
#include "logging/log.h"

#include <libgen.h>

int
main(int argc, char **argv)
{
	int arg_index;
	t_engine *scan_eng;
	t_opts scan_options;

	static const t_log_level verbose_to_level[] = {
		LOG_LEVEL_NONE,
		LOG_LEVEL_INFO,
		LOG_LEVEL_DEBUG,
	};

	log_level_set(LOG_LEVEL_FATAL);
	log_name_set(basename(argv[0]));

	scan_eng = scan_create();
	scan_init(scan_eng);
	scan_options_parse(&scan_options, &arg_index, argc, argv);

	int v = scan_options.verbose;
	if (v >= (int)(sizeof(verbose_to_level) / sizeof(*verbose_to_level)))
		v = (int)(sizeof(verbose_to_level) / sizeof(*verbose_to_level)) - 1;
	log_level_set(verbose_to_level[v]);
	log_message(LOG_LEVEL_DEBUG, "log level set to %d (-v count: %d)", verbose_to_level[v], v);

	log_message(LOG_LEVEL_DEBUG, "ft_nmap started");
	log_message(LOG_LEVEL_DEBUG, "scan engine created");
	log_message(LOG_LEVEL_DEBUG, "scan engine initialized");

	if (scan_options.num_file_targets > 0)
	{
		for (int i = 0; i < scan_options.num_file_targets; i++)
		{
			free(scan_options.target);
			scan_options.target = strdup(scan_options.file_targets[i]);
			scan_probe_list_destroy(scan_eng);
			scan_eng->probes_total = 0;
			scan_eng->probes_pending = NULL;
			scan_run(scan_eng, &scan_options);
			if (i < scan_options.num_file_targets - 1)
				printf("\n");
		}
	}
	else
		scan_run(scan_eng, &scan_options);

	log_message(LOG_LEVEL_DEBUG, "Scan run completed");
	scan_destroy(scan_eng);
	log_message(LOG_LEVEL_DEBUG, "ft_nmap finished");
	return 0;
}
