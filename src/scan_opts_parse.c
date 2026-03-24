#include "ft_nmap.h"
#include "logging/log.h"

#include <getopt.h>
#include <libgen.h>

extern char *optarg;
extern int optind;

typedef void (*f_scan_cli_option_handler)(t_scan_opts *opts, const char *arg);

typedef struct
{
	const char *name;
	int has_arg;
	int *flag;
	int val;
	f_scan_cli_option_handler validate;
} t_scan_cli_option;

t_scan_cli_option *
scan_cli_option_find(t_scan_cli_option *scan_cli_options, int val)
{
	while (scan_cli_options->name)
	{
		if (scan_cli_options->val == val)
			return scan_cli_options;
		++scan_cli_options;
	}
	return NULL;
}

size_t
scan_cli_options_count(t_scan_cli_option *cli_options)
{
	size_t count = 0;

	while (cli_options->name != NULL)
	{
		++count;
		++cli_options;
	}
	return count;
}

struct option *
scan_cli_options_to_long_options(t_scan_cli_option *cli_options)
{
	struct option *opts;
	int count = scan_cli_options_count(cli_options);

	opts = calloc(count + 1, sizeof(struct option));
	if (opts == NULL)
	{
		log_message(LOG_LEVEL_FATAL, "calloc failed");
		exit(EXIT_FAILURE);
	}
	for (int index = 0; index < count; ++index)
	{
		opts[index].name = cli_options[index].name;
		opts[index].has_arg = cli_options[index].has_arg;
		opts[index].flag = cli_options[index].flag;
		opts[index].val = cli_options[index].val;
	}
	return opts;
}

void
scan_cli_option_help(t_scan_opts *opts, const char *arg)
{
	(void)arg;
	print_usage(opts->program_name);
	exit(EXIT_SUCCESS);
}

void
scan_cli_option_ports(t_scan_opts *opts, const char *arg)
{
	const char *c;

	(void)arg;
	if (opts->portlist)
	{
		log_message(LOG_LEVEL_FATAL, "only one --ports option allowed, separate multiples ranges with commas.");
		exit(EXIT_FAILURE);
	}
	for (c = optarg; *c; ++c)
	{
		if (!isdigit((unsigned char)*c) && *c != ',' && *c != '-')
		{
			fprintf(stderr, "ft_nmap: invalid port expression: '%s'.\n", optarg);
			exit(EXIT_FAILURE);
		}
	}
	opts->portlist = strdup(optarg);
	if (opts->portlist == NULL)
	{
		log_message(LOG_LEVEL_FATAL, "strdup failed");
		exit(EXIT_FAILURE);
	}
}

void
scan_cli_option_ip(t_scan_opts *opts, const char *arg)
{
	(void)arg;
	if (opts->num_targets > 0)
	{
		log_message(LOG_LEVEL_FATAL, "you can only use --ip option once.");
		exit(EXIT_FAILURE);
	}
	if (!fqdn_is_valid(optarg))
	{
		log_message(LOG_LEVEL_FATAL, "invalid target: must be a valid IPv4 or hostname.");
		exit(EXIT_FAILURE);
	}
	opts->targets = malloc(sizeof(char *));
	if (opts->targets == NULL)
	{
		log_message(LOG_LEVEL_FATAL, "malloc failed");
		exit(EXIT_FAILURE);
	}
	opts->targets[0] = strdup(optarg);
	if (opts->targets[0] == NULL)
	{
		log_message(LOG_LEVEL_FATAL, "strdup failed");
		exit(EXIT_FAILURE);
	}
	opts->num_targets = 1;
}

void
scan_cli_option_file(t_scan_opts *opts, const char *arg)
{
	(void)arg;
	if (opts->filename)
	{
		log_message(LOG_LEVEL_FATAL, "you can only use --file option once.");
		exit(EXIT_FAILURE);
	}
	opts->filename = strdup(optarg);
	if (opts->filename == NULL)
	{
		log_message(LOG_LEVEL_FATAL, "strdup failed");
		exit(EXIT_FAILURE);
	}
}

void
scan_cli_option_speedup(t_scan_opts *opts, const char *arg)
{
	char *endptr;
	long n;

	n = strtol(arg, &endptr, 10);
	if (*endptr != '\0' || endptr == arg || n < 0 || n > MAXTHREADS)
	{
		log_message(LOG_LEVEL_FATAL, "speedup must be between 0 and %d.", MAXTHREADS);
		exit(EXIT_FAILURE);
	}
	opts->num_threads = (unsigned short)n;
}

void
scan_cli_option_scan(t_scan_opts *opts, const char *arg)
{
	(void)arg;
	opts->scan_flag = get_scan_type_by_name(optarg);
	if (opts->scan_flag == 0)
	{
		log_message(LOG_LEVEL_FATAL, "scan flag is invalid.");
		exit(EXIT_FAILURE);
	}
}

void
scan_cli_option_verbose(t_scan_opts *opts, const char *arg)
{
	(void)arg;
	++opts->verbose;
}

void
scan_cli_option_debug(t_scan_opts *opts, const char *arg)
{
	(void)arg;
	opts->verbose = 2;
}

static void
opts_validate(t_scan_opts *opts)
{
	if (opts->scan_flag == SCAN_UNDEFINED)
		opts->scan_flag = SCAN_ALL;

	if (opts->num_targets > 0 && opts->filename)
	{
		log_message(LOG_LEVEL_FATAL, "--ip and --file options cannot be used at the same time.");
		exit(EXIT_FAILURE);
	}

	if (opts->filename)
		ip_file_parse(opts, opts->filename);

	if (opts->num_targets == 0)
	{
		log_message(LOG_LEVEL_FATAL, "no target specified. Use --ip or --file.");
		exit(EXIT_FAILURE);
	}
}

void
scan_opts_parse(t_scan_opts *opts, int *out_arg_index, int argc, char **argv)
{
	int opt;
	struct option *long_opts;
	t_scan_cli_option cli_options[] =
	{
		{"help", no_argument, 0, 'h', scan_cli_option_help},
		{"ports", required_argument, 0, 'p', scan_cli_option_ports},
		{"ip", required_argument, 0, 'i', scan_cli_option_ip},
		{"file", required_argument, 0, 'f', scan_cli_option_file},
		{"speedup", required_argument, 0, 's', scan_cli_option_speedup},
		{"scan", required_argument, 0, 'S', scan_cli_option_scan},
		{"verbose", no_argument, 0, 'v', scan_cli_option_verbose},
		{"debug", no_argument, 0, 'd', scan_cli_option_debug},
		{0}
	};

	*opts = (t_scan_opts){0};
	opts->program_name = basename(argv[0]);

	if (argc < 2)
	{
		print_usage(opts->program_name);
		exit(EXIT_FAILURE);
	}

	long_opts = scan_cli_options_to_long_options(cli_options);
	while ((opt = getopt_long(argc, argv, "hvdp:i:f:", long_opts, NULL)) != -1)
	{
		t_scan_cli_option *cli_option = scan_cli_option_find(cli_options, opt);

		if (cli_option == NULL)
		{
			log_message(LOG_LEVEL_DEBUG, "invalid option: %c\n", opt);
			print_usage(opts->program_name);
			exit(EXIT_FAILURE);
		}
		if (cli_option->validate)
			cli_option->validate(opts, optarg);
	}

	free(long_opts);
	opts_validate(opts);
	*out_arg_index = optind;
}
