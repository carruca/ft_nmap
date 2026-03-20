#include "ft_nmap.h"
#include "logging/log.h"

#include <getopt.h>

extern char *optarg;
extern int optind;

typedef void (*f_scan_cli_option_handler)(t_opts *scan_options, const char *arg);

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
	static struct option *opts;
	int count = scan_cli_options_count(cli_options);

	if (opts != NULL)
		free(opts);
	opts = calloc(count + 1, sizeof(struct option));


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
scan_cli_option_help(t_opts *scan_options, const char *arg)
{
	(void)arg;
	print_usage(scan_options->program_name);
	exit(EXIT_SUCCESS);
}

void
scan_cli_option_ports(t_opts *scan_options, const char *arg)
{
	const char *c;

	(void)arg;
	if (scan_options->portlist)
	{
		log_message(LOG_LEVEL_FATAL, "only one --ports option allowed, separate multiples ranges with commas.");
		exit(EXIT_FAILURE);
	}
	for (c = optarg; *c; c++)
	{
		if (!isdigit((unsigned char)*c) && *c != ',' && *c != '-')
		{
			fprintf(stderr, "ft_nmap: invalid port expression: '%s'.\n", optarg);
			exit(EXIT_FAILURE);
		}
	}
	scan_options->portlist = strdup(optarg);
}

void
scan_cli_option_ip(t_opts *scan_options, const char *arg)
{
	(void)arg;
	if (scan_options->num_targets > 0)
	{
		log_message(LOG_LEVEL_FATAL, "you can only use --ip option once.");
		exit(EXIT_FAILURE);
	}
	if (!fqdn_is_valid(optarg))
	{
		log_message(LOG_LEVEL_FATAL, "invalid target: must be a valid IPv4 or hostname.");
		exit(EXIT_FAILURE);
	}
	scan_options->targets = malloc(sizeof(char *));
	if (scan_options->targets == NULL)
	{
		log_message(LOG_LEVEL_FATAL, "malloc failed");
		exit(EXIT_FAILURE);
	}
	scan_options->targets[0] = strdup(optarg);
	scan_options->num_targets = 1;
}

void
scan_cli_option_file(t_opts *scan_options, const char *arg)
{
	(void)arg;
	if (scan_options->filename)
	{
		log_message(LOG_LEVEL_FATAL, "you can only use --file option once.");
		exit(EXIT_FAILURE);
	}
	scan_options->filename = strdup(optarg);
}

void
scan_cli_option_speedup(t_opts *scan_options, const char *arg)
{
	int n;

	(void)arg;
	n = atoi(optarg);
	if (n < 0 || n > MAXTHREADS)
	{
		log_message(LOG_LEVEL_FATAL, "speedup must be between 0 and %d.", MAXTHREADS);
		exit(EXIT_FAILURE);
	}
	scan_options->num_threads = (unsigned short)n;
}

void
scan_cli_option_scan(t_opts *scan_options, const char *arg)
{
	(void)arg;
	scan_options->scan_flag = get_scan_type_by_name(optarg);
	if (scan_options->scan_flag == 0)
	{
		log_message(LOG_LEVEL_FATAL, "scan flag is invalid.");
		exit(EXIT_FAILURE);
	}
}

void
scan_cli_option_verbose(t_opts *scan_options, const char *arg)
{
	(void)arg;
	scan_options->verbose++;
}

void
scan_cli_option_debug(t_opts *scan_options, const char *arg)
{
	(void)arg;
	scan_options->verbose = 2;
}

static void
scan_options_validate(t_opts *scan_options)
{
	if (scan_options->scan_flag == SCAN_UNDEFINED)
		scan_options->scan_flag = SCAN_ALL;

	if (scan_options->num_targets > 0 && scan_options->filename)
	{
		log_message(LOG_LEVEL_FATAL, "--ip and --file options cannot be used at the same time.");
		exit(EXIT_FAILURE);
	}

	if (scan_options->filename)
		ip_file_parse(scan_options, scan_options->filename);

	if (scan_options->num_targets == 0)
	{
		log_message(LOG_LEVEL_FATAL, "no target specified. Use --ip or --file.");
		exit(EXIT_FAILURE);
	}
}

void
scan_options_parse(t_opts *scan_options, int *out_arg_index, int argc, char **argv)
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

	*scan_options = (t_opts){0};
	scan_options_program_name_set(scan_options, argv[0]);

	if (argc < 2)
	{
		print_usage(scan_options->program_name);
		exit(EXIT_FAILURE);
	}

	long_opts = scan_cli_options_to_long_options(cli_options);
	while ((opt = getopt_long(argc, argv, "hvdp:i:f:", long_opts, NULL)) != -1)
	{
		t_scan_cli_option *cli_option = scan_cli_option_find(cli_options, opt);

		if (cli_option == NULL)
		{
			log_message(LOG_LEVEL_DEBUG, "invalid option: %c\n", opt);
			print_usage(scan_options->program_name);
			exit(EXIT_FAILURE);
		}
		if (cli_option->validate)
			cli_option->validate(scan_options, optarg);
	}

	scan_options_validate(scan_options);
	*out_arg_index = optind;
}
