#include "ft_nmap.h"
#include "logging/log.h"

#include <getopt.h>

extern char *optarg;
extern int optind;

typedef void (*f_scan_cli_option_handler)(t_scan_options *scan_options, const char *arg);

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
scan_cli_option_help(t_scan_options *scan_options, const char *arg)
{
	(void)arg;
	print_usage(scan_options->program_name);
	exit(EXIT_SUCCESS);
}

void
scan_cli_option_ports(t_scan_options *scan_options, const char *arg)
{
	(void)arg;
	if (scan_options->portlist)
		print_error_and_exit(scan_options->program_name, "only one --ports option allowed, separate multiples ranges with commas.");
	scan_options->portlist = strdup(optarg);
}

void
scan_cli_option_ip(t_scan_options *scan_options, const char *arg)
{
	(void)arg;
	if (scan_options->target)
		print_error_and_exit(scan_options->program_name, "you can only use --ip option once.");
	scan_options->target = strdup(optarg);
}

void
scan_cli_option_file(t_scan_options *scan_options, const char *arg)
{
	(void)arg;
	if (scan_options->filename)
		print_error_and_exit(scan_options->program_name, "you can only use --file option once.");
	scan_options->filename = strdup(optarg);
}

void
scan_cli_option_speedup(t_scan_options *scan_options, const char *arg)
{
	(void)arg;
	if (scan_options->num_threads > MAXTHREADS)
		print_error_and_exit(scan_options->program_name, "speedup exceeded.");
	scan_options->num_threads = atoi(optarg);
}

void
scan_cli_option_scan(t_scan_options *scan_options, const char *arg)
{
	(void)arg;
	if (scan_options->scan_flag == 0)
		print_error_and_exit(scan_options->program_name, "scan flag is invalid.");
	scan_options->scan_flag = get_scan_type_by_name(optarg);
}

void
scan_cli_option_debug(t_scan_options *scan_options, const char *arg)
{
	(void)arg;
	scan_options->debugging = 1;
}

void
scan_options_parse(t_scan_options *scan_options, int *out_arg_index, int argc, char **argv) 
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
		{"debug", no_argument, 0, 'd', scan_cli_option_debug},
		{0}
	};

	*scan_options = (t_scan_options){0};

	scan_options_program_name_set(scan_options, argv[0]);
	long_opts = scan_cli_options_to_long_options(cli_options);

	if (argc < 2)
	{
		print_usage(scan_options->program_name);
		exit(EXIT_FAILURE);
	}

	while ((opt = getopt_long(argc, argv, "hdp:i:f:", long_opts, NULL)) != -1)
	{
		t_scan_cli_option *cli_option = scan_cli_option_find(cli_options, opt);

		if (cli_option == NULL)
		{
			log_message(LOG_LEVEL_DEBUG, "invalid option: %c\n", opt);
			print_usage(scan_options->program_name);
			exit(EXIT_FAILURE); 
		}

		if (cli_option->validate)
		{
			cli_option->validate(scan_options, optarg);
		}

	}

	if (scan_options->scan_flag == SCAN_UNDEFINED)
		scan_options->scan_flag = SCAN_ALL;

	if (scan_options->target && scan_options->filename)
		print_error_and_exit(scan_options->program_name, "--ip and --file options cannot be used at the same time.");

	if (scan_options->filename)
		nmap_ip_file_parse(scan_options->filename);

	*out_arg_index = optind;
}
