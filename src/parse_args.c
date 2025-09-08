#include "ft_nmap.h"

#include <getopt.h>

extern char *optarg;
extern int optind;

int
scan_options_parse(t_scan_options *out_opts, int *out_arg_index, int argc, char **argv) 
{
	int opt;
	char *program_name;

	struct option long_options[] =
	{
		{"help", no_argument, 0, 'h'},
		{"ports", required_argument, 0, 'p'},
		{"ip", required_argument, 0, 'i'},
		{"file", required_argument, 0, 'f'},
		{"speedup", required_argument, 0, 's'},
		{"scan", required_argument, 0, 'S'},
		{"debug", no_argument, 0, 'd'},
		{0}
	};

	program_name = get_program_name(argv[0]);

	if (argc < 2)
		print_usage_and_exit(program_name);

	while ((opt = getopt_long(argc, argv, "hdp:i:f:", long_options, NULL)) != -1)
	{
		switch (opt)
		{
			case 'p':
				if (out_opts->portlist)
					nmap_print_error_and_exit("only one --ports option allowed, separate multiples ranges with commas.");
				out_opts->portlist = strdup(optarg);
				break;
			case 'i':
				if (out_opts->target)
					nmap_print_error_and_exit("you can only use --ip option once.");
				out_opts->target = strdup(optarg);
				break;
			case 'f':
				out_opts->filename = strdup(optarg);
				break;
			case 's':
				out_opts->num_threads = atoi(optarg);
				if (out_opts->num_threads > MAXTHREADS)
					nmap_print_error_and_exit("speedup exceeded.");
				break;
			case 'S':
				out_opts->scan_flag = nmap_get_scan_technique_by_name(optarg);
				if (out_opts->scan_flag == 0)
					nmap_print_error_and_exit("scan flag is invalid.");
				break;
			case 'd':
				out_opts->debugging = 1;
				break;
			case 'h':
			default:
				print_usage_and_exit(program_name);
		}
	}

	if (out_opts->target && out_opts->filename)
		nmap_print_error_and_exit("--ip and --file options cannot be used at the same time.");

	if (out_opts->filename)
		nmap_ip_file_parse(out_opts->filename);

	*out_arg_index = optind;
	return 0;
}
