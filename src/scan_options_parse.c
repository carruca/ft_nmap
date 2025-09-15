#include "ft_nmap.h"

#include <getopt.h>

extern char *optarg;
extern int optind;

void
scan_options_parse(t_scan_options *scan_options, int *out_arg_index, int argc, char **argv) 
{
	int opt;

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

	if (argc < 2)
		print_usage_and_exit(scan_options->program_name);

	while ((opt = getopt_long(argc, argv, "hdp:i:f:", long_options, NULL)) != -1)
	{
		switch (opt)
		{
			case 'p':
				if (scan_options->portlist)
					print_error_and_exit(scan_options->program_name, "only one --ports option allowed, separate multiples ranges with commas.");
				scan_options->portlist = strdup(optarg);
				break;
			case 'i':
				if (scan_options->target)
					print_error_and_exit(scan_options->program_name, "you can only use --ip option once.");
				scan_options->target = strdup(optarg);
				break;
			case 'f':
				scan_options->filename = strdup(optarg);
				break;
			case 's':
				scan_options->num_threads = atoi(optarg);
				if (scan_options->num_threads > MAXTHREADS)
					print_error_and_exit(scan_options->program_name, "speedup exceeded.");
				break;
			case 'S':
				scan_options->scan_flag = get_scan_type_by_name(optarg);
				if (scan_options->scan_flag == 0)
					print_error_and_exit(scan_options->program_name, "scan flag is invalid.");
				break;
			case 'd':
				scan_options->debugging = 1;
				break;
			case 'h':
			default:
				print_usage_and_exit(scan_options->program_name);
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
