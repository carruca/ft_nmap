#include "ft_nmap.h"

void
scan_options_destroy(t_scan_options *opts)
{
	free(opts->target);
	free(opts->filename);
	free(opts->portlist);
	free(opts->program_name);
}
