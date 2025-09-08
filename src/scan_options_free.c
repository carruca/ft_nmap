#include "ft_nmap.h"

void
scan_options_destroy(t_scan_options *opts)
{
	if (opts->target) free(opts->target);
	if (opts->filename) free(opts->filename);
	if (opts->portlist) free(opts->portlist);
}
