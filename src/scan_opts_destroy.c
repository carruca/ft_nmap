#include "ft_nmap.h"

void
scan_opts_destroy(t_scan_opts *opts)
{
	free(opts->filename);
	free(opts->portlist);
	for (int i = 0; i < opts->num_targets; ++i)
		free(opts->targets[i]);
	free(opts->targets);
}
