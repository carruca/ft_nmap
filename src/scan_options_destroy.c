#include "ft_nmap.h"

void
scan_options_destroy(t_opts *opts)
{
	free(opts->filename);
	free(opts->portlist);
	free(opts->program_name);
	for (int i = 0; i < opts->num_targets; i++)
		free(opts->targets[i]);
	free(opts->targets);
}
