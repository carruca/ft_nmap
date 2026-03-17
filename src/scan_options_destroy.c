#include "ft_nmap.h"

void
scan_options_destroy(t_opts *opts)
{
	free(opts->target);
	free(opts->filename);
	free(opts->portlist);
	free(opts->program_name);
	for (int i = 0; i < opts->num_file_targets; i++)
		free(opts->file_targets[i]);
	free(opts->file_targets);
}
