#include "ft_nmap.h"

void
scan_destroy(t_engine *scan_eng)
{
	if (scan_eng)
	{
		scan_probe_list_destroy(scan_eng);
		scan_options_destroy(scan_eng->opts);
		free(scan_eng);
	}
}
