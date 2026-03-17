#include "ft_nmap.h"

void
scan_init(t_engine *scan_eng)
{
	*scan_eng = (t_engine){0};

	scan_eng->timing.timeout = 2.0;
}
