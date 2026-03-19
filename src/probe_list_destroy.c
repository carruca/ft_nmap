#include "ft_nmap.h"

#include <stdlib.h>

void
probe_list_destroy(t_engine *scan_eng)
{
	if (scan_eng)
		ft_lstclear(&scan_eng->probes, free);
}
