#include "ft_nmap.h"

#include <stdlib.h>

void scan_probe_list_destroy(t_engine *scan_eng)
{
    if (scan_eng)
	    ft_lstclear(&scan_eng->probes, free);
}
