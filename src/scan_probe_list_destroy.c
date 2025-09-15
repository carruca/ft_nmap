#include "ft_nmap.h"

#include <stdlib.h>

void scan_probe_list_destroy(t_scan_ctx *scan_ctx)
{
    if (scan_ctx)
	    ft_lstclear(&scan_ctx->probe_list, free);
}
