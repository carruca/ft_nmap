#include "ft_nmap.h"

#include <stdlib.h>

void
probe_list_destroy(t_scan_ctx *ctx)
{
	if (ctx)
		ft_lstclear(&ctx->probes, free);
}
