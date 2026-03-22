#include "ft_nmap.h"

void
scan_destroy(t_scan_ctx *ctx)
{
	if (ctx)
	{
		probe_list_destroy(ctx);
		free(ctx->ports);
		free(ctx);
	}
}
