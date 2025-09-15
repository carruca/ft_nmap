#include "ft_nmap.h"

void
scan_init(t_scan_ctx *scan_ctx)
{
	*scan_ctx = (t_scan_ctx){0};

	scan_ctx->max_outstanding = 1024;
	scan_ctx->global_timing.timeout = 2.0;
}
