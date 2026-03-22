#include "ft_nmap.h"
#include "logging/log.h"

#include <stdlib.h>

t_scan_ctx *scan_create(void)
{
	t_scan_ctx *ctx;

	ctx = calloc(1, sizeof(t_scan_ctx));
	if (!ctx)
	{
		log_message(LOG_LEVEL_FATAL, "Bad alloc");
		return NULL;
	}
	ctx->timeout = 2.0;
	return ctx;
}
