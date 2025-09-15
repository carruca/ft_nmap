#include "logging/log.h"
#include "logging/log_internal.h"

#include <stdlib.h>

t_log_ctx *log_config_ctx_create(const char *name, t_log_level level, FILE *output)
{
	t_log_ctx *log_ctx = malloc(sizeof(t_log_ctx));
	
	if (log_ctx == NULL)
		return NULL;
	
	log_config_ctx_set(log_ctx, name, level, output);	
	return log_ctx;
}

void log_config_ctx_set(t_log_ctx *log_ctx, const char *name, t_log_level level, FILE *output)
{
	if (name)
		log_ctx->name = name;
	if (output)
		log_ctx->output = output;
	log_ctx->level = level;
}

void log_config_ctx_destroy(t_log_ctx *log_ctx)
{
	free(log_ctx);
}

const t_log_ctx *log_config_default_get(void)
{
	return _log_config_default_ref();
}

void log_config_default_set(const char *name, t_log_level level, FILE *output)
{
	t_log_ctx *log_ctx = _log_config_default_ref();

	log_config_ctx_set(log_ctx, name, level, output);
}
