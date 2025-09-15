#include "logging/log.h"
#include "logging/log_internal.h"

__attribute__((constructor))
static void _log_config_init(void)
{
    t_log_ctx *log_ctx = _log_config_default_ref();
    
    log_ctx->name = DEFAULT_LOGNAME;
    log_ctx->level = DEFAULT_LOGLEVEL;
    log_ctx->output = DEFAULT_LOGSTREAM;
    log_ctx->start_time = time(NULL); 
}

t_log_ctx *_log_config_default_ref()
{
    static t_log_ctx log_ctx;
    
    return &log_ctx;
}
