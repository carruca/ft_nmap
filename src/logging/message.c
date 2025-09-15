#include "logging/log.h"
#include "logging/log_internal.h"

#include <stdio.h>
#include <stdarg.h>

int log_message(t_log_level level, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    log_vmessage(level, format, args);
    va_end(args);
    return 0;
}

int log_vmessage(t_log_level level, const char *format, va_list args)
{
    return log_vmessage_ctx(_log_config_default_ref(), level, format, args);
}

int log_message_ctx(t_log_ctx *log_ctx, t_log_level level, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    log_vmessage_ctx(log_ctx, level, format, args);
    va_end(args);
    return 0;
}

int log_vmessage_ctx(t_log_ctx *log_ctx, t_log_level level, const char *format, va_list args)
{
    if (log_ctx == NULL || level < log_ctx->level)
        return 0;

    fprintf(log_ctx->output, "[%s] %s: ", log_level_to_string(level), log_ctx->name);
    vfprintf(log_ctx->output, format, args);
    fprintf(log_ctx->output, "\n");
    return 0;
}
