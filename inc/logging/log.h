#ifndef LOG_H
# define LOG_H

# define DEFAULT_LOGNAME     "noname"
# define DEFAULT_LOGLEVEL    LOG_LEVEL_INFO
# define DEFAULT_LOGSTREAM   stderr

# include "log_level.h"

# include <stdarg.h>
# include <stdio.h>

typedef struct s_log_ctx t_log_ctx;

int log_message(t_log_level level, const char *format, ...);
int log_vmessage(t_log_level level, const char *format, va_list args);

int log_message_ctx(t_log_ctx *log_ctx, t_log_level level, const char *format, ...);
int log_vmessage_ctx(t_log_ctx *log_ctx, t_log_level level, const char *format, va_list args);

const t_log_ctx *log_config_default_get(void);
void log_config_default_set(const char *name, t_log_level level, FILE *output);
void log_config_ctx_set(t_log_ctx *log_ctx, const char *name, t_log_level level, FILE *output);
t_log_ctx *log_config_ctx_create(const char *name, t_log_level level, FILE *output);
void log_config_ctx_destroy(t_log_ctx *log_ctx);

const char *log_name_get(void);
void log_name_set(const char *name);

t_log_level log_level_get(void);
void log_level_set(t_log_level level);

FILE *log_stream_get(void);
void log_stream_set(FILE *output);

const char *log_level_to_string(t_log_level level);

#endif /* LOG_H */