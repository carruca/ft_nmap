#ifndef LOG_INTERNAL_H
# define LOG_INTERNAL_H

# include "log_level.h"

# include <time.h>
# include <stdio.h>

typedef struct s_log_ctx {
    const char *name;
    t_log_level level;
    FILE *output;
    time_t start_time;
} t_log_ctx;

t_log_ctx *_log_config_default_ref();

#endif /* LOG_INTERNAL_H */
