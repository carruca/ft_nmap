#include "logging/log_internal.h"

t_log_level log_level_get(void)
{
    return _log_config_default_ref()->level;
}

void log_level_set(t_log_level level)
{
    _log_config_default_ref()->level = level;
}