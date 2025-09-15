#include "logging/log_internal.h"

const char *log_name_get(void)
{
    return _log_config_default_ref()->name;
}

void log_name_set(const char *name)
{
    _log_config_default_ref()->name = name;
}