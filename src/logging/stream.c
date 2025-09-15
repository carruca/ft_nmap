#include "logging/log_internal.h"

#include <stdio.h>

FILE *log_stream_get(void)
{
    return _log_config_default_ref()->output;
}

void log_stream_set(FILE *output)
{
    _log_config_default_ref()->output = output;
}