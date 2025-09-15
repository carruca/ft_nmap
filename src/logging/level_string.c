#include "logging/log.h"

const char *log_level_to_string(t_log_level level)
{
  switch (level)
  {
    case LOG_LEVEL_DEBUG:
      return "DEBUG";
    case LOG_LEVEL_INFO:
      return "INFO";
    case LOG_LEVEL_WARN:
      return "WARN";
    case LOG_LEVEL_ERROR:
      return "ERROR";
    case LOG_LEVEL_FATAL:
      return "FATAL";
    default:
      return "UNKNOWN";
  }
}
