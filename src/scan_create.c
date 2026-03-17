#include "ft_nmap.h"
#include "logging/log.h"

#include <stdlib.h>

t_engine *scan_create(void)
{
    t_engine *scan_eng;

    scan_eng = calloc(1, sizeof(t_engine));
    if (!scan_eng)
    {
        log_message(LOG_LEVEL_FATAL, "Bad alloc");
        exit(EXIT_FAILURE);
    }
    return scan_eng;
}
