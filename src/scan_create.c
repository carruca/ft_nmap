#include "ft_nmap.h"

#include <stdlib.h>

t_scan_ctx *scan_create(void)
{
    t_scan_ctx *scan_ctx;

    scan_ctx = calloc(1, sizeof(t_scan_ctx));
    if (!scan_ctx)
        print_error_and_exit("", "Bad alloc");
    return scan_ctx;
}