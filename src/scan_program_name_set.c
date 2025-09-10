#include "ft_nmap.h"

#include <libgen.h>
#include <string.h>

void
scan_program_name_set(t_scan_ctx *scan_ctx, const char *path)
{
    const char *program_name;
    char copy_path[256];

    if (!scan_ctx || !path)
        return ;
    
    strncpy(copy_path, path, sizeof(copy_path) - 1);
    program_name = basename(copy_path);

    free(scan_ctx->program_name);
    scan_ctx->program_name = strdup(program_name); 
}
