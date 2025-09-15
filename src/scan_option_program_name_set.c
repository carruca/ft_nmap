#include "ft_nmap.h"

#include <libgen.h>
#include <string.h>

void
scan_option_program_name_set(t_scan_option *scan_option, const char *path)
{
    const char *program_name;
    char copy_path[256];

    if (!scan_ctx || !path)
        return ;
    
    strncpy(copy_path, path, sizeof(copy_path) - 1);
    program_name = basename(copy_path);

    free(scan_option->program_name);
    scan_option->program_name = strdup(program_name); 
}
