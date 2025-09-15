#include "ft_nmap.h"
#include "logging/log.h"

#include <libgen.h>
#include <string.h>

void
scan_options_program_name_set(t_scan_options *scan_options, const char *path)
{
    const char *program_name;
    char copy_path[256];

    if (scan_options == NULL)
    {
        log_message(LOG_LEVEL_ERROR, "scan_option_program_name_set: scan_optionw is NULL");
        return ;
    }
    
    strncpy(copy_path, path, sizeof(copy_path) - 1);
    program_name = basename(copy_path);

    free(scan_options->program_name);
    scan_options->program_name = strdup(program_name); 
}
