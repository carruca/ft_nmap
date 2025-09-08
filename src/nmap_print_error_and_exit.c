#include <stdio.h>
#include <stdlib.h>

void
nmap_print_error_and_exit(char *error)
{
  // FIX: calling function should pass program_name instead of hardcoding "ft_nmap"
	fprintf(stderr, "%s: %s\n", "ft_nmap", error);
	exit(EXIT_FAILURE);
}
