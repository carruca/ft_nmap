#include <stdio.h>
#include <stdlib.h>

void
print_error(char *program_name, char *error)
{
	fprintf(stderr, "%s: %s\n", program_name, error);
}

void
print_error_and_exit(char *program_name, char *error)
{
	print_error(program_name, error);
	exit(EXIT_FAILURE);
}