#include <string.h>

char *
get_program_name(char *arg)
{
	char *pos;

	pos = strrchr(arg, '/');
	if (pos == NULL)
		return arg;
	return pos + 1;
}
