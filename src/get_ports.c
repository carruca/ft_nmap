#include "ft_nmap.h"

#include <limits.h>

unsigned short *
get_ports(char *expr, unsigned int *number_of_ports)
{
	unsigned short *ports;
	int count, start, end;
	char *next, *dash;
	char checks[USHRT_MAX + 1];

	ports = malloc(MAXPORTS * sizeof(unsigned short));
	if (ports == NULL)
		return NULL;

	memset(checks, 0, MAXPORTS + 1);
	count = 0;
	next = expr;
	while (next != NULL)
	{
		next = strchr(expr, ',');
		if (next)
			*next = '\0';
		if (*expr == '-')
		{
			start = 1;
			end = atoi(expr + 1);
		}
		else
		{
			start = atoi(expr);
			end = start;
			dash = strchr(expr, '-');
			if (dash && *(dash + 1))
				end = atoi(dash + 1);
			else if (dash && !*(dash + 1))
				end = start + MAXPORTS - 1;
		}

		if (start < MINPORTS || start > end || end > USHRT_MAX)
			print_error_and_exit("", "port range is invalid.");

		for (int i = start; i <= end; ++i)
		{
			if (checks[i] == 0)
			{
				ports[count++] = i;
				checks[i] = 1;
			}
		}
		expr = next + 1;
	}
	*number_of_ports = count;
	return ports;
}
