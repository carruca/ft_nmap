#include "ft_nmap.h"
#include "logging/log.h"

#include <limits.h>

uint16_t *
get_ports(char *expr, uint16_t *number_of_ports)
{
	uint16_t *ports;
	int count, start, end;
	char *next, *dash;
	char checks[USHRT_MAX + 1];
	char *buf;

	buf = strdup(expr);
	if (buf == NULL)
		return NULL;
	expr = buf;

	ports = malloc(MAXPORTS * sizeof(uint16_t));
	if (ports == NULL)
	{
		free(buf);
		return NULL;
	}

	memset(checks, 0, sizeof(checks));
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
		{
			log_message(LOG_LEVEL_FATAL, "port range is invalid.");
			free(buf);
			free(ports);
			exit(EXIT_FAILURE);
		}

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
	free(buf);
	return ports;
}
