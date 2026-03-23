#include "ft_nmap.h"
#include "logging/log.h"

static int
parse_port(const char *str)
{
	char *end;
	long val;

	if (!str || !*str)
		return -1;
	val = strtol(str, &end, 10);
	if (end == str)
		return -1;
	return (int)val;
}

uint16_t *
get_ports(char *expr, uint16_t *number_of_ports)
{
	uint16_t *ports;
	int count, start, end;
	char *next, *dash;
	char *checks;
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

	checks = calloc(USHRT_MAX + 1, 1);
	if (checks == NULL)
	{
		free(buf);
		free(ports);
		return NULL;
	}

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
			end = parse_port(expr + 1);
		}
		else
		{
			start = parse_port(expr);
			end = start;
			dash = strchr(expr, '-');
			if (dash && *(dash + 1))
				end = parse_port(dash + 1);
			else if (dash && !*(dash + 1))
				end = start + MAXPORTS - 1;
		}

		if (start < 0 || start > end || end > USHRT_MAX)
		{
			fprintf(stderr, "ft_nmap: port numbers must be between 0 and %d.\n",
				USHRT_MAX);
			free(checks);
			free(buf);
			free(ports);
			exit(EXIT_FAILURE);
		}

		for (int i = start; i <= end; ++i)
		{
			if (checks[i] == 0)
			{
				if (count >= MAXPORTS)
				{
					fprintf(stderr, "ft_nmap: port count exceeds maximum of %d.\n",
						MAXPORTS);
					free(checks);
					free(buf);
					free(ports);
					exit(EXIT_FAILURE);
				}
				ports[count++] = i;
				checks[i] = 1;
			}
		}
		if (next)
			expr = next + 1;
	}
	*number_of_ports = count;
	free(checks);
	free(buf);
	return ports;
}
