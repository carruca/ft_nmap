#include "ft_nmap.h"

t_scan_type
get_scan_type_by_name(char *expr)
{
	const struct scan_mode *mode;

	for (int i = 0; i < MAXSCANS; ++i)
	{
		mode = get_scan_mode(i);
		printf("mode name = '%s', expr = '%s'\n", mode->name, expr);
		if (strcmp(mode->name, expr) == 0)
			return mode->flag;
	}
	return 0;
}
