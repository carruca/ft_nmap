#include "ft_nmap.h"
#include "logging/log.h"

#include <ctype.h>

static t_scan_type
scan_type_by_single_name(const char *name)
{
	const t_scan_def *def;
	char upper[16];
	size_t i;

	for (i = 0; i < sizeof(upper) - 1 && name[i]; ++i)
		upper[i] = (char)toupper((unsigned char)name[i]);
	upper[i] = '\0';

	for (int d = 0; (def = scan_def_by_index(d))->name != NULL; ++d)
	{
		if (strcmp(def->name, upper) == 0)
			return def->flag;
	}
	return 0;
}

t_scan_type
get_scan_type_by_name(char *expr)
{
	t_scan_type result;
	t_scan_type flag;
	char *buf;
	char *token;
	char *rest;

	buf = strdup(expr);
	if (buf == NULL)
		return 0;

	result = 0;
	rest = buf;
	while ((token = strtok_r(rest, ",", &rest)))
	{
		flag = scan_type_by_single_name(token);
		if (flag == 0)
		{
			log_message(LOG_LEVEL_FATAL, "unknown scan type: %s", token);
			free(buf);
			return 0;
		}
		result |= flag;
	}
	free(buf);
	return result;
}
