#include "ft_nmap.h"

static const char *
get_port_state_string(t_port_state state)
{
	static const char *strings[] =
	{
		"unknown",
		"testing",
		"open",
		"closed",
		"filtered",
		"unfiltered",
		"open|filtered"
	};

	return strings[state];
}

void
print_probe(void *content)
{
	struct servent *serv;
	t_probe *probe;


	probe = content;
	serv = getservbyport(htons(probe->port), NULL);

	printf("%-9u %-9s %-s\n",
		probe->port,
		get_port_state_string(probe->state),
		(serv) ? serv->s_name : "unknown");
}
