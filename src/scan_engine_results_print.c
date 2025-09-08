#include "ft_nmap.h"

void
print_scan_results(t_scan_ctx *engine)
{
	printf("IP address: %s\n",
		inet_ntoa(engine->target.sin_addr));
	printf("\n");
	printf("%-9s %-9s %-s\n", "PORT", "STATE", "SERVICE");
	ft_lstiter(engine->probe_list, print_probe);
/*	print_probe_list_if(PORT_OPEN, engine->probe_list);
	print_probe_list_if(PORT_CLOSED, engine->probe_list);
	print_probe_list_if(PORT_FILTERED, engine->probe_list);
	print_probe_list_if(PORT_UNFILTERED, engine->probe_list);
	print_probe_list_if(PORT_OPENFILTERED, engine->probe_list);
*/}
