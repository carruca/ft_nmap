#include "ft_nmap.h"

#include <ctype.h>

static const char *
port_state_str(t_port_state state)
{
	static const char *strings[] = {
		"open", "closed", "filtered", "unfiltered", "open|filtered"
	};
	return strings[state];
}

static void
print_probe_line(t_probe *probe)
{
	struct servent *serv;
	const t_scan_def *def;
	char port_col[16];

	serv = getservbyport(htons(probe->dst_port), NULL);
	def = scan_def_by_flag(probe->scan_type);
	snprintf(port_col, sizeof(port_col), "%u/%s",
		probe->dst_port, def ? def->name : "?");
	for (int i = 0; port_col[i]; ++i)
		port_col[i] = (char)tolower((unsigned char)port_col[i]);
	printf("%-10s %-14s %-s\n",
		port_col,
		port_state_str(probe->result),
		serv ? serv->s_name : "unknown");
}

void
scan_results_print(t_scan_thread *threads, int num_threads,
	const char *target, double scan_duration)
{
	printf("Scan took %.2f sec\n", scan_duration);
	char *resolved_ip = inet_ntoa(threads[0].dst.sin_addr);
	if (strcmp(target, resolved_ip) == 0)
		printf("Scan results for %s\n", target);
	else
		printf("Scan results for %s (%s)\n", target, resolved_ip);
	printf("%-10s %-14s %-s\n", "PORT", "STATE", "SERVICE");

	int has_open = 0;
	int has_other = 0;
	for (int t = 0; t < num_threads; ++t)
		for (int i = 0; threads[t].probes[i] != NULL; ++i)
			if (threads[t].probes[i]->result == PORT_OPEN)
				has_open = 1;
			else
				has_other = 1;

	const t_scan_def *def;
	for (int d = 0; (def = scan_def_by_index(d))->name != NULL; ++d)
		for (int t = 0; t < num_threads; ++t)
			for (int i = 0; threads[t].probes[i] != NULL; ++i)
			{
				t_probe *probe = threads[t].probes[i];
				if (probe->scan_type == def->flag && probe->result == PORT_OPEN)
					print_probe_line(probe);
			}

	if (has_open && has_other)
		printf("\n");

	for (int d = 0; (def = scan_def_by_index(d))->name != NULL; ++d)
		for (int t = 0; t < num_threads; ++t)
			for (int i = 0; threads[t].probes[i] != NULL; ++i)
			{
				t_probe *probe = threads[t].probes[i];
				if (probe->scan_type == def->flag && probe->result != PORT_OPEN)
					print_probe_line(probe);
			}
}
