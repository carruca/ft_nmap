#include "ft_nmap.h"

#include <ctype.h>
#include <stdbool.h>

static const char *
port_state_str(t_port_state state)
{
	static const char *strings[] = {
		"open", "closed", "filtered", "unfiltered", "open|filtered"
	};
	if ((int)state < 0 || (size_t)state >= sizeof(strings) / sizeof(*strings))
		return "unknown";
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

static inline void
print_thread_probes_by_scan_type(t_scan_thread *thread, t_scan_type scan_flag, int open)
{
	for (int i = 0; thread->probes[i] != NULL; ++i)
	{
		t_probe *probe = thread->probes[i];
		if (probe->scan_type == scan_flag && (probe->result == PORT_OPEN) == open)
			print_probe_line(probe);
	}
}

static void
scan_results_print_open_or_not(t_scan_thread *threads, int num_threads, int open)
{
	const t_scan_def *def;

	for (int d = 0; (def = scan_def_by_index(d))->name != NULL; ++d)
		for (int thread_index = 0; thread_index < num_threads; ++thread_index)
			print_thread_probes_by_scan_type(&threads[thread_index], def->flag, open);
}

static inline void
update_open_other_flags(t_scan_thread *threads, int thread_index, int *has_open, int *has_other)
{
	for (int index = 0; threads[thread_index].probes[index] != NULL; ++index)
		{
			if (threads[thread_index].probes[index]->result == PORT_OPEN)
			{
				*has_open = 1;
			}
			else
			{
				*has_other = 1;
			}
		}
}

void
scan_results_print(t_scan_thread *threads, int num_threads,
	const char *target, double scan_duration)
{
	int has_open = 0;
	int has_other = 0;
	char *resolved_ip = inet_ntoa(threads[0].dst.sin_addr);

	printf("Scan took %.2f sec\n", scan_duration);
	if (strcmp(target, resolved_ip) == 0)
	{
		printf("Scan results for %s\n", target);
	}
	else
  {
		printf("Scan results for %s (%s)\n", target, resolved_ip);
	}

	printf("%-10s %-14s %-s\n", "PORT", "STATE", "SERVICE");

	for (int index = 0; index < num_threads; ++index)
	{
		update_open_other_flags(threads, index, &has_open, &has_other);
	}

	scan_results_print_open_or_not(threads, num_threads, true);

	if (has_open && has_other)
		printf("\n");

	scan_results_print_open_or_not(threads, num_threads, false);
}
