#include "ft_nmap.h"
#include "logging/log.h"

void
scan_config_print(const t_engine *scan_eng, int num_ports)
{
	const t_scan_def *def;
	const t_opts *opts;

	if (scan_eng == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "scan_config_print: scan_eng is NULL");
		return;
	}

	opts = scan_eng->opts;
	printf("Scan configurations\n");
	printf("Target IP-Address : %s\n", inet_ntoa(scan_eng->dst.sin_addr));
	printf("No of ports to scan : %d\n", num_ports);
	printf("Scans to be performed :");
	for (int pos = 0; (def = scan_def_by_index(pos))->name != NULL; pos++)
	{
		if (def->flag & opts->scan_flag)
			printf(" %s", def->name);
	}
	printf("\n");
	printf("No of threads : %d\n", opts->num_threads);
	printf("Scanning...\n");
}
