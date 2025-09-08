#include "ft_nmap.h"

void
scan_engine_config_print(const t_scan_ctx *scan_ctx, int num_ports)
{
	const struct scan_mode *mode;

	printf("Scan configurations\n");
	printf("Target IP-Address : %s\n",
		inet_ntoa(scan_ctx->target.sin_addr));
	printf("No of ports to scan : %d\n", num_ports);
	printf("Scans to be performed :");
	for (int pos = 0; pos < MAXSCANS; ++pos)
	{
		mode = get_scan_mode(pos); 
		if (mode->flag & scan_ctx->opts.scan_flag)
			printf(" %s", mode->name);
	}
	printf("\n");
	printf("No of threads : %d\n", scan_ctx->opts.num_threads);
	printf("Scanning...\n");
	printf("\n");
}
