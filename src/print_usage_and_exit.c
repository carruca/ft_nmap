#include <stdio.h>
#include <stdlib.h>

void
print_usage_and_exit(char *name)
{
	printf("%s [OPTIONS]\n"
    "--help        Print this help screen\n"
		"--ports       Ports to scan (ex: '-p 1-10' or '-p 1,2,3' or '-p 1,5-15')\n"
    "--ip          IP address to scan in dot format\n"
    "--file        File name containing IP addresses to scan\n"
    "--speedup     [max 250] number of parallel threads to use\n"
    "--scan        Scan type: SYN/NULL/FIN/XMAS/ACK/UDP\n",
    name);
	exit(EXIT_FAILURE);
}
