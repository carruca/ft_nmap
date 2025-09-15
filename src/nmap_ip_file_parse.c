#include "ft_nmap.h"

void
nmap_ip_file_parse(const char *filename)
{
	FILE *stream;
	char nextline[HOST_NAME_MAX];

/*
 * TODO: stores ip address/hostname somewhere
 */
	stream = fopen(filename, "r");
	if (stream == NULL)
		print_error_and_exit("", "fopen: not able to open the file.");

	while (fgets(nextline, sizeof(nextline), stream))
	fclose(stream);
}
