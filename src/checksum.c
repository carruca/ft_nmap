#include <stddef.h>

unsigned short
checksum(char *buffer, size_t bufsize)
{
	register int sum = 0;
	unsigned short *wp;

	for (wp = (unsigned short *)buffer; bufsize > 1; wp++, bufsize -= 2)
		sum += *wp;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}
