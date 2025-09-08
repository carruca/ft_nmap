#include "ft_nmap.h"

#include <stdlib.h>
#include <string.h>

t_packet *
packet_create(const u_char *data, size_t size, struct timeval tv)
{
	t_packet *packet;

	packet = malloc(sizeof(t_packet));
	if (packet == NULL)
		return NULL;

	packet->data = malloc(size);
	if (packet->data == NULL)
	{
		free(packet);
		return NULL;
	}

	memcpy(packet->data, data, size);
	packet->size = size;
	packet->ts = tv;
	return packet;
}
