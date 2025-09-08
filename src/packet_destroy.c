#include "ft_nmap.h"

void
packet_destroy(t_packet *packet)
{
	if (packet != NULL)
	{
		free(packet->data);
		free(packet);
	}
}
