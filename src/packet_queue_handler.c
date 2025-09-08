#include "ft_nmap.h"

void
packet_queue_handler(t_packet_queue *queue,
	const u_char *data, size_t size, struct timeval tv)
{
	t_packet *packet;

	packet = packet_create(data, size, tv);
	if (packet == NULL)
		return ;

	if (!packet_enqueue(queue, packet))
		packet_destroy(packet);
}
