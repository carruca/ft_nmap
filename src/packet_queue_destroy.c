#include "ft_nmap.h"

void
packet_queue_destroy(t_packet_queue *queue)
{
	if (queue)
	{
		pthread_cond_destroy(&queue->not_empty);
		pthread_cond_destroy(&queue->not_full);
		pthread_mutex_destroy(&queue->mutex);
		free(queue);
	}
}
