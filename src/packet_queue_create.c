#include "ft_nmap.h"

t_packet_queue *
packet_queue_create()
{
	t_packet_queue *queue;

	queue = calloc(1, sizeof(t_packet_queue));
	if (queue == NULL) return NULL;

	pthread_mutex_init(&queue->mutex, NULL);
	pthread_cond_init(&queue->not_empty, NULL);
	pthread_cond_init(&queue->not_full, NULL);
	return queue;
}
