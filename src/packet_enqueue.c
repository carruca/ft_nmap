#include "ft_nmap.h"

int
packet_enqueue(t_packet_queue *queue, t_packet *pkt)
{
	t_list *node;

	pthread_mutex_lock(&queue->mutex);

	while (queue->count >= MAX_PKTQUEUE
		&& !queue->shutdown)
		pthread_cond_wait(&queue->not_full, &queue->mutex);

	if (queue->shutdown)
	{
		pthread_mutex_unlock(&queue->mutex);
		return 0;
	}

	node = ft_lstnew(pkt);
	if (node == NULL)
	{
		pthread_mutex_unlock(&queue->mutex);
		return 0;
	}

	ft_lstadd_back(&queue->head, node);
	queue->tail = node;
	++queue->count;

	pthread_cond_signal(&queue->not_empty);

	pthread_mutex_unlock(&queue->mutex);
	return 1;
}
