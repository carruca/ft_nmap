#include "ft_nmap.h"

t_packet *
packet_dequeue(t_packet_queue *queue)
{
	t_packet *pkt;
	t_list *node;

	pthread_mutex_lock(&queue->mutex);

	while (queue->count == 0
		&& !queue->shutdown)
		pthread_cond_wait(&queue->not_empty, &queue->mutex);

	if ((queue->shutdown && queue->count == 0)
		|| queue->head ==  NULL)
	{
		pthread_mutex_unlock(&queue->mutex);
		return NULL;
	}

	node = queue->head;
	pkt = (t_packet *)node->content;
	queue->head = queue->head->next;
	if (!queue->head)
		queue->tail = NULL;
	--queue->count;

	free(node);
	pthread_cond_signal(&queue->not_full);

	pthread_mutex_unlock(&queue->mutex);
	return pkt;
}
