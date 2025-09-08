#include "ft_nmap.h"

void *
packet_worker_thread(void *arg)
{
	t_scan_ctx *engine;
	t_packet *packet;

	engine = (t_scan_ctx *)arg;
	while ((packet = packet_dequeue(engine->capture_queue)) != NULL)
	{
		pthread_mutex_lock(&engine->engine_mutex);
		packet_response(engine, packet->ts, packet->data);
		pthread_mutex_unlock(&engine->engine_mutex);

		packet_destroy(packet);
	}
	return NULL;
}
