#include "ft_nmap.h"

int
send_worker_create(t_scan_worker *worker, int id, t_scan_ctx *engine)
{
	worker->thread_id = id;
	worker->tcp_socket = get_raw_socket_by_protocol("tcp");
	worker->active = 1;
	worker->engine = engine;

	if (pthread_create(&worker->thread, NULL, send_worker_thread, worker) != 0)
	{
		close(worker->tcp_socket);
		return -1;
	}
	return 0;
}
