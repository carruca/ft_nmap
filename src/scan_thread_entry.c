#include "ft_nmap.h"
#include "logging/log.h"

void
*scan_thread_entry(void *data)
{
	t_scan_thread *thread;

	thread = (t_scan_thread *)data;
	log_message(LOG_LEVEL_DEBUG, "Initiating parallel scan %d [%d probes]",
		thread->thread_id, count_probes(thread->probes));
	scan_thread_run(thread, thread->opts);
	log_message(LOG_LEVEL_DEBUG, "Completed parallel scan %d", thread->thread_id);
	return NULL;
}
