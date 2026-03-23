#include "ft_nmap.h"

void
scan_thread_destroy(t_scan_thread *thread)
{
	if (thread->pcap_handle)
		pcap_close(thread->pcap_handle);
	if (thread->tcp_sock > 0)
		close(thread->tcp_sock);
	if (thread->udp_sock > 0)
		close(thread->udp_sock);
	free(thread->probes);
}
