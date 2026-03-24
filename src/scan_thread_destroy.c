#include "ft_nmap.h"

void
scan_thread_destroy(t_scan_thread *thread)
{
	if (thread->pcap_handle)
	{
		pcap_close(thread->pcap_handle);
		thread->pcap_handle = NULL;
	}
	if (thread->tcp_sock > 0)
	{
		close(thread->tcp_sock);
		thread->tcp_sock = -1;
	}
	if (thread->udp_sock > 0)
	{
		close(thread->udp_sock);
		thread->udp_sock = -1;
	}
	free(thread->probes);
	thread->probes = NULL;
}
