#include "ft_nmap.h"

void
packet_response(t_scan_ctx *engine,
	struct timeval ts, const u_char *pkt_data)
{
	unsigned short sport;
	unsigned int ip_hlen;
	struct iphdr *ih;
	struct tcphdr *th;
	t_list *current_node;

	pkt_data += ETH_HLEN;
	ih = (struct iphdr*)pkt_data;
	ip_hlen = ih->ihl << 2;

	switch(ih->protocol)
	{
		case IPPROTO_TCP:
			th = (struct tcphdr *)(pkt_data + ip_hlen);
			sport = ntohs(th->th_sport);
	}

	current_node = engine->probe_list;
	while (current_node)
	{
		if (probe_update(engine, current_node->content, sport, ts, th))
			break;
		current_node = current_node->next;
	}
}
