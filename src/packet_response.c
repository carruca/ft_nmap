#include "ft_nmap.h"
#include "logging/log.h"

/*
** packet_match_probe
**
** Procesa un paquete capturado por pcap dentro del contexto de un hilo.
** Busca en el array de probes del hilo aquel cuyo src_port coincide
** con el destination port de la respuesta recibida.
**
** Retorna 1 si se resolvió un probe, 0 en caso contrario.
*/
int
packet_match_probe(t_scan_thread *info,
	struct timeval ts, const u_char *pkt_data)
{
	struct iphdr	ih;
	struct tcphdr	th;
	unsigned int	ip_hlen;
	uint16_t		dport;
	t_probe			*probe;

	pkt_data += (info->datalink == DLT_EN10MB) ? ETH_HLEN : NULL_HDR_LEN;
	memcpy(&ih, pkt_data, sizeof(struct iphdr));

	if (ih.protocol != IPPROTO_TCP)
		return 0;

	ip_hlen = ih.ihl << 2;
	memcpy(&th, pkt_data + ip_hlen, sizeof(struct tcphdr));

	/*
	** dport de la respuesta = sport que nosotros usamos al enviar.
	** Así identificamos a qué probe pertenece sin necesidad de
	** sincronización entre hilos (cada hilo tiene su propio rango).
	*/
	dport = ntohs(th.th_dport);

	for (int i = 0; info->probes[i] != NULL; i++)
	{
		probe = info->probes[i];

		if (probe->status != PROBE_SENT)
			continue;
		if (probe->src_port != dport)
			continue;

		probe->time_recv = ts;
		probe->status = PROBE_REPLIED;

		if (th.th_flags & TH_SYN)
			probe->result = PORT_OPEN;
		else if (th.th_flags & TH_RST)
			probe->result = PORT_CLOSED;
		else
			probe->result = PORT_FILTERED;

		if (probe->result == PORT_OPEN)
			log_message(LOG_LEVEL_INFO, "Discovered open port %u/tcp on %s",
				probe->dst_port, probe->dst_ip);
		else
			log_message(LOG_LEVEL_DEBUG, "Discovered %s port %u/tcp on %s",
				probe->result == PORT_CLOSED ? "closed" : "filtered",
				probe->dst_port,
				probe->dst_ip);

		return 1;
	}
	return 0;
}

