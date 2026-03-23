#include "ft_nmap.h"
#include "logging/log.h"

static int
check_tcp(t_probe *probe, struct timeval ts, const u_char *ip_ptr, uint32_t caplen)
{
	struct iphdr ih;
	struct tcphdr th;
	unsigned int ip_hlen;
	const t_scan_def *def;

	if (caplen < sizeof(struct iphdr))
		return 0;
	memcpy(&ih, ip_ptr, sizeof(struct iphdr));
	ip_hlen = ih.ihl << 2;
	if (ip_hlen < sizeof(struct iphdr) || caplen < ip_hlen + sizeof(struct tcphdr))
		return 0;
	memcpy(&th, ip_ptr + ip_hlen, sizeof(struct tcphdr));

	if (probe->status != PROBE_SENT)
		return 0;
	def = scan_def_by_flag(probe->scan_type);
	if (!def || def->proto != PROTO_TCP)
		return 0;
	if (probe->src_port != ntohs(th.th_dport))
		return 0;

	probe->time_recv = ts;
	probe->status = PROBE_REPLIED;
	probe->result = def->classify(th.th_flags);

	if (probe->result == PORT_OPEN)
		log_message(LOG_LEVEL_INFO, "Discovered open port %u/tcp on %s",
			probe->dst_port, probe->dst_ip);
	else
		log_message(LOG_LEVEL_DEBUG, "%s scan: port %u on %s is %s",
			def->name, probe->dst_port, probe->dst_ip,
			probe->result == PORT_CLOSED ? "closed" : "filtered/unfiltered");
	return 1;
}

static int
check_icmp_unreach(t_probe *probe, struct timeval ts, const u_char *ip_ptr, uint32_t caplen)
{
	struct iphdr outer_ih;
	struct icmphdr icmph;
	struct iphdr inner_ih;
	struct udphdr inner_uh;
	struct tcphdr inner_th;
	unsigned int outer_ip_hlen;
	unsigned int inner_ip_hlen;
	const u_char *inner;
	const t_scan_def *def;

	if (caplen < sizeof(struct iphdr))
		return 0;
	memcpy(&outer_ih, ip_ptr, sizeof(struct iphdr));
	outer_ip_hlen = outer_ih.ihl << 2;
	if (outer_ip_hlen < sizeof(struct iphdr) || caplen < outer_ip_hlen + sizeof(struct icmphdr))
		return 0;
	memcpy(&icmph, ip_ptr + outer_ip_hlen, sizeof(struct icmphdr));

	if (icmph.type != ICMP_DEST_UNREACH)
		return 0;

	if (caplen < outer_ip_hlen + 8 + sizeof(struct iphdr))
		return 0;
	inner = ip_ptr + outer_ip_hlen + 8;
	memcpy(&inner_ih, inner, sizeof(struct iphdr));
	inner_ip_hlen = inner_ih.ihl << 2;
	if (inner_ip_hlen < sizeof(struct iphdr))
		return 0;

	if (probe->status != PROBE_SENT)
		return 0;

	def = scan_def_by_flag(probe->scan_type);
	if (!def)
		return 0;

	if (def->proto == PROTO_UDP && icmph.code == ICMP_PORT_UNREACH)
	{
		if (caplen < (unsigned)(outer_ip_hlen + 8 + inner_ip_hlen + sizeof(struct udphdr)))
			return 0;
		memcpy(&inner_uh, inner + inner_ip_hlen, sizeof(struct udphdr));
		if (probe->src_port != ntohs(inner_uh.uh_sport))
			return 0;
		probe->time_recv = ts;
		probe->status = PROBE_REPLIED;
		probe->result = PORT_CLOSED;
		log_message(LOG_LEVEL_DEBUG, "UDP port %u on %s is closed (ICMP unreachable)",
			probe->dst_port, probe->dst_ip);
		return 1;
	}

	if (def->flag & (SCAN_NULL | SCAN_FIN | SCAN_XMAS))
	{
		if (caplen < (unsigned)(outer_ip_hlen + 8 + inner_ip_hlen + sizeof(struct tcphdr)))
			return 0;
		memcpy(&inner_th, inner + inner_ip_hlen, sizeof(struct tcphdr));
		if (probe->src_port != ntohs(inner_th.th_sport))
			return 0;
		probe->time_recv = ts;
		probe->status = PROBE_REPLIED;
		probe->result = PORT_FILTERED;
		log_message(LOG_LEVEL_DEBUG, "%s scan: port %u on %s is filtered (ICMP unreachable)",
			def->name, probe->dst_port, probe->dst_ip);
		return 1;
	}

	return 0;
}

static int
check_udp(t_probe *probe, struct timeval ts, const u_char *ip_ptr, uint32_t caplen)
{
	struct iphdr ih;
	struct udphdr uh;
	unsigned int ip_hlen;

	if (caplen < sizeof(struct iphdr))
		return 0;
	memcpy(&ih, ip_ptr, sizeof(struct iphdr));
	ip_hlen = ih.ihl << 2;
	if (ip_hlen < sizeof(struct iphdr) || caplen < ip_hlen + sizeof(struct udphdr))
		return 0;
	memcpy(&uh, ip_ptr + ip_hlen, sizeof(struct udphdr));

	const t_scan_def *def;

	if (probe->status != PROBE_SENT)
		return 0;
	def = scan_def_by_flag(probe->scan_type);
	if (!def || def->proto != PROTO_UDP)
		return 0;
	if (probe->src_port != ntohs(uh.uh_dport))
		return 0;

	probe->time_recv = ts;
	probe->status = PROBE_REPLIED;
	probe->result = PORT_OPEN;

	log_message(LOG_LEVEL_INFO, "Discovered open port %u/udp on %s",
		probe->dst_port, probe->dst_ip);
	return 1;
}

int
probe_match(t_probe *probe, struct timeval ts, const u_char *pkt_data, uint32_t caplen, int datalink)
{
	struct iphdr ih;
	uint32_t hdr_len;

	hdr_len = (datalink == DLT_EN10MB) ? ETH_HLEN : NULL_HDR_LEN;
	if (caplen < hdr_len + sizeof(struct iphdr))
		return 0;
	pkt_data += hdr_len;
	caplen -= hdr_len;
	memcpy(&ih, pkt_data, sizeof(struct iphdr));

	if (ih.protocol == IPPROTO_TCP)
		return check_tcp(probe, ts, pkt_data, caplen);
	if (ih.protocol == IPPROTO_ICMP)
		return check_icmp_unreach(probe, ts, pkt_data, caplen);
	if (ih.protocol == IPPROTO_UDP)
		return check_udp(probe, ts, pkt_data, caplen);
	return 0;
}
