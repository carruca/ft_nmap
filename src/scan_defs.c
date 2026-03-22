#include "ft_nmap.h"

static t_port_state classify_syn(uint8_t flags);
static t_port_state classify_ack(uint8_t flags);
static t_port_state classify_stealth(uint8_t flags);

static const t_scan_def g_scan_defs[] = {
	{"SYN",  SCAN_SYN,  PROTO_TCP, TH_SYN,                       classify_syn    },
	{"ACK",  SCAN_ACK,  PROTO_TCP, TH_ACK,                       classify_ack    },
	{"FIN",  SCAN_FIN,  PROTO_TCP, TH_FIN,                       classify_stealth},
	{"XMAS", SCAN_XMAS, PROTO_TCP, TH_FIN | TH_URG | TH_PUSH,   classify_stealth},
	{"NULL", SCAN_NULL, PROTO_TCP, 0,                             classify_stealth},
	{"UDP",  SCAN_UDP,  PROTO_UDP, 0,                             NULL            },
	{NULL,   0,         0,         0,                             NULL            },
};

const t_scan_def *
scan_def_by_index(int index)
{
	return &g_scan_defs[index];
}

const t_scan_def *
scan_def_by_flag(t_scan_type flag)
{
	for (int i = 0; g_scan_defs[i].name != NULL; ++i)
		if (g_scan_defs[i].flag == flag)
			return &g_scan_defs[i];
	return NULL;
}

static t_port_state
classify_syn(uint8_t flags)
{
	if ((flags & TH_SYN) && (flags & TH_ACK))
		return PORT_OPEN;
	if (flags & TH_RST)
		return PORT_CLOSED;
	return PORT_FILTERED;
}

static t_port_state
classify_ack(uint8_t flags)
{
	if (flags & TH_RST)
		return PORT_UNFILTERED;
	return PORT_FILTERED;
}

static t_port_state
classify_stealth(uint8_t flags)
{
	if (flags & TH_RST)
		return PORT_CLOSED;
	return PORT_OPENFILTERED;
}
