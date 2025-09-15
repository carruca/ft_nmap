#include <stdint.h>
#include <netinet/tcp.h>

struct pseudo_header
{
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t zero;
	uint8_t proto;
	uint16_t th_len;
	struct tcphdr th;
};
