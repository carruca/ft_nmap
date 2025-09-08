#include "ft_nmap.h"
#include "tcp_checksum.h"

#include <string.h>
#include <arpa/inet.h>


unsigned short
tcp_checksum(
	const struct sockaddr_in *src_sockaddr,
	const struct sockaddr_in *dst_sockaddr,
	const struct tcphdr *th)
{
  struct pseudo_header psh;
  size_t th_len;

  th_len = sizeof(struct tcphdr);
	psh.src_addr = src_sockaddr->sin_addr.s_addr;
  psh.dst_addr = dst_sockaddr->sin_addr.s_addr;
  psh.zero = 0;
	psh.proto = IPPROTO_TCP;
	psh.th_len = htons(th_len);
	memcpy(&psh.th, th, th_len);

	return checksum((char *)&psh, sizeof(struct pseudo_header));
}
