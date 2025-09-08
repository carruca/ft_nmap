#include "ft_nmap.h"

#include <errno.h>

extern int errno;

int
get_raw_socket_by_protocol(const char *protocol_name)
{
	int raw_socket;
	struct protoent *proto;

	proto = getprotobyname(protocol_name);
	if (proto == NULL)
		error(EXIT_FAILURE, errno, "getprotobyname");

	raw_socket = socket(AF_INET, SOCK_RAW, proto->p_proto);
	if (raw_socket < 0)
		error(EXIT_FAILURE, errno, "socket");
	return raw_socket;
}
