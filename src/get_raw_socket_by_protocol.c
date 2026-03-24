#include "ft_nmap.h"
#include "logging/log.h"

#include <errno.h>
#include <string.h>

int
get_raw_socket_by_protocol(const char *protocol_name)
{
	int raw_socket;
	struct protoent *proto;

	proto = getprotobyname(protocol_name);
	if (proto == NULL)
	{
		log_message(LOG_LEVEL_ERROR, "get_raw_socket_by_protocol: getprotobyname(%s) failed", protocol_name);
		return -1;
	}

	raw_socket = socket(AF_INET, SOCK_RAW, proto->p_proto);
	if (raw_socket < 0)
	{
		log_message(LOG_LEVEL_ERROR, "get_raw_socket_by_protocol: socket failed: %s", strerror(errno));
		return -1;
	}
	return raw_socket;
}
