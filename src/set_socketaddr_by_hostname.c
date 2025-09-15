#include "ft_nmap.h"

int
set_sockaddr_by_hostname(struct sockaddr_in *sockaddr, const char *hostname)
{
	struct addrinfo hints, *res;
	int s;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;

	s = getaddrinfo(hostname, NULL, &hints, &res);
	if (s != 0)
	{
		fprintf(stderr, "ft_nmap: failed to resolve \"%s\": %s\n", hostname, gai_strerror(s));
		return 1;
	}
	memcpy(sockaddr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return 0;
}
