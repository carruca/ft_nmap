#include "ft_nmap.h"
#include "logging/log.h"

int
scan_resolve_target(struct sockaddr_in *sockaddr, const char *hostname)
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
	log_message(LOG_LEVEL_DEBUG, "Resolved %s to %s",
		hostname, inet_ntoa(sockaddr->sin_addr));
	freeaddrinfo(res);
	return 0;
}
