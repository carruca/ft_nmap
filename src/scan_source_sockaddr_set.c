#include "ft_nmap.h"
#include <ifaddrs.h>

int
scan_source_sockaddr_set(struct sockaddr_in *sockaddr)
{
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
		return 1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr != NULL
			&& ifa->ifa_addr->sa_family == AF_INET
			&& !strcmp(ifa->ifa_name,"eth0"))
		{
			memcpy(sockaddr, ifa->ifa_addr, sizeof(struct sockaddr));
			break;
		}
	}
	freeifaddrs(ifaddr);
	return 0;
}
