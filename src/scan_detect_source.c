#include "ft_nmap.h"
#include "logging/log.h"

int
scan_detect_source(struct sockaddr_in *sockaddr, const struct sockaddr_in *dst)
{
	int sock;
	socklen_t len;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		log_message(LOG_LEVEL_ERROR, "source addr: socket failed");
		return 1;
	}

	if (connect(sock, (const struct sockaddr *)dst, sizeof(*dst)) < 0)
	{
		log_message(LOG_LEVEL_ERROR, "source addr: connect failed");
		close(sock);
		return 1;
	}

	len = sizeof(*sockaddr);
	if (getsockname(sock, (struct sockaddr *)sockaddr, &len) < 0)
	{
		log_message(LOG_LEVEL_ERROR, "source addr: getsockname failed");
		close(sock);
		return 1;
	}

	close(sock);
	return 0;
}
