/*  gcc -g -Wall -Wextra -pedantic -o sockaddr sockaddr.c && ./sockaddr */
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int get_ip_port(struct sockaddr_storage *addr, char *ip, uint16_t *port)
{
	if (!addr || (!ip && !port))
		return 1;
	if (addr->ss_family == AF_INET)
	{
		struct sockaddr_in *addr_v4 = (struct sockaddr_in *)addr;
		if (port)
			*port = ntohs(addr_v4->sin_port);
		/* inet_ntoa 返回系统分配的静态地址 */
		// if (ip)
		// {
		// 	char *res = inet_ntoa(addr_v4->sin_addr);
		// 	memcpy(ip, res, strlen(res));
		// }

		inet_ntop(AF_INET, &(addr_v4->sin_addr), ip, INET_ADDRSTRLEN);
		return 0;
	}
	else if (addr->ss_family == AF_INET6)
	{
		struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)addr;
		if (port)
			*port = ntohs(addr_v6->sin6_port);
		if (ip)
		{
			const char *res = inet_ntop(AF_INET6, &(addr_v6->sin6_addr), ip, INET6_ADDRSTRLEN);
			if (!res)
			{
				fprintf(stderr, "inet_ntop AF_INET6 failed\n");
				return -1;
			}
		}
		return 0;
	}
	return -1;
}

int main()
{
	struct sockaddr_in addrV4;
	addrV4.sin_family = AF_INET;
	addrV4.sin_port = htons(4433);

	addrV4.sin_addr.s_addr = INADDR_LOOPBACK;
	int res;
	res = inet_aton("127.0.0.1", &(addrV4.sin_addr));
	if (res == 0)
	{
		fprintf(stderr, "inet_aton failed");
		exit(-1);
	}
	// inet_pton(AF_INET, "127.0.1.2", &addrV4.sin_addr);

	char ip[INET_ADDRSTRLEN];
	uint16_t port;
	get_ip_port((struct sockaddr_storage *)&addrV4, ip, &port);
	printf("ip: %s, port: %d\n", ip, port);

	struct sockaddr_in6 addrV6;
	addrV6.sin6_family = AF_INET6;
	addrV6.sin6_port = htons(4433);
	// inet_pton(AF_INET6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", &(addrV6.sin6_addr));
	// inet_pton(AF_INET6, "fe80::1234:5678:9abc:def0", &(addrV6.sin6_addr));
	inet_pton(AF_INET6, "::ffff:1.2.3.4", &(addrV6.sin6_addr));
	// addrV6.sin6_scope_id = if_nametoindex("eth0");
	char ip6[INET6_ADDRSTRLEN];
	uint16_t port6;
	get_ip_port((struct sockaddr_storage *)&addrV6, ip6, &port6);
	printf("ip: %s, port: %d\n", ip6, port6);
}
