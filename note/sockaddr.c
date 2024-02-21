#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>

int get_ip_port(struct sockaddr_in *ipv4, char *ip, uint16_t *port)
{
	// struct sockaddr_in *ipv4 = (struct sockaddr_in *)addr;
	*port = ntohs(ipv4->sin_port);
	inet_ntop(ipv4->sin_family, &(ipv4->sin_addr), ip, INET_ADDRSTRLEN);
	return 0;
}

int main()
{
	struct sockaddr_in addrV4;
	addrV4.sin_family = AF_INET;
	addrV4.sin_port = htons(4433);

	// addrV4.sin_addr.s_addr = INADDR_LOOPBACK;
	inet_pton(AF_INET, "127.0.1.2", &addrV4.sin_addr);

	char ip[INET_ADDRSTRLEN];
	uint16_t port;
	(void)get_ip_port(&addrV4, ip, &port);

	printf("ip: %s, port: %d\n", ip, port);
}
