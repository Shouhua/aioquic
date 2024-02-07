#include "list.h"

typedef struct _client
{
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	ngtcp2_conn *conn;
	ngtcp2_crypto_conn_ref conn_ref;
	ngtcp2_ccerr last_error;

	struct sockaddr_storage local_addr;
	socklen_t local_addrlen;
	struct sockaddr_storage remote_addr;
	socklen_t remote_addrlen;

	struct list_head stream_list;
	struct stream stream;

	int sock_fd;  // UDP socket for send and receive quic stream data
	int timer_fd; // timer for idle
	int epoll_fd; // epoll file descriptor
	int sig_fd;	  // handle INT,QUIT singal by converting it to file descriptor
} client;