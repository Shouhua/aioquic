#include "list.h"
#include "stream.h"
#include "errno.h"
#include "time.h"
#include "signal.h"
#include "stdio.h"

typedef struct _connection connection;

connection *connection_new(int sock_fd, SSL_CTX *ctx, SSL *ssl);
void connection_free(connection *conn);
void contcion_add_stream(connection *conn, stream *s);
int connection_start(connection *conn);

struct _connection
{
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	ngtcp2_conn *nt2_conn;
	ngtcp2_crypto_conn_ref ng2_conn_ref;
	// ngtcp2_ccerr ng2_last_error;

	struct sockaddr_storage local_addr;
	socklen_t local_addrlen;
	struct sockaddr_storage remote_addr;
	socklen_t remote_addrlen;

	struct list_head streams;

	int sock_fd;  // UDP socket for send and receive quic stream data
	int timer_fd; // timer for idle

	int is_closed;
};

connection *connection_new(int sock_fd, SSL_CTX *ctx, SSL *ssl)
{
	connection *conn = (connection *)malloc(sizeof(connection));
	conn->ssl_ctx = ctx;
	conn->ssl = ssl;
	conn->sock_fd = sock_fd;
	conn->timer_fd = -1;
	conn->is_closed = 1;
	return conn;
}

void connection_free(connection *conn)
{
	if (!conn)
		return;

	struct list_head *el, *el1;
	list_for_each_safe(el, el1, &conn->streams)
	{
		list_del(el);
		stream *s = list_entry(el, stream, link);
		if (s)
			stream_free(s);
	}

	if (conn->ssl)
		SSL_free(conn->ssl);
	if (conn->ssl_ctx)
		SSL_CTX_free(C->ssl_ctx);
	if (conn->nt2_conn)
		ngtcp2_conn_del(conn->nt2_conn);
	if (c->sock_fd > 0)
		close(c->sock_fd);
	if (c->timer_fd > 0)
		close(c->timer_fd);

	free(conn);
}

void contcion_add_stream(connection *conn, stream *s)
{
	list_add_tail(&conn->streams, &s->link);
}

int connection_start(connection *conn)
{
	setup_quictls_for_quic(conn->ssl, conn->nt2_conn, conn->ng2_conn_ref);
	conn->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (conn->timer_fd < 0)
	{
		perror("timerfd_create");
		return -1;
	}

	return 0;
}