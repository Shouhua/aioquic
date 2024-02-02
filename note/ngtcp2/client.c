#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/signalfd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define MAX_EVENTS 64
#define MAX_BUFFER 1280
#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT "4433"

struct stream
{
	int64_t stream_id;
	char *data;
	size_t datalen;
	size_t nwrite;
};

struct client
{
	ngtcp2_crypto_conn_ref conn_ref;
	struct sockaddr_storage local_addr;
	socklen_t local_addrlen;
	struct sockaddr_storage remote_addr;
	socklen_t remote_addrlen;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	ngtcp2_conn *conn;

	struct stream stream;

	ngtcp2_ccerr last_error;

	int sock_fd;
	int timer_fd;
	int epoll_fd;
	int sig_fd;
};

uint64_t timestamp(void)
{
	struct timespec tp;
	if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0)
		return 0;
	return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

int send_packet(struct client *c, uint8_t *data, size_t datalen)
{
	struct iovec iov = {data, datalen};
	struct msghdr msg = {0};
	ssize_t nwrite;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	do
	{
		nwrite = sendmsg(c->sock_fd, &msg, 0);
	} while (nwrite == -1 && errno == EINTR);

	if (nwrite == -1)
	{
		fprintf(stderr, "sendmsg: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int write_to_stream(struct client *c)
{
	int ret;
	int64_t stream_id = c->stream.stream_id;
	ngtcp2_path_storage ps;
	ngtcp2_path_storage_zero(&ps);

	uint8_t stream_buf[MAX_BUFFER];
	uint64_t ts = timestamp();

	ngtcp2_pkt_info pi;
	int flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

	for (;;)
	{
		ngtcp2_vec datav;
		if (stream_id == -1)
		{
			datav.base = NULL;
			datav.len = 0;
		}
		else
		{
			datav.base = (uint8_t *)c->stream.data;
			datav.len = c->stream.datalen;
			if (c->stream.nwrite >= c->stream.datalen)
			{
				flags &= ~NGTCP2_WRITE_STREAM_FLAG_MORE;
				stream_id = -1;
				datav.base = NULL;
				datav.len = 0;
			}
		}

		ngtcp2_ssize nread, nwrite;
		nwrite = ngtcp2_conn_writev_stream(c->conn,
										   &ps.path,
										   &pi,
										   stream_buf, sizeof(stream_buf),
										   &nread, flags,
										   stream_id,
										   &datav, 1,
										   ts);
		// fprintf(stdout, "c->stream.stream_id: %ld, stream_id: %ld, flags: %d, nwrite: %ld, pdatalen: %ld\n",
		//    c->stream.stream_id,
		//    stream_id,
		//    flags,
		//    nwrite,
		//    nread);
		if (nwrite < 0)
		{
			switch (nwrite)
			{
			case NGTCP2_ERR_WRITE_MORE:
				c->stream.nwrite += (size_t)nread;
				continue;
			default:
				fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n",
						ngtcp2_strerror((int)nwrite));
				ngtcp2_ccerr_set_liberr(&c->last_error, (int)nwrite, NULL, 0);
				return -1;
			}
		}
		// 不能写入frame，因为buffer太小或者拥塞控制了, 只能继续读和等待
		if (nwrite == 0)
			return 0;
		if (c->stream.stream_id > -1 && nread > 0)
			c->stream.nwrite += (size_t)nread;

		ret = send_packet(c, (uint8_t *)stream_buf, nwrite);
		if (ret < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fprintf(stderr, "send_packet失败\n");
			return EXIT_FAILURE;
		}
		if (c->stream.stream_id > -1 && c->stream.nwrite >= c->stream.datalen)
			break;
	}

	return 0;
}

int connection_write(struct client *c)
{
	write_to_stream(c);

	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(c->conn);
	ngtcp2_tstamp now = timestamp();
	struct itimerspec it;
	memset(&it, 0, sizeof(it));
	if (timerfd_settime(c->timer_fd, 0, &it, NULL) < 0)
	{
		perror("timerfd_settime发生错误");
		return EXIT_FAILURE;
	}
	if (expiry < now)
	{
		it.it_value.tv_sec = 0;
		it.it_value.tv_nsec = 1;
	}
	else
	{
		it.it_value.tv_sec = (expiry - now) / NGTCP2_SECONDS;
		it.it_value.tv_nsec = ((expiry - now) % NGTCP2_SECONDS) / NGTCP2_NANOSECONDS;
	}
	if (timerfd_settime(c->timer_fd, 0, &it, NULL) < 0)
	{
		perror("timerfd_settime发生错误");
		return EXIT_FAILURE;
	}
	// fprintf(stdout, "设置定时器, sec: %ld, nsec: %ld\n", it.it_value.tv_sec, it.it_value.tv_nsec);

	return 0;
}

void connection_free(struct client *c)
{
	if (c->conn)
		ngtcp2_conn_del(c->conn);
	SSL_free(c->ssl);
	SSL_CTX_free(c->ssl_ctx);

	epoll_ctl(c->epoll_fd, EPOLL_CTL_DEL, c->sock_fd, NULL);
	if (c->timer_fd > 0)
		close(c->timer_fd);
	if (c->sock_fd > 0)
		close(c->sock_fd);
	if (c->epoll_fd > 0)
		close(c->epoll_fd);
}

void connection_close(struct client *c)
{
	ngtcp2_ssize nwrite;
	ngtcp2_pkt_info pi;
	ngtcp2_path_storage ps;
	uint8_t buf[MAX_BUFFER];

	if (ngtcp2_conn_in_closing_period(c->conn) ||
		ngtcp2_conn_in_draining_period(c->conn))
	{
		goto fin;
	}

	ngtcp2_path_storage_zero(&ps);

	nwrite = ngtcp2_conn_write_connection_close(
		c->conn, &ps.path, &pi, buf, sizeof(buf), &c->last_error, timestamp());
	if (nwrite < 0)
	{
		fprintf(stderr, "ngtcp2_conn_write_connection_close: %s\n",
				ngtcp2_strerror((int)nwrite));
		goto fin;
	}

	send_packet(c, buf, (size_t)nwrite);
fin:
	epoll_ctl(c->epoll_fd, EPOLL_CTL_DEL, c->timer_fd, NULL);
}

int handle_stdin(struct client *c)
{
	int ret;
	char buf[MAX_BUFFER];
	size_t nread = 0;

	memset(buf, 0, MAX_BUFFER);
	while (nread < sizeof(buf))
	{
		ret = read(STDIN_FILENO, buf + nread, sizeof(buf) - nread);
		if (ret == -1)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			perror("读取STDIN_FILENO错误");
			return EXIT_FAILURE;
		}
		else if (ret == 0)
		{
			return 0;
		}
		else
			nread += ret;
	}
	if (nread == sizeof(buf))
	{
		perror("读取STDIN_FILENO的buf满了");
		return EXIT_FAILURE;
	}

	if (strncmp(buf, "exit", 4) == 0)
	{
		connection_close(c);
		connection_free(c);
		exit(EXIT_SUCCESS);
	}

	int64_t stream_id = c->stream.stream_id;
	c->stream.data = buf;
	c->stream.datalen = nread - 1;
	c->stream.nwrite = 0;
	if (stream_id == -1)
	{
		if (!ngtcp2_conn_get_streams_bidi_left(c->conn))
		{
			perror("没有可用的bidi stream");
			return EXIT_FAILURE;
		}

		if (ngtcp2_conn_open_bidi_stream(c->conn, &stream_id, NULL) < 0)
		{
			perror("ngtcp2_conn_open_bidi_stream失败");
			return EXIT_FAILURE;
		}
		c->stream.stream_id = stream_id;
	}

	connection_write(c);
	return nread;
}

int handle_timer(struct client *c)
{
	int ret;
	ret = ngtcp2_conn_handle_expiry(c->conn, timestamp());
	if (ret < 0)
	{
		fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror((int)ret));
		return EXIT_FAILURE;
	}
	ret = connection_write(c);
	if (ret < 0)
	{
		fprintf(stderr, "connection_write出问题了\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int setup_stdin(int epoll_fd)
{
	int flags;
	struct epoll_event ev;

	flags = fcntl(STDIN_FILENO, F_GETFL, 0);
	if (flags < 0)
	{
		perror("获取STDIN_FILENO F_GETFL错误");
		return EXIT_FAILURE;
	}
	flags = fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
	if (flags < 0)
	{
		perror("设置STDIN_FILENO F_SETFL错误");
		return EXIT_FAILURE;
	}

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = STDIN_FILENO;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) == -1)
	{
		perror("epoll_ctl添加STDIN_FILENO失败");
		return EXIT_FAILURE;
	}
	return 0;
}

int setup_timer(int epoll_fd)
{
	struct epoll_event ev;
	int timer_fd = -1;

	timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (timer_fd < 0)
	{
		perror("timerfd_create失败");
		return EXIT_FAILURE;
	}
	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = timer_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev) == -1)
	{
		perror("epoll_ctl添加timer_fd失败");
		return EXIT_FAILURE;
	}
	return timer_fd;
}

int resolve_and_connect(const char *host, const char *port,
						struct sockaddr *local_addr, size_t *local_addrlen,
						struct sockaddr *remote_addr, size_t *remote_addrlen)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int ret, fd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	ret = getaddrinfo(host, port, &hints, &result);
	if (ret != 0)
		return -1;

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK,
					rp->ai_protocol);
		if (fd == -1)
			continue;

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
		{
			*remote_addrlen = rp->ai_addrlen;
			memcpy(remote_addr, rp->ai_addr, rp->ai_addrlen);

			socklen_t len = (socklen_t)*local_addrlen;
			if (getsockname(fd, local_addr, &len) == -1)
				return -1;
			*local_addrlen = len;
			break;
		}

		close(fd);
	}

	freeaddrinfo(result);

	if (rp == NULL)
		return -1;

	return fd;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_store_ctx)
{
	int error_code = preverify_ok ? X509_V_OK : X509_STORE_CTX_get_error(x509_store_ctx);
	if (error_code != X509_V_OK)
	{
		const char *error_string = X509_verify_cert_error_string(error_code);
		fprintf(stdout, "verify_callback失败: %s\n", error_string);
	}
	return preverify_ok;
}

int numeric_host_family(const char *hostname, int family)
{
	uint8_t dst[sizeof(struct in6_addr)];
	return inet_pton(family, hostname, dst) == 1;
}

int numeric_host(const char *hostname)
{
	return numeric_host_family(hostname, AF_INET) ||
		   numeric_host_family(hostname, AF_INET6);
}

int client_ssl_init(struct client *c, const char *cafile)
{
	int err;

	c->ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (!c->ssl_ctx)
	{
		fprintf(stderr, "SSL_CTX_new: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	if (cafile)
		err = SSL_CTX_load_verify_locations(c->ssl_ctx, cafile, NULL);
	else
		SSL_CTX_set_default_verify_paths(c->ssl_ctx);
	if (err == 0)
	{
		fprintf(stderr, "Could not load trusted certificates: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	SSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL); // 默认证书校验
	SSL_CTX_set_mode(c->ssl_ctx, SSL_MODE_AUTO_RETRY);

	if (ngtcp2_crypto_quictls_configure_client_context(c->ssl_ctx) != 0)
	{
		fprintf(stderr, "ngtcp2_crypto_quictls_configure_client_context failed\n");
		return -1;
	}

	c->ssl = SSL_new(c->ssl_ctx);
	if (!c->ssl)
	{
		fprintf(stderr, "SSL_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	SSL_set_app_data(c->ssl, &c->conn_ref);
	SSL_set_connect_state(c->ssl);
	// SSL_set_alpn_protos(c->ssl, (const unsigned char *)ALPN, sizeof(ALPN) - 1);
	if (!numeric_host(REMOTE_HOST))
	{
		SSL_set_tlsext_host_name(c->ssl, REMOTE_HOST); // SNI
	}

	err = SSL_set1_host(c->ssl, "localhost"); // cert hostname
	if (err != 1)
	{
		fprintf(stderr, "SSL_set1_host失败\n");
		return EXIT_FAILURE;
	}

	/* For NGTCP2_PROTO_VER_V1 */
	SSL_set_quic_transport_version(c->ssl, TLSEXT_TYPE_quic_transport_parameters);

	return 0;
}

void log_printf(void *user_data, const char *fmt, ...)
{
	va_list ap;
	(void)user_data;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
}

void rand_cb(uint8_t *dest, size_t destlen,
			 const ngtcp2_rand_ctx *rand_ctx)
{
	size_t i;
	(void)rand_ctx;

	for (i = 0; i < destlen; ++i)
	{
		*dest = (uint8_t)random();
	}
}

int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
							 uint8_t *token, size_t cidlen,
							 void *user_data)
{
	(void)conn;
	(void)user_data;

	if (RAND_bytes(cid->data, (int)cidlen) != 1)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	cid->datalen = cidlen;

	if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

int recv_stream_data_cb(ngtcp2_conn *conn __attribute__((unused)),
						uint32_t flags __attribute__((unused)),
						int64_t stream_id,
						uint64_t offset __attribute__((unused)),
						const uint8_t *data, size_t datalen,
						void *user_data __attribute__((unused)),
						void *stream_user_data __attribute__((unused)))
{
	char buf[datalen + 1];
	snprintf(buf, datalen + 1, "%s", data);
	fprintf(stdout, "收到 %zu 字节 from stream #%zd: %s\n", datalen, stream_id, buf);
	return 0;
}

int client_quic_init(struct client *c,
					 struct sockaddr *remote_addr,
					 socklen_t remote_addrlen,
					 struct sockaddr *local_addr,
					 socklen_t local_addrlen)
{
	ngtcp2_path path = {
		{
			(struct sockaddr *)local_addr,
			local_addrlen,
		},
		{
			(struct sockaddr *)remote_addr,
			remote_addrlen,
		},
		NULL,
	};
	ngtcp2_callbacks callbacks = {
		/* Use the default implementation from ngtcp2_crypto */
		.client_initial = ngtcp2_crypto_client_initial_cb,
		.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		.recv_retry = ngtcp2_crypto_recv_retry_cb,
		.update_key = ngtcp2_crypto_update_key_cb,
		.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,

		// .acked_stream_data_offset = acked_stream_data_offset_cb,
		.recv_stream_data = recv_stream_data_cb,
		.rand = rand_cb,
		.get_new_connection_id = get_new_connection_id_cb,
	};
	ngtcp2_cid dcid, scid;
	ngtcp2_settings settings;
	ngtcp2_transport_params params;
	int rv;

	dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
	if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1)
	{
		fprintf(stderr, "RAND_bytes failed\n");
		return -1;
	}

	scid.datalen = 8;
	if (RAND_bytes(scid.data, (int)scid.datalen) != 1)
	{
		fprintf(stderr, "RAND_bytes failed\n");
		return -1;
	}

	ngtcp2_settings_default(&settings);

	settings.initial_ts = timestamp();
	// settings.log_printf = log_printf;

	ngtcp2_transport_params_default(&params);

	params.initial_max_streams_uni = 3;
	params.initial_max_stream_data_bidi_local = 128 * 1024;
	params.initial_max_data = 1024 * 1024;
	// params.max_idle_timeout = 10 * NGTCP2_SECONDS;

	rv = ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
								&callbacks, &settings, &params, NULL, c);
	if (rv != 0)
	{
		fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
		return -1;
	}

	ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

	ngtcp2_conn_set_keep_alive_timeout(c->conn, 59 * NGTCP2_SECONDS);

	return 0;
}

ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	struct client *c = conn_ref->user_data;
	return c->conn;
}

ssize_t recv_packet(int fd, uint8_t *data, size_t data_size,
					struct sockaddr *remote_addr, size_t *remote_addrlen)
{
	struct iovec iov;
	iov.iov_base = data;
	iov.iov_len = data_size;

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	msg.msg_name = remote_addr;
	msg.msg_namelen = *remote_addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ssize_t ret;

	do
		ret = recvmsg(fd, &msg, MSG_DONTWAIT);
	while (ret < 0 && errno == EINTR);

	*remote_addrlen = msg.msg_namelen;

	return ret;
}

int connection_read(struct client *c)
{
	uint8_t buf[MAX_BUFFER];
	ngtcp2_ssize ret;
	for (;;)
	{
		struct sockaddr_storage remote_addr;
		size_t remote_addrlen = sizeof(remote_addr);
		ret = recv_packet(c->sock_fd, buf, sizeof(buf),
						  (struct sockaddr *)&remote_addr, &remote_addrlen);
		if (ret < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			perror("recv_packet发生错误");
			return -1;
		}

		ngtcp2_path path;
		memcpy(&path, ngtcp2_conn_get_path(c->conn), sizeof(path));
		path.remote.addrlen = remote_addrlen;
		path.remote.addr = (struct sockaddr *)&remote_addr;

		ngtcp2_pkt_info pi;
		memset(&pi, 0, sizeof(pi));

		ret = ngtcp2_conn_read_pkt(c->conn, &path, &pi, buf, ret,
								   timestamp());
		if (ret < 0)
		{
			fprintf(stderr, "ngtcp2_conn_read_pkt发生错误: %s ", ngtcp2_strerror(ret));
			if (ret == NGTCP2_ERR_CRYPTO)
			{
				uint8_t e = ngtcp2_conn_get_tls_alert(c->conn);
				fprintf(stderr, "%s\n", SSL_alert_desc_string_long(e));
			}
			exit(EXIT_FAILURE);
		}
	}
	return 0;
}

int handle_sig(struct client *c)
{
	struct signalfd_siginfo sfd_si;
	if (read(c->sig_fd, &sfd_si, sizeof(struct signalfd_siginfo)) == -1)
		return EXIT_FAILURE;

	if (sfd_si.ssi_signo == SIGQUIT)
	{
		fprintf(stdout, "QUIT信号触发\n");
	}
	if (sfd_si.ssi_signo == SIGINT)
	{
		fprintf(stdout, "INT信号触发\n");
	}
	if (c->conn)
	{
		connection_close(c);
	}
	connection_free(c);
	exit(EXIT_SUCCESS);
}

int setup_sig(int epoll_fd)
{
	sigset_t mask;
	int sig_fd;
	/*
	 * Setup SIGALRM to be delivered via SignalFD
	 * */
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	/*
	 * Block these signals so that they are not handled
	 * in the usual way. We want them to be handled via
	 * SignalFD.
	 * */
	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
	{
		perror("sigprocmask失败");
		return EXIT_FAILURE;
	}
	sig_fd = signalfd(-1, &mask, 0);
	if (sig_fd == -1)
	{
		perror("signalfd失败");
		return EXIT_FAILURE;
	}

	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = sig_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sig_fd, &ev) == -1)
	{
		close(sig_fd);
		perror("epoll_ctl添加signal fd失败");
		return EXIT_FAILURE;
	}
	return sig_fd;
}

int main(int argc, char *argv[])
{
	(void)argc;
	char *cafile = argv[1];
	int epoll_fd = -1, timer_fd = -1, sock_fd = -1, sig_fd = -1;
	struct sockaddr_storage local_addr, remote_addr;
	size_t local_addrlen = sizeof(local_addr), remote_addrlen;
	struct client c;

	ngtcp2_ccerr_default(&c.last_error);
	c.stream.stream_id = -1;

	sock_fd = resolve_and_connect(
		REMOTE_HOST, REMOTE_PORT,
		(struct sockaddr *)&local_addr,
		&local_addrlen,
		(struct sockaddr *)&remote_addr,
		&remote_addrlen);

	if (sock_fd < 0)
	{
		fprintf(stderr, "resolve_and_connect失败\n");
		return EXIT_FAILURE;
	}
	c.sock_fd = sock_fd;
	c.local_addr = local_addr;
	c.local_addrlen = local_addrlen;
	c.remote_addr = remote_addr;
	c.remote_addrlen = remote_addrlen;

	if (client_ssl_init(&c, cafile) < 0)
	{
		fprintf(stderr, "client_ssl_init失败\n");
		return EXIT_FAILURE;
	}

	if (client_quic_init(&c,
						 (struct sockaddr *)&remote_addr,
						 remote_addrlen,
						 (struct sockaddr *)&local_addr,
						 local_addrlen) < 0)
	{
		fprintf(stderr, "client_quic_init错误\n");
		return EXIT_FAILURE;
	}

	c.conn_ref.get_conn = get_conn;
	c.conn_ref.user_data = &c;

	epoll_fd = epoll_create1(0);
	if (epoll_fd == -1)
	{
		perror("创建epoll fd错误");
		return EXIT_FAILURE;
	}
	c.epoll_fd = epoll_fd;

	if (setup_stdin(epoll_fd) < 0)
	{
		fprintf(stderr, "setup_stdin失败\n");
		return EXIT_FAILURE;
	}

	timer_fd = setup_timer(epoll_fd);
	if (timer_fd < 0)
	{
		fprintf(stderr, "setup_timer失败\n");
		return EXIT_FAILURE;
	}
	c.timer_fd = timer_fd;

	sig_fd = setup_sig(epoll_fd);
	if (sig_fd < 0)
	{
		fprintf(stderr, "setup_sig失败\n");
		return EXIT_FAILURE;
	}
	c.sig_fd = sig_fd;

	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	ev.data.fd = c.sock_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c.sock_fd, &ev) == -1)
	{
		perror("epoll_ctl添加quic socket失败");
		return EXIT_FAILURE;
	}

	for (;;)
	{
		struct epoll_event events[MAX_EVENTS];
		int nfds;

		nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if (nfds < 0)
		{
			perror("epoll_wait发生错误");
			return EXIT_FAILURE;
		}

		for (int n = 0; n < nfds; n++)
		{
			if (events[n].data.fd == sig_fd)
			{
				if (handle_sig(&c) < 0)
					return EXIT_FAILURE;
			}
			if (events[n].data.fd == c.sock_fd)
			{
				if (events[n].events & EPOLLIN)
				{
					if (connection_read(&c) < -1)
					{
						fprintf(stderr, "connection_read错误\n");
						return EXIT_FAILURE;
					}
				}
				if (events[n].events & EPOLLOUT)
				{
					if (connection_write(&c) < -1)
					{
						fprintf(stderr, "connection_write错误\n");
						return EXIT_FAILURE;
					}
				}
			}
			if (events[n].data.fd == timer_fd)
			{
				if (handle_timer(&c) < 0)
					return EXIT_FAILURE;
			}
			if (events[n].data.fd == STDIN_FILENO)
			{
				if (handle_stdin(&c) < 0)
					return EXIT_FAILURE;
			}
		}
	}

	return EXIT_SUCCESS;
}
