/**
 * gcc -Wall -Wextra -pedantic -g -o client client.c -lssl -lcrypto
 * ./client localhost 4434 ../../tests/ssl_cert_with_chain.pem
 */
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int main(int argc, char *argv[])
{
	int exit_code = 0;
	int err = 0;

	if (argc < 3)
	{
		fprintf(stderr, "Usage: %s ip port cert_path\n", argv[0]);
		return -1;
	}

	const size_t BUF_SIZE = 16 * 1024;
	char *in_buf = malloc(BUF_SIZE);
	char *out_buf = malloc(BUF_SIZE);

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

	const char *trusted_cert_fname = argv[3];
	if (trusted_cert_fname)
		err = SSL_CTX_load_verify_locations(ctx, trusted_cert_fname, NULL);
	else
		err = SSL_CTX_set_default_verify_paths(ctx);
	if (err < 0)
		fprintf(stderr, "Could not load trusted certificates\n");

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	const char *hostname = argv[1];
	const char *port = argv[2];
	BIO *ssl_bio = BIO_new_ssl_connect(ctx);
	BIO_set_conn_hostname(ssl_bio, hostname);
	BIO_set_conn_port(ssl_bio, port);

	SSL *ssl = NULL;
	BIO_get_ssl(ssl_bio, &ssl);
	// 用于tls1.2中SNI匹配
	SSL_set_tlsext_host_name(ssl, hostname);
	// 使用此值与证书里面的host是否一致
	SSL_set1_host(ssl, hostname);

	err = BIO_do_connect(ssl_bio);
	if (err <= 0)
		fprintf(stderr, "Could not connect to server %s on port %s\n", hostname, port);

	snprintf(
		out_buf,
		BUF_SIZE,
		"GET / HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Connection: close\r\n"
		"User-Agent: Example TLS client\r\n"
		"\r\n",
		hostname);
	int request_length = strlen(out_buf);
	printf("*** Sending to the server:\n");
	printf("%s", out_buf);
	int nbytes_written = BIO_write(ssl_bio, out_buf, request_length);
	if (nbytes_written != request_length)
		fprintf(stderr, "Could not send all data to the server\n");
	printf("*** Sending to the server finished\n");
	printf("*** Receiving from the server:\n");
	while ((SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) != SSL_RECEIVED_SHUTDOWN)
	{
		int nbytes_read = BIO_read(ssl_bio, in_buf, BUF_SIZE);
		if (nbytes_read <= 0)
		{
			int ssl_error = SSL_get_error(ssl, nbytes_read);
			// if (ssl_error == SSL_ERROR_ZERO_RETURN)
			// break;
			fprintf(stderr, "Error %i while reading data from the server\n", ssl_error);
			ERR_print_errors_fp(stderr);
			break;
		}
		fwrite(in_buf, 1, nbytes_read, stdout);
	}
	printf("*** Receiving from the server finished\n");

	BIO_ssl_shutdown(ssl_bio);
	if (ssl_bio)
		BIO_free_all(ssl_bio);
	if (ctx)
		SSL_CTX_free(ctx);
	free(out_buf);
	free(in_buf);
	if (ERR_peek_error())
	{
		fprintf(stderr, "Errors from the OpenSSL error queue:\n");
		ERR_print_errors_fp(stderr);
		ERR_clear_error();
	}
	return exit_code;
}