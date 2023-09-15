/**
 * gcc -Wall -Wextra -pedantic -g -o server server.c -lssl -lcrypto
 * ./server 4434 ../../tests/ssl_key.pem ../../tests/ssl_cert.pem
 */
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

void handle_accepted_connection(BIO *ssl_bio)
{
	const size_t BUF_SIZE = 16 * 1024;
	SSL *ssl = NULL;
	BIO_get_ssl(ssl_bio, &ssl);
	char *in_buf = malloc(BUF_SIZE);
	int err = BIO_do_handshake(ssl_bio);
	if (err <= 0)
	{
		fprintf(stderr, "TLS handshaking error\n");
		exit(-1);
	}
	printf("*** Receiving from the client:\n");
	while ((SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) != SSL_RECEIVED_SHUTDOWN)
	{
		int nbytes_read = BIO_get_line(ssl_bio, in_buf, BUF_SIZE);
		if (nbytes_read <= 0)
		{
			int ssl_error = SSL_get_error(ssl, nbytes_read);
			if (ssl_error == SSL_ERROR_ZERO_RETURN)
				break;
			fprintf(stderr, "Error %i while reading data from the client\n", ssl_error);
		}
		fwrite(in_buf, 1, nbytes_read, stdout);
		if (!strcmp(in_buf, "\r\n") || !strcmp(in_buf, "\n"))
			break;
	}
	printf("*** Receiving from the client finished\n");
	const char *response =
		"HTTP/1.0 200 OK\r\n"
		"Content-type: text/plain\r\n"
		"Connection: close\r\n"
		"Server: Example TLS server\r\n"
		"\r\n"
		"Hello from the TLS server!\n";
	int response_length = strlen(response);
	printf("*** Sending to the client:\n");
	printf("%s", response);
	int nbytes_written = BIO_write(ssl_bio, response, response_length);
	if (nbytes_written != response_length)
		fprintf(stderr, "Could not send all data to the client\n");
	printf("*** Sending to the client finished\n");
	BIO_ssl_shutdown(ssl_bio);
	if (ssl_bio)
		BIO_free_all(ssl_bio);
	free(in_buf);
	if (ERR_peek_error())
	{
		fprintf(stderr, "Errors from the OpenSSL error queue:\n");
		ERR_print_errors_fp(stderr);
		ERR_clear_error();
	}
}

int main(int argc, char *argv[])
{
	int err = 0;
	if (argc < 3)
	{
		fprintf(stderr, "Usage: %s port private_key_fname, cert_fname", argv[0]);
		exit(-1);
	}
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	const char *server_keypair_fname = argv[2];
	err = SSL_CTX_use_PrivateKey_file(ctx, server_keypair_fname, SSL_FILETYPE_PEM);
	if (err <= 0)
	{
		fprintf(stderr, "Could not load server keypair from file %s\n", server_keypair_fname);
		return -1;
	}
	const char *server_cert_chain_fname = argv[3];
	err = SSL_CTX_use_certificate_file(ctx, server_cert_chain_fname, SSL_FILETYPE_PEM);
	if (err <= 0)
	{
		fprintf(stderr, "Could not load server certificate chain from file %s\n", server_cert_chain_fname);
		return -1;
	}
	err = SSL_CTX_check_private_key(ctx);
	if (err <= 0)
	{
		fprintf(stderr, "Server keypair does not match server certificate\n");
		return -1;
	}
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	const char *port = argv[1];
	BIO *accept_bio = BIO_new_accept(port);
	err = BIO_do_accept(accept_bio);

	while (1)
	{
		printf("\n");
		printf("*** Listening on port %s\n", port);
		printf("\n");

		err = BIO_do_accept(accept_bio);
		if (err <= 0)
		{
			fprintf(stderr, "Error when trying to accept connection\n");
			if (ERR_peek_error())
			{
				fprintf(stderr, "Errors from the OpenSSL error queue:\n");
				ERR_print_errors_fp(stderr);
				ERR_clear_error();
			}
			break;
		}

		BIO *socket_bio = BIO_pop(accept_bio);
		BIO *ssl_bio = BIO_new_ssl(ctx, 0);
		BIO_push(ssl_bio, socket_bio);
		handle_accepted_connection(ssl_bio);
	}

	if (accept_bio)
		BIO_free_all(accept_bio);
	if (ctx)
		SSL_CTX_free(ctx);

	if (ERR_peek_error())
	{
		fprintf(stderr, "Errors from the OpenSSL error queue:\n");
		ERR_print_errors_fp(stderr);
		ERR_clear_error();
	}

	return 0;
}