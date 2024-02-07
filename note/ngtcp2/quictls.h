#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

SSL_CTX *ssl_ctx_new(const char *cafile, int is_client)
{
    int err;
    SSL_CTX *ssl_ctx;
    SSL_METHOD *method;
    int verify_mode;

    method = is_client ? TLS_client_method() : TLS_server_method();
    ssl_ctx = SSL_CTX_new(method);
    if (!ssl_ctx)
    {
        fprintf(stderr, "SSL_CTX_new: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }
    if (cafile)
        err = SSL_CTX_load_verify_locations(ssl_ctx, cafile, NULL);
    else
        SSL_CTX_set_default_verify_paths(ssl_ctx);
    if (err == 0)
    {
        fprintf(stderr, "Could not load trusted certificates: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    verify_mode = is_client ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT : SSL_VERIFY_NONE;

    SSL_CTX_set_verify(ssl_ctx, verify_mode, NULL);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

    if (ngtcp2_crypto_quictls_configure_client_context(ssl_ctx) != 0)
    {
        fprintf(stderr, "ngtcp2_crypto_quictls_configure_client_context failed\n");
        goto fail;
    }

    return ssl_ctx;
fail:
    if (ssl_ctx)
        SSL_CTX_free(ssl_ctx);
    return NULL;
}

SSL *ssl_new(SSL_CTX *ctx, const char *hostname)
{
    int err;
    SSL *ssl;

    ssl = SSL_new(ctx);
    if (!ssl)
    {
        fprintf(stderr, "SSL_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    // TODO handle error
    SSL_set_tlsext_host_name(ssl, hostname); // SNI
    err = SSL_set1_host(ssl, hostname);      // cert hostname
    if (err != 1)
    {
        fprintf(stderr, "SSL_set1_host失败\n");
        goto fail;
    }

    return ssl;
fail:
    if (ssl)
        SSL_free(ssl);
    return NULL;
}

void setup_quictls_for_quic(SSL *ssl, ngtcp2_conn *conn, ngtcp2_crypto_conn_ref *ref)
{
    SSL_set_app_data(ssl, ref);

    /* For NGTCP2_PROTO_VER_V1 */
    SSL_set_quic_transport_version(ssl, TLSEXT_TYPE_quic_transport_parameters);
}