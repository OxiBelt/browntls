/* One bounded TLS 1.3 exchange using upstream OpenSSL's RFC 9934 loader. */
#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ech.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

static const char request[] = "hello from browntls\n";
static const char reply[] = "sltnworb morf olleh\n";

static void fail(const char *stage)
{
    fprintf(stderr, "%s (OpenSSL error 0x%lx)\n", stage, ERR_peek_last_error());
    exit(EXIT_FAILURE);
}

static void load_ech(SSL_CTX *ctx, const char *path, int server)
{
    BIO *input = BIO_new_file(path, "r");
    OSSL_ECHSTORE *store = OSSL_ECHSTORE_new(NULL, NULL);
    int configs = 0, keys = 0;
    if (input == NULL || store == NULL ||
        OSSL_ECHSTORE_read_pem(store, input, OSSL_ECH_NO_RETRY) != 1 ||
        OSSL_ECHSTORE_num_entries(store, &configs) != 1 || configs != 1 ||
        OSSL_ECHSTORE_num_keys(store, &keys) != 1 || keys != server ||
        SSL_CTX_set1_echstore(ctx, store) != 1)
        fail("load RFC 9934 PEM");
    OSSL_ECHSTORE_free(store);
    BIO_free(input);
}

static BIO *tcp_connection(const char *endpoint, int server)
{
    if (!server) {
        BIO *connect = BIO_new_connect(endpoint);
        if (connect == NULL || BIO_do_connect(connect) <= 0)
            fail("connect TCP socket");
        return connect;
    }
    BIO *listener = BIO_new_accept(endpoint);
    if (listener == NULL || BIO_do_accept(listener) <= 0)
        fail("listen on TCP socket");
    puts("listening");
    fflush(stdout);
    if (BIO_do_accept(listener) <= 0)
        fail("accept TCP socket");
    BIO *connection = BIO_pop(listener);
    BIO_free(listener);
    if (connection == NULL)
        fail("detach accepted TCP socket");
    return connection;
}

static void send_data(SSL *ssl, const char *data)
{
    size_t written = 0, len = strlen(data);
    if (SSL_write_ex(ssl, data, len, &written) != 1 || written != len)
        fail("write TLS application data");
}

static void expect_data(SSL *ssl, const char *expected)
{
    char data[64];
    size_t len = 0, read;
    while (len < strlen(expected)) {
        if (SSL_read_ex(ssl, data + len, sizeof(data) - len, &read) != 1 || read == 0)
            fail("read TLS application data");
        len += read;
    }
    if (len != strlen(expected) || memcmp(data, expected, len) != 0)
        fail("unexpected TLS application data");
}

int main(int argc, char **argv)
{
    int server = argc > 1 && strcmp(argv[1], "server") == 0;
    if ((server && argc != 7) ||
        (!server && (argc != 6 || strcmp(argv[1], "client") != 0)))
        fail("usage: openssl-ech server ENDPOINT INNER ECH_PEM CERT KEY\n"
             "       openssl-ech client ENDPOINT INNER ECH_PEM CA");
    if (OPENSSL_version_major() != 4 || OPENSSL_version_minor() != 0 ||
        OPENSSL_version_patch() != 3)
        fail("expected OpenSSL 4.0.3");
    alarm(45);
    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL || SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set1_groups_list(ctx, "X25519") != 1 ||
        SSL_CTX_set_num_tickets(ctx, 0) != 1)
        fail("configure TLS 1.3 context");
    load_ech(ctx, argv[4], server);
    if (server) {
        if (SSL_CTX_use_certificate_chain_file(ctx, argv[5]) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, argv[6], SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx) != 1)
            fail("load inner-name TLS certificate and key");
    } else {
        if (SSL_CTX_load_verify_locations(ctx, argv[5], NULL) != 1)
            fail("load fixture CA");
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
        fail("create TLS connection");
    if (!server && (SSL_set1_dnsname(ssl, argv[3]) != 1 ||
                    SSL_ech_set1_server_names(ssl, argv[3], NULL, 0) != 1))
        fail("configure inner SNI and certificate name verification");
    BIO *connection = tcp_connection(argv[2], server);
    SSL_set_bio(ssl, connection, connection);
    if ((server ? SSL_accept(ssl) : SSL_connect(ssl)) != 1)
        fail("TLS handshake");
    if (!server && (SSL_get0_peer_certificate(ssl) == NULL ||
                    SSL_get_verify_result(ssl) != X509_V_OK))
        fail("server certificate verification");
    char *inner = NULL, *outer = NULL;
    int status = SSL_ech_get1_status(ssl, &inner, &outer);
    OPENSSL_free(inner);
    OPENSSL_free(outer);
    if (status != SSL_ECH_STATUS_SUCCESS)
        fail("ECH was not accepted");
    if (server) {
        const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (name == NULL || strcmp(name, argv[3]) != 0)
            fail("unexpected inner SNI");
        expect_data(ssl, request);
        send_data(ssl, reply);
    } else {
        send_data(ssl, request);
        expect_data(ssl, reply);
    }
    if (SSL_shutdown(ssl) < 0)
        fail("send close_notify");
    puts(server ? "accepted TLSv1.3, inner SNI and data verified" :
                  "accepted TLSv1.3, server certificate and data verified");
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return EXIT_SUCCESS;
}
