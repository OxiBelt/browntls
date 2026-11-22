/* One TLS 1.3 server using the pinned BoringSSL delegated-credential API. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pool.h>
#include <openssl/ssl.h>

static const char request[] = "BoringSSL delegated credential interoperability";

static void fail(const char *stage)
{
    fprintf(stderr, "%s (BoringSSL error 0x%x)\n", stage,
            (unsigned)ERR_peek_last_error());
    exit(EXIT_FAILURE);
}

static unsigned char *read_file(const char *path, size_t *len)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0)
        fail("open input file");
    long size = ftell(file);
    if (size <= 0 || fseek(file, 0, SEEK_SET) != 0)
        fail("size input file");
    unsigned char *data = malloc((size_t)size);
    if (data == NULL || fread(data, 1, (size_t)size, file) != (size_t)size)
        fail("read input file");
    fclose(file);
    *len = (size_t)size;
    return data;
}

static void serve(const char *cert_path, const char *dc_path, const char *key_path)
{
    size_t cert_len, dc_len;
    unsigned char *cert_der = read_file(cert_path, &cert_len);
    unsigned char *dc_der = read_file(dc_path, &dc_len);
    CRYPTO_BUFFER *cert = CRYPTO_BUFFER_new(cert_der, cert_len, NULL);
    CRYPTO_BUFFER *dc = CRYPTO_BUFFER_new(dc_der, dc_len, NULL);
    free(cert_der);
    free(dc_der);
    BIO *key_file = BIO_new_file(key_path, "r");
    EVP_PKEY *key = key_file == NULL ? NULL : PEM_read_bio_PrivateKey(key_file, NULL, NULL, NULL);
    BIO_free(key_file);
    if (cert == NULL || dc == NULL || key == NULL)
        fail("load delegated credential inputs");

    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL_CREDENTIAL *credential = SSL_CREDENTIAL_new_delegated();
    if (ctx == NULL || credential == NULL ||
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_num_tickets(ctx, 0) != 1 ||
        SSL_CREDENTIAL_set1_cert_chain(credential, &cert, 1) != 1 ||
        SSL_CREDENTIAL_set1_delegated_credential(credential, dc) != 1 ||
        SSL_CREDENTIAL_set1_private_key(credential, key) != 1 ||
        SSL_CREDENTIAL_is_complete(credential) != 1 ||
        SSL_CTX_add1_credential(ctx, credential) != 1)
        fail("configure BoringSSL delegated credential");
    SSL_CREDENTIAL_free(credential);
    CRYPTO_BUFFER_free(cert);
    CRYPTO_BUFFER_free(dc);
    EVP_PKEY_free(key);

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(4433),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0)
        fail("listen on TCP socket");
    puts("listening");
    fflush(stdout);
    int accepted = accept(listener, NULL, NULL);
    close(listener);
    if (accepted < 0)
        fail("accept TCP socket");
    BIO *connection = BIO_new_socket(accepted, BIO_CLOSE);
    if (connection == NULL)
        fail("detach accepted TCP socket");

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
        fail("create TLS connection");
    SSL_set_bio(ssl, connection, connection);
    if (SSL_accept(ssl) != 1)
        fail("TLS 1.3 handshake");

    char line[256];
    size_t used = 0;
    while (used < sizeof(line) - 1) {
        int n = SSL_read(ssl, line + used, (int)(sizeof(line) - 1 - used));
        if (n <= 0)
            fail("read application data");
        used += (size_t)n;
        if (memchr(line, '\n', used) != NULL)
            break;
    }
    if (used == sizeof(line) - 1 || line[used - 1] != '\n' ||
        used != sizeof(request) || memcmp(line, request, sizeof(request) - 1) != 0)
        fail("unexpected application data");
    for (size_t i = 0; i < used - 1; i++)
        line[i] = request[used - 2 - i];
    line[used - 1] = '\n';
    if (SSL_write(ssl, line, (int)used) != (int)used || SSL_shutdown(ssl) < 0)
        fail("write application reply");

    puts("accepted TLS 1.3 delegated credential and data");
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

int main(int argc, char **argv)
{
    if (argc != 4)
        fail("usage: boringssl-dc-server CERT_DER CREDENTIAL_DER PRIVATE_KEY_PEM");
    alarm(50);
    serve(argv[1], argv[2], argv[3]);
    return EXIT_SUCCESS;
}
