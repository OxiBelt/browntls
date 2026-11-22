#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define PORT "4433"
#define CERT_DIR "/pki/ecdsa-p256/"

struct wire_state { int sent_zstd; int received_zstd; };

static void fail(const char *where)
{
    fprintf(stderr, "%s\n", where);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static void message_callback(int write_p, int version, int content_type,
                             const void *buffer, size_t length, SSL *ssl,
                             void *argument)
{
    (void)version;
    (void)ssl;
    if (content_type != SSL3_RT_HANDSHAKE || length < 6)
        return;
    const unsigned char *message = buffer;
    if (message[0] != SSL3_MT_COMPRESSED_CERTIFICATE)
        return;
    unsigned int algorithm = ((unsigned int)message[4] << 8) | message[5];
    struct wire_state *wire = argument;
    if (algorithm == TLSEXT_comp_cert_zstd) {
        if (write_p)
            wire->sent_zstd++;
        else
            wire->received_zstd++;
    }
}

static int socket_for(int server, const char *host)
{
    struct addrinfo hints = {0};
    struct addrinfo *addresses = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = server ? AI_PASSIVE : 0;
    if (getaddrinfo(server ? NULL : host, PORT, &hints, &addresses) != 0)
        fail("resolve endpoint");
    int fd = socket(addresses->ai_family, addresses->ai_socktype, 0);
    if (fd < 0)
        fail("create socket");
    struct timeval timeout = {.tv_sec = 20};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
        fail("set socket timeout");
    if (server) {
        int reuse = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
            bind(fd, addresses->ai_addr, addresses->ai_addrlen) != 0 || listen(fd, 1) != 0)
            fail("listen");
        puts("listening");
        fflush(stdout);
        int accepted = accept(fd, NULL, NULL);
        if (accepted < 0)
            fail("accept");
        close(fd);
        fd = accepted;
    } else if (connect(fd, addresses->ai_addr, addresses->ai_addrlen) != 0) {
        fail("connect");
    }
    freeaddrinfo(addresses);
    return fd;
}

static void write_all(SSL *ssl, const char *message)
{
    char line[128];
    int length = snprintf(line, sizeof(line), "%s\n", message);
    if (length < 0 || (size_t)length >= sizeof(line))
        fail("format application data");
    size_t written = 0;
    if (SSL_write_ex(ssl, line, (size_t)length, &written) != 1 ||
        written != (size_t)length)
        fail("write application data");
}

static void expect(SSL *ssl, const char *expected)
{
    char data[128];
    size_t length = strlen(expected);
    size_t offset = 0;
    if (length >= sizeof(data))
        fail("application fixture too long");
    while (offset <= length) {
        size_t received = 0;
        if (SSL_read_ex(ssl, data + offset, length + 1 - offset, &received) != 1 ||
            received == 0)
            fail("read application data");
        offset += received;
    }
    if (memcmp(data, expected, length) != 0 || data[length] != '\n')
        fail("verify application data");
}

int main(int argc, char **argv)
{
    if (argc != 4 || (strcmp(argv[1], "server") && strcmp(argv[1], "client")))
        fail("usage: openssl-zstd server|client HOST MESSAGE");
    if (OPENSSL_version_major() != 4 || COMP_zstd_oneshot() == NULL)
        fail("requires the OpenSSL 4 Zstandard peer");
    int server = strcmp(argv[1], "server") == 0;
    const char *request = argv[3];
    char reply[128];
    size_t length = strlen(request);
    if (length >= sizeof(reply) - 1)
        fail("application fixture too long");
    for (size_t i = 0; i < length; i++)
        reply[i] = request[length - i - 1];
    reply[length] = '\0';
    SSL_CTX *ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (ctx == NULL || SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1)
        fail("create TLS 1.3 context");
    int preference[] = {TLSEXT_comp_cert_zstd};
    if (SSL_CTX_set1_cert_comp_preference(ctx, preference, 1) != 1)
        fail("restrict certificate compression to Zstandard");

    char file[128];
    snprintf(file, sizeof(file), "%sca.pem", CERT_DIR);
    if (SSL_CTX_load_verify_locations(ctx, file, NULL) != 1)
        fail("load CA");
    snprintf(file, sizeof(file), "%s%s.pem", CERT_DIR, server ? "server" : "client");
    if (SSL_CTX_use_certificate_chain_file(ctx, file) != 1)
        fail("load certificate");
    snprintf(file, sizeof(file), "%s%s.key", CERT_DIR, server ? "server" : "client");
    if (SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1)
        fail("load private key");
    if (server && SSL_CTX_compress_certs(ctx, TLSEXT_comp_cert_zstd) != 1)
        fail("pre-compress server certificate with Zstandard");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER |
                       (server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), NULL);

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
        fail("create TLS connection");
    struct wire_state wire = {0};
    SSL_set_msg_callback(ssl, message_callback);
    SSL_set_msg_callback_arg(ssl, &wire);
    if (!server && (SSL_set_tlsext_host_name(ssl, "tls-server") != 1 ||
                    SSL_set1_dnsname(ssl, "tls-server") != 1))
        fail("set client server name and verification name");
    int fd = socket_for(server, argv[2]);
    SSL_set_fd(ssl, fd);
    if ((server ? SSL_accept(ssl) : SSL_connect(ssl)) != 1)
        fail("TLS handshake");
    if (SSL_version(ssl) != TLS1_3_VERSION || SSL_get_verify_result(ssl) != X509_V_OK ||
        SSL_get0_peer_certificate(ssl) == NULL)
        fail("TLS 1.3 mutual certificate authentication failed");

    if (server) {
        expect(ssl, request);
        write_all(ssl, reply);
    } else {
        write_all(ssl, request);
        expect(ssl, reply);
    }
    printf("{\"event\":\"wire\",\"role\":\"%s\",\"sent_zstd\":%d,"
           "\"received_zstd\":%d,\"mutual_auth\":true,\"data\":true}\n",
           server ? "server" : "client", wire.sent_zstd, wire.received_zstd);
    int shutdown = SSL_shutdown(ssl);
    if (shutdown == 0)
        shutdown = SSL_shutdown(ssl);
    if (shutdown != 1)
        fail("complete bidirectional close_notify");
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return 0;
}
