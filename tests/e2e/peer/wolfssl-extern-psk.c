/* RFC 9973 independent TLS/DTLS 1.3 peer for the e2e harness. */
#define _POSIX_C_SOURCE 200809L
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define IDENTITY "browntls-e2e-rfc9973"
#define MAX_PSK 64

static unsigned char psk[MAX_PSK];
static unsigned int psk_len;

static void fail(const char *what)
{
    perror(what);
    exit(1);
}

static void check(int ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "%s failed\n", what);
        exit(1);
    }
}

static void load_psk(const char *path)
{
    FILE *file = fopen(path, "rb");
    check(file != NULL, "open PSK file");
    psk_len = (unsigned int)fread(psk, 1, sizeof(psk), file);
    check(!ferror(file) && feof(file), "read bounded PSK file");
    check(fclose(file) == 0, "close PSK file");
    check(psk_len >= 16, "PSK length");
}

static unsigned int client_psk(WOLFSSL *ssl, const char *hint, char *identity,
                               unsigned int identity_max, unsigned char *key,
                               unsigned int key_max, const char **cipher)
{
    size_t identity_len = sizeof(IDENTITY) - 1;
    (void)ssl;
    (void)hint;
    if (identity_len + 1 > identity_max || psk_len > key_max)
        return 0;
    memcpy(identity, IDENTITY, identity_len + 1);
    memcpy(key, psk, psk_len);
    *cipher = wolfSSL_get_cipher_name_by_hash(ssl, "SHA256");
    return psk_len;
}

static unsigned int server_psk(WOLFSSL *ssl, const char *identity,
                               unsigned char *key, unsigned int key_max,
                               const char **cipher)
{
    (void)ssl;
    if (identity == NULL || strcmp(identity, IDENTITY) != 0 || psk_len > key_max)
        return 0;
    memcpy(key, psk, psk_len);
    *cipher = wolfSSL_get_cipher_name_by_hash(ssl, "SHA256");
    return psk_len;
}

static int endpoint(int server, int udp, const char *host, const char *port)
{
    struct addrinfo hints, *addresses, *address;
    int fd = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_flags = server ? AI_PASSIVE : 0;
    check(getaddrinfo(host, port, &hints, &addresses) == 0, "resolve endpoint");
    for (address = addresses; address != NULL; address = address->ai_next) {
        fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0)
            continue;
        if (server) {
            int one = 1;
            (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            if (bind(fd, address->ai_addr, address->ai_addrlen) == 0 &&
                (udp || listen(fd, 1) == 0)) {
                puts("listening");
                fflush(stdout);
                break;
            }
        } else if (connect(fd, address->ai_addr, address->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    check(fd >= 0, "open endpoint socket");
    if (server && !udp) {
        int peer = accept(fd, NULL, NULL);
        if (peer < 0)
            fail("accept");
        close(fd);
        fd = peer;
    }
    if (server && udp) {
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        unsigned char first_packet[2048];
        check(recvfrom(fd, first_packet, sizeof(first_packet), MSG_PEEK,
                       (struct sockaddr *)&peer, &peer_len) > 0,
              "wait for DTLS ClientHello");
        check(connect(fd, (struct sockaddr *)&peer, peer_len) == 0,
              "connect DTLS peer");
    }
    return fd;
}

static void exchange(WOLFSSL *ssl, int server, int udp)
{
    const char *request = "RFC 9973 external PSK interoperability";
    char line[256], reply[256], expected[256], request_line[256];
    int n, payload_len, request_len, i;
    payload_len = (int)strlen(request);
    request_len = payload_len + (udp ? 0 : 1);
    memcpy(request_line, request, (size_t)payload_len);
    if (!udp)
        request_line[payload_len] = '\n';
    request_line[request_len] = '\0';
    for (i = 0; i < payload_len; ++i)
        expected[i] = request[payload_len - i - 1];
    if (!udp)
        expected[payload_len] = '\n';
    expected[request_len] = '\0';
    expected[payload_len + 1] = '\0';
    if (!server)
        check(wolfSSL_write(ssl, request_line, request_len) == request_len,
              "write authenticated request");
    n = wolfSSL_read(ssl, line, (int)sizeof(line) - 1);
    check(n > 0, "read authenticated request");
    line[n] = '\0';
    if (!server) {
        check(n == request_len && strcmp(line, expected) == 0, "verify reply data");
    } else {
        check(n == request_len && memcmp(line, request_line, (size_t)request_len) == 0,
              "verify request data");
        for (i = 0; i < payload_len; ++i)
            reply[i] = line[payload_len - i - 1];
        if (!udp)
            reply[payload_len] = '\n';
        check(wolfSSL_write(ssl, reply, request_len) == request_len,
              "write authenticated reply");
    }
    check(wolfSSL_shutdown(ssl) >= 0, "send close_notify");
    puts("verified TLS 1.3 cert_with_extern_psk, certificate, payload and close_notify");
}

int main(int argc, char **argv)
{
    int server, udp, fd, ret;
    const char *role, *transport, *host, *port, *ca, *cert, *key, *psk_file;
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    WOLFSSL_METHOD *method;

    if (argc != 9) {
        fprintf(stderr, "usage: wolfssl-extern-psk server|client tcp|udp HOST PORT CA CERT KEY PSK_FILE\n");
        return 2;
    }
    role = argv[1];
    transport = argv[2];
    host = argv[3];
    port = argv[4];
    ca = argv[5];
    cert = argv[6];
    key = argv[7];
    psk_file = argv[8];
    server = strcmp(role, "server") == 0;
    udp = strcmp(transport, "udp") == 0;
    check(server || strcmp(role, "client") == 0, "role");
    check(udp || strcmp(transport, "tcp") == 0, "transport");
    load_psk(psk_file);
    check(wolfSSL_Init() == WOLFSSL_SUCCESS, "wolfSSL_Init");
    method = udp ? (server ? wolfDTLSv1_3_server_method() : wolfDTLSv1_3_client_method())
                 : (server ? wolfTLSv1_3_server_method() : wolfTLSv1_3_client_method());
    ctx = wolfSSL_CTX_new(method);
    check(ctx != NULL, "create TLS 1.3 context");
    wolfSSL_CTX_set_psk_client_tls13_callback(ctx, client_psk);
    wolfSSL_CTX_set_psk_server_tls13_callback(ctx, server_psk);
    check(wolfSSL_CTX_set_cert_with_extern_psk(ctx, 1) == WOLFSSL_SUCCESS,
          "enable certificate with external PSK");
    check(wolfSSL_CTX_require_psk(ctx) == 0, "require external PSK");
    if (server) {
        check(wolfSSL_CTX_use_certificate_file(ctx, cert, WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS,
              "load server certificate");
        check(wolfSSL_CTX_use_PrivateKey_file(ctx, key, WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS,
              "load server key");
    } else {
        check(wolfSSL_CTX_load_verify_locations(ctx, ca, NULL) == WOLFSSL_SUCCESS,
              "load certificate authority");
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    }
    fd = endpoint(server, udp, host, port);
    ssl = wolfSSL_new(ctx);
    check(ssl != NULL, "create TLS connection");
    check(wolfSSL_set_fd(ssl, fd) == WOLFSSL_SUCCESS, "set socket");
    check(wolfSSL_set_cert_with_extern_psk(ssl, 1) == WOLFSSL_SUCCESS,
          "enable connection certificate with external PSK");
    if (!server)
        check(wolfSSL_check_domain_name(ssl, host) == WOLFSSL_SUCCESS,
              "set certificate DNS name");
    ret = server ? wolfSSL_accept(ssl) : wolfSSL_connect(ssl);
    check(ret == WOLFSSL_SUCCESS, "TLS 1.3 handshake");
    check(wolfSSL_get_verify_result(ssl) == 0, "verify peer certificate");
    if (!server) {
        WOLFSSL_X509 *peer = wolfSSL_get_peer_certificate(ssl);
        check(peer != NULL, "require peer certificate");
        wolfSSL_X509_free(peer);
    }
    exchange(ssl, server, udp);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    close(fd);
    memset(psk, 0, sizeof(psk));
    return 0;
}
