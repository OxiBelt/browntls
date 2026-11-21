/* One full mTLS connection on the isolated Docker test network, not a service.
 * No browntls code is linked here. SSL owns the BIO; main owns its UDP fd.
 * The server selects one sender then connects the socket before BIO I/O.
 */
#define _POSIX_C_SOURCE 200809L
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

static const char request[] = "hello from browntls";
static const char reply[] = "sltnworb morf olleh";
static const char path[] = "/pki/ecdsa-p256/";

static void fail(const char *stage)
{
    fprintf(stderr, "%s\n", stage);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static void check(SSL *ssl, int result, const char *stage)
{
    if (result == 1)
        return;
    fprintf(stderr, "%s: OpenSSL error %d\n", stage, SSL_get_error(ssl, result));
    fail(stage);
}

static int peer_socket(SSL *ssl, int server, const char *host, const char *port)
{
    struct addrinfo hints = {0};
    struct addrinfo *addresses;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = server ? AI_PASSIVE : 0;
    if (getaddrinfo(server ? NULL : host, port, &hints, &addresses) != 0)
        fail("cannot resolve DTLS endpoint");

    int fd = socket(addresses->ai_family, addresses->ai_socktype, 0);
    if (fd < 0)
        fail("cannot open UDP socket");
    struct timeval timeout = { .tv_sec = 30 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
        fail("cannot set socket timeout");

    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    if (server) {
        if (bind(fd, addresses->ai_addr, addresses->ai_addrlen) != 0)
            fail("cannot bind UDP socket");
        puts("listening");
        fflush(stdout);
        char byte;
        /* Leave the first ClientHello queued for SSL_accept. */
        if (recvfrom(fd, &byte, sizeof(byte), MSG_PEEK,
                     (struct sockaddr *)&peer, &peer_len) <= 0)
            fail("waiting for DTLS client");
    } else {
        if (addresses->ai_addrlen > sizeof(peer))
            fail("unexpected UDP address length");
        memcpy(&peer, addresses->ai_addr, addresses->ai_addrlen);
        peer_len = addresses->ai_addrlen;
        if (SSL_set_tlsext_host_name(ssl, host) != 1 ||
            SSL_set1_host(ssl, host) != 1)
            fail("set certificate DNS name and SNI");
        SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    }
    freeaddrinfo(addresses);
    if (connect(fd, (struct sockaddr *)&peer, peer_len) != 0)
        fail("cannot connect UDP socket");
    BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (bio == NULL)
        fail("allocate datagram BIO");
    if (BIO_ctrl_set_connected(bio, &peer) <= 0)
        fail("set connected datagram BIO");
    SSL_set_bio(ssl, bio, bio);
    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
    if (SSL_set_mtu(ssl, 1200) <= 0)
        fail("set DTLS MTU");
    return fd;
}

static void send_data(SSL *ssl, const char *data)
{
    size_t written = 0;
    check(ssl, SSL_write_ex(ssl, data, strlen(data), &written), "write payload");
    if (written != strlen(data))
        fail("short authenticated DTLS write");
}

static void expect_data(SSL *ssl, const char *expected)
{
    char data[1200];
    size_t len = 0;
    check(ssl, SSL_read_ex(ssl, data, sizeof(data), &len), "read payload");
    if (len != strlen(expected) || memcmp(data, expected, len) != 0)
        fail("unexpected authenticated DTLS data");
}

static void expect_close(SSL *ssl)
{
    char byte;
    int result = SSL_read(ssl, &byte, sizeof(byte));
    if (SSL_get_error(ssl, result) != SSL_ERROR_ZERO_RETURN)
        fail("expected authenticated close_notify");
}

static void shutdown_peer(SSL *ssl, int server)
{
    /* Server sends first; client reads that alert before acknowledging it. */
    if (!server)
        expect_close(ssl);
    int result = SSL_shutdown(ssl);
    if (result < 0)
        check(ssl, result, "send close_notify");
    if (server)
        expect_close(ssl);
    check(ssl, SSL_shutdown(ssl), "complete bidirectional shutdown");
    int both = SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN;
    if ((SSL_get_shutdown(ssl) & both) != both)
        fail("missing close_notify in one direction");
}

int main(int argc, char **argv)
{
    if (argc != 4 || (strcmp(argv[1], "server") && strcmp(argv[1], "client")))
        fail("usage: openssl-dtls server|client HOST PORT");
    /* Bound the whole one-shot test in addition to individual socket I/O. */
    alarm(60);
    if (OPENSSL_version_major() != 3 || OPENSSL_version_minor() != 5)
        fail("this oracle requires OpenSSL 3.5.x");
    int server = strcmp(argv[1], "server") == 0;
    char file[sizeof(path) + 20];
    SSL_CTX *ctx = SSL_CTX_new(server ? DTLS_server_method() : DTLS_client_method());
    if (ctx == NULL)
        fail("create DTLS context");
    if (SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION) != 1 ||
        SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256") != 1 ||
        SSL_CTX_set1_groups_list(ctx, "P-256") != 1)
        fail("configure DTLS 1.2 ECDSA/GCM with P-256");
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    snprintf(file, sizeof(file), "%sca.pem", path);
    if (SSL_CTX_load_verify_locations(ctx, file, NULL) != 1)
        fail("load test CA");
    snprintf(file, sizeof(file), "%s%s.pem", path, argv[1]);
    if (SSL_CTX_use_certificate_chain_file(ctx, file) != 1)
        fail("load test certificate");
    snprintf(file, sizeof(file), "%s%s.key", path, argv[1]);
    if (SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1)
        fail("load matching test key");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER |
                       (server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), NULL);

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
        fail("allocate DTLS connection");
    int fd = peer_socket(ssl, server, argv[2], argv[3]);
    check(ssl, server ? SSL_accept(ssl) : SSL_connect(ssl), "DTLS handshake");
    if (SSL_version(ssl) != DTLS1_2_VERSION ||
        SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(ssl)) != 0xc02b ||
        SSL_get_extms_support(ssl) != 1 || SSL_session_reused(ssl) != 0 ||
        SSL_get_verify_result(ssl) != X509_V_OK || SSL_get0_peer_certificate(ssl) == NULL)
        fail("expected full verified mTLS DTLS 1.2 ECDSA/GCM handshake with EMS");
    if (server) {
        expect_data(ssl, request);
        send_data(ssl, reply);
    } else {
        send_data(ssl, request);
        expect_data(ssl, reply);
    }
    shutdown_peer(ssl, server);
    puts("verified DTLSv1.2, ECDHE-ECDSA-AES128-GCM-SHA256, EMS, mTLS, "
         "full handshake, payloads and close_notify");
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return 0;
}
