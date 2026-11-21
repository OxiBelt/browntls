/* A one-connection mutual-authentication oracle for the Docker DTLS test. */
#define _POSIX_C_SOURCE 200809L
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

static const char request[] = "hello from browntls";
static const char reply[] = "sltnworb morf olleh";
static const char path[] = "/pki/ecdsa-p256/";
static const unsigned short pqc_groups[] = {
    WOLFSSL_X25519MLKEM768,
    WOLFSSL_SECP256R1MLKEM768,
    WOLFSSL_SECP384R1MLKEM1024,
};
static const char *const pqc_names[] = {
    "X25519MLKEM768", "secp256r1MLKEM768", "secp384r1MLKEM1024",
};

static void fail(const char *stage)
{
    fprintf(stderr, "%s\n", stage);
    exit(1);
}

static void check(WOLFSSL *ssl, int result, const char *stage)
{
    if (result == WOLFSSL_SUCCESS)
        return;
    fprintf(stderr, "%s: wolfSSL error %d\n", stage,
            wolfSSL_get_error(ssl, result));
    exit(1);
}

static int peer_socket(WOLFSSL *ssl, int server, const char *host, const char *port)
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
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
        fail("cannot set receive timeout");
    check(ssl, wolfSSL_set_fd(ssl, fd), "set DTLS socket");

    if (server) {
        if (bind(fd, addresses->ai_addr, addresses->ai_addrlen) != 0)
            fail("cannot bind UDP socket");
        puts("listening");
        fflush(stdout);
        char byte;
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        if (recvfrom(fd, &byte, sizeof(byte), MSG_PEEK,
                     (struct sockaddr *)&peer, &peer_len) <= 0)
            fail("waiting for DTLS client");
        check(ssl, wolfSSL_dtls_set_peer(ssl, &peer, peer_len), "set client address");
    } else {
        check(ssl, wolfSSL_dtls_set_peer(ssl, addresses->ai_addr, addresses->ai_addrlen),
              "set server address");
        check(ssl, wolfSSL_check_domain_name(ssl, host), "set certificate DNS name");
    }
    freeaddrinfo(addresses);
    return fd;
}

static void send_data(WOLFSSL *ssl, const char *data)
{
    int len = (int)strlen(data);
    if (wolfSSL_write(ssl, data, len) != len)
        fail("failed to send authenticated DTLS data");
}

static void expect_data(WOLFSSL *ssl, const char *expected)
{
    char data[1200];
    int len = wolfSSL_read(ssl, data, sizeof(data));
    if (len <= 0 || (size_t)len != strlen(expected) || memcmp(data, expected, (size_t)len))
        fail("unexpected authenticated DTLS data");
}

static void expect_close(WOLFSSL *ssl)
{
    char byte;
    int result = wolfSSL_read(ssl, &byte, sizeof(byte));
    if (wolfSSL_get_error(ssl, result) != WOLFSSL_ERROR_ZERO_RETURN)
        fail("expected authenticated close_notify");
}

static void send_close(WOLFSSL *ssl)
{
    int result = wolfSSL_shutdown(ssl);
    if (result != WOLFSSL_SUCCESS && result != WOLFSSL_SHUTDOWN_NOT_DONE)
        check(ssl, result, "send close_notify");
}

int main(int argc, char **argv)
{
    const char *cid_version = NULL;
    const char *pqc_group = NULL;
    if (argc < 4 || (strcmp(argv[1], "server") && strcmp(argv[1], "client")))
        fail("usage: wolfssl-dtls server|client HOST PORT [--cid 1.2|1.3] [--group NAME]");
    for (int i = 4; i < argc; i += 2) {
        if (i + 1 >= argc)
            fail("missing option value");
        if (strcmp(argv[i], "--cid") == 0 && cid_version == NULL &&
            (strcmp(argv[i + 1], "1.2") == 0 || strcmp(argv[i + 1], "1.3") == 0))
            cid_version = argv[i + 1];
        else if (strcmp(argv[i], "--group") == 0 && pqc_group == NULL)
            pqc_group = argv[i + 1];
        else
            fail("usage: wolfssl-dtls server|client HOST PORT [--cid 1.2|1.3] [--group NAME]");
    }
    if (cid_version != NULL && pqc_group != NULL)
        fail("CID and RFC 10024 groups are separate DTLS cases");
    int server = strcmp(argv[1], "server") == 0;
    int cid = cid_version != NULL;
    int v12 = cid && strcmp(cid_version, "1.2") == 0;
    unsigned short group = 0;
    if (pqc_group != NULL) {
        for (size_t i = 0; i < sizeof(pqc_names) / sizeof(pqc_names[0]); ++i) {
            if (strcmp(pqc_group, pqc_names[i]) == 0)
                group = pqc_groups[i];
        }
        if (group == 0)
            fail("unsupported RFC 10024 group");
    }
    char file[sizeof(path) + 20];
    if (wolfSSL_Init() != WOLFSSL_SUCCESS)
        fail("initialize wolfSSL");
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(v12 ?
        (server ? wolfDTLSv1_2_server_method() : wolfDTLSv1_2_client_method()) :
        (server ? wolfDTLSv1_3_server_method() : wolfDTLSv1_3_client_method()));
    if (ctx == NULL)
        fail("create DTLS context");
    snprintf(file, sizeof(file), "%sca.pem", path);
    if (wolfSSL_CTX_load_verify_locations(ctx, file, NULL) != WOLFSSL_SUCCESS)
        fail("load test CA");
    snprintf(file, sizeof(file), "%s%s.pem", path, argv[1]);
    if (wolfSSL_CTX_use_certificate_file(ctx, file, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        fail("load test certificate");
    snprintf(file, sizeof(file), "%s%s.key", path, argv[1]);
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, file, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        fail("load test key");
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
                          (server ? WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), NULL);

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        fail("allocate DTLS connection");
    if (v12)
        check(ssl, wolfSSL_UseSecureRenegotiation(ssl), "enable RFC 5746 indication");
    if (cid) {
        unsigned char local_cid[] = {0x11, 0x23, 0x35, 0x47, 0x59, 0x6b, 0x7d, 0x8f};
        check(ssl, wolfSSL_dtls_cid_use(ssl), "enable CID");
        check(ssl, wolfSSL_dtls_cid_set(ssl, local_cid, sizeof(local_cid)), "set CID");
    }
    if (pqc_group != NULL) {
        check(ssl, wolfSSL_UseSupportedCurve(ssl, group), "restrict RFC 10024 group");
        if (!server)
            check(ssl, wolfSSL_NoKeyShares(ssl), "send a small initial ClientHello");
    }
    int fd = peer_socket(ssl, server, argv[2], argv[3]);
    /* Match browntls's DTLS datagram budget in both directions. */
    if (pqc_group != NULL)
        check(ssl, wolfSSL_dtls_set_mtu(ssl, 1200), "set DTLS MTU");
    check(ssl, server ? wolfSSL_accept(ssl) : wolfSSL_connect(ssl), "DTLS handshake");
    if (strcmp(wolfSSL_get_version(ssl), v12 ? "DTLSv1.2" : "DTLSv1.3") != 0)
        fail("negotiated unexpected version");
    if (pqc_group != NULL) {
        WOLFSSL_X509 *cert = wolfSSL_get_peer_certificate(ssl);
        if (cert == NULL || wolfSSL_get_verify_result(ssl) != 0 ||
            wolfSSL_session_reused(ssl))
            fail("expected verified peer certificate and full RFC 10024 handshake");
        wolfSSL_X509_free(cert);
    }
    if (cid) {
        unsigned int rx = 0, tx = 0;
        WOLFSSL_X509 *cert = wolfSSL_get_peer_certificate(ssl);
        if (cert == NULL || wolfSSL_get_verify_result(ssl) != 0 ||
            wolfSSL_session_reused(ssl))
            fail("expected verified peer certificate and full handshake");
        wolfSSL_X509_free(cert);
        if (!wolfSSL_dtls_cid_is_enabled(ssl) ||
            wolfSSL_dtls_cid_get_rx_size(ssl, &rx) != WOLFSSL_SUCCESS ||
            wolfSSL_dtls_cid_get_tx_size(ssl, &tx) != WOLFSSL_SUCCESS ||
            rx == 0 || tx == 0)
            fail("expected negotiated nonempty CIDs in both directions");
    }
    if (server) {
        expect_data(ssl, request);
        send_data(ssl, reply);
        send_close(ssl);
        expect_close(ssl);
    } else {
        send_data(ssl, request);
        expect_data(ssl, reply);
        expect_close(ssl);
        send_close(ssl);
    }
    if (pqc_group != NULL)
        printf("verified DTLSv1.3, %s, mTLS, full handshake, payloads and close_notify\n",
               pqc_group);
    else if (cid)
        printf("verified DTLSv1.%s, bidirectional CID, mTLS, full handshake, payloads and close_notify\n",
               v12 ? "2" : "3");
    else
        puts("verified DTLSv1.3, payloads and close_notify");
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    close(fd);
    return 0;
}
