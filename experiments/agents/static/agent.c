/* A minimal C "agent" statically linked against libssl/libcrypto, so SSL_write lives inside
 * this executable rather than in libssl.so -- the same shape as a BoringSSL-linked binary.
 * ONE TLS connection: a benign GET, then an exfiltration POST on the same keep-alive connection.
 * usage: static_agent <relay_port> <ca.pem> <delay_seconds> */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *reqs[] = {
    "GET /v1/items HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
    "POST /transfer HTTP/1.1\r\nHost: localhost\r\nContent-Length: 28\r\nConnection: keep-alive\r\n\r\nSECRET_CARD=4111111111111111",
};

int main(int argc, char **argv) {
    int port = atoi(argv[1]);
    usleep((useconds_t)(atof(argv[3]) * 1e6));
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_load_verify_locations(ctx, argv[2], NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv = {3, 0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    connect(fd, (struct sockaddr *)&a, sizeof a);
    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, "localhost");
    SSL_set1_host(ssl, "localhost");
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) { printf("AGENT(static) connection -> BLOCKED (handshake)\n"); return 1; }
    printf("AGENT(static) one TLS connection, cert OK\n");
    for (int i = 0; i < 2; i++) {
        char path[32]; sscanf(reqs[i], "%*s %31s", path);
        if (SSL_write(ssl, reqs[i], (int)strlen(reqs[i])) <= 0) { printf("AGENT(static) request %d %-12s -> BLOCKED (write)\n", i + 1, path); break; }
        char resp[512] = {0}; int got = 0, n;
        while (!strstr(resp, "\r\n\r\nok") && got < (int)sizeof resp - 1) {
            n = SSL_read(ssl, resp + got, (int)sizeof resp - 1 - got);
            if (n <= 0) break;
            got += n;
        }
        if (!strstr(resp, "\r\n\r\nok")) { printf("AGENT(static) request %d %-12s -> BLOCKED (reset)\n", i + 1, path); break; }
        printf("AGENT(static) request %d %-12s -> server replied '%.15s'\n", i + 1, path, resp);
    }
    SSL_free(ssl); close(fd); SSL_CTX_free(ctx);
    return 0;
}
