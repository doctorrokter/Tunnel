/*
 * dns_live - bt_lookup against a real DNS server over a real UDP socket: replies made by real
 * software (its compression, its CNAME chains), compared with what getaddrinfo says.
 *
 *   dns_live <server-ip> <name>...
 *
 * Exit 0 when every name resolved and each address set agrees with getaddrinfo's. Not a unit test:
 * it needs the network (build.sh live).
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "bt_resolve.h"

static int sock = -1;

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * BT_NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

static void send_up(void* ctx, const bt_addr* server, const uint8_t* q, size_t len)
{
    struct sockaddr_in sin;
    (void)ctx;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(BT_DNS_PORT);
    memcpy(&sin.sin_addr, server->addr, 4);
    sendto(sock, q, len, 0, (struct sockaddr*)&sin, sizeof(sin));
}

/* Does getaddrinfo know this address for the name? */
static int system_knows(const char* name, const bt_addr* a)
{
    struct addrinfo hints, *res, *p;
    int found = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = a->family == 4 ? AF_INET : AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(name, NULL, &hints, &res) != 0) return 0;
    for (p = res; p; p = p->ai_next) {
        if (a->family == 4 && memcmp(&((struct sockaddr_in*)p->ai_addr)->sin_addr, a->addr, 4) == 0) found = 1;
        if (a->family == 6 && memcmp(&((struct sockaddr_in6*)p->ai_addr)->sin6_addr, a->addr, 16) == 0) found = 1;
    }
    freeaddrinfo(res);
    return found;
}

static int one(const bt_addr* server, const char* name)
{
    bt_lookup l;
    uint64_t start = mono_ns(), deadline;
    size_t i;
    int ok = 1;

    bt_lookup_start(&l, name, server, 1, 1, 1, NULL, start);
    while ((deadline = bt_lookup_tick(&l, mono_ns(), send_up, NULL)) != BT_NEVER) {
        struct pollfd pfd = { sock, POLLIN, 0 };
        uint64_t now = mono_ns();
        int timeout = deadline > now ? (int)((deadline - now) / 1000000) + 1 : 0;
        if (poll(&pfd, 1, timeout) > 0) {
            uint8_t buf[BT_DNS_MSG_MAX];
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &flen);
            if (n > 0) {
                bt_addr fa;
                memset(&fa, 0, sizeof(fa));
                fa.family = 4;
                memcpy(fa.addr, &from.sin_addr, 4);
                bt_lookup_receive(&l, &fa, ntohs(from.sin_port), buf, (size_t)n, mono_ns());
            }
        }
    }
    printf("%-28s %4u ms  ", name, (unsigned)((mono_ns() - start) / 1000000));
    if (l.state != BT_LOOKUP_DONE) {
        printf("FAILED: %s\n", bt_lookup_error_text(l.error));
        return 0;
    }
    for (i = 0; i < l.n; i++) {
        char text[64];
        int known = system_knows(name, &l.addrs[i]);
        inet_ntop(l.addrs[i].family == 4 ? AF_INET : AF_INET6, l.addrs[i].addr, text, sizeof(text));
        printf("%s%s ", text, known ? "" : "(!)");
        if (!known) ok = 0;
    }
    printf(" ttl %u\n", l.ttl);
    return ok;
}

int main(int argc, char** argv)
{
    bt_addr server;
    int i, ok = 1;

    if (argc < 3) {
        fprintf(stderr, "usage: dns_live <server-ip> <name>...\n");
        return 2;
    }
    memset(&server, 0, sizeof(server));
    server.family = 4;
    if (inet_pton(AF_INET, argv[1], server.addr) != 1) return 2;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 2;
    for (i = 2; i < argc; i++)
        if (!one(&server, argv[i])) ok = 0;
    printf("%s\n", ok ? "all agree with getaddrinfo" : "MISMATCH or failure ((!) = getaddrinfo does not know it)");
    return ok ? 0 : 1;
}
