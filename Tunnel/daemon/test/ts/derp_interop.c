/*
 * ts_derp against a real DERP server (derp_interop.sh starts one): two clients log in over plain
 * HTTP, trade packets both ways, a burst goes through whole, and a disco-shaped packet to a key
 * nobody has comes back as PeerGone "not here". Blocking sockets and a poll loop - a test driver;
 * the daemon's own loop is bt_tailscale.
 *
 *   derp_interop <server IPv4> <port>
 */

#include "test_util.h"
#include "../../src/ts_derp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    const char* name;
    int         fd;
    ts_derp*    c;
    wg_key      sk, pk;
    int         n_ready;
    int         n_packets;
    uint8_t     last_src[32];
    uint8_t     last[2048];
    size_t      last_len;
    int         n_gone;
    int         gone_reason;
    uint8_t     gone_key[32];
} client;

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int write_all(int fd, const uint8_t* p, size_t n)
{
    while (n) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return 0;
        p += w;
        n -= (size_t)w;
    }
    return 1;
}

static int c_write(void* ctx, const uint8_t* a, size_t alen, const uint8_t* b, size_t blen)
{
    client* k = (client*)ctx;
    return write_all(k->fd, a, alen) && (!blen || write_all(k->fd, b, blen));
}

static void c_packet(void* ctx, const uint8_t src[32], uint8_t* data, size_t len)
{
    client* k = (client*)ctx;
    memcpy(k->last_src, src, 32);
    k->last_len = len < sizeof(k->last) ? len : sizeof(k->last);
    memcpy(k->last, data, k->last_len);
    k->n_packets++;
}

static void c_ready(void* ctx, const char* json, size_t len)
{
    client* k = (client*)ctx;
    k->n_ready++;
    printf("    %s: ServerInfo %.*s\n", k->name, (int)len, json);
}

static void c_gone(void* ctx, const uint8_t key[32], int reason)
{
    client* k = (client*)ctx;
    memcpy(k->gone_key, key, 32);
    k->gone_reason = reason;
    k->n_gone++;
}

/* TCP, the upgrade by hand, the rest of the reply into the client. */
static int connect_client(client* k, const char* ip, int port)
{
    struct sockaddr_in sa;
    char req[256], resp[4096];
    size_t have = 0;
    ts_derp_io io;
    char* end;

    memset(&io, 0, sizeof(io));
    io.ctx = k;
    io.write = c_write;
    io.packet = c_packet;
    io.ready = c_ready;
    io.peer_gone = c_gone;
    k->c = (ts_derp*)malloc(sizeof(ts_derp));
    if (!k->c || !wg_key_generate(&k->sk, &k->pk)) return 0;
    ts_derp_init(k->c, &k->sk, &k->pk, 1, NULL, &io);

    k->fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (k->fd < 0 || inet_pton(AF_INET, ip, &sa.sin_addr) != 1 ||
        connect(k->fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        fprintf(stderr, "    %s: connect: %s\n", k->name, strerror(errno));
        return 0;
    }
    snprintf(req, sizeof(req),
             "GET /derp HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: bbtunnel-test\r\nUpgrade: DERP\r\n"
             "Connection: Upgrade\r\n\r\n", ip, port);
    if (!write_all(k->fd, (const uint8_t*)req, strlen(req))) return 0;
    for (;;) {
        ssize_t r = recv(k->fd, resp + have, sizeof(resp) - 1 - have, 0);
        if (r <= 0) return 0;
        have += (size_t)r;
        resp[have] = '\0';
        if ((end = strstr(resp, "\r\n\r\n")) != NULL) break;
        if (have == sizeof(resp) - 1) return 0;
    }
    if (strncmp(resp, "HTTP/1.1 101", 12) != 0) {
        fprintf(stderr, "    %s: %.*s\n", k->name, (int)(end - resp), resp);
        return 0;
    }
    end += 4;
    return ts_derp_input(k->c, (const uint8_t*)end, have - (size_t)(end - resp));
}

/* Reads whatever the clients have until `done` or the deadline. */
static int pump(client* ks, int n, int (*done)(client*), uint64_t ms)
{
    uint64_t until = now_ms() + ms;
    struct pollfd p[4];
    uint8_t buf[16384];
    int i;

    while (!done(ks)) {
        int left = (int)(until - now_ms());
        if ((int64_t)(until - now_ms()) <= 0) return 0;
        for (i = 0; i < n; i++) {
            p[i].fd = ks[i].fd;
            p[i].events = POLLIN;
            p[i].revents = 0;
        }
        if (poll(p, (nfds_t)n, left) < 0 && errno != EINTR) return 0;
        for (i = 0; i < n; i++) {
            ssize_t r;
            if (!(p[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            r = recv(ks[i].fd, buf, sizeof(buf), 0);
            if (r <= 0) {
                fprintf(stderr, "    %s: the server closed\n", ks[i].name);
                return 0;
            }
            if (!ts_derp_input(ks[i].c, buf, (size_t)r)) {
                fprintf(stderr, "    %s: %s\n", ks[i].name, ks[i].c->error);
                return 0;
            }
        }
    }
    return 1;
}

static int both_ready(client* k) { return k[0].c->state == TS_DERP_READY && k[1].c->state == TS_DERP_READY; }
static int b_has_one(client* k) { return k[1].n_packets >= 1; }
static int a_has_one(client* k) { return k[0].n_packets >= 1; }
static int burst_target;
static int b_has_burst(client* k) { return k[1].n_packets >= burst_target; }
static int a_gone(client* k) { return k[0].n_gone >= 1; }

int main(int argc, char** argv)
{
    client k[2];
    uint8_t data[1400], nobody[32], disco[100];
    int i, port;

    if (argc != 3) {
        fprintf(stderr, "usage: derp_interop <server IPv4> <port>\n");
        return 2;
    }
    port = atoi(argv[2]);
    if (!wg_crypto_init()) return 2;
    memset(k, 0, sizeof(k));
    k[0].name = "A";
    k[1].name = "B";
    printf("ts_derp against %s:%d\n", argv[1], port);

    CHECK(connect_client(&k[0], argv[1], port));
    CHECK(connect_client(&k[1], argv[1], port));
    if (t_failures) return t_summary("derp interop");
    CHECK(pump(k, 2, both_ready, 5000));
    CHECK(k[0].n_ready == 1 && k[1].n_ready == 1);
    printf("  %-40s %s\n", "login", t_failures ? "FAILED" : "ok");

    /* A to B, and the answer back. */
    for (i = 0; i < (int)sizeof(data); i++) data[i] = (uint8_t)(i * 13);
    CHECK(ts_derp_send(k[0].c, k[1].pk.b, data, 1000));
    CHECK(pump(k, 2, b_has_one, 5000));
    CHECK(k[1].last_len == 1000);
    CHECK_MEM(k[1].last, data, 1000);
    CHECK_MEM(k[1].last_src, k[0].pk.b, 32);
    CHECK(ts_derp_send(k[1].c, k[0].pk.b, data + 7, 60));
    CHECK(pump(k, 2, a_has_one, 5000));
    CHECK(k[0].last_len == 60);
    CHECK_MEM(k[0].last, data + 7, 60);
    CHECK_MEM(k[0].last_src, k[1].pk.b, 32);
    printf("  %-40s %s\n", "packets both ways", t_failures ? "FAILED" : "ok");

    /* A burst in rounds: every packet arrives, in order (the last one is the last sent). */
    {
        int round, sent = 0;
        k[1].n_packets = 0;
        for (round = 0; round < 40; round++) {
            for (i = 0; i < 25; i++) {
                data[0] = (uint8_t)sent;
                data[1] = (uint8_t)(sent >> 8);
                CHECK(ts_derp_send(k[0].c, k[1].pk.b, data, 1200));
                sent++;
            }
            burst_target = sent;
            CHECK(pump(k, 2, b_has_burst, 5000));
        }
        CHECK(k[1].n_packets == 1000);
        CHECK(k[1].last[0] == (uint8_t)999 && k[1].last[1] == (uint8_t)(999 >> 8));
        printf("  %-40s %s\n", "1000 packets of 1200 bytes", t_failures ? "FAILED" : "ok");
    }

    /* To a key nobody has: a disco-shaped packet brings PeerGone "not here" (the server answers
     * only those), a plain one nothing. */
    memset(nobody, 0x6b, 32);
    memset(disco, 0, sizeof(disco));
    memcpy(disco, "TS\xf0\x9f\x92\xac", 6);
    CHECK(ts_derp_send(k[0].c, nobody, disco, sizeof(disco)));
    CHECK(pump(k, 2, a_gone, 5000));
    CHECK(k[0].gone_reason == TS_DERP_GONE_NOT_HERE);
    CHECK_MEM(k[0].gone_key, nobody, 32);
    printf("  %-40s %s\n", "PeerGone for an unknown key", t_failures ? "FAILED" : "ok");

    for (i = 0; i < 2; i++) {
        ts_derp_clear(k[i].c);
        free(k[i].c);
        close(k[i].fd);
    }
    return t_summary("derp interop");
}
