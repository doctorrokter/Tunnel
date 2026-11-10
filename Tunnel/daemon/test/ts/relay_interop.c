/*
 * bt_ts_relay against real DERP servers (relay_interop.sh starts two `derper -dev`): two sets of
 * relays - two nodes - make region 1 their home and trade packets through it; the measurement
 * finds both regions; a packet to region 2 opens a connection there and gets through; the home
 * server goes away and comes back, and home follows it.
 *
 *   relay_interop <derper 1 pid file> <port 1> <port 2>
 */

#include "test_util.h"
#include "../../src/bt_log.h"
#include "../../src/bt_tls.h"
#include "../../src/bt_ts_relay.h"

#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    const char* name;
    bt_relays*  rs;
    wg_key      sk, pk;
    int         home_up;
    int         home_changes;
    int         packets;
    int         region_last;
    uint8_t     src_last[32];
    uint8_t     last[1500];
    size_t      last_len;
    int         measured;
    int         best;
} node;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void on_packet(void* ctx, int region, const uint8_t src[32], uint8_t* data, size_t len)
{
    node* n = (node*)ctx;
    n->packets++;
    n->region_last = region;
    memcpy(n->src_last, src, 32);
    n->last_len = len < sizeof(n->last) ? len : sizeof(n->last);
    memcpy(n->last, data, n->last_len);
}

static void on_home(void* ctx, int up)
{
    node* n = (node*)ctx;
    n->home_up = up;
    n->home_changes++;
}

static void on_measured(void* ctx, const int64_t* region, const uint64_t* ns, size_t count)
{
    node* n = (node*)ctx;
    size_t i;
    uint64_t best_ns = 0;

    n->measured++;
    n->best = 0;
    for (i = 0; i < count; i++) {
        printf("    %s: region %d: %llu us\n", n->name, (int)region[i], (unsigned long long)(ns[i] / 1000));
        if (ns[i] && (!n->best || ns[i] < best_ns)) {
            n->best = (int)region[i];
            best_ns = ns[i];
        }
    }
}

static node N[2];

/* One loop turn for both nodes, up to `ms`. */
static void turn(int ms)
{
    struct pollfd p[64];
    int cnt[2], k, i, total = 0;
    uint64_t now = now_ns(), next = BT_NEVER;

    for (i = 0; i < 2; i++) {
        uint64_t d = bt_relays_tick(N[i].rs, now);
        if (d < next) next = d;
    }
    for (i = 0; i < 2; i++) {
        cnt[i] = bt_relays_pollfds(N[i].rs, p + total, 64 - total);
        total += cnt[i];
    }
    if (next != BT_NEVER && next > now && (int)((next - now) / 1000000) < ms) ms = (int)((next - now) / 1000000) + 1;
    if (next != BT_NEVER && next <= now) ms = 0;
    poll(p, (nfds_t)total, ms);
    now = now_ns();
    for (i = 0, k = 0; i < 2; i++) {
        int j;
        for (j = 0; j < cnt[i]; j++, k++)
            if (p[k].revents) bt_relays_io(N[i].rs, &p[k], now);
    }
}

static int wait_for(int (*cond)(void), int ms)
{
    uint64_t until = now_ns() + (uint64_t)ms * 1000000ULL;
    while (!cond()) {
        if (now_ns() >= until) return 0;
        turn(50);
    }
    return 1;
}

static int both_home(void) { return N[0].home_up && N[1].home_up; }
static int b_got(void) { return N[1].packets > 0; }
static int a_got(void) { return N[0].packets > 0; }
static int both_measured(void) { return N[0].measured && N[1].measured; }
static int a_home_down(void) { return !N[0].home_up; }
static int burst;
static int b_burst(void) { return N[1].packets >= burst; }

static void region(bt_relay_region* g, int id, uint16_t port)
{
    memset(g, 0, sizeof(*g));
    g->id = id;
    snprintf(g->code, sizeof(g->code), "r%d", id);
    g->n_nodes = 1;
    snprintf(g->nodes[0].host, sizeof(g->nodes[0].host), "127.0.0.1");
    snprintf(g->nodes[0].name, sizeof(g->nodes[0].name), "%da", id);
    g->nodes[0].v4.family = 4;
    inet_pton(AF_INET, "127.0.0.1", g->nodes[0].v4.addr);
    g->nodes[0].port = port;
}

int main(int argc, char** argv)
{
    bt_relay_region map[2];
    bt_relay_io io;
    uint8_t data[1400];
    char err[128];
    int i;
    uint64_t now;

    if (argc != 4) {
        fprintf(stderr, "usage: relay_interop <derper 1 pid file> <port 1> <port 2>\n");
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    bt_log_set_stderr(1);
    bt_log_set_level(BT_LOG_INFO);
    if (!wg_crypto_init() || !bt_tls_init(err, sizeof(err))) return 2;
    region(&map[0], 1, (uint16_t)atoi(argv[2]));
    region(&map[1], 2, (uint16_t)atoi(argv[3]));
    for (i = 0; i < 2; i++) {
        memset(&io, 0, sizeof(io));
        io.ctx = &N[i];
        io.packet = on_packet;
        io.home = on_home;
        io.measured = on_measured;
        N[i].name = i ? "B" : "A";
        if (!wg_key_generate(&N[i].sk, &N[i].pk)) return 2;
        N[i].rs = bt_relays_new(&N[i].sk, &N[i].pk, 1, N[i].name, &io);
        if (!N[i].rs) return 2;
        now = now_ns();
        bt_relays_set_map(N[i].rs, map, 2, now);
        bt_relays_set_home(N[i].rs, 1, now);
    }
    printf("bt_ts_relay against derper on :%s and :%s\n", argv[2], argv[3]);

    CHECK(wait_for(both_home, 5000));
    CHECK(bt_relays_home(N[0].rs) == 1 && bt_relays_home_up(N[0].rs));
    printf("  %-40s %s\n", "home up", t_failures ? "FAILED" : "ok");

    /* Through home, both ways. */
    for (i = 0; i < (int)sizeof(data); i++) data[i] = (uint8_t)(i * 3);
    CHECK(bt_relays_send(N[0].rs, 1, N[1].pk.b, data, 1000, now_ns()));
    CHECK(wait_for(b_got, 5000));
    CHECK(N[1].last_len == 1000 && N[1].region_last == 1);
    CHECK_MEM(N[1].src_last, N[0].pk.b, 32);
    CHECK(bt_relays_send(N[1].rs, 1, N[0].pk.b, data, 77, now_ns()));
    CHECK(wait_for(a_got, 5000));
    CHECK(N[0].last_len == 77);
    printf("  %-40s %s\n", "packets through home", t_failures ? "FAILED" : "ok");

    /* Region 2 for B: A sends there before B is connected there - nothing arrives, B is not
     * there; B opens it by sending, then A's packet arrives through region 2. The first packet
     * waits in the queue while the connection logs in. */
    N[1].packets = 0;
    CHECK(bt_relays_send(N[1].rs, 2, N[0].pk.b, data, 10, now_ns()));
    CHECK(!bt_relays_open(N[1].rs, 2));
    for (i = 0; i < 40; i++) turn(50);
    CHECK(bt_relays_open(N[1].rs, 2));
    N[1].packets = 0;
    CHECK(bt_relays_send(N[0].rs, 2, N[1].pk.b, data, 500, now_ns()));
    CHECK(wait_for(b_got, 5000));
    CHECK(N[1].region_last == 2 && N[1].last_len == 500);
    printf("  %-40s %s\n", "a second region on demand", t_failures ? "FAILED" : "ok");

    /* A burst: 300 packets in rounds, every one through. */
    {
        int round;
        N[1].packets = 0;
        burst = 0;
        for (round = 0; round < 10; round++) {
            for (i = 0; i < 30; i++) CHECK(bt_relays_send(N[0].rs, 1, N[1].pk.b, data, 1200, now_ns()));
            burst += 30;
            CHECK(wait_for(b_burst, 5000));
        }
        CHECK(N[1].packets == 300);
        printf("  %-40s %s\n", "300 packets of 1200 bytes", t_failures ? "FAILED" : "ok");
    }

    /* The measurement: both regions answer. */
    {
        static const int64_t both[2] = { 1, 2 };
        bt_relays_measure(N[0].rs, both, 2, now_ns());
        bt_relays_measure(N[1].rs, both, 2, now_ns());
    }
    CHECK(wait_for(both_measured, 5000));
    CHECK(N[0].best == 1 || N[0].best == 2);
    printf("  %-40s %s\n", "home measurement", t_failures ? "FAILED" : "ok");

    /* Home's server goes away (the script's derper 1 is stopped): home is down; it comes back
     * (the script restarts it) and home follows by itself. */
    {
        FILE* f = fopen(argv[1], "r");
        int pid = 0;
        if (f) {
            if (fscanf(f, "%d", &pid) != 1) pid = 0;
            fclose(f);
        }
        CHECK(pid > 0);
        if (pid <= 0) return t_summary("relay interop");
        kill(pid, SIGUSR1);                     /* the script: stop derper 1, start it again in 2 s */
        CHECK(wait_for(a_home_down, 5000));
        CHECK(wait_for(both_home, 20000));
        N[1].packets = 0;
        CHECK(bt_relays_send(N[0].rs, 1, N[1].pk.b, data, 64, now_ns()));
        CHECK(wait_for(b_got, 5000));
        printf("  %-40s %s\n", "home reconnects after its server restarts", t_failures ? "FAILED" : "ok");
    }

    for (i = 0; i < 2; i++) {
        bt_relay_stats st;
        bt_relays_stats(N[i].rs, &st);
        printf("    %s: in %llu, out %llu, dropped %llu\n", N[i].name, (unsigned long long)st.packets_in,
               (unsigned long long)st.packets_out, (unsigned long long)st.dropped);
        bt_relays_free(N[i].rs);
    }
    bt_tls_fini();
    return t_summary("relay interop");
}
