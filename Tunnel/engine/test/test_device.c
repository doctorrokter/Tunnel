/*
 * wg_device + wg_peer: devices wired through an in-memory network and a fake clock. The first
 * packet opening a session, the five timers each at its own time, roaming, cookies under load,
 * simultaneous initiations, the staged-packet queue - and cryptokey routing: packets chosen by
 * destination, checked by source, cut to their own length. Then the owner that routes by peer
 * (Tailscale over DERP): a relay that knows nodes by their peer, not by an address, plain and
 * through AmneziaWG, with the sender vouched for and without; and the AllowedIPs table moving to a
 * bigger pool while it is in use.
 */

#include "test_util.h"
#include "../src/wg_awg.h"
#include "../src/wg_device.h"

#define MS   1000000ULL
#define SEC  WG_NSEC_PER_SEC
#define T0   (1000 * SEC)
#define LOG  64

/* ------------------------------------------------------------------------------ the network */

typedef struct {
    wg_device   dev;
    wg_peer     peer;                   /* its peer: the other node (A: B) */
    wg_peer     peer2;                  /* A only, in the three-node tests: C */
    uint8_t     stage[4096];
    uint8_t     stage2[4096];
    wg_allowedips_node aips[64];
    uint8_t     tun4[4];                /* its address inside the tunnel: 10.10.0.<host> */
    wg_endpoint addr;                   /* where its datagrams come from */
    int         sent[5];                /* datagrams sent, by message type */
    uint64_t    log_at[LOG];            /* when each went out, and its type */
    uint32_t    log_type[LOG];
    int         nlog;
    int         delivered;
    uint8_t     last_pkt[2048];
    size_t      last_len;
    wg_endpoint last_to;                /* where send sent the last datagram */
    /* routed by peer (send_peer) */
    wg_awg      awg;
    int         routed[2][5];           /* by peer (peer, peer2) and message type; [0]: no message */
    int         misrouted;              /* send_peer with a stranger's peer, or `to` not the label */
} node;

typedef struct {
    wg_endpoint to, from;
    uint8_t     data[2048];
    size_t      len;
    node*       dst;                    /* through the relay: to this node... */
    wg_peer*    as;                     /* ...from this peer of its */
} frame;

static node NA, NB, NC;
static wg_drop_reason g_why;
static uint64_t g_now;
static frame g_net[64];
static int g_net_n;
static int g_drop_a_to_b, g_drop_b_to_a;

/* What the owner puts at every peer it routes, and passes as their datagrams' source. */
static const wg_endpoint LABEL = { WG_EP_OWNER, { 0 }, 0 };
static int g_vouch;                     /* the relay names the sender: wg_device_receive_from */

static void net_send(void* ctx, const wg_endpoint* to, const uint8_t* msg, size_t len)
{
    node* n = (node*)ctx;
    uint32_t type = wg_load32(msg);
    frame* f;

    if (type >= 1 && type <= 4) n->sent[type]++;
    if (n->nlog < LOG) {
        n->log_at[n->nlog] = g_now;
        n->log_type[n->nlog] = type;
        n->nlog++;
    }
    n->last_to = *to;
    if ((n == &NA && g_drop_a_to_b) || (n == &NB && g_drop_b_to_a)) return;
    CHECK(g_net_n < 64 && len <= sizeof(f->data));
    if (g_net_n == 64 || len > sizeof(f->data)) return;
    f = &g_net[g_net_n++];
    f->to = *to;
    f->from = n->addr;
    memcpy(f->data, msg, len);
    f->len = len;
    f->dst = NULL;
    f->as = NULL;
}

static void net_deliver(void* ctx, wg_peer* from, uint8_t* data, size_t len)
{
    node* n = (node*)ctx;
    (void)from;
    n->delivered++;
    memcpy(n->last_pkt, data, len < sizeof(n->last_pkt) ? len : sizeof(n->last_pkt));
    n->last_len = len;
}

static void net_wall(void* ctx, uint64_t* sec, uint32_t* nsec)
{
    (void)ctx;
    *sec = 1759140000ULL + g_now / SEC;
    *nsec = (uint32_t)(g_now % SEC);
}

/* Delivers everything in flight, and whatever the deliveries send, in order. */
static void pump(void)
{
    static frame f;
    node* dst;
    int guard = 0;

    while (g_net_n && guard++ < 1000) {
        f = g_net[0];
        memmove(g_net, g_net + 1, (size_t)(g_net_n - 1) * sizeof(frame));
        g_net_n--;
        if (f.dst && g_vouch) {                         /* the relay: by peer, from the label */
            wg_device_receive_from(&f.dst->dev, f.as, f.data, f.len, &LABEL, g_now);
            continue;
        }
        if (f.dst) {
            wg_device_receive(&f.dst->dev, f.data, f.len, &LABEL, g_now);
            continue;
        }
        dst = wg_endpoint_equal(&f.to, &NA.addr) ? &NA
            : wg_endpoint_equal(&f.to, &NB.addr) ? &NB
            : wg_endpoint_equal(&f.to, &NC.addr) ? &NC : NULL;
        if (dst) wg_device_receive(&dst->dev, f.data, f.len, &f.from, g_now);
    }
    CHECK(guard < 1000);
}

static uint64_t next_deadline(void)
{
    uint64_t a = wg_device_next_deadline(&NA.dev), b = wg_device_next_deadline(&NB.dev);
    uint64_t c = wg_device_next_deadline(&NC.dev);      /* a zeroed NC is down: WG_NEVER */
    if (b < a) a = b;
    return c < a ? c : a;
}

/* Runs the clock to `until`, firing every timer on the way at its own deadline. */
static void run_until(uint64_t until)
{
    uint64_t t;
    int guard = 0;

    pump();
    while ((t = next_deadline()) <= until && guard++ < 10000) {
        if (t > g_now) g_now = t;
        wg_device_tick(&NA.dev, g_now);
        wg_device_tick(&NB.dev, g_now);
        wg_device_tick(&NC.dev, g_now);
        pump();
    }
    CHECK(guard < 10000);
    if (until > g_now) g_now = until;
}

static void node_init(node* n, uint8_t host)
{
    wg_key sk, pk;

    memset(n, 0, sizeof(*n));
    wg_device_init(&n->dev);
    n->dev.ctx = n;
    n->dev.send = net_send;
    n->dev.deliver = net_deliver;
    n->dev.wall_clock = net_wall;
    CHECK(wg_key_generate(&sk, &pk));
    CHECK(wg_device_set_private_key(&n->dev, &sk));
    CHECK(wg_device_set_allowedips_storage(&n->dev, n->aips, sizeof(n->aips) / sizeof(n->aips[0])));
    n->addr.family = 4;
    n->addr.addr[0] = 10;
    n->addr.addr[3] = host;
    n->addr.port = 51820;
    n->tun4[0] = 10;
    n->tun4[1] = 10;
    n->tun4[3] = host;
}

/*
 * A is the client and knows where B is; B learns A's endpoint from A's first initiation. Inside the
 * tunnel A is 10.10.0.1 and B 10.10.0.2, and each allows exactly the other's address.
 */
static void setup(void)
{
    g_now = T0;
    g_net_n = 0;
    g_drop_a_to_b = g_drop_b_to_a = 0;
    memset(&NC, 0, sizeof(NC));
    node_init(&NA, 1);
    node_init(&NB, 2);
    CHECK(wg_device_add_peer(&NA.dev, &NA.peer, &NB.dev.local.public_key, NA.stage, sizeof(NA.stage)));
    CHECK(wg_device_add_peer(&NB.dev, &NB.peer, &NA.dev.local.public_key, NB.stage, sizeof(NB.stage)));
    CHECK(wg_peer_allow(&NA.peer, 4, NB.tun4, 32));
    CHECK(wg_peer_allow(&NB.peer, 4, NA.tun4, 32));
    wg_peer_set_endpoint(&NA.peer, &NB.addr);
    wg_device_up(&NA.dev, g_now);
    wg_device_up(&NB.dev, g_now);
}

/* setup(), and C (10.10.0.3) as A's second peer; C allows only A's address. */
static void setup_three(void)
{
    setup();
    node_init(&NC, 3);
    CHECK(wg_device_add_peer(&NA.dev, &NA.peer2, &NC.dev.local.public_key, NA.stage2, sizeof(NA.stage2)));
    CHECK(wg_device_add_peer(&NC.dev, &NC.peer, &NA.dev.local.public_key, NC.stage, sizeof(NC.stage)));
    CHECK(wg_peer_allow(&NC.peer, 4, NA.tun4, 32));
    wg_peer_set_endpoint(&NA.peer2, &NC.addr);
    wg_device_up(&NC.dev, g_now);
}

static uint8_t pkt[1500];

/* An IPv4 packet of `len` bytes (a 20-byte header, then seed, seed+1, ...) into pkt. */
static void ip4_packet(size_t len, const uint8_t src[4], const uint8_t dst[4], uint8_t seed)
{
    size_t i;

    memset(pkt, 0, 20);
    pkt[0] = 0x45;
    pkt[2] = (uint8_t)(len >> 8);
    pkt[3] = (uint8_t)len;
    pkt[8] = 64;
    pkt[9] = 17;
    memcpy(pkt + 12, src, 4);
    memcpy(pkt + 16, dst, 4);
    for (i = 20; i < len; i++) pkt[i] = (uint8_t)(seed + (i - 20));
}

/* A packet from node n to any address, routed by the device. */
static int send_to(node* n, const uint8_t dst[4], size_t len, uint8_t seed)
{
    ip4_packet(len, n->tun4, dst, seed);
    return wg_device_send(&n->dev, pkt, len, g_now, &g_why);
}

/* A packet between A and B, inside the tunnel. */
static int send_from(node* n, size_t len, uint8_t seed)
{
    return send_to(n, n == &NA ? NB.tun4 : NA.tun4, len, seed);
}

/* A's first packet opens a session both sides hold, at T0. */
static void open_session(void)
{
    CHECK(send_from(&NA, 100, 1));
    pump();
    CHECK(NB.delivered == 1);
}

/* ------------------------------------------------------------------------------ staged queue */

TEST(stage_ring)
{
    uint8_t mem[50], out[64], a[10], b[20];
    wg_stage q;
    size_t len;

    memset(a, 0xaa, sizeof(a));
    memset(b, 0xbb, sizeof(b));
    wg_stage_init(&q, mem, sizeof(mem));

    /* Three records, two taken off: the next ones wrap around the end of the ring. */
    CHECK(wg_stage_push(&q, a, 10) && wg_stage_push(&q, a, 10) && wg_stage_push(&q, a, 10));
    wg_stage_drop(&q);
    wg_stage_drop(&q);
    CHECK(wg_stage_push(&q, b, 20));
    CHECK(wg_stage_push(&q, NULL, 0));                  /* a keepalive */
    CHECK(q.count == 3 && q.dropped == 0);
    CHECK(wg_stage_peek(&q, out) == 10 && memcmp(out, a, 10) == 0);
    wg_stage_drop(&q);
    CHECK(wg_stage_peek(&q, out) == 20 && memcmp(out, b, 20) == 0);
    wg_stage_drop(&q);
    CHECK(wg_stage_peek(&q, out) == 0);
    wg_stage_drop(&q);
    CHECK(q.count == 0 && q.used == 0);

    /* Too big for the ring at all: refused. Just fitting: everything else makes room. */
    CHECK(wg_stage_push(&q, a, 10) && wg_stage_push(&q, a, 10));
    CHECK(!wg_stage_push(&q, out, 49));
    CHECK(wg_stage_push(&q, out, 48));
    CHECK(q.count == 1 && q.dropped == 2);
    len = wg_stage_peek(&q, out);
    CHECK(len == 48);

    /* No memory: nothing can be staged, and that is not an error elsewhere. */
    wg_stage_init(&q, NULL, 0);
    CHECK(!wg_stage_push(&q, NULL, 0));
}

/* ------------------------------------------------------------------------------ sessions */

TEST(first_packet_opens_the_session)
{
    setup();
    CHECK(send_from(&NA, 100, 7));
    CHECK(NA.sent[1] == 1 && NA.sent[4] == 0);          /* staged behind an initiation */
    CHECK(NA.peer.staged.count == 1);

    pump();
    CHECK(NB.sent[2] == 1);
    CHECK(NA.sent[4] == 1 && NA.peer.staged.count == 0);   /* the packet itself confirmed the keys */
    CHECK(NB.delivered == 1 && NB.last_len == 100);        /* padded to 112 on the wire, cut back */
    CHECK(memcmp(NB.last_pkt, pkt, 100) == 0);
    CHECK(wg_endpoint_equal(&NB.peer.endpoint, &NA.addr)); /* B learned where A is */
    CHECK(NA.peer.has_handshake && NB.peer.has_handshake);
    CHECK(NB.peer.session.current && !NB.peer.session.next);

    /* Byte counts are datagrams, both ways. */
    CHECK(NA.peer.tx_bytes == WG_INIT_LEN + WG_DATA_MSG_LEN(112));
    CHECK(NB.peer.rx_bytes == NA.peer.tx_bytes);
    CHECK(NB.peer.tx_bytes == WG_RESP_LEN && NA.peer.rx_bytes == WG_RESP_LEN);

    /* The answer rides the confirmed session. */
    CHECK(send_from(&NB, 60, 9));
    pump();
    CHECK(NA.delivered == 1 && NB.sent[4] == 1 && NB.sent[1] == 0);
}

TEST(initiate_confirms_with_a_keepalive)
{
    setup();
    wg_peer_initiate(&NA.peer, g_now);
    pump();
    CHECK(NA.sent[1] == 1 && NB.sent[2] == 1);
    CHECK(NA.sent[4] == 1);                             /* nothing staged: a keepalive */
    CHECK(NB.delivered == 0);
    CHECK(NB.peer.session.current && !NB.peer.session.next);
}

TEST(retransmits_then_gives_up)
{
    int i, spaced = 1;

    setup();
    g_drop_a_to_b = 1;
    CHECK(send_from(&NA, 100, 1));
    run_until(T0 + 200 * SEC);

    /* 1 + 19 retries, each REKEY_TIMEOUT plus up to 334 ms of jitter after the last... */
    CHECK(NA.sent[1] == 20);
    for (i = 1; i < NA.nlog; i++) {
        uint64_t gap = NA.log_at[i] - NA.log_at[i - 1];
        if (gap < 5 * SEC || gap >= 5 * SEC + 334 * MS) spaced = 0;
    }
    CHECK(spaced);
    /* ...then it gives up: the packet is dropped, the leftovers wiped in 540 s. */
    CHECK(NA.peer.staged.count == 0);
    CHECK(NA.peer.t_retransmit_handshake == WG_NEVER);
    CHECK(NA.peer.t_zero_key_material != WG_NEVER);
}

TEST(passive_keepalive)
{
    setup();
    open_session();

    /* B got data and has nothing to say: 10 s later it answers with a keepalive. */
    run_until(T0 + 10 * SEC - 1);
    CHECK(NB.sent[4] == 0);
    run_until(T0 + 10 * SEC);
    CHECK(NB.sent[4] == 1);
    /* A keepalive is not data: nobody answers it, and A sees no reason to rehandshake. */
    run_until(T0 + 60 * SEC);
    CHECK(NA.sent[4] == 1 && NB.sent[4] == 1 && NA.sent[1] == 1);

    /* Data sent back in time makes the keepalive unnecessary. */
    setup();
    open_session();
    g_now = T0 + 3 * SEC;
    CHECK(send_from(&NB, 50, 2));
    run_until(T0 + 30 * SEC);
    CHECK(NB.sent[4] == 1);
}

TEST(keepalive_after_more_data)
{
    int i, at10 = 0, at20 = 0;

    /* More data while B's keepalive is pending: after it goes out, another one is due in 10 s. */
    setup();
    open_session();
    g_now = T0 + 5 * SEC;
    CHECK(send_from(&NA, 30, 1));
    run_until(T0 + 25 * SEC);
    CHECK(NB.sent[4] == 2);
    for (i = 0; i < NB.nlog; i++) {
        if (NB.log_type[i] != WG_MSG_DATA) continue;
        if (NB.log_at[i] == T0 + 10 * SEC) at10 = 1;
        if (NB.log_at[i] == T0 + 20 * SEC) at20 = 1;
    }
    CHECK(at10 && at20);
}

TEST(new_handshake_when_the_peer_goes_quiet)
{
    setup();
    open_session();
    run_until(T0 + 11 * SEC);                           /* B's keepalive has arrived */

    g_drop_b_to_a = 1;                                  /* from now on B is not heard */
    g_now = T0 + 20 * SEC;
    CHECK(send_from(&NA, 100, 3));
    run_until(T0 + 35 * SEC - 1);
    CHECK(NA.sent[1] == 1);
    run_until(T0 + 35 * SEC + 334 * MS);                /* KEEPALIVE + REKEY_TIMEOUT + jitter */
    CHECK(NA.sent[1] == 2);
}

TEST(rekey_after_two_minutes)
{
    uint32_t k1;

    setup();
    open_session();
    run_until(T0 + 121 * SEC);
    REQUIRE(NA.peer.session.current);
    k1 = NA.peer.session.current->local_index;

    /* The initiator's session is 2 minutes old: the packet goes on it, and a rekey starts. */
    CHECK(send_from(&NA, 100, 4));
    CHECK(NA.sent[1] == 2);
    pump();
    CHECK(NB.delivered == 2);
    REQUIRE(NA.peer.session.current && NA.peer.session.previous);
    CHECK(NA.peer.session.current->local_index != k1 && NA.peer.session.previous->local_index == k1);
    CHECK(NB.peer.session.current && NB.peer.session.previous && !NB.peer.session.next);
}

TEST(lastminute_rekey_when_receiving)
{
    setup();
    open_session();
    run_until(T0 + 166 * SEC);
    CHECK(NA.sent[1] == 1);

    /* A sends nothing, but its session is about to be rejected: receiving renews it, once. */
    CHECK(send_from(&NB, 60, 5));
    pump();
    CHECK(NA.delivered == 1);
    CHECK(NA.sent[1] == 2);
    CHECK(NA.peer.session.previous && NB.peer.session.current && !NB.peer.session.next);
}

TEST(zero_key_material)
{
    setup();
    open_session();
    run_until(T0 + 540 * SEC - 1);
    CHECK(NA.peer.session.current && NB.peer.session.current);

    /* Three REJECT_AFTER_TIMEs with no new session: every key is wiped, on both sides. */
    run_until(T0 + 540 * SEC);
    CHECK(!NA.peer.session.current && !NA.peer.session.previous && !NA.peer.session.next);
    CHECK(!NB.peer.session.current && !NB.peer.session.previous && !NB.peer.session.next);
}

TEST(persistent_keepalive)
{
    int i, k = 0, spaced = 1;
    uint64_t last = 0;

    setup();

    /* Turning it on sends a keepalive at once; without a session that is a handshake first. */
    wg_peer_set_persistent_keepalive(&NA.peer, 25, g_now);
    CHECK(NA.sent[1] == 1 && NA.sent[4] == 0);
    pump();
    CHECK(NA.sent[4] == 1);                             /* the staged keepalive confirmed it */

    /* Then every 25 s of silence. */
    run_until(T0 + 60 * SEC);
    CHECK(NA.sent[4] == 3);
    for (i = 0; i < NA.nlog; i++) {
        if (NA.log_type[i] != WG_MSG_DATA) continue;
        if (k++ && NA.log_at[i] - last != 25 * SEC) spaced = 0;
        last = NA.log_at[i];
    }
    CHECK(spaced);

    /* Off again: no more keepalives. */
    wg_peer_set_persistent_keepalive(&NA.peer, 0, g_now);
    run_until(T0 + 120 * SEC);
    CHECK(NA.sent[4] == 3);

    /* Configured before the device comes up: up starts it. */
    setup();
    wg_device_down(&NA.dev);
    wg_peer_set_persistent_keepalive(&NA.peer, 25, g_now);
    CHECK(NA.sent[1] == 0);
    wg_device_up(&NA.dev, g_now);
    CHECK(NA.sent[1] == 1);
}

TEST(roaming)
{
    uint8_t junk[64];
    wg_endpoint elsewhere;

    setup();
    open_session();

    /* A moves (Wi-Fi to LTE): B follows its authentic packets, and the answer finds A there. */
    NA.addr.addr[3] = 99;
    CHECK(send_from(&NA, 80, 6));
    pump();
    CHECK(wg_endpoint_equal(&NB.peer.endpoint, &NA.addr));
    CHECK(send_from(&NB, 40, 7));
    pump();
    CHECK(NA.delivered == 1);

    /* A forgery from somewhere else moves nothing. */
    REQUIRE(NB.peer.session.current);
    memset(junk, 0x5a, sizeof(junk));
    wg_store32(junk + WG_DATA_OFF_TYPE, WG_MSG_DATA);
    wg_store32(junk + WG_DATA_OFF_RECEIVER, NB.peer.session.current->local_index);
    elsewhere = NA.addr;
    elsewhere.addr[3] = 66;
    CHECK(!wg_device_receive(&NB.dev, junk, sizeof(junk), &elsewhere, g_now));
    CHECK(NB.peer.last_drop == WG_DROP_FORGED);
    CHECK(wg_endpoint_equal(&NB.peer.endpoint, &NA.addr));
}

TEST(cookie_under_load)
{
    setup();
    NB.dev.under_load = 1;

    /* B demands proof of address: a cookie reply instead of a response. */
    CHECK(send_from(&NA, 100, 1));
    pump();
    CHECK(NB.sent[3] == 1 && NB.sent[2] == 0);
    CHECK(NA.peer.cookie.has_cookie);

    /* The retransmit carries mac2, and B answers it. */
    run_until(T0 + 6 * SEC);
    CHECK(NA.sent[1] == 2 && NB.sent[2] == 1);
    CHECK(NB.delivered == 1);
}

TEST(disable_cookies)
{
    /* AmneziaWG's DisableCookies: "under load" is off altogether - no cookie reply, no mac2. */
    setup();
    NB.dev.under_load = 1;
    NB.dev.disable_cookies = 1;
    CHECK(send_from(&NA, 100, 1));
    pump();
    CHECK(NB.sent[3] == 0 && NB.sent[2] == 1 && NB.delivered == 1);
}

/* ------------------------------------------------------------------------------ AmneziaWG's timings */

static wg_range range(uint32_t lo, uint32_t hi)
{
    wg_range r;
    r.lo = lo;
    r.hi = hi;
    return r;
}

TEST(timings_as_ranges)
{
    wg_timing t = wg_timing_wireguard;
    uint64_t gap, d, seen[64];
    int i, j, ok = 1, distinct = 0;

    /* Retransmits: each after a DRAWN rekey timeout plus jitter; given up after the drawn number
     * of attempts plus two initiations, as in amneziawg-go's log line. */
    setup();
    t.rekey_timeout = range(3, 7);
    t.max_handshake_attempts = range(3, 3);
    t.reject_after_time = range(150, 170);
    wg_device_set_timing(&NA.dev, &t);
    CHECK(NA.peer.session.reject_after_ns == 170 * SEC);   /* keys live to the top of the range */
    g_drop_a_to_b = 1;
    CHECK(send_from(&NA, 100, 1));
    run_until(T0 + 200 * SEC);
    CHECK(NA.sent[1] == 5);
    for (i = 1; i < NA.nlog; i++) {
        gap = NA.log_at[i] - NA.log_at[i - 1];
        if (gap < 3 * SEC || gap >= 7 * SEC + 334 * MS) ok = 0;
    }
    CHECK(ok);
    /* the leftovers go after three times the TOP of the reject range */
    d = NA.peer.t_zero_key_material - NA.log_at[NA.nlog - 1];
    CHECK(d > 510 * SEC && d < 510 * SEC + 7 * SEC + 334 * MS);

    /* Initiations: at most one per the BOTTOM of the rekey range. */
    setup();
    wg_device_set_timing(&NA.dev, &t);
    g_drop_a_to_b = 1;
    wg_peer_initiate(&NA.peer, g_now);
    g_now += 3 * SEC - 1;
    wg_peer_initiate(&NA.peer, g_now);
    CHECK(NA.sent[1] == 1);
    g_now += 1;
    wg_peer_initiate(&NA.peer, g_now);
    CHECK(NA.sent[1] == 2);

    /* A session: the leftovers are wiped three times the top of the reject range later. */
    setup();
    wg_device_set_timing(&NA.dev, &t);
    open_session();
    CHECK(NA.peer.t_zero_key_material == T0 + 510 * SEC);

    /* The persistent keepalive is drawn anew after every packet either way. */
    wg_peer_set_persistent_keepalive_range(&NA.peer, range(20, 30), g_now);
    for (i = 0; i < 200; i++) {
        CHECK(send_from(&NA, 60, (uint8_t)i));
        d = NA.peer.t_persistent_keepalive - g_now;
        if (d < 20 * SEC || d > 30 * SEC || d % SEC) ok = 0;
        for (j = 0; j < distinct && seen[j] != d; j++) {}
        if (j == distinct && distinct < 64) seen[distinct++] = d;
        pump();
    }
    CHECK(ok && distinct == 11);

    /* The passive keepalive waits a drawn keepalive timeout; a new handshake after sending waits
     * the TOP of the keepalive range plus a drawn rekey timeout plus jitter. */
    t = wg_timing_wireguard;
    t.keepalive_timeout = range(8, 12);
    t.rekey_timeout = range(3, 7);
    wg_device_set_timing(&NB.dev, &t);
    wg_device_set_timing(&NA.dev, &t);
    CHECK(send_from(&NB, 60, 0));                       /* both timers from the loop above stop */
    pump();
    CHECK(NA.peer.t_new_handshake == WG_NEVER && NB.peer.t_send_keepalive == WG_NEVER);
    for (i = 0, distinct = 0; i < 100; i++) {
        CHECK(send_from(&NA, 60, (uint8_t)i));
        d = NA.peer.t_new_handshake - g_now;
        if (d < 15 * SEC || d >= 19 * SEC + 334 * MS) ok = 0;
        pump();
        d = NB.peer.t_send_keepalive - g_now;
        if (d < 8 * SEC || d > 12 * SEC || d % SEC) ok = 0;
        for (j = 0; j < distinct && seen[j] != d; j++) {}
        if (j == distinct && distinct < 64) seen[distinct++] = d;
        CHECK(send_from(&NB, 60, (uint8_t)i));          /* answered: both timers stop */
        pump();
    }
    CHECK(ok && distinct == 5);
}

TEST(lastminute_rekey_with_ranges)
{
    wg_timing t = wg_timing_wireguard;

    /* The initiator renews keys it only receives on once they are older than a drawn reject time
     * less the BOTTOMS of the keepalive and rekey ranges: here between 139 and 159 s. */
    setup();
    t.rekey_after_time = range(1000, 1000);             /* the sending side's rekey out of the way */
    t.reject_after_time = range(150, 170);
    t.keepalive_timeout = range(8, 12);
    t.rekey_timeout = range(3, 7);
    wg_device_set_timing(&NA.dev, &t);
    open_session();
    run_until(T0 + 138 * SEC);
    CHECK(send_from(&NB, 60, 1));
    pump();
    CHECK(NA.delivered == 1 && NA.sent[1] == 1);
    run_until(T0 + 160 * SEC);
    CHECK(send_from(&NB, 60, 2));
    pump();
    CHECK(NA.delivered == 2 && NA.sent[1] == 2);

    /* With the reject time fixed at 160 the point is exact: 160 - 8 - 3 = 149 s, the bottoms of the
     * keepalive and rekey ranges (their tops would make it 141). */
    setup();
    t.reject_after_time = range(160, 160);
    wg_device_set_timing(&NA.dev, &t);
    open_session();
    run_until(T0 + 148 * SEC);
    CHECK(send_from(&NB, 60, 1));
    pump();
    CHECK(NA.delivered == 1 && NA.sent[1] == 1);
    run_until(T0 + 149 * SEC);
    CHECK(send_from(&NB, 60, 2));
    pump();
    CHECK(NA.delivered == 2 && NA.sent[1] == 2);
}

TEST(padded_keepalive)
{
    /* AmneziaWG pads keepalives with zeroes: a packet that starts with a zero byte is one, not a
     * packet that is not IP. */
    uint8_t zeros[48];

    setup();
    open_session();
    memset(zeros, 0, sizeof(zeros));
    CHECK(wg_device_send_to_peer(&NA.dev, &NA.peer, zeros, sizeof(zeros), g_now));
    pump();
    CHECK(NB.delivered == 1 && NB.peer.last_drop == WG_DROP_NONE);
    zeros[0] = 0x10;                                    /* version 1: not IP */
    CHECK(wg_device_send_to_peer(&NA.dev, &NA.peer, zeros, sizeof(zeros), g_now));
    pump();
    CHECK(NB.delivered == 1 && NB.peer.last_drop == WG_DROP_NOT_IP);
}

/* A codec that asks for a megabyte of padding: the device gives it what its buffers hold. */
static int greedy_classify(void* st, uint8_t* d, size_t len, uint32_t* type, size_t* off, size_t* mlen)
{
    return wg_codec_wireguard.classify(st, d, len, type, off, mlen);
}

static size_t greedy_padding(void* st, size_t len, size_t mtu)
{
    (void)st;
    (void)len;
    (void)mtu;
    return (size_t)1 << 20;
}

static const wg_codec_ops greedy_ops = {
    "greedy", NULL, NULL, NULL, greedy_classify, greedy_padding, NULL
};

TEST(a_greedy_codec_is_capped)
{
    uint64_t before;

    setup();
    open_session();
    NA.dev.codec.ops = &greedy_ops;
    g_drop_a_to_b = 1;
    before = NA.peer.tx_bytes;
    CHECK(send_from(&NA, 100, 3));
    CHECK(NA.peer.tx_bytes - before == WG_DATA_MSG_LEN(WG_MAX_PACKET + WG_PADDING_MULTIPLE));
}

TEST(simultaneous_initiation)
{
    setup();
    wg_peer_set_endpoint(&NB.peer, &NA.addr);           /* peer to peer: both know each other */

    /* Both initiate before either initiation arrives. */
    CHECK(send_from(&NA, 100, 1));
    CHECK(send_from(&NB, 90, 2));
    pump();
    CHECK(NA.sent[2] == 1 && NB.sent[2] == 1);          /* each answered the other... */
    CHECK(NA.delivered == 0 && NB.delivered == 0);      /* ...and neither answer found its initiation */

    /* The retransmit timers, apart by their jitter, settle it within one REKEY_TIMEOUT. */
    run_until(T0 + 6 * SEC);
    CHECK(NA.delivered == 1 && NB.delivered == 1);
}

TEST(staged_queue_keeps_the_newest)
{
    int i;

    setup();
    wg_stage_init(&NA.peer.staged, NA.stage, 300);      /* room for two 100-byte packets */
    g_drop_a_to_b = 1;
    for (i = 0; i < 5; i++) CHECK(send_from(&NA, 100, (uint8_t)(10 * i)));
    CHECK(NA.peer.staged.count == 2 && NA.peer.staged.dropped == 3);
    CHECK(NA.sent[1] == 1);                             /* one initiation: the rest rate-limited */

    g_drop_a_to_b = 0;
    run_until(T0 + 6 * SEC);
    CHECK(NB.delivered == 2);
    CHECK(NB.last_pkt[20] == 40);                       /* the newest, and it came last */
}

TEST(no_endpoint_no_traffic)
{
    setup();
    CHECK(!send_from(&NB, 100, 1));                     /* B has never heard from A */
    CHECK(g_why == WG_DROP_NO_ENDPOINT);
    CHECK(NB.sent[1] == 0 && NB.peer.staged.count == 0);
}

TEST(private_key_change)
{
    wg_key sk, pk;

    setup();
    open_session();
    CHECK(wg_key_generate(&sk, &pk));
    CHECK(wg_device_set_private_key(&NA.dev, &sk));

    /* The old session stops sending: the packet waits for a handshake under the new identity,
     * which B - still expecting the old key - does not answer. */
    CHECK(send_from(&NA, 100, 1));
    CHECK(NA.sent[1] == 2 && NA.sent[4] == 1);
    pump();
    CHECK(NB.sent[2] == 1 && NB.delivered == 1);
}

TEST(down_and_up)
{
    setup();
    open_session();
    wg_device_down(&NA.dev);
    CHECK(!NA.peer.session.current && NA.peer.staged.count == 0);
    CHECK(wg_device_next_deadline(&NA.dev) == WG_NEVER);
    CHECK(!send_from(&NA, 100, 1) && g_why == WG_DROP_DOWN);

    /* Up again at the same instant: a fresh handshake, not held back by the rate limit. */
    wg_device_up(&NA.dev, g_now);
    CHECK(send_from(&NA, 100, 1));
    CHECK(NA.sent[1] == 2);
}

TEST(garbage_is_dropped)
{
    uint8_t buf[200];

    setup();
    open_session();
    memset(buf, 0, sizeof(buf));
    CHECK(!wg_device_receive(&NB.dev, buf, 3, &NA.addr, g_now));             /* no type */
    wg_store32(buf, 9);
    CHECK(!wg_device_receive(&NB.dev, buf, 100, &NA.addr, g_now));           /* no such type */
    wg_store32(buf, WG_MSG_INITIATION);
    CHECK(!wg_device_receive(&NB.dev, buf, WG_INIT_LEN - 1, &NA.addr, g_now));  /* wrong length */
    CHECK(!wg_device_receive(&NB.dev, buf, WG_INIT_LEN, &NA.addr, g_now));      /* bad mac1 */
    wg_store32(buf, WG_MSG_RESPONSE);
    CHECK(!wg_device_receive(&NB.dev, buf, WG_RESP_LEN, &NA.addr, g_now));
    wg_store32(buf, WG_MSG_COOKIE);
    CHECK(!wg_device_receive(&NB.dev, buf, WG_COOKIE_MSG_LEN, &NA.addr, g_now));
    wg_store32(buf, WG_MSG_DATA);
    CHECK(!wg_device_receive(&NB.dev, buf, WG_DATA_MSG_LEN(0) - 1, &NA.addr, g_now));
    CHECK(!wg_device_receive(&NB.dev, buf, WG_DATA_MSG_LEN(16), &NA.addr, g_now));  /* unknown index */

    /* None of it disturbed the session. */
    CHECK(send_from(&NA, 100, 3));
    pump();
    CHECK(NB.delivered == 2);
}

/* ------------------------------------------------------------------------------ routing */

static const uint8_t ANY4[4] = { 0, 0, 0, 0 };
static const uint8_t LAN_C[4] = { 10, 20, 0, 0 };       /* 10.20.0.0/16 lives behind C */
static const uint8_t IN_C[4] = { 10, 20, 5, 5 };
static const uint8_t EDGE_C[4] = { 10, 20, 255, 255 };
static const uint8_t PAST_C[4] = { 10, 21, 0, 1 };
static const uint8_t OUTSIDE[4] = { 1, 1, 1, 1 };

TEST(routes_by_destination)
{
    /* A full tunnel through B, with one network through C: the more specific route wins. */
    setup_three();
    CHECK(wg_peer_allow(&NA.peer, 4, ANY4, 0));
    CHECK(wg_peer_allow(&NA.peer2, 4, LAN_C, 16));

    CHECK(send_to(&NA, IN_C, 60, 1));
    pump();
    CHECK(NC.delivered == 1 && NB.delivered == 0);
    CHECK(send_to(&NA, OUTSIDE, 60, 2));
    pump();
    CHECK(NB.delivered == 1 && NC.delivered == 1);
    CHECK(send_to(&NA, EDGE_C, 60, 3) && send_to(&NA, PAST_C, 60, 4));
    pump();
    CHECK(NC.delivered == 2 && NB.delivered == 2);
}

TEST(no_route_no_packet)
{
    setup();                                            /* A routes only 10.10.0.2/32, to B */
    CHECK(!send_to(&NA, OUTSIDE, 60, 1));
    CHECK(g_why == WG_DROP_NO_ROUTE);
    CHECK(NA.sent[1] == 0 && NA.peer.staged.count == 0);
}

TEST(inner_source_is_checked)
{
    static const uint8_t spoofed[4] = { 10, 99, 0, 1 };

    setup();
    open_session();

    /* B may send from 10.10.0.2 only. A packet from elsewhere is authentic - B sealed it - and
     * still refused: otherwise a peer could inject traffic as any other. */
    ip4_packet(60, spoofed, NA.tun4, 5);
    CHECK(wg_device_send(&NB.dev, pkt, 60, g_now, &g_why));
    pump();
    CHECK(NA.delivered == 0 && NA.peer.last_drop == WG_DROP_WRONG_SOURCE);

    CHECK(send_from(&NB, 60, 5));
    pump();
    CHECK(NA.delivered == 1);
}

TEST(padding_is_cut_off)
{
    setup();
    open_session();
    CHECK(send_from(&NA, 37, 1));                       /* 48 bytes on the wire, 37 delivered */
    pump();
    CHECK(NB.delivered == 2 && NB.last_len == 37);
    CHECK(memcmp(NB.last_pkt, pkt, 37) == 0);
}

TEST(only_ip_goes_through)
{
    setup();
    open_session();

    /* Not IP: the device refuses to route it... */
    memset(pkt, 0x11, 64);
    CHECK(!wg_device_send(&NA.dev, pkt, 64, g_now, &g_why) && g_why == WG_DROP_NOT_IP);
    /* ...and pushed through anyway, the receiver refuses to deliver it. */
    CHECK(wg_device_send_to_peer(&NA.dev, &NA.peer, pkt, 64, g_now));
    pump();
    CHECK(NB.delivered == 1 && NB.peer.last_drop == WG_DROP_NOT_IP);

    /* A header claiming more than there is: the same, both ways. */
    ip4_packet(40, NA.tun4, NB.tun4, 1);
    pkt[3] = 200;
    CHECK(!wg_device_send(&NA.dev, pkt, 40, g_now, &g_why) && g_why == WG_DROP_BAD_LENGTH);
    CHECK(wg_device_send_to_peer(&NA.dev, &NA.peer, pkt, 40, g_now));
    pump();
    CHECK(NB.delivered == 1 && NB.peer.last_drop == WG_DROP_BAD_LENGTH);
}

TEST(ipv6_inside)
{
    static const uint8_t zero6[16] = { 0 };
    static const uint8_t a6[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    static const uint8_t far6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5 };
    size_t i;

    setup();
    CHECK(wg_peer_allow(&NA.peer, 6, zero6, 0));        /* all of IPv6 through B */
    CHECK(wg_peer_allow(&NB.peer, 6, a6, 128));         /* A speaks as fd00::1 */

    memset(pkt, 0, 40);
    pkt[0] = 0x60;
    pkt[5] = 40;                                        /* 40 + 40 bytes */
    pkt[6] = 17;
    pkt[7] = 64;
    memcpy(pkt + 8, a6, 16);
    memcpy(pkt + 24, far6, 16);
    for (i = 40; i < 80; i++) pkt[i] = (uint8_t)i;
    CHECK(wg_device_send(&NA.dev, pkt, 80, g_now, &g_why));
    pump();
    CHECK(NB.delivered == 1 && NB.last_len == 80);
    CHECK(memcmp(NB.last_pkt, pkt, 80) == 0);
}

TEST(a_prefix_moves_between_peers)
{
    setup_three();
    CHECK(wg_peer_allow(&NA.peer, 4, LAN_C, 16));       /* first through B */
    CHECK(send_to(&NA, IN_C, 60, 1));
    pump();
    CHECK(NB.delivered == 1 && NC.delivered == 0);

    CHECK(wg_peer_allow(&NA.peer2, 4, LAN_C, 16));      /* now C: the prefix moves */
    CHECK(!wg_peer_disallow(&NA.peer, 4, LAN_C, 16));   /* B does not hold it any more */
    CHECK(send_to(&NA, IN_C, 60, 2));
    pump();
    CHECK(NB.delivered == 1 && NC.delivered == 1);
}

TEST(a_removed_peer_takes_its_routes)
{
    setup_three();
    CHECK(wg_peer_allow(&NA.peer2, 4, LAN_C, 16));
    CHECK(send_to(&NA, IN_C, 60, 1));
    pump();
    CHECK(NC.delivered == 1);

    wg_device_remove_peer(&NA.dev, &NA.peer2);
    CHECK(!send_to(&NA, IN_C, 60, 2) && g_why == WG_DROP_NO_ROUTE);
    CHECK(NA.dev.allowedips.used == 1);                 /* B's 10.10.0.2/32 is all that is left */
}

TEST(allowedips_move_to_a_bigger_pool)
{
    static wg_allowedips_node big[512];
    wg_allowedips_node* old = NULL;
    uint8_t host[4] = { 10, 30, 0, 0 };
    int i, n;

    /* A's 64 nodes fill up with C's host routes, the way a netmap grows... */
    setup_three();
    for (n = 0; n < 200; n++) {
        host[3] = (uint8_t)(n + 1);
        if (!wg_peer_allow(&NA.peer2, 4, host, 32)) break;
    }
    CHECK(n > 20 && n < 64);

    /* ...so the table moves - not to a smaller pool - and what did not fit, fits. The new pool
     * comes as it is (garbage), the old one is the owner's again and may be scribbled over. */
    memset(big, 0x5a, sizeof(big));
    CHECK(!wg_device_grow_allowedips(&NA.dev, big, 32, &old) && old == NULL);
    CHECK(wg_device_grow_allowedips(&NA.dev, big, 512, &old));
    CHECK(old == NA.aips && NA.dev.allowedips.nodes == big && NA.dev.allowedips.cap == 512);
    memset(NA.aips, 0xa5, sizeof(NA.aips));
    for (i = n; i < 200; i++) {
        host[3] = (uint8_t)(i + 1);
        CHECK(wg_peer_allow(&NA.peer2, 4, host, 32));
    }

    /* Routes from before the move and after it, and B's, lead where they did. */
    host[3] = 1;
    CHECK(send_to(&NA, host, 60, 1));
    host[3] = 200;
    CHECK(send_to(&NA, host, 60, 2));
    CHECK(send_to(&NA, NB.tun4, 60, 3));
    pump();
    CHECK(NC.delivered == 2 && NB.delivered == 1);
    host[3] = 201;
    CHECK(!send_to(&NA, host, 60, 4) && g_why == WG_DROP_NO_ROUTE);
}

/* ------------------------------------------------------------------------------ routed by peer */

/*
 * The owner routes by peer, as Tailscale does over DERP: send_peer names the peer, and the relay
 * hands the datagram to the node that peer is, as coming from the sender's peer there - the key a
 * DERP frame carries. Every endpoint is the label, nobody has an address; A has B and C.
 */

/* Which node peer `p` of node `n` is, and which of that node's peers `n` is there. NULL: `p` is
 * not n's. */
static node* relay_route(node* n, const wg_peer* p, wg_peer** as)
{
    if (n == &NA && p == &NA.peer) {
        *as = &NB.peer;
        return &NB;
    }
    if (n == &NA && p == &NA.peer2) {
        *as = &NC.peer;
        return &NC;
    }
    if ((n == &NB || n == &NC) && p == &n->peer) {
        *as = n == &NB ? &NA.peer : &NA.peer2;
        return &NA;
    }
    return NULL;
}

/* The message a datagram carries as the other end will find it - the sender's codec on a copy
 * (both ends share its parameters); 0 for junk and I-packets. */
static uint32_t wire_type(node* n, const uint8_t* msg, size_t len)
{
    uint8_t copy[2048];
    uint32_t type;
    size_t off, mlen;

    if (len > sizeof(copy)) return 0;
    memcpy(copy, msg, len);
    if (!n->dev.codec.ops->classify(n->dev.codec.st, copy, len, &type, &off, &mlen)) return 0;
    return type <= 4 ? type : 0;
}

static void net_send_peer(void* ctx, wg_peer* p, const wg_endpoint* to, const uint8_t* msg, size_t len)
{
    node* n = (node*)ctx;
    wg_peer* as = NULL;
    node* dst = relay_route(n, p, &as);
    frame* f;

    if (!dst || !wg_endpoint_equal(to, &LABEL)) n->misrouted++;
    n->routed[p == &n->peer2][wire_type(n, msg, len)]++;
    if (!dst || (n == &NA && dst == &NB && g_drop_a_to_b) || (n == &NB && g_drop_b_to_a)) return;
    CHECK(g_net_n < 64 && len <= sizeof(f->data));
    if (g_net_n == 64 || len > sizeof(f->data)) return;
    f = &g_net[g_net_n++];
    f->to = *to;
    f->from = LABEL;
    memcpy(f->data, msg, len);
    f->len = len;
    f->dst = dst;
    f->as = as;
}

/* A, B and C as in setup_three(), routed by peer: send_peer on every node and the label at every
 * peer, as the daemon will put it at every Tailscale peer. `awg`: all of them speak AmneziaWG with
 * it. `vouch`: the relay names the sender (wg_device_receive_from), or leaves it to the index. */
static void setup_routed(const wg_awg_params* awg, int vouch)
{
    node* all[3];
    int i;

    g_now = T0;
    g_net_n = 0;
    g_drop_a_to_b = g_drop_b_to_a = 0;
    g_vouch = vouch;
    node_init(&NA, 1);
    node_init(&NB, 2);
    node_init(&NC, 3);
    CHECK(wg_device_add_peer(&NA.dev, &NA.peer, &NB.dev.local.public_key, NA.stage, sizeof(NA.stage)));
    CHECK(wg_device_add_peer(&NA.dev, &NA.peer2, &NC.dev.local.public_key, NA.stage2, sizeof(NA.stage2)));
    CHECK(wg_device_add_peer(&NB.dev, &NB.peer, &NA.dev.local.public_key, NB.stage, sizeof(NB.stage)));
    CHECK(wg_device_add_peer(&NC.dev, &NC.peer, &NA.dev.local.public_key, NC.stage, sizeof(NC.stage)));
    CHECK(wg_peer_allow(&NA.peer, 4, NB.tun4, 32) && wg_peer_allow(&NA.peer2, 4, NC.tun4, 32));
    CHECK(wg_peer_allow(&NB.peer, 4, NA.tun4, 32) && wg_peer_allow(&NC.peer, 4, NA.tun4, 32));
    wg_peer_set_endpoint(&NA.peer2, &LABEL);
    all[0] = &NA;
    all[1] = &NB;
    all[2] = &NC;
    for (i = 0; i < 3; i++) {
        all[i]->dev.send_peer = net_send_peer;
        if (awg) wg_awg_attach(&all[i]->awg, awg, &all[i]->dev);
        wg_peer_set_endpoint(&all[i]->peer, &LABEL);
        wg_device_up(&all[i]->dev, g_now);
    }
}

/* A packet from node `from` to node `to`'s tunnel address; 1 when `to` got it. */
static int routed_trip(node* from, node* to, uint8_t seed)
{
    int before = to->delivered;

    if (!send_to(from, to->tun4, 80, seed)) return 0;
    pump();
    return to->delivered == before + 1;
}

/* Takes the oldest datagram in flight off the network, undelivered. */
static const frame* take(void)
{
    static frame f;

    if (!g_net_n) return NULL;
    f = g_net[0];
    memmove(g_net, g_net + 1, (size_t)(g_net_n - 1) * sizeof(frame));
    g_net_n--;
    return &f;
}

/* Hands a datagram to `n` vouched for as coming from `as`. A copy: the device decrypts in place,
 * and a test offers the same bytes again. */
static int receive_as(node* n, wg_peer* as, const frame* f)
{
    static uint8_t buf[2048];

    memcpy(buf, f->data, f->len);
    return wg_device_receive_from(&n->dev, as, buf, f->len, &LABEL, g_now);
}

TEST(send_peer_names_the_peer)
{
    /* A's initiations, then the packets that waited for them: each to its own peer. */
    setup_routed(NULL, 0);
    CHECK(send_to(&NA, NB.tun4, 100, 1));
    CHECK(NA.routed[0][WG_MSG_INITIATION] == 1 && NA.routed[1][WG_MSG_INITIATION] == 0);
    CHECK(send_to(&NA, NC.tun4, 100, 2));
    CHECK(NA.routed[1][WG_MSG_INITIATION] == 1);
    pump();
    CHECK(NB.routed[0][WG_MSG_RESPONSE] == 1 && NC.routed[0][WG_MSG_RESPONSE] == 1);
    CHECK(NA.routed[0][WG_MSG_DATA] == 1 && NA.routed[1][WG_MSG_DATA] == 1);
    CHECK(NB.delivered == 1 && NC.delivered == 1);

    /* Data back from both; 10 s later A's keepalives, one to each (nothing to deliver in them). */
    CHECK(routed_trip(&NB, &NA, 3) && routed_trip(&NC, &NA, 4));
    CHECK(NB.routed[0][WG_MSG_DATA] == 1 && NC.routed[0][WG_MSG_DATA] == 1);
    run_until(T0 + 10 * SEC);
    CHECK(NA.routed[0][WG_MSG_DATA] == 2 && NA.routed[1][WG_MSG_DATA] == 2);
    CHECK(NB.delivered == 1 && NC.delivered == 1);

    /* Nothing to a stranger, `to` always the label, nothing through send. */
    CHECK(NA.misrouted == 0 && NB.misrouted == 0 && NC.misrouted == 0);
    CHECK(NA.nlog == 0 && NB.nlog == 0 && NC.nlog == 0);

    /* A retransmitted initiation names its peer as well. */
    setup_routed(NULL, 0);
    g_drop_a_to_b = 1;
    wg_peer_initiate(&NA.peer, g_now);
    run_until(T0 + 6 * SEC);
    CHECK(NA.routed[0][WG_MSG_INITIATION] == 2 && NA.routed[1][WG_MSG_INITIATION] == 0);

    /* A cookie reply answers the source of a handshake message - no peer is proven yet - so it
     * leaves by send, to the label, although B routes by peer. */
    setup_routed(NULL, 0);
    NB.dev.under_load = 1;
    wg_peer_initiate(&NA.peer, g_now);
    pump();
    CHECK(NB.sent[WG_MSG_COOKIE] == 1 && NB.nlog == 1 && wg_endpoint_equal(&NB.last_to, &LABEL));
    CHECK(NB.routed[0][WG_MSG_COOKIE] == 0 && NB.routed[0][WG_MSG_RESPONSE] == 0);

    /* A device that routes by peer needs no send at all to reach its peers. */
    setup_routed(NULL, 0);
    NA.dev.send = NULL;
    NB.dev.send = NULL;
    CHECK(routed_trip(&NA, &NB, 5) && routed_trip(&NB, &NA, 6));
}

TEST(relay_carries_the_tunnel)
{
    int vouch, i, ok;

    for (vouch = 0; vouch <= 1; vouch++) {
        /* B starts without an endpoint for A: it learns the label from A's initiation. */
        setup_routed(NULL, vouch);
        memset(&NB.peer.endpoint, 0, sizeof(NB.peer.endpoint));
        CHECK(!send_to(&NB, NA.tun4, 60, 1) && g_why == WG_DROP_NO_ENDPOINT);
        CHECK(routed_trip(&NA, &NB, 1) && routed_trip(&NA, &NC, 2));
        CHECK(wg_endpoint_equal(&NB.peer.endpoint, &LABEL));

        /* Three minutes of round trips with both: A renews each session once, at 126 s. */
        for (i = 1, ok = 1; i <= 25; i++) {
            run_until(T0 + (uint64_t)i * 7 * SEC);
            if (!routed_trip(&NA, &NB, (uint8_t)i) || !routed_trip(&NB, &NA, (uint8_t)i)
                || !routed_trip(&NA, &NC, (uint8_t)i) || !routed_trip(&NC, &NA, (uint8_t)i))
                ok = 0;
        }
        CHECK(ok);
        CHECK(NA.routed[0][WG_MSG_INITIATION] == 2 && NA.routed[1][WG_MSG_INITIATION] == 2);
        CHECK(NB.routed[0][WG_MSG_INITIATION] == 0 && NC.routed[0][WG_MSG_INITIATION] == 0);
        CHECK(NA.peer.session.previous && NA.peer2.session.previous);

        /* Roaming had nothing to move: every endpoint is the label still. */
        CHECK(wg_endpoint_equal(&NA.peer.endpoint, &LABEL) && wg_endpoint_equal(&NA.peer2.endpoint, &LABEL));
        CHECK(wg_endpoint_equal(&NB.peer.endpoint, &LABEL) && wg_endpoint_equal(&NC.peer.endpoint, &LABEL));
        CHECK(NA.misrouted == 0 && NB.misrouted == 0 && NC.misrouted == 0);
        CHECK(NA.nlog == 0 && NB.nlog == 0 && NC.nlog == 0);
    }
}

TEST(relay_with_amneziawg)
{
    static const char i1[] = "<b 0xc70000000108><r 16><t>";
    wg_awg_params p;
    const char* why;
    uint32_t window;
    int t, i, ok;

    /* 3.x: prefixes, type ranges, header protection, trailers, an I-packet and three junk. H1-H3
     * narrow: with trailers, a data datagram whose bytes happen to fall in a handshake range is
     * taken for that message and lost (the reference does the same), and wide ranges would make
     * that a coin toss over a few hundred datagrams. */
    wg_awg_params_default(&p);
    for (t = 1; t <= 4; t++) {
        p.s[t] = (uint32_t)(12 + 4 * t);
        p.h[t].lo = (uint32_t)t * 100000;
        p.h[t].hi = (uint32_t)t * 100000 + (t < 4 ? 999 : 99999);
    }
    for (t = 0; t < WG_KEY_LEN; t++) p.hp_key[t] = (uint8_t)(t * 5 + 3);
    p.random_trailers = 1;
    p.jc = 3;
    p.jmin = 20;
    p.jmax = 60;
    REQUIRE(wg_awg_parse_chain(&p.i[1], i1, strlen(i1), &why) && wg_awg_check(&p, &why));

    /* Ahead of each initiation its I-packet and junk, to the peer the initiation is for. */
    setup_routed(&p, 1);
    CHECK(send_to(&NA, NB.tun4, 100, 1) && send_to(&NA, NC.tun4, 100, 2));
    CHECK(NA.routed[0][0] == 4 && NA.routed[1][0] == 4);
    CHECK(NA.routed[0][WG_MSG_INITIATION] == 1 && NA.routed[1][WG_MSG_INITIATION] == 1);
    pump();
    CHECK(NB.delivered == 1 && NC.delivered == 1);
    CHECK(NB.routed[0][WG_MSG_RESPONSE] == 1 && NC.routed[0][WG_MSG_RESPONSE] == 1);

    /* The UDP window: a label never moves, so it only grows and never starts over - what the
     * reference's mobile builds do - and the relay carries whatever it grows to. */
    CHECK(NA.awg.udp_window == WG_AWG_UDP_WINDOW);
    ip4_packet(1300, NB.tun4, NA.tun4, 7);
    CHECK(wg_device_send(&NB.dev, pkt, 1300, g_now, &g_why));
    pump();
    CHECK(NA.delivered == 1 && NA.last_len == 1300);
    window = NA.awg.udp_window;
    CHECK(window > 1300);
    for (i = 1, ok = 1; i <= 25; i++) {
        run_until(T0 + (uint64_t)i * 7 * SEC);
        if (!routed_trip(&NA, &NB, (uint8_t)i) || !routed_trip(&NB, &NA, (uint8_t)i)
            || !routed_trip(&NA, &NC, (uint8_t)i) || !routed_trip(&NC, &NA, (uint8_t)i))
            ok = 0;
    }
    CHECK(ok);
    CHECK(NA.awg.udp_window == window);

    /* The rekey at 126 s: another initiation to each peer, with junk of its own. */
    CHECK(NA.routed[0][WG_MSG_INITIATION] == 2 && NA.routed[0][0] == 8);
    CHECK(NA.routed[1][WG_MSG_INITIATION] == 2 && NA.routed[1][0] == 8);
    CHECK(NA.misrouted == 0 && NB.misrouted == 0 && NC.misrouted == 0);
    CHECK(NA.nlog == 0 && NB.nlog == 0 && NC.nlog == 0);
}

TEST(receive_from_checks_the_sender)
{
    const frame* f;

    /* B's initiation vouched for as C's: C's key is not in it. Refused before anything happened -
     * the same bytes as B's are taken after, so not even their timestamp was spent. */
    setup_routed(NULL, 1);
    wg_peer_initiate(&NB.peer, g_now);
    REQUIRE((f = take()) != NULL && f->dst == &NA);
    CHECK(!receive_as(&NA, &NA.peer2, f));
    CHECK(g_net_n == 0 && NA.peer.noise.hs.state == WG_HS_ZEROED && NA.peer2.noise.hs.state == WG_HS_ZEROED);
    CHECK(receive_as(&NA, &NA.peer, f));
    CHECK(g_net_n == 1 && NA.routed[0][WG_MSG_RESPONSE] == 1 && NA.dev.rx_from == NULL);

    /* B's response vouched for as C's, while A waits for C's too: another index, refused, and C's
     * initiation is still out. As B's it opens the session. */
    setup_routed(NULL, 1);
    wg_peer_initiate(&NA.peer2, g_now);
    wg_peer_initiate(&NA.peer, g_now);
    REQUIRE(take() != NULL);                            /* C's initiation: it never arrives */
    REQUIRE((f = take()) != NULL && f->dst == &NB);
    CHECK(receive_as(&NB, &NB.peer, f));
    REQUIRE((f = take()) != NULL && f->dst == &NA);
    CHECK(!receive_as(&NA, &NA.peer2, f));
    CHECK(NA.peer2.noise.hs.state == WG_HS_CREATED_INITIATION && !NA.peer.has_handshake);
    CHECK(receive_as(&NA, &NA.peer, f) && NA.peer.has_handshake);
    pump();                                             /* A's keepalive confirms it at B */

    /* B's data vouched for as C's: not an index of C's, and C says so; as B's it is delivered. */
    CHECK(send_to(&NB, NA.tun4, 60, 5));
    REQUIRE((f = take()) != NULL && f->dst == &NA);
    CHECK(!receive_as(&NA, &NA.peer2, f) && NA.peer2.last_drop == WG_DROP_UNKNOWN_INDEX);
    CHECK(NA.delivered == 0);
    CHECK(receive_as(&NA, &NA.peer, f) && NA.delivered == 1);

    /* A's data for B, at A's device as from B's peer - another device's, whose keys WOULD open
     * it: refused all the same. At B, as that peer, it is delivered. */
    CHECK(send_to(&NA, NB.tun4, 60, 6));
    REQUIRE((f = take()) != NULL && f->dst == &NB);
    CHECK(!receive_as(&NA, &NB.peer, f) && NB.delivered == 0);
    CHECK(receive_as(&NB, &NB.peer, f) && NB.delivered == 1);

    /* A cookie reply (B under load) comes by send, to the label. Vouched for as C's it is refused
     * - C has no handshake with that index; as B's it gives A the cookie. */
    setup_routed(NULL, 1);
    NB.dev.under_load = 1;
    wg_peer_initiate(&NA.peer, g_now);
    REQUIRE((f = take()) != NULL);
    CHECK(!receive_as(&NB, &NB.peer, f));
    REQUIRE((f = take()) != NULL && !f->dst && wg_endpoint_equal(&f->to, &LABEL));
    CHECK(!receive_as(&NA, &NA.peer2, f) && !NA.peer2.cookie.has_cookie);
    CHECK(receive_as(&NA, &NA.peer, f) && NA.peer.cookie.has_cookie);
    CHECK(!receive_as(&NA, NULL, f));                   /* no sender: nothing to vouch with */
    CHECK(NA.dev.rx_from == NULL);
}

static uint32_t g_forced_index;
static int g_force_index;

/* Real randomness, except that the next 4-byte draw - the index A's next response takes - is
 * g_forced_index, once. */
static int forcing_rng(void* ctx, void* buf, size_t len)
{
    (void)ctx;
    if (g_force_index && len == sizeof(g_forced_index)) {
        g_force_index = 0;
        memcpy(buf, &g_forced_index, sizeof(g_forced_index));
        return 1;
    }
    return wg_random(buf, len);
}

TEST(a_fresh_index_is_free_at_every_peer)
{
    const frame* f;

    /* A has a session with B. C's initiation, vouched for as C's, is answered with an index drawn
     * as B's first: free at C, it would still name B's keys to everyone who looks an index up
     * without a vouch - so it is refused, and drawn again. */
    setup_routed(NULL, 1);
    CHECK(routed_trip(&NA, &NB, 1));
    REQUIRE(NA.peer.session.current != NULL);
    g_forced_index = NA.peer.session.current->local_index;
    NA.dev.local.rng.fn = forcing_rng;
    wg_peer_initiate(&NC.peer, g_now);
    REQUIRE((f = take()) != NULL && f->dst == &NA);
    g_force_index = 1;
    CHECK(receive_as(&NA, &NA.peer2, f));
    CHECK(!g_force_index);                              /* the forced draw was made */
    REQUIRE(NA.peer2.session.next != NULL);
    CHECK(NA.peer2.session.next->local_index != g_forced_index);
    pump();
    CHECK(routed_trip(&NC, &NA, 2) && routed_trip(&NA, &NB, 3));
}

TEST(receive_from_takes_garbage)
{
    static frame seeds[16];
    static uint8_t buf[2048];
    uint64_t x = 0x9e3779b97f4a7c15ULL;
    const frame* f;
    int nseeds = 0, i, k, before;
    size_t len;

    /* Real datagrams of every kind to mutate: A's handshakes and data, B's and C's data, and an
     * initiation to A (C renews its session: a mutant under B's name meets the key check). */
    setup_routed(NULL, 1);
    for (i = 0; i < 3; i++) {
        if (i == 0) CHECK(send_to(&NA, NB.tun4, 60, 1) && send_to(&NA, NC.tun4, 60, 2));
        if (i == 1) CHECK(send_to(&NB, NA.tun4, 60, 3) && send_to(&NC, NA.tun4, 60, 4));
        if (i == 2) {
            g_now += 6 * SEC;                           /* past C's rate limit on initiations */
            wg_peer_initiate(&NC.peer, g_now);
        }
        while ((f = take()) != NULL) {
            if (nseeds < 16) seeds[nseeds++] = *f;
            if (f->dst) receive_as(f->dst, f->as, f);
        }
    }
    CHECK(nseeds >= 10 && NA.delivered == 2 && NB.delivered == 1 && NC.delivered == 1);
    CHECK(NC.routed[0][WG_MSG_INITIATION] == 1 && NA.routed[1][WG_MSG_RESPONSE] == 1);

    /* Bits flipped, cut short, or as they were but vouched for as either peer - at A. */
    before = NA.delivered;
    for (i = 0; i < 20000; i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        f = &seeds[x % (uint64_t)nseeds];
        len = f->len;
        memcpy(buf, f->data, len);
        for (k = 0; k < (int)((x >> 8) % 4); k++) buf[(x >> (16 + 8 * k)) % len] ^= (uint8_t)(1 << k);
        if ((x >> 50) % 8 == 0) len = (size_t)(x >> 20) % (len + 1);
        wg_device_receive_from(&NA.dev, (x >> 60) & 1 ? &NA.peer : &NA.peer2, buf, len, &LABEL,
                               g_now + SEC);
        g_net_n = 0;                                    /* whatever it provoked, dropped */
    }
    CHECK(NA.delivered == before && NA.dev.rx_from == NULL);

    /* Still a tunnel, to both. */
    g_now += 2 * SEC;
    CHECK(routed_trip(&NA, &NB, 9) && routed_trip(&NB, &NA, 9));
    CHECK(routed_trip(&NA, &NC, 9) && routed_trip(&NC, &NA, 9));
}

int main(void)
{
    if (!wg_crypto_init()) {
        fprintf(stderr, "wg_crypto_init failed\n");
        return 2;
    }
    RUN(stage_ring);
    RUN(first_packet_opens_the_session);
    RUN(initiate_confirms_with_a_keepalive);
    RUN(retransmits_then_gives_up);
    RUN(passive_keepalive);
    RUN(keepalive_after_more_data);
    RUN(new_handshake_when_the_peer_goes_quiet);
    RUN(rekey_after_two_minutes);
    RUN(lastminute_rekey_when_receiving);
    RUN(zero_key_material);
    RUN(persistent_keepalive);
    RUN(roaming);
    RUN(cookie_under_load);
    RUN(disable_cookies);
    RUN(timings_as_ranges);
    RUN(lastminute_rekey_with_ranges);
    RUN(padded_keepalive);
    RUN(a_greedy_codec_is_capped);
    RUN(simultaneous_initiation);
    RUN(staged_queue_keeps_the_newest);
    RUN(no_endpoint_no_traffic);
    RUN(private_key_change);
    RUN(down_and_up);
    RUN(garbage_is_dropped);
    RUN(routes_by_destination);
    RUN(no_route_no_packet);
    RUN(inner_source_is_checked);
    RUN(padding_is_cut_off);
    RUN(only_ip_goes_through);
    RUN(ipv6_inside);
    RUN(a_prefix_moves_between_peers);
    RUN(a_removed_peer_takes_its_routes);
    RUN(allowedips_move_to_a_bigger_pool);
    RUN(send_peer_names_the_peer);
    RUN(relay_carries_the_tunnel);
    RUN(relay_with_amneziawg);
    RUN(receive_from_checks_the_sender);
    RUN(a_fresh_index_is_free_at_every_peer);
    RUN(receive_from_takes_garbage);
    wg_crypto_cleanup();
    return t_summary("test_device");
}
