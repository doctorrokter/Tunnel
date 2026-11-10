/*
 * The whole engine, the way the daemon will use it: a server's and a client's .conf, parsed, applied
 * to two devices, the devices wired through an in-memory network and a fake clock. The session
 * comes up by itself (persistent keepalive), packets go both ways by routing, keys roll over; the
 * same runs through an obfuscating test codec (the hooks alone), and through AmneziaWG itself with
 * profiles of each generation, 1.x to 3.x, the wire watched datagram by datagram.
 */

#include "test_util.h"
#include "../src/wg_conf.h"
#include "../src/wg_device.h"

#define MS   1000000ULL
#define SEC  WG_NSEC_PER_SEC
#define T0   (1000 * SEC)

/* ------------------------------------------------------------------------------ a test codec */

/*
 * Other values in the type field, a random prefix on every message, junk datagrams ahead of every
 * initiation, 16 extra bytes of padding inside data. Not AmneziaWG's exact format - its shapes.
 */
typedef struct {
    uint32_t h[5];
    size_t   prefix;
    int      junk;
    int      junk_sent;
} obfs;

static void obfs_stamp(void* st, uint32_t type, uint8_t* msg, size_t len)
{
    (void)len;
    wg_store32(msg, ((obfs*)st)->h[type]);
}

static size_t obfs_wrap(void* st, uint32_t type, const uint8_t* msg, size_t len, uint8_t* out, size_t cap)
{
    obfs* o = (obfs*)st;
    (void)type;
    if (o->prefix + len > cap || !wg_random(out, o->prefix)) return 0;
    memcpy(out + o->prefix, msg, len);
    return o->prefix + len;
}

static void obfs_before(void* st, uint8_t* buf, size_t cap, wg_emit_fn emit, void* ctx)
{
    obfs* o = (obfs*)st;
    size_t n;
    int i;

    for (i = 0; i < o->junk; i++) {
        n = 40 + (size_t)i * 13;
        if (n > cap || !wg_random(buf, n)) return;
        emit(ctx, buf, n);
        o->junk_sent++;
    }
}

static int obfs_classify(void* st, uint8_t* d, size_t len, uint32_t* type, size_t* off, size_t* mlen)
{
    obfs* o = (obfs*)st;
    uint32_t h, t;

    if (len < o->prefix + 4) return 0;
    h = wg_load32(d + o->prefix);
    for (t = 1; t <= 4; t++) {
        if (h == o->h[t] && wg_codec_length_ok(t, len - o->prefix)) {
            *type = t;
            *off = o->prefix;
            *mlen = len - o->prefix;
            return 1;
        }
    }
    return 0;
}

static size_t obfs_padding(void* st, size_t len, size_t mtu)
{
    (void)st;
    return wg_data_padding(len, mtu) + 16;
}

static const wg_codec_ops obfs_ops = {
    "obfs", obfs_stamp, obfs_wrap, obfs_before, obfs_classify, obfs_padding, NULL
};

static const obfs OBFS = { { 0, 0x5f3e1a01u, 0x9c02b4e7u, 0x13572468u, 0xfeedc0deu }, 17, 3, 0 };

/* ------------------------------------------------------------------------------ hosts and wire */

typedef struct {
    wg_device          dev;
    wg_conf            conf;
    wg_conf_peer       cpeers[2];
    wg_prefix          callowed[8];
    wg_peer            peers[2];
    uint8_t            stage[2 * 8192];
    wg_allowedips_node nodes[32];
    obfs               codec;
    wg_awg             awg;
    char               text[2048];
    wg_endpoint        addr;            /* its UDP address */
    int                datagrams;
    int                canonical;       /* datagrams that a plain WireGuard parser would accept */
    int                initiations;     /* handshake initiations among them */
    size_t             last_dgram;
    /* AmneziaWG: what its own classify makes of each datagram it sends */
    int                awg_sent[5];     /* by message type */
    int                unreadable;      /* junk and I-packets */
    int                run;             /* unreadable ones since the last message */
    int                ahead_min, ahead_max;        /* unreadable ones before each initiation */
    int                trailers;        /* handshake messages longer than prefix + message */
    size_t             data_min, data_max;          /* data datagram lengths */
    int                delivered;
    uint8_t            last[2048];
    size_t             last_len;
} host;

typedef struct {
    wg_endpoint to, from;
    uint8_t     data[2048];
    size_t      len;
} frame;

static host SRV, CLI;
static uint64_t g_now;
static frame g_net[64];
static int g_net_n;

/* An AmneziaWG datagram as the peer will read it (same S, H and key): its classify on a copy. */
static void awg_observe(host* h, const uint8_t* msg, size_t len)
{
    static const size_t canon[4] = { 0, WG_INIT_LEN, WG_RESP_LEN, WG_COOKIE_MSG_LEN };
    uint8_t copy[2048];
    uint32_t t;
    size_t off, mlen;

    if (len > sizeof(copy)) return;
    memcpy(copy, msg, len);
    if (!wg_codec_awg.classify(&h->awg, copy, len, &t, &off, &mlen)) {
        h->unreadable++;
        h->run++;
        return;
    }
    h->awg_sent[t]++;
    if (t == WG_MSG_INITIATION) {
        h->initiations++;
        if (h->initiations == 1 || h->run < h->ahead_min) h->ahead_min = h->run;
        if (h->run > h->ahead_max) h->ahead_max = h->run;
    }
    if (t < WG_MSG_DATA && len > off + canon[t]) h->trailers++;
    if (t == WG_MSG_DATA) {
        if (!h->data_min || len < h->data_min) h->data_min = len;
        if (len > h->data_max) h->data_max = len;
    }
    h->run = 0;
}

static void net_send(void* ctx, const wg_endpoint* to, const uint8_t* msg, size_t len)
{
    host* h = (host*)ctx;
    uint32_t init = h->dev.codec.ops == &obfs_ops ? h->codec.h[WG_MSG_INITIATION] : WG_MSG_INITIATION;
    size_t at = h->dev.codec.ops == &obfs_ops ? h->codec.prefix : 0;
    frame* f;

    h->datagrams++;
    h->last_dgram = len;
    if (len >= 4 && wg_codec_length_ok(wg_load32(msg), len)) h->canonical++;
    if (h->dev.codec.ops == &wg_codec_awg) awg_observe(h, msg, len);
    else if (len == at + WG_INIT_LEN && wg_load32(msg + at) == init) h->initiations++;
    CHECK(g_net_n < 64 && len <= sizeof(f->data));
    if (g_net_n == 64 || len > sizeof(f->data)) return;
    f = &g_net[g_net_n++];
    f->to = *to;
    f->from = h->addr;
    memcpy(f->data, msg, len);
    f->len = len;
}

static void net_deliver(void* ctx, wg_peer* from, uint8_t* pkt, size_t len)
{
    host* h = (host*)ctx;
    (void)from;
    h->delivered++;
    memcpy(h->last, pkt, len < sizeof(h->last) ? len : sizeof(h->last));
    h->last_len = len;
}

static void net_wall(void* ctx, uint64_t* sec, uint32_t* nsec)
{
    (void)ctx;
    *sec = 1759140000ULL + g_now / SEC;
    *nsec = (uint32_t)(g_now % SEC);
}

static void pump(void)
{
    static frame f;
    host* dst;
    int guard = 0;

    while (g_net_n && guard++ < 1000) {
        f = g_net[0];
        memmove(g_net, g_net + 1, (size_t)(g_net_n - 1) * sizeof(frame));
        g_net_n--;
        dst = wg_endpoint_equal(&f.to, &SRV.addr) ? &SRV : wg_endpoint_equal(&f.to, &CLI.addr) ? &CLI : NULL;
        if (dst) wg_device_receive(&dst->dev, f.data, f.len, &f.from, g_now);
    }
    CHECK(guard < 1000);
}

static void run_until(uint64_t until)
{
    uint64_t a, b, t;
    int guard = 0;

    pump();
    for (;;) {
        a = wg_device_next_deadline(&SRV.dev);
        b = wg_device_next_deadline(&CLI.dev);
        t = a < b ? a : b;
        if (t > until || guard++ >= 10000) break;
        if (t > g_now) g_now = t;
        wg_device_tick(&SRV.dev, g_now);
        wg_device_tick(&CLI.dev, g_now);
        pump();
    }
    CHECK(guard < 10000);
    if (until > g_now) g_now = until;
}

static const char SERVER_CONF[] =
    "[Interface]\n"
    "PrivateKey = %s\n"
    "ListenPort = 51820\n"
    "Address = 10.8.0.1/24, fd08::1/64\n"
    "%s"                                /* AmneziaWG's keys, if any */
    "\n"
    "[Peer]  # the phone\n"
    "PublicKey = %s\n"
    "PresharedKey = %s\n"
    "AllowedIPs = 10.8.0.2/32, fd08::2/128\n";

static const char CLIENT_CONF[] =
    "[Interface]\n"
    "PrivateKey = %s\n"
    "Address = 10.8.0.2/32, fd08::2/128\n"
    "DNS = 10.8.0.1\n"
    "MTU = 1380\n"
    "%s"
    "\n"
    "[Peer]\n"
    "PublicKey = %s\n"
    "PresharedKey = %s\n"
    "AllowedIPs = 0.0.0.0/0, ::/0\n"
    "Endpoint = 192.0.2.1:51820\n"
    "PersistentKeepalive = %s\n";

static void host_init(host* h, const char* text, uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                      uint16_t port, int obfuscated)
{
    char err[128];

    memset(h, 0, sizeof(*h));
    memcpy(h->text, text, strlen(text) + 1);
    wg_device_init(&h->dev);
    h->dev.ctx = h;
    h->dev.send = net_send;
    h->dev.deliver = net_deliver;
    h->dev.wall_clock = net_wall;
    CHECK(wg_device_set_allowedips_storage(&h->dev, h->nodes, 32));
    if (obfuscated) {
        h->codec = OBFS;
        h->dev.codec.ops = &obfs_ops;
        h->dev.codec.st = &h->codec;
    }
    wg_conf_init(&h->conf, h->cpeers, 2, h->callowed, 8);
    CHECK(wg_conf_parse(&h->conf, h->text, strlen(h->text)));
    CHECK(wg_conf_apply(&h->conf, &h->dev, &h->awg, h->peers, h->stage, 8192, g_now, err, sizeof(err)));
    h->addr.family = 4;
    h->addr.addr[0] = a;
    h->addr.addr[1] = b;
    h->addr.addr[2] = c;
    h->addr.addr[3] = d;
    h->addr.port = port;
}

/* Two fresh .conf files for one server and one phone, with extra [Interface] lines for each (its
 * AmneziaWG keys) and the phone's PersistentKeepalive; `obfs_*` puts the test codec on a side. */
static void start_with(const char* srv_extra, const char* cli_extra, const char* keepalive,
                       int obfs_server, int obfs_client)
{
    wg_key ssk, spk, csk, cpk, psk;
    char s64[45], sp64[45], c64[45], cp64[45], p64[45], text[2048];

    g_now = T0;
    g_net_n = 0;
    CHECK(wg_key_generate(&ssk, &spk) && wg_key_generate(&csk, &cpk) && wg_random(psk.b, 32));
    wg_key_to_base64(s64, &ssk);
    wg_key_to_base64(sp64, &spk);
    wg_key_to_base64(c64, &csk);
    wg_key_to_base64(cp64, &cpk);
    wg_key_to_base64(p64, &psk);

    snprintf(text, sizeof(text), SERVER_CONF, s64, srv_extra, cp64, p64);
    host_init(&SRV, text, 192, 0, 2, 1, 51820, obfs_server);
    snprintf(text, sizeof(text), CLIENT_CONF, c64, cli_extra, sp64, p64, keepalive);
    host_init(&CLI, text, 198, 51, 100, 7, 40000, obfs_client);

    wg_device_up(&SRV.dev, g_now);
    wg_device_up(&CLI.dev, g_now);
}

static void start(int obfs_server, int obfs_client)
{
    start_with("", "", "25", obfs_server, obfs_client);
}

static uint8_t pkt[1500];

static const uint8_t PHONE4[4] = { 10, 8, 0, 2 };
static const uint8_t WEB4[4] = { 1, 1, 1, 1 };

static void ip4(const uint8_t src[4], const uint8_t dst[4], size_t len, uint8_t seed)
{
    size_t i;
    memset(pkt, 0, 20);
    pkt[0] = 0x45;
    pkt[2] = (uint8_t)(len >> 8);
    pkt[3] = (uint8_t)len;
    pkt[8] = 64;
    pkt[9] = 6;
    memcpy(pkt + 12, src, 4);
    memcpy(pkt + 16, dst, 4);
    for (i = 20; i < len; i++) pkt[i] = (uint8_t)(seed + i);
}

/* The phone to the web and back, once. */
static int round_trip(uint8_t seed)
{
    wg_drop_reason why;
    int s = SRV.delivered, c = CLI.delivered;

    ip4(PHONE4, WEB4, 120, seed);
    if (!wg_device_send(&CLI.dev, pkt, 120, g_now, &why)) return 0;
    pump();
    ip4(WEB4, PHONE4, 90, (uint8_t)(seed + 1));
    if (!wg_device_send(&SRV.dev, pkt, 90, g_now, &why)) return 0;
    pump();
    return SRV.delivered == s + 1 && CLI.delivered == c + 1 && CLI.last_len == 90;
}

/* ------------------------------------------------------------------------------ tests */

TEST(two_conf_files_make_a_tunnel)
{
    static const uint8_t phone6[16] = { 0xfd, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    static const uint8_t far6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    wg_drop_reason why;

    start(0, 0);
    /* Up: the phone's persistent keepalive has started the handshake by itself. */
    pump();
    CHECK(CLI.peers[0].has_handshake && SRV.peers[0].has_handshake);
    CHECK(wg_endpoint_equal(&SRV.peers[0].endpoint, &CLI.addr));
    CHECK(CLI.dev.mtu == 1380);

    CHECK(round_trip(1));

    /* IPv6 through the same tunnel */
    memset(pkt, 0, 40);
    pkt[0] = 0x60;
    pkt[5] = 24;
    pkt[6] = 17;
    pkt[7] = 64;
    memcpy(pkt + 8, phone6, 16);
    memcpy(pkt + 24, far6, 16);
    CHECK(wg_device_send(&CLI.dev, pkt, 64, g_now, &why));
    pump();
    CHECK(SRV.delivered == 2 && SRV.last_len == 64);

    /* A full-size packet is padded no further than the phone's MTU of 1380 (1377 would round up
     * to 1392). */
    ip4(PHONE4, WEB4, 1377, 3);
    CHECK(wg_device_send(&CLI.dev, pkt, 1377, g_now, &why));
    CHECK(CLI.last_dgram == WG_DATA_MSG_LEN(1380));
    pump();
    CHECK(SRV.delivered == 3 && SRV.last_len == 1377);

    /* The phone may send as 10.8.0.2 and fd08::2 only - the server's file allows it nothing else. */
    ip4(WEB4, WEB4, 60, 4);
    CHECK(wg_device_send(&CLI.dev, pkt, 60, g_now, &why));
    pump();
    CHECK(SRV.delivered == 3 && SRV.peers[0].last_drop == WG_DROP_WRONG_SOURCE);

    /* Plain WireGuard on the wire, every datagram of it. */
    CHECK(CLI.canonical == CLI.datagrams && SRV.canonical == SRV.datagrams);
}

TEST(five_minutes_of_traffic)
{
    int i, rounds = 0, ok = 1;

    start(0, 0);
    pump();
    /* A round trip every 7 s. The phone initiated, so it renews the session every two minutes;
     * no packet is lost across the switch. */
    for (i = 1; i <= 42; i++) {
        run_until(T0 + (uint64_t)i * 7 * SEC);
        if (!round_trip((uint8_t)i)) ok = 0;
        rounds++;
    }
    CHECK(ok && rounds == 42);
    CHECK(CLI.initiations == 3 && SRV.initiations == 0);   /* at 0, 126 and 252 s */
    CHECK(CLI.peers[0].session.previous != NULL);
}

TEST(through_an_obfuscating_codec)
{
    int i, ok = 1;

    start(1, 1);
    pump();
    CHECK(CLI.peers[0].has_handshake && SRV.peers[0].has_handshake);
    for (i = 1; i <= 30; i++) {
        run_until(T0 + (uint64_t)i * 7 * SEC);
        if (!round_trip((uint8_t)i)) ok = 0;
    }
    CHECK(ok);

    /* Nothing on the wire parses as WireGuard; junk went ahead of every initiation; data carries
     * the codec's extra padding. */
    CHECK(CLI.canonical == 0 && SRV.canonical == 0);
    CHECK(CLI.initiations == 2 && CLI.codec.junk_sent == 3 * CLI.initiations);
    ip4(PHONE4, WEB4, 100, 9);
    CHECK(wg_device_send(&CLI.dev, pkt, 100, g_now, NULL));
    CHECK(CLI.last_dgram == OBFS.prefix + WG_DATA_MSG_LEN(112 + 16));
    pump();
    CHECK(SRV.last_len == 100);
}

TEST(cookie_through_the_codec)
{
    /* The server is under load: its cookie reply must travel in the codec's format too, or the
     * phone could never prove its address. */
    start(1, 1);
    SRV.dev.under_load = 1;
    pump();
    CHECK(CLI.peers[0].cookie.has_cookie && !CLI.peers[0].has_handshake);
    CHECK(SRV.canonical == 0);
    run_until(T0 + 6 * SEC);                            /* the retry carries mac2 */
    CHECK(CLI.peers[0].has_handshake && SRV.peers[0].has_handshake);
    CHECK(round_trip(1));
}

TEST(codecs_must_match)
{
    /* The phone speaks the obfuscated format, the server plain WireGuard: nothing gets through. */
    start(0, 1);
    run_until(T0 + 30 * SEC);
    CHECK(!CLI.peers[0].has_handshake && !SRV.peers[0].has_handshake);
    CHECK(SRV.peers[0].endpoint.family == 0);           /* it never heard a thing it could read */
    CHECK(CLI.initiations >= 5);                        /* the phone keeps retrying */

    /* and the other way round */
    start(1, 0);
    run_until(T0 + 30 * SEC);
    CHECK(!CLI.peers[0].has_handshake && !SRV.peers[0].has_handshake);
}

/* ------------------------------------------------------------------------------ AmneziaWG */

/* 1.x: junk ahead of initiations, prefixes on the handshake, fixed type values */
#define AWG1 "S1 = 52\nS2 = 16\nH1 = 1027243093\nH2 = 1413412324\nH3 = 2069839512\nH4 = 1661493127\n"
#define AWG1_PHONE "Jc = 4\nJmin = 40\nJmax = 70\n"

/* 2.0: every message behind a prefix, type ranges, signature packets */
#define AWG2 "S1 = 24\nS2 = 32\nS3 = 16\nS4 = 20\n" \
             "H1 = 100000-100999\nH2 = 200000-200999\nH3 = 300000-300999\nH4 = 400000-499999\n"
#define AWG2_PHONE "Jc = 5\nJmin = 10\nJmax = 50\n"                          \
                   "I1 = <b 0xc70000000108ce1bfe8e8c5a0f2a><r 32><t>\n"   \
                   "I2 = <b 0xdead><rc 8><rd 4>\n"                        \
                   "I5 = <dz 16>\n"

/* 3.x: header protection and random trailers (both ends must agree), padding and moved timers
 * (the phone's own) */
#define AWG3_KEY "HeaderProtectionKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"
#define AWG3 AWG2 AWG3_KEY "RandomTrailers = on\n"
#define AWG3_PHONE AWG2_PHONE "ContentPaddingAddition = 8-48\nRekeyAfterTime = 100-110\n" \
                              "KeepaliveTimeout = 8-12\n"

/* A round trip every 7 s; 1 when every one made it. */
static int traffic(int rounds)
{
    int i, ok = 1;

    for (i = 1; i <= rounds; i++) {
        run_until(T0 + (uint64_t)i * 7 * SEC);
        if (!round_trip((uint8_t)i)) ok = 0;
    }
    return ok;
}

TEST(amneziawg_1)
{
    start_with(AWG1, AWG1 AWG1_PHONE, "25", 0, 0);
    pump();
    CHECK(CLI.dev.codec.ops == &wg_codec_awg && SRV.dev.codec.ops == &wg_codec_awg);
    CHECK(CLI.peers[0].has_handshake && SRV.peers[0].has_handshake);
    CHECK(traffic(30));

    /* Nothing reads as WireGuard; four junk datagrams ahead of each initiation, none from the
     * server, which has no junk configured. */
    CHECK(CLI.canonical == 0 && SRV.canonical == 0);
    CHECK(CLI.initiations == 2 && CLI.ahead_min == 4 && CLI.ahead_max == 4 && CLI.unreadable == 8);
    CHECK(SRV.unreadable == 0 && SRV.awg_sent[WG_MSG_RESPONSE] == 2);
    CHECK(CLI.trailers == 0 && SRV.trailers == 0);

    /* 1.x puts nothing in front of data */
    ip4(PHONE4, WEB4, 100, 9);
    CHECK(wg_device_send(&CLI.dev, pkt, 100, g_now, NULL));
    CHECK(CLI.last_dgram == WG_DATA_MSG_LEN(112));
    pump();
    CHECK(SRV.last_len == 100);
}

TEST(amneziawg_2)
{
    start_with(AWG2, AWG2 AWG2_PHONE, "25", 0, 0);
    pump();
    CHECK(CLI.peers[0].has_handshake && SRV.peers[0].has_handshake);
    CHECK(traffic(30));
    CHECK(CLI.canonical == 0 && SRV.canonical == 0);

    /* I1, I2, I5, then five junk datagrams, ahead of every initiation */
    CHECK(CLI.initiations == 2 && CLI.ahead_min == 8 && CLI.ahead_max == 8);

    /* data behind its 20-byte prefix */
    ip4(PHONE4, WEB4, 100, 9);
    CHECK(wg_device_send(&CLI.dev, pkt, 100, g_now, NULL));
    CHECK(CLI.last_dgram == 20 + WG_DATA_MSG_LEN(112));
    pump();
    CHECK(SRV.last_len == 100);

    /* Under load, the cookie reply travels as S3 + H3 too, and the retry gets through. */
    start_with(AWG2, AWG2 AWG2_PHONE, "25", 0, 0);
    SRV.dev.under_load = 1;
    pump();
    CHECK(SRV.awg_sent[WG_MSG_COOKIE] == 1 && CLI.peers[0].cookie.has_cookie);
    CHECK(!CLI.peers[0].has_handshake);
    run_until(T0 + 6 * SEC);
    CHECK(CLI.peers[0].has_handshake && round_trip(1));
    CHECK(SRV.canonical == 0);
}

TEST(amneziawg_3)
{
    size_t lens[40], lo = 0xffff, hi = 0;
    int i, j, distinct = 0;

    start_with(AWG3, AWG3 AWG3_PHONE, "20-30", 0, 0);
    pump();
    CHECK(CLI.awg.hp && SRV.awg.hp && CLI.awg.p.random_trailers && SRV.awg.p.random_trailers);
    CHECK(CLI.dev.timing.rekey_after_time.lo == 100 && CLI.dev.timing.keepalive_timeout.hi == 12);
    CHECK(CLI.peers[0].persistent_keepalive.lo == 20 && CLI.peers[0].persistent_keepalive.hi == 30);
    CHECK(CLI.peers[0].has_handshake && SRV.peers[0].has_handshake);

    /* Five minutes: the phone renews its session 100 to 110 s after each handshake (at the next
     * packet it sends), so three initiations in all. */
    CHECK(traffic(42));
    CHECK(CLI.canonical == 0 && SRV.canonical == 0);
    CHECK(CLI.initiations == 3 && CLI.ahead_min == 8 && CLI.ahead_max == 8);

    /* Random trailers on the handshake, both ways; the server pads its data at random too. */
    CHECK(CLI.trailers > 0 && SRV.trailers > 0);
    CHECK(SRV.data_max > SRV.data_min);

    /* The phone's ContentPaddingAddition: a 120-byte packet goes out 8 to 48 bytes longer. */
    for (i = 0; i < 40; i++) {
        ip4(PHONE4, WEB4, 120, (uint8_t)i);
        CHECK(wg_device_send(&CLI.dev, pkt, 120, g_now, NULL));
        pump();
        lens[i] = CLI.last_dgram;
        if (lens[i] < lo) lo = lens[i];
        if (lens[i] > hi) hi = lens[i];
        for (j = 0; j < i && lens[j] != lens[i]; j++) {}
        if (j == i) distinct++;
    }
    CHECK(lo >= 20 + WG_DATA_MSG_LEN(120 + 8) && hi <= 20 + WG_DATA_MSG_LEN(120 + 48) && distinct > 10);
    CHECK(SRV.last_len == 120);

    /* The phone's keepalives are padded with zeroes too, and the server takes them as keepalives
     * - under the old rule (empty only) every one would have been "not IP". */
    CHECK(SRV.peers[0].last_drop == WG_DROP_NONE);

    /* Under load: a cookie reply with its trailer and header protection, then the retry. */
    start_with(AWG3, AWG3 AWG3_PHONE, "20-30", 0, 0);
    SRV.dev.under_load = 1;
    pump();
    CHECK(SRV.awg_sent[WG_MSG_COOKIE] == 1 && CLI.peers[0].cookie.has_cookie);
    run_until(T0 + 6 * SEC);
    CHECK(CLI.peers[0].has_handshake && round_trip(1));

    /* DisableCookies: no cookie reply, however loaded the server says it is. */
    start_with(AWG3 "DisableCookies = on\n", AWG3 AWG3_PHONE, "20-30", 0, 0);
    SRV.dev.under_load = 1;
    pump();
    CHECK(SRV.awg_sent[WG_MSG_COOKIE] == 0 && CLI.peers[0].has_handshake && SRV.peers[0].has_handshake);
}

TEST(amneziawg_window_follows_the_path)
{
    start_with(AWG3, AWG3 AWG3_PHONE, "25", 0, 0);
    pump();
    REQUIRE(SRV.peers[0].has_handshake);
    CHECK(SRV.awg.udp_window == WG_AWG_UDP_WINDOW);

    /* A big packet from the phone: the server learns the path carries a datagram that size. */
    ip4(PHONE4, WEB4, 1300, 1);
    CHECK(wg_device_send(&CLI.dev, pkt, 1300, g_now, NULL));
    pump();
    CHECK(SRV.last_len == 1300 && SRV.awg.udp_window == CLI.last_dgram - 16);

    /* The phone moves: the server starts over at 500, and a small packet does not widen it. */
    CLI.addr.port = 40001;
    ip4(PHONE4, WEB4, 100, 2);
    CHECK(wg_device_send(&CLI.dev, pkt, 100, g_now, NULL));
    pump();
    CHECK(SRV.last_len == 100 && wg_endpoint_equal(&SRV.peers[0].endpoint, &CLI.addr));
    CHECK(SRV.awg.udp_window == WG_AWG_UDP_WINDOW);
    CHECK(round_trip(3));                               /* and the tunnel follows it there */
}

TEST(amneziawg_must_match)
{
    /* Another header protection key: nothing is recognised. */
    start_with(AWG3, AWG2 AWG2_PHONE "HeaderProtectionKey = BAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"
               "RandomTrailers = on\n", "25", 0, 0);
    run_until(T0 + 30 * SEC);
    CHECK(!CLI.peers[0].has_handshake && !SRV.peers[0].has_handshake);
    CHECK(SRV.peers[0].endpoint.family == 0 && CLI.initiations >= 5);

    /* Another S1: the server never finds the initiation. */
    start_with(AWG1, "S1 = 51\nS2 = 16\nH1 = 1027243093\nH2 = 1413412324\nH3 = 2069839512\nH4 = 1661493127\n",
               "25", 0, 0);
    run_until(T0 + 30 * SEC);
    CHECK(!CLI.peers[0].has_handshake && SRV.peers[0].endpoint.family == 0);

    /* Another H4: the handshake goes through, the data does not. */
    start_with(AWG2, "S1 = 24\nS2 = 32\nS3 = 16\nS4 = 20\nH1 = 100000-100999\nH2 = 200000-200999\n"
               "H3 = 300000-300999\nH4 = 500000-599999\n", "25", 0, 0);
    pump();
    CHECK(CLI.peers[0].has_handshake && !round_trip(1));

    /* Plain WireGuard on one side: nothing. */
    start_with("", AWG1, "25", 0, 0);
    run_until(T0 + 30 * SEC);
    CHECK(!CLI.peers[0].has_handshake && SRV.peers[0].endpoint.family == 0);
}

int main(void)
{
    if (!wg_crypto_init()) {
        fprintf(stderr, "wg_crypto_init failed\n");
        return 2;
    }
    RUN(two_conf_files_make_a_tunnel);
    RUN(five_minutes_of_traffic);
    RUN(through_an_obfuscating_codec);
    RUN(cookie_through_the_codec);
    RUN(codecs_must_match);
    RUN(amneziawg_1);
    RUN(amneziawg_2);
    RUN(amneziawg_3);
    RUN(amneziawg_window_follows_the_path);
    RUN(amneziawg_must_match);
    wg_crypto_cleanup();
    return t_summary("test_stack");
}
