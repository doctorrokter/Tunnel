/*
 * Everything that takes input from outside - datagrams from the network, a .conf from the user,
 * packets from tun, text forms of keys and addresses - fed random and mutated garbage under
 * ASan/UBSan. Every input sits in a heap buffer of exactly its own size, so a read one byte past it
 * is caught. Nothing may crash, and afterwards the device must still work.
 *
 * The generator is seeded: a failure reproduces with the same seed (printed on the first line;
 * WG_FUZZ_SEED=<hex> in the environment picks another).
 */

#include "test_util.h"
#include "../src/wg_conf.h"
#include "../src/wg_device.h"

#define SEC WG_NSEC_PER_SEC
#define T0  (1000 * SEC)

static uint64_t xs = 0x6a09e667f3bcc909ULL;

static uint64_t rnd(void)
{
    xs ^= xs >> 12;
    xs ^= xs << 25;
    xs ^= xs >> 27;
    return xs * 0x2545f4914f6cdd1dULL;
}

static uint8_t* exact_copy(const void* src, size_t len)
{
    uint8_t* p = (uint8_t*)malloc(len ? len : 1);
    if (len) memcpy(p, src, len);
    return p;
}

/* One of a few kinds of damage to buf[0..*len), within cap bytes. */
static void mutate(uint8_t* buf, size_t* len, size_t cap)
{
    size_t n = *len, i, at;
    int k = (int)(rnd() % 6), times = 1 + (int)(rnd() % 4);

    switch (k) {
    case 0:                                             /* flip bits */
        while (n && times--) buf[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8));
        break;
    case 1:                                             /* random bytes */
        while (n && times--) buf[rnd() % n] = (uint8_t)rnd();
        break;
    case 2:                                             /* cut short */
        if (n) *len = rnd() % n;
        break;
    case 3:                                             /* grow with junk */
        at = n + 1 + rnd() % 64;
        if (at > cap) at = cap;
        for (i = n; i < at; i++) buf[i] = (uint8_t)rnd();
        *len = at;
        break;
    case 4:                                             /* interesting values */
        while (n && times--) {
            static const uint8_t special[] = { 0, 1, 2, 3, 4, 0x7f, 0x80, 0xff, '=', '[', ']', ',', '/', ':', '\n', '#' };
            buf[rnd() % n] = special[rnd() % sizeof(special)];
        }
        break;
    default:                                            /* duplicate a slice */
        if (n > 2 && n < cap) {
            size_t from = rnd() % n, cnt = 1 + rnd() % (n - from);
            if (n + cnt > cap) cnt = cap - n;
            memmove(buf + from + cnt, buf + from, n - from);
            *len = n + cnt;
        }
        break;
    }
}

static void net_wall_fixed(void* ctx, uint64_t* sec, uint32_t* nsec)
{
    (void)ctx;
    *sec = 1759140000ULL;
    *nsec = 0;
}

/* ------------------------------------------------------------------------------ text inputs */

static const char BASE_CONF[] =
    "[Interface]\n"
    "PrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"
    "Address = 10.8.0.2/32, fd08::2/128\n"
    "DNS = 10.8.0.1, home.lan\n"
    "MTU = 1380\n"
    "Jc = 4\nJmin = 10\nJmax = 50\nH2 = 100-200\nI1 = <b 0x01><r 4>\n"
    "S1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH4 = 1000-2000\n"
    "HeaderProtectionKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"
    "ContentPaddingAddition = 0-64\nRandomTrailers = on\nDisableCookies = off\n"
    "RekeyTimeout = 4-6\nMaxHandshakeAttempts = 10-20\n"
    "I2 = <b 0xdead><rc 8><rd 4><t><dz 3>\n"
    "[Peer]\n"
    "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\n"
    "PresharedKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"
    "AllowedIPs = 0.0.0.0/0, ::/0, 10.1.0.0/16\n"
    "Endpoint = [2001:db8::1]:51820\n"
    "PersistentKeepalive = 20-30\n";

static wg_device conf_dev;
static wg_awg conf_awg;
static wg_awg_params conf_params;

TEST(conf_garbage)
{
    static uint8_t buf[4096];
    static wg_allowedips_node nodes[8];
    wg_conf c;
    wg_conf_peer peers[2];
    wg_prefix allowed[4];
    wg_peer dpeers[2];
    char err[128];
    size_t len;
    uint8_t* in;
    long i, parsed = 0, applied = 0;

    for (i = 0; i < 20000; i++) {
        len = sizeof(BASE_CONF) - 1;
        memcpy(buf, BASE_CONF, len);
        if (i % 10 == 0) {                              /* now and then, pure noise */
            len = rnd() % 512;
            for (size_t j = 0; j < len; j++) buf[j] = (uint8_t)rnd();
        } else {
            int m = 1 + (int)(rnd() % 3);
            while (m--) mutate(buf, &len, sizeof(buf));
        }
        in = exact_copy(buf, len);
        wg_conf_init(&c, peers, 2, allowed, 4);         /* small: the "too many" paths too */
        if (wg_conf_parse(&c, (const char*)in, len)) {
            parsed++;
            /* what parsed is whole: its AmneziaWG set is valid, and it goes onto a device */
            CHECK(wg_conf_awg_params(&c, &conf_params, err, sizeof(err)));
            if (i % 4 == 1) {
                wg_device_init(&conf_dev);
                CHECK(wg_device_set_allowedips_storage(&conf_dev, nodes, 8));
                if (wg_conf_apply(&c, &conf_dev, &conf_awg, dpeers, NULL, 0, T0, err, sizeof(err))) applied++;
            }
        }
        CHECK(c.error_line >= 0 && strlen(c.error) < sizeof(c.error));
        free(in);
    }
    CHECK(parsed > 0 && applied > 0);                   /* some mutations are harmless */
}

TEST(chain_garbage)
{
    static const char base[] = "<b 0xc6000000010843290a47ba8ba2ed000044d0><r 16><t><rc 5><rd 3><dz 4><d><ds>";
    static uint8_t buf[512];
    wg_awg_params p;
    wg_awg_chain c;
    const char* why;
    uint8_t *in, *out;
    size_t len;
    long i, parsed = 0;

    wg_awg_params_default(&p);
    wg_device_init(&conf_dev);
    conf_dev.wall_clock = net_wall_fixed;
    wg_awg_attach(&conf_awg, &p, &conf_dev);
    for (i = 0; i < 50000; i++) {
        len = sizeof(base) - 1;
        memcpy(buf, base, len);
        if (i % 10 == 0) {
            len = rnd() % 128;
            for (size_t j = 0; j < len; j++) buf[j] = (uint8_t)"<>brtcdsz 0x19aF+-"[rnd() % 18];
        } else {
            int m = 1 + (int)(rnd() % 3);
            while (m--) mutate(buf, &len, sizeof(buf));
        }
        in = exact_copy(buf, len);
        why = NULL;
        if (wg_awg_parse_chain(&c, (const char*)in, len, &why)) {
            parsed++;
            out = (uint8_t*)malloc(c.len ? c.len : 1);  /* exactly what it says it builds */
            CHECK(wg_awg_chain_build(&conf_awg, &c, out) == c.len);
            free(out);
        } else {
            CHECK(why && why[0]);
        }
        free(in);
    }
    CHECK(parsed > 0);
}

TEST(text_forms_garbage)
{
    char s[64];
    uint8_t* in;
    wg_key k;
    wg_prefix p;
    uint8_t a[16];
    int fam;
    size_t len, j;
    long i;

    for (i = 0; i < 50000; i++) {
        len = rnd() % 50;
        for (j = 0; j < len; j++) s[j] = "0123456789abcdefABCDEF:./=[]+ xAZ"[rnd() % 33];
        in = exact_copy(s, len);
        (void)wg_key_from_base64(&k, (const char*)in, len);
        (void)wg_addr_parse((const char*)in, len, &fam, a);
        (void)wg_prefix_parse((const char*)in, len, &p);
        free(in);
    }
    CHECK(1);
}

TEST(ip_header_garbage)
{
    uint8_t buf[80];
    uint8_t* in;
    wg_ip ip;
    size_t len, j;
    long i, ok = 0;

    for (i = 0; i < 100000; i++) {
        len = rnd() % sizeof(buf);
        for (j = 0; j < len; j++) buf[j] = (uint8_t)rnd();
        if (len && rnd() % 2) buf[0] = (uint8_t)((rnd() % 2 ? 0x40 : 0x60) | (buf[0] & 0x0f));
        in = exact_copy(buf, len);
        if (wg_ip_parse(in, len, &ip)) {
            ok++;
            CHECK(ip.len <= len);
        }
        free(in);
    }
    CHECK(ok > 0);
}

/* ------------------------------------------------------------------------------ the wire */

typedef struct {
    wg_device          dev;
    wg_awg             awg;
    wg_peer            peer;
    uint8_t            stage[8192];
    wg_allowedips_node nodes[16];
    wg_endpoint        addr;
    uint8_t            tun4[4];
    int                delivered;
} node;

static node NA, NB;
static uint64_t g_now;

/* What the devices sent, kept as seeds for the mutations; the last 64 of them. */
static uint8_t seeds[64][1600];
static size_t seed_len[64];
static int nseeds, seed_next;

/* Datagrams in flight between A and B. */
static uint8_t inflight[64][1600];
static size_t inflight_len[64];
static node* inflight_to[64];
static int ninflight;

static void net_send(void* ctx, const wg_endpoint* to, const uint8_t* msg, size_t len)
{
    node* n = (node*)ctx;
    (void)to;
    if (len > 1600) return;
    memcpy(seeds[seed_next], msg, len);
    seed_len[seed_next] = len;
    seed_next = (seed_next + 1) % 64;
    if (nseeds < 64) nseeds++;
    if (ninflight < 64) {
        memcpy(inflight[ninflight], msg, len);
        inflight_len[ninflight] = len;
        inflight_to[ninflight] = n == &NA ? &NB : &NA;
        ninflight++;
    }
}

static void net_deliver(void* ctx, wg_peer* from, uint8_t* pkt, size_t len)
{
    (void)from;
    (void)pkt;
    (void)len;
    ((node*)ctx)->delivered++;
}

static void net_wall(void* ctx, uint64_t* sec, uint32_t* nsec)
{
    (void)ctx;
    *sec = 1759140000ULL + g_now / SEC;
    *nsec = 0;
}

static void pump(void)
{
    int guard = 0, i;
    uint8_t* in;
    node* to;
    wg_endpoint from;

    while (ninflight && guard++ < 1000) {
        in = exact_copy(inflight[0], inflight_len[0]);
        to = inflight_to[0];
        from = to == &NA ? NB.addr : NA.addr;
        i = (int)inflight_len[0];
        ninflight--;
        memmove(inflight, inflight + 1, (size_t)ninflight * sizeof(inflight[0]));
        memmove(inflight_len, inflight_len + 1, (size_t)ninflight * sizeof(inflight_len[0]));
        memmove(inflight_to, inflight_to + 1, (size_t)ninflight * sizeof(inflight_to[0]));
        wg_device_receive(&to->dev, in, (size_t)i, &from, g_now);
        free(in);
    }
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
    CHECK(wg_key_generate(&sk, &pk) && wg_device_set_private_key(&n->dev, &sk));
    CHECK(wg_device_set_allowedips_storage(&n->dev, n->nodes, 16));
    n->addr.family = 4;
    n->addr.addr[0] = 192;
    n->addr.addr[3] = host;
    n->addr.port = 51820;
    n->tun4[0] = 10;
    n->tun4[3] = host;
}

static int send_ip(node* from, node* to, size_t len)
{
    uint8_t pkt[256];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[3] = (uint8_t)len;
    memcpy(pkt + 12, from->tun4, 4);
    memcpy(pkt + 16, to->tun4, 4);
    return wg_device_send(&from->dev, pkt, len, g_now, NULL);
}

/* Real traffic between two devices, then a barrage of mutated real datagrams and noise at both;
 * with `p`, both speak AmneziaWG with those parameters. */
static void barrage(const wg_awg_params* p)
{
    static uint8_t buf[2048];
    wg_endpoint src;
    uint8_t* in;
    size_t len;
    long i;
    int a_before, b_before;

    g_now = T0;
    nseeds = seed_next = ninflight = 0;
    node_init(&NA, 1);
    node_init(&NB, 2);
    if (p) {
        wg_awg_attach(&NA.awg, p, &NA.dev);
        wg_awg_attach(&NB.awg, p, &NB.dev);
    }
    CHECK(wg_device_add_peer(&NA.dev, &NA.peer, &NB.dev.local.public_key, NA.stage, sizeof(NA.stage)));
    CHECK(wg_device_add_peer(&NB.dev, &NB.peer, &NA.dev.local.public_key, NB.stage, sizeof(NB.stage)));
    CHECK(wg_peer_allow(&NA.peer, 4, NB.tun4, 32) && wg_peer_allow(&NB.peer, 4, NA.tun4, 32));
    wg_peer_set_endpoint(&NA.peer, &NB.addr);
    wg_device_up(&NA.dev, g_now);
    wg_device_up(&NB.dev, g_now);

    /* A real exchange first, so there are real messages of every kind to mutate. */
    CHECK(send_ip(&NA, &NB, 60));
    pump();
    CHECK(send_ip(&NB, &NA, 60));
    pump();
    NB.dev.under_load = 1;                              /* a cookie reply among the seeds */
    wg_peer_initiate(&NA.peer, g_now + 6 * SEC);
    pump();
    NB.dev.under_load = 0;
    CHECK(nseeds >= 5 && NA.delivered == 1 && NB.delivered == 1);

    /* The barrage: mutated real messages and noise, to both sides, from anywhere. */
    for (i = 0; i < 60000; i++) {
        if (rnd() % 8 == 0) {
            len = rnd() % 200;
            for (size_t j = 0; j < len; j++) buf[j] = (uint8_t)rnd();
            if (len >= 4 && rnd() % 2) wg_store32(buf, (uint32_t)(1 + rnd() % 4));
        } else {
            int s = (int)(rnd() % (uint64_t)nseeds);
            len = seed_len[s];
            memcpy(buf, seeds[s], len);
            mutate(buf, &len, sizeof(buf));
        }
        src = rnd() % 4 ? NA.addr : NB.addr;
        if (rnd() % 8 == 0) src.addr[2] = (uint8_t)rnd();
        in = exact_copy(buf, len);
        wg_device_receive(rnd() % 2 ? &NA.dev : &NB.dev, in, len, &src, g_now + 7 * SEC);
        free(in);
        ninflight = 0;                                  /* whatever the garbage provoked, dropped */
    }

    /* Still a tunnel: both ways, at once. */
    g_now += 8 * SEC;
    a_before = NA.delivered;
    b_before = NB.delivered;
    CHECK(send_ip(&NA, &NB, 80));
    pump();
    CHECK(send_ip(&NB, &NA, 80));
    pump();
    CHECK(NB.delivered == b_before + 1 && NA.delivered == a_before + 1);
    CHECK(wg_endpoint_equal(&NB.peer.endpoint, &NA.addr));      /* no forgery moved it */
    if (p) CHECK(NA.awg.udp_window < 1600 && NB.awg.udp_window < 1600);   /* nor grew the window */
}

TEST(datagram_garbage)
{
    barrage(NULL);
}

TEST(datagram_garbage_amneziawg)
{
    static const char i1[] = "<b 0xc70000000108><r 20><t>";
    wg_awg_params p;
    const char* why;
    int t;

    /* 3.x at its fullest: header protection, trailers, ranges, signature packets and junk */
    wg_awg_params_default(&p);
    for (t = 1; t <= 4; t++) {
        p.s[t] = (uint32_t)(12 + t * 5);
        p.h[t].lo = (uint32_t)t * 100000;
        p.h[t].hi = (uint32_t)t * 100000 + 99999;
    }
    for (t = 0; t < WG_KEY_LEN; t++) p.hp_key[t] = (uint8_t)(t * 7 + 1);
    p.random_trailers = 1;
    p.content_padding.lo = 0;
    p.content_padding.hi = 64;
    p.jc = 3;
    p.jmin = 20;
    p.jmax = 90;
    CHECK(wg_awg_parse_chain(&p.i[1], i1, strlen(i1), &why) && wg_awg_check(&p, &why));
    barrage(&p);
}

int main(void)
{
    const char* seed = getenv("WG_FUZZ_SEED");      /* another run: WG_FUZZ_SEED=<hex> */

    if (seed) xs = strtoull(seed, NULL, 16) | 1;
    printf("test_fuzz: seed %016llx\n", (unsigned long long)xs);
    if (!wg_crypto_init()) return 2;
    RUN(conf_garbage);
    RUN(chain_garbage);
    RUN(text_forms_garbage);
    RUN(ip_header_garbage);
    RUN(datagram_garbage);
    RUN(datagram_garbage_amneziawg);
    wg_crypto_cleanup();
    return t_summary("test_fuzz");
}
