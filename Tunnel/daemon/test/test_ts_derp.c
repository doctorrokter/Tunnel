/*
 * ts_derp: the login byte for byte (ClientInfo opens with the server's key, ServerInfo from it is
 * taken, from anyone else refused), every frame a client meets, frames split anywhere (each piece
 * in a heap block of its own, so a read past a piece is an ASan error), frames too large for the
 * buffer, upcalls that break the client, the hostile greetings and frames, the wipe, and a fuzzer
 * over whole server streams. Against a real server: test/ts/derp_interop.sh (derper and
 * Headscale). The mutation check of this test: build/ts-mut/mutate.py.
 *
 * Seeded like the other fuzzers: BT_FUZZ_SEED=<hex> picks another run.
 */

#include "test_util.h"
#include "../src/ts_derp.h"
#include "wg_salsa.h"

static const uint8_t MAGIC[8] = { 0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91 };

/* ------------------------------------------------------------------ the client's side */

typedef struct {
    uint8_t   out[300 * 1024];              /* what the client wrote */
    size_t    n_out;
    int       refuse;                       /* the write upcall says no */
    int       writes;

    uint8_t   src[32];
    uint8_t   pkt[TS_DERP_MAX_PACKET];
    size_t    pkt_len;
    int       n_packets;
    size_t    total_in;

    char      info[TS_DERP_MAX_PACKET];
    size_t    info_len;
    int       n_ready;

    uint8_t   gone[32];
    int       gone_reason;
    int       n_gone;

    char      health[512];
    size_t    health_len;
    int       n_health;

    uint32_t  rc_in, rc_for;
    int       n_restart;

    ts_derp*  echo;                         /* on a packet, send it back from here */
    ts_derp*  poke;                         /* on any other upcall, send a packet from here */
} sink;

/* What the daemon may do from any upcall: send. */
static void s_poke(sink* s)
{
    if (s->poke) ts_derp_send(s->poke, s->gone, s->pkt, 0);
}

static int s_write(void* ctx, const uint8_t* a, size_t alen, const uint8_t* b, size_t blen)
{
    sink* s = (sink*)ctx;
    s->writes++;
    if (s->refuse || s->n_out + alen + blen > sizeof(s->out)) return 0;
    memcpy(s->out + s->n_out, a, alen);
    s->n_out += alen;
    if (blen) memcpy(s->out + s->n_out, b, blen);
    s->n_out += blen;
    return 1;
}

static void s_packet(void* ctx, const uint8_t src[32], uint8_t* data, size_t len)
{
    sink* s = (sink*)ctx;
    memcpy(s->src, src, 32);
    memcpy(s->pkt, data, len);
    s->pkt_len = len;
    s->n_packets++;
    s->total_in += len;
    if (s->echo) ts_derp_send(s->echo, src, data, len);
}

static void s_ready(void* ctx, const char* json, size_t len)
{
    sink* s = (sink*)ctx;
    memcpy(s->info, json, len);
    s->info_len = len;
    s->n_ready++;
    s_poke(s);
}

static void s_gone(void* ctx, const uint8_t key[32], int reason)
{
    sink* s = (sink*)ctx;
    memcpy(s->gone, key, 32);
    s->gone_reason = reason;
    s->n_gone++;
    s_poke(s);
}

static void s_health(void* ctx, const char* text, size_t len)
{
    sink* s = (sink*)ctx;
    if (len > sizeof(s->health)) len = sizeof(s->health);
    memcpy(s->health, text, len);
    s->health_len = len;
    s->n_health++;
    s_poke(s);
}

static void s_restarting(void* ctx, uint32_t in, uint32_t for_ms)
{
    sink* s = (sink*)ctx;
    s->rc_in = in;
    s->rc_for = for_ms;
    s->n_restart++;
    s_poke(s);
}

/* A scripted random source: the ClientInfo nonce is known. */
static int counting_rng(void* ctx, void* buf, size_t len)
{
    uint8_t* p = (uint8_t*)buf;
    uint8_t* next = (uint8_t*)ctx;
    size_t i;
    for (i = 0; i < len; i++) p[i] = (*next)++;
    return 1;
}

/* A random source with nothing to give. */
static int no_rng(void* ctx, void* buf, size_t len)
{
    return 0;
}

static uint8_t rng_next;
static const wg_rng RNG = { counting_rng, &rng_next };
static const wg_rng NO_RNG = { no_rng, NULL };

static sink S;
static ts_derp C;
static wg_key c_sk, c_pk;

static void client_new_rng(int preferred, const wg_rng* rng)
{
    ts_derp_io io;
    memset(&S, 0, sizeof(S));
    memset(&io, 0, sizeof(io));
    io.ctx = &S;
    io.write = s_write;
    io.packet = s_packet;
    io.ready = s_ready;
    io.peer_gone = s_gone;
    io.health = s_health;
    io.restarting = s_restarting;
    rng_next = 0x40;
    ts_derp_init(&C, &c_sk, &c_pk, preferred, rng, &io);
}

static void client_new(int preferred)
{
    client_new_rng(preferred, &RNG);
}

/*
 * One piece of the stream in a heap block of exactly its size, as a read hands it over: reading
 * past the end of the piece is then an ASan error, not a peek at the next piece of the same array.
 */
static int input_heap(const uint8_t* data, size_t len)
{
    uint8_t* piece = (uint8_t*)malloc(len ? len : 1);
    int r;

    if (!piece) return 0;
    memcpy(piece, data, len);
    r = ts_derp_input(&C, piece, len);
    free(piece);
    return r;
}

static int all_zero(const void* p, size_t n)
{
    const uint8_t* b = (const uint8_t*)p;
    size_t i;
    for (i = 0; i < n; i++)
        if (b[i]) return 0;
    return 1;
}

/* ------------------------------------------------------------------ the server's side */

typedef struct {
    wg_key  sk, pk;
    uint8_t shared[32];                     /* with the client */
} server;

static server SV;

static size_t put_frame(uint8_t* out, uint8_t type, const void* p, size_t len)
{
    out[0] = type;
    out[1] = (uint8_t)(len >> 24);
    out[2] = (uint8_t)(len >> 16);
    out[3] = (uint8_t)(len >> 8);
    out[4] = (uint8_t)len;
    if (len) memcpy(out + 5, p, len);
    return 5 + len;
}

static size_t f_server_key(uint8_t* out, const server* s, size_t extra)
{
    uint8_t p[8 + 32 + 64];
    memcpy(p, MAGIC, 8);
    memcpy(p + 8, s->pk.b, 32);
    memset(p + 40, 0xee, extra);
    return put_frame(out, TS_DERP_SERVER_KEY, p, 40 + extra);
}

/* ServerInfo sealed with `key` (normally the client's and the server's shared key). */
static size_t f_server_info(uint8_t* out, const uint8_t key[32], const char* json)
{
    static uint8_t p[24 + 16 + 8192];
    size_t n = strlen(json);
    memset(p, 0x5a, 24);
    if (n > 8192 || !wg_secretbox_seal(p + 24, (const uint8_t*)json, n, p, key)) return 0;
    return put_frame(out, TS_DERP_SERVER_INFO, p, 24 + 16 + n);
}

static size_t f_recv(uint8_t* out, const uint8_t src[32], const uint8_t* data, size_t len)
{
    static uint8_t p[32 + TS_DERP_MAX_PACKET + 64];
    memcpy(p, src, 32);
    if (len) memcpy(p + 32, data, len);
    return put_frame(out, TS_DERP_RECV_PACKET, p, 32 + len);
}

static int server_init(void)
{
    return wg_key_generate(&SV.sk, &SV.pk) && wg_box_beforenm(SV.shared, &c_pk, &SV.sk);
}

/* The client's frames, as the server reads them: the next one from `*off`. */
static int next_frame(const sink* s, size_t* off, uint8_t* type, const uint8_t** p, uint32_t* len)
{
    if (*off + 5 > s->n_out) return 0;
    *type = s->out[*off];
    *len = ((uint32_t)s->out[*off + 1] << 24) | ((uint32_t)s->out[*off + 2] << 16) |
           ((uint32_t)s->out[*off + 3] << 8) | s->out[*off + 4];
    if (*off + 5 + *len > s->n_out) return 0;
    *p = s->out + *off + 5;
    *off += 5 + *len;
    return 1;
}

static uint8_t in[400 * 1024];

/* Server key, then its info: the client logged in, READY. */
static int login_ok(int preferred)
{
    size_t n;
    client_new(preferred);
    n = f_server_key(in, &SV, 0);
    n += f_server_info(in + n, SV.shared, "{\"version\":2}");
    return ts_derp_input(&C, in, n) && C.state == TS_DERP_READY && S.n_ready == 1;
}

/* ------------------------------------------------------------------ the login */

TEST(test_login)
{
    size_t n, off = 0;
    uint8_t type, json[128], nonce[24];
    const uint8_t* p;
    uint32_t len;
    int i;

    client_new(1);
    CHECK(C.state == TS_DERP_WAIT_KEY);
    n = f_server_key(in, &SV, 0);
    REQUIRE(ts_derp_input(&C, in, n));
    CHECK(C.state == TS_DERP_WAIT_INFO);
    CHECK_MEM(C.server, SV.pk.b, 32);

    /* ClientInfo: our key, a nonce, the box. */
    REQUIRE(next_frame(&S, &off, &type, &p, &len));
    CHECK(type == TS_DERP_CLIENT_INFO);
    CHECK(len == 32 + 24 + 16 + strlen(ts_derp_client_info));
    CHECK_MEM(p, c_pk.b, 32);
    for (i = 0; i < 24; i++) nonce[i] = (uint8_t)(0x40 + i);
    CHECK_MEM(p + 32, nonce, 24);
    REQUIRE(len - 32 - 24 - 16 < sizeof(json));
    CHECK(wg_secretbox_open(json, p + 32 + 24, len - 32 - 24, p + 32, SV.shared));
    CHECK(memcmp(json, ts_derp_client_info, strlen(ts_derp_client_info)) == 0);
    CHECK(strcmp(ts_derp_client_info, "{\"version\":2,\"CanAckPings\":true}") == 0);

    /* Home region: NotePreferred(1) right after. */
    REQUIRE(next_frame(&S, &off, &type, &p, &len));
    CHECK(type == TS_DERP_NOTE_PREFERRED && len == 1 && p[0] == 1);
    CHECK(off == S.n_out);

    /* ServerInfo: READY, the JSON handed up. */
    n = f_server_info(in, SV.shared, "{\"version\":2,\"TokenBucketBytesPerSecond\":1000}");
    REQUIRE(ts_derp_input(&C, in, n));
    CHECK(C.state == TS_DERP_READY);
    CHECK(S.n_ready == 1);
    CHECK(S.info_len == strlen("{\"version\":2,\"TokenBucketBytesPerSecond\":1000}"));
    CHECK(memcmp(S.info, "{\"version\":2,\"TokenBucketBytesPerSecond\":1000}", S.info_len) == 0);

    /* Sent again later, it comes up again. */
    REQUIRE(ts_derp_input(&C, in, n));
    CHECK(S.n_ready == 2 && C.state == TS_DERP_READY);

    /* Not the home region: no NotePreferred. */
    client_new(0);
    n = f_server_key(in, &SV, 0);
    REQUIRE(ts_derp_input(&C, in, n));
    off = 0;
    REQUIRE(next_frame(&S, &off, &type, &p, &len));
    CHECK(type == TS_DERP_CLIENT_INFO);
    CHECK(off == S.n_out);
}

TEST(test_login_in_pieces)
{
    size_t n, i;

    /* A byte at a time, and a greeting longer than the key (for future use): the same login. */
    client_new(0);
    n = f_server_key(in, &SV, 24);
    n += f_server_info(in + n, SV.shared, "{}");
    for (i = 0; i < n; i++) REQUIRE(input_heap(in + i, 1));
    CHECK(C.state == TS_DERP_READY);
    CHECK(S.n_ready == 1 && S.info_len == 2);
    CHECK_MEM(C.server, SV.pk.b, 32);

    /* An empty input changes nothing. */
    CHECK(ts_derp_input(&C, in, 0));
    CHECK(C.state == TS_DERP_READY);
}

TEST(test_note_preferred)
{
    size_t n, off = 0;
    uint8_t type;
    const uint8_t* p;
    uint32_t len;

    /* Before the login: it goes with the login. */
    client_new(0);
    CHECK(ts_derp_note_preferred(&C, 1));
    CHECK(S.n_out == 0);
    n = f_server_key(in, &SV, 0);
    REQUIRE(ts_derp_input(&C, in, n));
    REQUIRE(next_frame(&S, &off, &type, &p, &len));
    REQUIRE(next_frame(&S, &off, &type, &p, &len));
    CHECK(type == TS_DERP_NOTE_PREFERRED && len == 1 && p[0] == 1);

    /* After: a frame of its own, either way. */
    CHECK(ts_derp_note_preferred(&C, 0));
    REQUIRE(next_frame(&S, &off, &type, &p, &len));
    CHECK(type == TS_DERP_NOTE_PREFERRED && len == 1 && p[0] == 0);
}

/* ------------------------------------------------------------------ frames */

TEST(test_packets)
{
    uint8_t src1[32], src2[32], data[1500];
    size_t n = 0, cut;
    int i;

    REQUIRE(login_ok(0));
    memset(src1, 0x11, 32);
    memset(src2, 0x22, 32);
    for (i = 0; i < 1500; i++) data[i] = (uint8_t)(i * 7);

    /* Three in one read: each delivered whole with its source. */
    n += f_recv(in + n, src1, data, 148);
    n += f_recv(in + n, src2, data, 1500);
    n += f_recv(in + n, src1, data, 0);
    REQUIRE(ts_derp_input(&C, in, n));
    CHECK(S.n_packets == 3);
    CHECK(S.total_in == 148 + 1500);
    CHECK_MEM(S.src, src1, 32);
    CHECK(S.pkt_len == 0);
    CHECK(C.packets_in == 3);

    /* Split at every place, each piece in a block of its own: the same. */
    n = f_recv(in, src2, data, 1500);
    for (cut = 0; cut <= n; cut += 37) {
        S.n_packets = 0;
        REQUIRE(input_heap(in, cut));
        REQUIRE(input_heap(in + cut, n - cut));
        CHECK(S.n_packets == 1);
        CHECK(S.pkt_len == 1500);
        CHECK_MEM(S.pkt, data, 1500);
        CHECK_MEM(S.src, src2, 32);
    }

    /* The largest there may be arrives; one byte more is skipped, and the stream goes on. */
    {
        static uint8_t big[TS_DERP_MAX_PACKET + 1];
        memset(big, 0xab, sizeof(big));
        S.n_packets = 0;
        n = f_recv(in, src1, big, TS_DERP_MAX_PACKET);
        REQUIRE(ts_derp_input(&C, in, n));
        CHECK(S.n_packets == 1 && S.pkt_len == TS_DERP_MAX_PACKET);
        n = f_recv(in, src1, big, TS_DERP_MAX_PACKET + 1);
        n += f_recv(in + n, src2, data, 100);
        REQUIRE(ts_derp_input(&C, in, n));
        CHECK(S.n_packets == 2);
        CHECK(S.pkt_len == 100);
        CHECK_MEM(S.src, src2, 32);
        CHECK(C.dropped_in == 1);
    }

    /* Shorter than a key: dropped, the stream goes on. */
    n = put_frame(in, TS_DERP_RECV_PACKET, src1, 31);
    n += f_recv(in + n, src1, data, 10);
    S.n_packets = 0;
    REQUIRE(ts_derp_input(&C, in, n));
    CHECK(S.n_packets == 1 && S.pkt_len == 10);
    CHECK(C.dropped_in == 2);
}

TEST(test_send)
{
    uint8_t dst[32], data[TS_DERP_MAX_PACKET + 1], type;
    const uint8_t* p;
    uint32_t len;
    size_t off;

    memset(dst, 0x33, 32);
    memset(data, 0x44, sizeof(data));

    /* Not before the login. */
    client_new(0);
    CHECK(!ts_derp_send(&C, dst, data, 10));
    CHECK(S.n_out == 0);

    /* Right after ClientInfo it may (Go's client does), and once READY. */
    {
        size_t n = f_server_key(in, &SV, 0);
        REQUIRE(ts_derp_input(&C, in, n));
    }
    off = S.n_out;
    CHECK(ts_derp_send(&C, dst, data, 10));
    REQUIRE(next_frame(&S, &off, &type, &p, &len));
    CHECK(type == TS_DERP_SEND_PACKET && len == 42);
    CHECK_MEM(p, dst, 32);
    CHECK_MEM(p + 32, data, 10);

    REQUIRE(login_ok(0));
    off = S.n_out;
    CHECK(ts_derp_send(&C, dst, data, TS_DERP_MAX_PACKET));
    REQUIRE(next_frame(&S, &off, &type, &p, &len));
    CHECK(type == TS_DERP_SEND_PACKET && len == 32 + TS_DERP_MAX_PACKET);
    CHECK(!ts_derp_send(&C, dst, data, TS_DERP_MAX_PACKET + 1));
    CHECK(ts_derp_send(&C, dst, data, 0));
    CHECK(C.packets_out == 2);

    /* A WireGuard-sized packet: every byte of the length on the wire. */
    off = S.n_out;
    CHECK(ts_derp_send(&C, dst, data, 1400));
    REQUIRE(next_frame(&S, &off, &type, &p, &len));
    CHECK(type == TS_DERP_SEND_PACKET && len == 32 + 1400);
    CHECK_MEM(p + 32, data, 1400);
    CHECK(off == S.n_out);
    CHECK(C.state == TS_DERP_READY);
}

TEST(test_small_frames)
{
    uint8_t p[64], type;
    const uint8_t* q;
    uint32_t len;
    size_t n, off;
    int i;

    REQUIRE(login_ok(0));
    for (i = 0; i < 64; i++) p[i] = (uint8_t)(0xa0 + i);

    /* Ping: its first 8 bytes back in a Pong. A short one is dropped. */
    off = S.n_out;
    n = put_frame(in, TS_DERP_PING, p, 8);
    n += put_frame(in + n, TS_DERP_PING, p + 8, 12);
    n += put_frame(in + n, TS_DERP_PING, p, 7);
    REQUIRE(ts_derp_input(&C, in, n));
    REQUIRE(next_frame(&S, &off, &type, &q, &len));
    CHECK(type == TS_DERP_PONG && len == 8);
    CHECK_MEM(q, p, 8);
    REQUIRE(next_frame(&S, &off, &type, &q, &len));
    CHECK(type == TS_DERP_PONG && len == 8);
    CHECK_MEM(q, p + 8, 8);
    CHECK(off == S.n_out);

    /* PeerGone, with a reason and without (an old server: "disconnected"); short = dropped. */
    p[32] = TS_DERP_GONE_NOT_HERE;
    n = put_frame(in, TS_DERP_PEER_GONE, p, 33);
    REQUIRE(ts_derp_input(&C, in, n));
    CHECK(S.n_gone == 1 && S.gone_reason == TS_DERP_GONE_NOT_HERE);
    CHECK_MEM(S.gone, p, 32);
    n = put_frame(in, TS_DERP_PEER_GONE, p + 1, 32);
    n += put_frame(in + n, TS_DERP_PEER_GONE, p, 31);
    REQUIRE(ts_derp_input(&C, in, n));
    CHECK(S.n_gone == 2 && S.gone_reason == TS_DERP_GONE_DISCONNECTED);
    CHECK_MEM(S.gone, p + 1, 32);

    /* Health: the text; empty = healthy again. */
    n = put_frame(in, TS_DERP_HEALTH, "duplicate", 9);
    n += put_frame(in + n, TS_DERP_HEALTH, "", 0);
    REQUIRE(ts_derp_input(&C, in, n));
    CHECK(S.n_health == 2 && S.health_len == 0);

    /* Restarting: two big-endian durations. */
    {
        uint8_t r[8] = { 0, 0, 0x03, 0xe8, 0, 0, 0x27, 0x10 };
        n = put_frame(in, TS_DERP_RESTARTING, r, 8);
        n += put_frame(in + n, TS_DERP_RESTARTING, r, 7);
        REQUIRE(ts_derp_input(&C, in, n));
        CHECK(S.n_restart == 1 && S.rc_in == 1000 && S.rc_for == 10000);
    }

    /* Skipped, not answered: KeepAlive, Pong, PeerPresent, a second ServerKey, unknown types -
     * large ones too. */
    off = S.n_out;
    n = put_frame(in, TS_DERP_KEEP_ALIVE, NULL, 0);
    n += put_frame(in + n, TS_DERP_PONG, p, 8);
    n += put_frame(in + n, TS_DERP_PEER_PRESENT, p, 41);
    n += f_server_key(in + n, &SV, 0);
    n += put_frame(in + n, 0x7f, p, 64);
    {
        static uint8_t junk[200 * 1024];
        memset(junk, 0x5c, sizeof(junk));
        n += put_frame(in + n, 0x42, junk, sizeof(junk));
    }
    n += f_recv(in + n, p, p, 5);
    S.n_packets = 0;
    REQUIRE(ts_derp_input(&C, in, n));
    CHECK(S.n_out == off);
    CHECK(S.n_packets == 1 && S.pkt_len == 5);
    CHECK(C.state == TS_DERP_READY);
}

/*
 * A frame too large for the buffer is skipped whatever its type: nothing of it is handed up or
 * answered. The buffer still holds the frame before - a packet the engine may have decrypted in
 * place - so one that slipped through would hand that up again, or send 8 bytes of it to the
 * server in a Pong.
 */
TEST(test_oversized)
{
    static const uint8_t types[] = { TS_DERP_RECV_PACKET, TS_DERP_PING, TS_DERP_PEER_GONE, TS_DERP_HEALTH,
                                     TS_DERP_RESTARTING };
    static uint8_t big[TS_DERP_KEY_LEN + TS_DERP_MAX_PACKET + 1];     /* a byte over the buffer */
    uint8_t src[32], data[100];
    size_t i, n, off;

    REQUIRE(login_ok(0));
    memset(big, 0x6b, sizeof(big));
    memset(src, 0x21, sizeof(src));
    memset(data, 0x99, sizeof(data));
    for (i = 0; i < sizeof(types); i++) {
        S.n_packets = 0;
        off = S.n_out;
        n = f_recv(in, src, data, sizeof(data));
        n += put_frame(in + n, types[i], big, sizeof(big));
        n += f_recv(in + n, src, data, 10);
        REQUIRE(ts_derp_input(&C, in, n));
        CHECK(S.n_packets == 2 && S.pkt_len == 10);
        CHECK(S.n_out == off);
        CHECK(S.n_gone == 0 && S.n_health == 0 && S.n_restart == 0);
        CHECK(C.dropped_in == i + 1);
        CHECK(C.state == TS_DERP_READY);
    }
}

/* The packet upcall sends at once - through the same client - as the engine's reply does. */
TEST(test_reentry)
{
    uint8_t src[32], data[200], type;
    const uint8_t* p;
    uint32_t len;
    size_t n, off;

    REQUIRE(login_ok(0));
    S.echo = &C;
    memset(src, 0x77, 32);
    memset(data, 0x12, sizeof(data));
    off = S.n_out;
    n = f_recv(in, src, data, sizeof(data));
    n += f_recv(in + n, src, data, 20);
    REQUIRE(ts_derp_input(&C, in, n));
    CHECK(S.n_packets == 2);
    REQUIRE(next_frame(&S, &off, &type, &p, &len));
    CHECK(type == TS_DERP_SEND_PACKET && len == 32 + sizeof(data));
    CHECK_MEM(p, src, 32);
    REQUIRE(next_frame(&S, &off, &type, &p, &len));
    CHECK(type == TS_DERP_SEND_PACKET && len == 32 + 20);
}

/*
 * An upcall whose send cannot be queued breaks the client, and nothing after its frame is handled:
 * the rest of the same read does not come up from a client that is BROKEN.
 */
TEST(test_upcall_breaks)
{
    uint8_t src[32], data[64], r[8] = { 0, 0, 0x03, 0xe8, 0, 0, 0x27, 0x10 };
    size_t n = 0;
    int kind;

    memset(src, 0x31, sizeof(src));
    memset(data, 0x32, sizeof(data));
    for (kind = 0; kind < 5; kind++) {
        REQUIRE(login_ok(0));
        switch (kind) {
        case 0:
            n = f_recv(in, src, data, sizeof(data));
            break;
        case 1:
            n = f_server_info(in, SV.shared, "{}");
            break;
        case 2:
            n = put_frame(in, TS_DERP_PEER_GONE, src, 32);
            break;
        case 3:
            n = put_frame(in, TS_DERP_HEALTH, "x", 1);
            break;
        default:
            n = put_frame(in, TS_DERP_RESTARTING, r, 8);
            break;
        }
        n += f_recv(in + n, src, data, 10);
        S.echo = &C;
        S.poke = &C;
        S.refuse = 1;
        S.n_packets = 0;
        CHECK(!ts_derp_input(&C, in, n));
        CHECK(C.state == TS_DERP_BROKEN && C.error != NULL);
        CHECK(S.n_packets == (kind == 0 ? 1 : 0));
    }
}

/* ts_derp_clear leaves no key and no packet in the struct. */
TEST(test_clear)
{
    uint8_t src[32], data[64];
    size_t n;

    REQUIRE(login_ok(0));
    memset(src, 0x41, sizeof(src));
    memset(data, 0x42, sizeof(data));
    n = f_recv(in, src, data, sizeof(data));
    REQUIRE(ts_derp_input(&C, in, n));
    REQUIRE(S.n_packets == 1);
    ts_derp_clear(&C);
    CHECK(all_zero(C.priv.b, sizeof(C.priv.b)));
    CHECK(all_zero(C.shared, sizeof(C.shared)));
    CHECK(all_zero(C.buf, sizeof(C.buf)));
}

/* ------------------------------------------------------------------ what breaks it */

static int breaks(const uint8_t* data, size_t n)
{
    int r = ts_derp_input(&C, data, n);
    return r == 0 && C.state == TS_DERP_BROKEN && C.error != NULL;
}

TEST(test_hostile)
{
    uint8_t p[2048], other[32];
    size_t n, i;
    server wrong;

    memset(p, 0, sizeof(p));

    /* Not a DERP server: another frame first, a short or long greeting, no magic (any of its 8
     * bytes wrong). */
    client_new(0);
    n = put_frame(in, TS_DERP_RECV_PACKET, p, 40);
    CHECK(breaks(in, n));
    client_new(0);
    memcpy(p, MAGIC, 8);
    n = put_frame(in, TS_DERP_SERVER_KEY, p, 39);
    CHECK(breaks(in, n));
    client_new(0);
    n = put_frame(in, TS_DERP_SERVER_KEY, p, 1025);
    CHECK(breaks(in, n));
    for (i = 0; i < 8; i++) {
        client_new(0);
        n = f_server_key(in, &SV, 0);
        in[5 + i] ^= 1;
        CHECK(breaks(in, n));
        CHECK(S.n_out == 0);
    }
    client_new(0);
    CHECK(breaks((const uint8_t*)"HTTP/1.1 200 OK\r\n", 17));

    /* The first frame of another type breaks it even when it carries a whole greeting (ServerInfo
     * before ServerKey, say); a greeting too short for the key breaks it at its header, whatever
     * the bytes after it would hold. */
    client_new(0);
    n = f_server_key(in, &SV, 0);
    in[0] = TS_DERP_SERVER_INFO;
    CHECK(breaks(in, n));
    client_new(0);
    n = f_server_key(in, &SV, 0);
    in[0] = TS_DERP_RECV_PACKET;
    CHECK(breaks(in, n));
    CHECK(S.n_out == 0);
    client_new(0);
    put_frame(in, TS_DERP_SERVER_KEY, p, 39);
    CHECK(breaks(in, 5));

    /* 1024 bytes is the longest greeting the reference reads: still a server. */
    client_new(0);
    memcpy(p + 8, SV.pk.b, 32);
    memset(p + 40, 0xee, 1024 - 40);
    n = put_frame(in, TS_DERP_SERVER_KEY, p, 1024);
    CHECK(ts_derp_input(&C, in, n) && C.state == TS_DERP_WAIT_INFO);
    CHECK_MEM(C.server, SV.pk.b, 32);

    /* No random bytes for the nonce: no login goes out sealed under whatever the stack held. */
    client_new_rng(0, &NO_RNG);
    n = f_server_key(in, &SV, 0);
    CHECK(breaks(in, n));
    CHECK(S.n_out == 0);

    /* A key with no usable secret (zero, a low-order point). */
    client_new(0);
    memset(p + 8, 0, 32);
    n = put_frame(in, TS_DERP_SERVER_KEY, p, 40);
    CHECK(breaks(in, n));
    CHECK(S.n_out == 0);

    /* ServerInfo tampered with, short, or from another key. */
    client_new(0);
    n = f_server_key(in, &SV, 0);
    n += f_server_info(in + n, SV.shared, "{\"version\":2}");
    in[n - 3] ^= 0x80;
    CHECK(breaks(in, n));
    CHECK(S.n_ready == 0);
    client_new(0);
    n = f_server_key(in, &SV, 0);
    n += put_frame(in + n, TS_DERP_SERVER_INFO, p, 39);
    CHECK(breaks(in, n));
    client_new(0);
    REQUIRE(wg_key_generate(&wrong.sk, &wrong.pk));
    REQUIRE(wg_box_beforenm(wrong.shared, &c_pk, &wrong.sk));
    n = f_server_key(in, &SV, 0);
    n += f_server_info(in + n, wrong.shared, "{\"version\":2}");
    CHECK(breaks(in, n));

    /* ... or too long: its text is opened into a buffer of 4096 bytes - that many are taken, one
     * more is refused before anything is opened. */
    {
        static char json[4098];
        memset(json, 'j', sizeof(json));
        json[4096] = '\0';
        client_new(0);
        n = f_server_key(in, &SV, 0);
        n += f_server_info(in + n, SV.shared, json);
        CHECK(ts_derp_input(&C, in, n) && C.state == TS_DERP_READY);
        CHECK(S.n_ready == 1 && S.info_len == 4096);
        json[4096] = 'j';
        json[4097] = '\0';
        client_new(0);
        n = f_server_key(in, &SV, 0);
        n += f_server_info(in + n, SV.shared, json);
        CHECK(breaks(in, n));
        CHECK(S.n_ready == 0);
    }

    /* A frame of 1 MiB is the largest there may be: skipped, the stream goes on. */
    REQUIRE(login_ok(0));
    {
        static const uint8_t mib[5] = { 0x42, 0x00, 0x10, 0x00, 0x00 };
        size_t left = TS_DERP_FRAME_MAX;
        REQUIRE(ts_derp_input(&C, mib, sizeof(mib)));
        memset(in, 0, sizeof(in));
        while (left) {
            size_t k = left < sizeof(in) ? left : sizeof(in);
            REQUIRE(ts_derp_input(&C, in, k));
            left -= k;
        }
        n = f_recv(in, p, p, 10);
        S.n_packets = 0;
        REQUIRE(ts_derp_input(&C, in, n));
        CHECK(S.n_packets == 1 && S.pkt_len == 10);
        CHECK(C.state == TS_DERP_READY);
    }

    /* A frame over 1 MiB, READY or not. */
    REQUIRE(login_ok(0));
    in[0] = TS_DERP_RECV_PACKET;
    in[1] = 0x00;
    in[2] = 0x10;
    in[3] = 0x00;
    in[4] = 0x01;
    CHECK(breaks(in, 5));

    /* Broken stays broken: nothing more comes out, nothing more goes in. */
    memset(other, 1, 32);
    n = f_recv(in, other, p, 10);
    S.n_packets = 0;
    CHECK(!ts_derp_input(&C, in, n));
    CHECK(S.n_packets == 0);
    CHECK(!ts_derp_send(&C, other, p, 10));
    CHECK(!ts_derp_note_preferred(&C, 1));

    /* A write refused: the login breaks the client. */
    client_new(0);
    S.refuse = 1;
    n = f_server_key(in, &SV, 0);
    CHECK(breaks(in, n));
    CHECK(S.writes == 1);

    /* ... and so does a packet then. */
    REQUIRE(login_ok(0));
    S.refuse = 1;
    CHECK(!ts_derp_send(&C, other, p, 10));
    CHECK(C.state == TS_DERP_BROKEN);
}

/* ------------------------------------------------------------------ fuzzing */

static uint64_t xs = 0x9e3779b97f4a7c15ULL;

static uint64_t rnd(void)
{
    xs ^= xs >> 12;
    xs ^= xs << 25;
    xs ^= xs >> 27;
    return xs * 0x2545f4914f6cdd1dULL;
}

static uint8_t seed_stream[64 * 1024];
static size_t seed_len;
static uint8_t fz[96 * 1024];

static void build_seed(void)
{
    uint8_t src[32], data[1400], r[8] = { 0, 0, 0, 1, 0, 0, 0, 2 };
    size_t n = 0;
    int i;

    memset(src, 0x5e, 32);
    for (i = 0; i < (int)sizeof(data); i++) data[i] = (uint8_t)i;
    n += f_server_key(seed_stream + n, &SV, 0);
    n += f_server_info(seed_stream + n, SV.shared, "{\"version\":2}");
    for (i = 0; i < 12; i++) n += f_recv(seed_stream + n, src, data, (size_t)(i * 117) % 1400);
    n += put_frame(seed_stream + n, TS_DERP_PING, data, 8);
    n += put_frame(seed_stream + n, TS_DERP_KEEP_ALIVE, NULL, 0);
    n += put_frame(seed_stream + n, TS_DERP_PEER_GONE, data, 33);
    n += put_frame(seed_stream + n, TS_DERP_HEALTH, "x", 1);
    n += put_frame(seed_stream + n, TS_DERP_RESTARTING, r, 8);
    n += f_server_info(seed_stream + n, SV.shared, "{}");
    seed_len = n;
}

static void mutate(uint8_t* buf, size_t* len, size_t cap)
{
    size_t n = *len, i, at;
    int k = (int)(rnd() % 6), times = 1 + (int)(rnd() % 4);

    switch (k) {
    case 0: while (n && times--) buf[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8)); break;
    case 1: while (n && times--) buf[rnd() % n] = (uint8_t)rnd(); break;
    case 2: if (n) *len = rnd() % n; break;
    case 3:
        at = n + 1 + rnd() % 256;
        if (at > cap) at = cap;
        for (i = n; i < at; i++) buf[i] = (uint8_t)rnd();
        *len = at;
        break;
    case 4:
        /* a length field: the most interesting four bytes of any frame */
        if (n > 5) {
            size_t f = rnd() % (n - 5);
            buf[f + 1 + rnd() % 4] = (uint8_t)rnd();
        }
        break;
    default:
        if (n > 2) {
            size_t from = rnd() % n, cnt = 1 + rnd() % (n - from);
            if (n + cnt <= cap) {
                memmove(buf + from + cnt, buf + from, n - from);
                *len = n + cnt;
            }
        }
        break;
    }
}

TEST(test_fuzz)
{
    int iter, iters = 3000, broke = 0, ready = 0;
    const char* seed = getenv("BT_FUZZ_SEED");

    if (seed) xs = strtoull(seed, NULL, 16) | 1;
    build_seed();
    for (iter = 0; iter < iters; iter++) {
        size_t len = seed_len, off = 0;
        int m, muts = 1 + (int)(rnd() % 3);

        memcpy(fz, seed_stream, seed_len);
        for (m = 0; m < muts; m++) mutate(fz, &len, sizeof(fz));
        client_new((int)(rnd() & 1));
        while (off < len) {
            size_t chunk = 1 + rnd() % 3000;
            if (chunk > len - off) chunk = len - off;
            if (!input_heap(fz + off, chunk)) break;
            off += chunk;
            if (rnd() % 8 == 0) ts_derp_send(&C, fz, fz, rnd() % 100);
        }
        /* Properties: broken has a reason and stays broken; packets never exceed the limit;
         * READY only with the server's key; what went out is whole frames. */
        if (C.state == TS_DERP_BROKEN) {
            broke++;
            CHECK(C.error != NULL);
            CHECK(!ts_derp_input(&C, seed_stream, 5));
        }
        if (C.state == TS_DERP_READY) {
            ready++;
            CHECK(memcmp(C.server, SV.pk.b, 32) == 0);
        }
        CHECK(S.pkt_len <= TS_DERP_MAX_PACKET);
        {
            size_t o = 0;
            uint8_t type;
            const uint8_t* p;
            uint32_t flen;
            while (next_frame(&S, &o, &type, &p, &flen)) {}
            CHECK(o == S.n_out);
        }
        ts_derp_clear(&C);
    }
    printf("    fuzz: %d streams, %d broke, %d logged in\n", iters, broke, ready);
    CHECK(broke > 0 && ready > 0);
}

int main(void)
{
    if (!wg_crypto_init()) return 2;
    if (!wg_key_generate(&c_sk, &c_pk) || !server_init()) return 2;
    printf("ts_derp\n");
    RUN(test_login);
    RUN(test_login_in_pieces);
    RUN(test_note_preferred);
    RUN(test_packets);
    RUN(test_send);
    RUN(test_small_frames);
    RUN(test_oversized);
    RUN(test_reentry);
    RUN(test_upcall_breaks);
    RUN(test_clear);
    RUN(test_hostile);
    RUN(test_fuzz);
    return t_summary("ts_derp");
}
