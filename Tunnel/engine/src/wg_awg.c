/*
 * wg_awg - see wg_awg.h. Each piece names the amneziawg-go code it matches (device/send.go,
 * receive.go, noise-protocol.go, noise-types.go, obf*.go at b5928ef); written from reading it, no
 * code taken.
 */

#include "wg_awg.h"
#include "wg_device.h"

#include <string.h>

enum { OP_BYTES = 1, OP_TIME, OP_RAND, OP_RANDCHARS, OP_RANDDIGITS, OP_ZEROS, OP_NOTHING };

static const size_t MSG_LEN[4] = { 0, WG_INIT_LEN, WG_RESP_LEN, WG_COOKIE_MSG_LEN };
#define TRANSPORT_MIN (WG_DATA_HEADER_LEN + WG_TAG_LEN)     /* the reference's MinMessageSize */

/* --------------------------------------------------------------------- randomness */

/* See wg_awg.rkey. Should OpenSSL fail to give a key, the bytes are zeroes. */
static void random_bytes(wg_awg* a, uint8_t* p, size_t n)
{
    static const uint8_t nonce[12] = { 0 };
    const wg_rng* rng = &a->dev->local.rng;
    size_t k;

    if (!n) return;
    if (rng->fn) {
        if (!wg_rng_bytes(rng, p, n)) memset(p, 0, n);
        return;
    }
    while (n) {
        if (!a->rleft) {
            if (!a->rblocks && !wg_random(a->rkey, sizeof(a->rkey))) {
                memset(p, 0, n);
                return;
            }
            memset(a->rbuf, 0, sizeof(a->rbuf));
            wg_chacha20_xor(a->rbuf, a->rbuf, sizeof(a->rbuf), a->rkey, nonce, a->rblocks);
            a->rblocks = a->rblocks + 1 == WG_AWG_REKEY_BLOCKS ? 0 : a->rblocks + 1;
            a->rleft = sizeof(a->rbuf);
        }
        k = n < a->rleft ? n : a->rleft;
        memcpy(p, a->rbuf + sizeof(a->rbuf) - a->rleft, k);
        a->rleft -= (uint32_t)k;
        p += k;
        n -= k;
    }
}

/* Uniform in [0, n), 0 for n == 0: the reference's fastrandn, by multiply-shift. */
static uint32_t randn(wg_awg* a, uint32_t n)
{
    uint8_t r[4];

    if (!n) return 0;
    random_bytes(a, r, sizeof(r));
    return (uint32_t)(((uint64_t)wg_load32(r) * n) >> 32);
}

/* A value of the range, both ends included (UintRange.PickOne; its full range 0..2^32-1 gives lo,
 * as there). A single value costs no randomness. */
static uint32_t pick(wg_awg* a, wg_range r)
{
    return r.hi > r.lo ? r.lo + randn(a, r.hi - r.lo + 1) : r.lo;
}

/* The UDP window only grows, up to the largest datagram known to pass. */
static void grow(wg_awg* a, size_t size)
{
    if (size > a->udp_window) a->udp_window = size > 0xffffffffu ? 0xffffffffu : (uint32_t)size;
}

static int in_range(wg_range r, uint32_t v)
{
    return r.lo <= v && v <= r.hi;
}

/* --------------------------------------------------------------------- parameters */

void wg_awg_params_default(wg_awg_params* p)
{
    int t;

    memset(p, 0, sizeof(*p));
    for (t = 1; t <= 4; t++) p->h[t].lo = p->h[t].hi = (uint32_t)t;
}

static int zero_key(const uint8_t k[WG_KEY_LEN])
{
    uint8_t acc = 0;
    int i;
    for (i = 0; i < WG_KEY_LEN; i++) acc |= k[i];
    return acc == 0;
}

int wg_awg_check(const wg_awg_params* p, const char** why)
{
    int i, j;

    for (i = 1; i <= 4; i++) {
        if (p->h[i].lo > p->h[i].hi) {
            *why = "an H range runs backwards";
            return 0;
        }
        for (j = i + 1; j <= 4; j++) {
            if (p->h[i].lo <= p->h[j].hi && p->h[j].lo <= p->h[i].hi) {
                *why = "H1-H4 must not overlap (H not set means 1, 2, 3, 4)";
                return 0;
            }
        }
        if (p->s[i] > WG_AWG_MAX_PREFIX) {
            *why = "S1-S4 larger than 1024";
            return 0;
        }
        if (!zero_key(p->hp_key) && p->s[i] < 12) {
            *why = "with HeaderProtectionKey every S1-S4 must be at least 12";
            return 0;
        }
    }
    if (p->jc && p->jmin > p->jmax) {
        *why = "Jmin is larger than Jmax";
        return 0;
    }
    return 1;
}

int wg_awg_is_plain(const wg_awg_params* p)
{
    int t;

    if (p->jc || p->random_trailers || p->content_padding.lo || p->content_padding.hi
        || !zero_key(p->hp_key))
        return 0;
    for (t = 1; t <= 4; t++) {
        if (p->s[t]) return 0;
        if (p->h[t].lo != (uint32_t)t || p->h[t].hi != (uint32_t)t) return 0;
    }
    for (t = 1; t <= 5; t++)
        if (p->i[t].nops) return 0;
    return 1;
}

/* --------------------------------------------------------------------- I-packets (obf*.go) */

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

/* strconv.Atoi, minus the negative numbers the reference then crashes on. Stops before 65540;
 * what is too long for a packet add_op refuses. */
static int parse_count(const char* s, size_t n, uint32_t* out)
{
    uint32_t v = 0;
    size_t i = 0;

    if (n && s[0] == '+') i = 1;
    if (i == n) return 0;
    for (; i < n; i++) {
        if (s[i] < '0' || s[i] > '9' || v > 6553) return 0;
        v = v * 10 + (uint32_t)(s[i] - '0');
    }
    *out = v;
    return 1;
}

static int add_op(wg_awg_chain* c, int kind, uint32_t len, uint16_t off, const char** why)
{
    if (c->nops == WG_AWG_CHAIN_OPS) {
        *why = "too many tags in one I-packet";
        return 0;
    }
    if (c->len + len > 65535) {
        *why = "an I-packet longer than 65535 bytes";
        return 0;
    }
    c->ops[c->nops].kind = (uint8_t)kind;
    c->ops[c->nops].len = (uint16_t)len;
    c->ops[c->nops].off = off;
    c->nops++;
    c->len += len;
    return 1;
}

int wg_awg_parse_chain(wg_awg_chain* c, const char* spec, size_t len, const char** why)
{
    const char *p = spec, *end = spec + len, *lt, *gt, *name, *arg;
    size_t name_n, arg_n, i;
    uint32_t n;
    int hi, lo;

    memset(c, 0, sizeof(*c));
    for (;;) {
        lt = (const char*)memchr(p, '<', (size_t)(end - p));
        if (!lt) break;
        gt = (const char*)memchr(lt, '>', (size_t)(end - lt));
        if (!gt) {
            *why = "missing enclosing >";
            return 0;
        }
        /* strings.Fields: the first word is the name, the second the argument, the rest ignored */
        for (name = lt + 1; name < gt && is_space(*name); name++) {}
        for (name_n = 0; name + name_n < gt && !is_space(name[name_n]); name_n++) {}
        for (arg = name + name_n; arg < gt && is_space(*arg); arg++) {}
        for (arg_n = 0; arg + arg_n < gt && !is_space(arg[arg_n]); arg_n++) {}
        p = gt + 1;

        if (!name_n) {
            *why = "empty tag";
            return 0;
        }
        if (name_n == 1 && name[0] == 'b') {
            if (arg_n >= 2 && arg[0] == '0' && arg[1] == 'x') {         /* only a lowercase 0x */
                arg += 2;
                arg_n -= 2;
            }
            if (!arg_n) {
                *why = "<b> needs hex bytes";
                return 0;
            }
            if (arg_n % 2) {
                *why = "<b> has an odd number of hex digits";
                return 0;
            }
            if (c->ndata + arg_n / 2 > WG_AWG_CHAIN_BYTES) {
                *why = "too many <b> bytes in one I-packet";
                return 0;
            }
            for (i = 0; i < arg_n; i += 2) {
                hi = hex_digit(arg[i]);
                lo = hex_digit(arg[i + 1]);
                if (hi < 0 || lo < 0) {
                    *why = "<b> has a character that is not hex";
                    return 0;
                }
                c->data[c->ndata + i / 2] = (uint8_t)(hi << 4 | lo);
            }
            if (!add_op(c, OP_BYTES, (uint32_t)(arg_n / 2), (uint16_t)c->ndata, why)) return 0;
            c->ndata += arg_n / 2;
        } else if (name_n == 1 && name[0] == 't') {
            if (!add_op(c, OP_TIME, 4, 0, why)) return 0;
        } else if ((name_n == 1 && name[0] == 'r') || (name_n == 2 && name[0] == 'r' && name[1] == 'c')
                   || (name_n == 2 && name[0] == 'r' && name[1] == 'd')
                   || (name_n == 2 && name[0] == 'd' && name[1] == 'z')) {
            if (!parse_count(arg, arg_n, &n)) {
                *why = "<r>, <rc>, <rd> and <dz> need a count, 0 or more";
                return 0;
            }
            if (!add_op(c, name_n == 1 ? OP_RAND : name[1] == 'c' ? OP_RANDCHARS
                           : name[1] == 'd' ? OP_RANDDIGITS : OP_ZEROS, n, 0, why))
                return 0;
        } else if ((name_n == 1 && name[0] == 'd') || (name_n == 2 && name[0] == 'd' && name[1] == 's')) {
            /* the packet's own data, and it as base64: an I-packet carries none - zero bytes */
            if (!add_op(c, OP_NOTHING, 0, 0, why)) return 0;
        } else {
            *why = "unknown tag (b, t, r, rc, rd, d, ds, dz)";
            return 0;
        }
    }
    return 1;
}

size_t wg_awg_chain_build(wg_awg* a, const wg_awg_chain* c, uint8_t* out)
{
    static const char letters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const char digits[] = "0123456789";
    wg_device* d = a->dev;
    uint64_t sec = 0;
    uint32_t nsec, t;
    size_t o = 0, k;
    int i;

    for (i = 0; i < c->nops; i++) {
        uint8_t* q = out + o;
        size_t n = c->ops[i].len;

        switch (c->ops[i].kind) {
        case OP_BYTES:
            memcpy(q, c->data + c->ops[i].off, n);
            break;
        case OP_TIME:                                   /* uint32(unix seconds), big-endian */
            if (d->wall_clock) d->wall_clock(d->ctx, &sec, &nsec);
            t = (uint32_t)sec;
            q[0] = (uint8_t)(t >> 24);
            q[1] = (uint8_t)(t >> 16);
            q[2] = (uint8_t)(t >> 8);
            q[3] = (uint8_t)t;
            break;
        case OP_RAND:
            random_bytes(a, q, n);
            break;
        case OP_RANDCHARS:
            random_bytes(a, q, n);
            for (k = 0; k < n; k++) q[k] = (uint8_t)letters[q[k] % 52];
            break;
        case OP_RANDDIGITS:
            random_bytes(a, q, n);
            for (k = 0; k < n; k++) q[k] = (uint8_t)digits[q[k] % 10];
            break;
        case OP_ZEROS:
            memset(q, 0, n);
            break;
        default:
            break;
        }
        o += n;
    }
    return o;
}

/* --------------------------------------------------------------------- the codec */

/* Header protection: n bytes at p XORed with ChaCha20 (nonce = the datagram's first 12 bytes,
 * counter 0) - from `block0` when the caller has that block already, which a data header's 16
 * bytes never outgrow. */
static void protect(const wg_awg* a, const uint8_t* datagram, uint8_t* p, size_t n,
                    const uint8_t* block0)
{
    uint8_t nonce[12];
    size_t i;

    if (block0) {
        for (i = 0; i < n && i < 64; i++) p[i] ^= block0[i];
        if (n <= 64) return;
        p += 64;
        n -= 64;
    }
    memcpy(nonce, datagram, sizeof(nonce));
    wg_chacha20_xor(p, p, n, a->p.hp_key, nonce, block0 ? 1 : 0);
}

/* CreateMessage*: the type is picked anew for every message. */
static void awg_stamp(void* st, uint32_t type, uint8_t* msg, size_t len)
{
    wg_awg* a = (wg_awg*)st;
    (void)len;
    if (type >= 1 && type <= 4) wg_store32(msg, pick(a, a->p.h[type]));
}

/* SendHandshake* and RoutineEncryption: prefix, message, header protection, trailer. */
static size_t awg_wrap(void* st, uint32_t type, const uint8_t* msg, size_t len, uint8_t* out, size_t cap)
{
    wg_awg* a = (wg_awg*)st;
    size_t s, t = 0, base;
    uint32_t window;

    if (type < 1 || type > 4) return 0;
    s = a->p.s[type];
    base = s + len;
    if (type != WG_MSG_DATA && a->p.random_trailers) {
        /* a cookie reply is the device's, with the fixed window; the others the peer's */
        window = type == WG_MSG_COOKIE ? WG_AWG_UDP_WINDOW : a->udp_window;
        t = window < base ? 0 : randn(a, (uint32_t)(window - base));
    }
    if (base + t > cap) return 0;

    random_bytes(a, out, s);
    memcpy(out + s, msg, len);
    if (a->hp) protect(a, out, out + s, type == WG_MSG_DATA ? WG_DATA_HEADER_LEN : len, NULL);
    random_bytes(a, out + base, t);
    return base + t;
}

/* SendHandshakeInitiation: the I-packets, then the junk. */
static void awg_before_initiation(void* st, uint8_t* buf, size_t cap, wg_emit_fn emit, void* ctx)
{
    wg_awg* a = (wg_awg*)st;
    uint32_t j, n;
    int i;

    for (i = 1; i <= 5; i++) {
        if (!a->p.i[i].nops || a->p.i[i].len > cap) continue;
        emit(ctx, buf, wg_awg_chain_build(a, &a->p.i[i], buf));
    }
    for (j = 0; j < a->p.jc; j++) {
        n = a->p.jmax > a->p.jmin ? a->p.jmin + randn(a, a->p.jmax - a->p.jmin) : a->p.jmin;
        if (n > cap) return;
        random_bytes(a, buf, n);
        emit(ctx, buf, n);
    }
}

/* RoutineReceiveIncoming + DeterminePacketTypeAndPadding. */
static int awg_classify(void* st, uint8_t* d, size_t len, uint32_t* type, size_t* off, size_t* mlen)
{
    wg_awg* a = (wg_awg*)st;
    uint8_t ks[64];                                     /* keystream block 0; [0:4] masks the type */
    size_t s, exp;
    uint32_t t, h;

    if (len < TRANSPORT_MIN) return 0;
    memset(ks, 0, sizeof(ks));
    if (a->hp) protect(a, d, ks, sizeof(ks), NULL);

    for (t = 1; t <= 4; t++) {
        s = a->p.s[t];
        if (t < 4) {
            exp = s + MSG_LEN[t];
            if (!(len == exp || (a->p.random_trailers && len > exp))) continue;
        } else if (len < s + TRANSPORT_MIN) {
            break;
        }
        h = wg_load32(d + s) ^ wg_load32(ks);
        if (!in_range(a->p.h[t], h)) continue;

        /* First match wins, as in the reference: undo the header protection over exactly what
         * the sender covered, and hand over the message as its macs saw it. */
        *type = t;
        *off = s;
        *mlen = t < 4 ? MSG_LEN[t] : len - s;
        if (a->hp) protect(a, d, d + s, t < 4 ? MSG_LEN[t] : WG_DATA_HEADER_LEN, ks);
        return 1;
    }
    return 0;
}

/* RoutineEncryption's choice of zeroes inside the sealed packet; the packet itself widens the
 * window first. */
static size_t awg_padding(void* st, size_t len, size_t mtu)
{
    wg_awg* a = (wg_awg*)st;
    size_t size = len + TRANSPORT_MIN + a->p.s[4], add;

    grow(a, size);
    if (a->p.content_padding.lo || a->p.content_padding.hi) {
        add = pick(a, a->p.content_padding);
        return add < a->udp_window - size ? add : a->udp_window - size;
    }
    if (a->p.random_trailers) return randn(a, (uint32_t)(a->udp_window - size));
    return wg_data_padding(len, mtu);
}

/*
 * The window learns from authentic data only (RoutineSequentialReceiver: the prefix, the header and
 * the padded packet - the datagram less its tag), and starts over when the peer moves
 * (SetEndpointFromPacket). Unlike the reference: there the "move" compares endpoint POINTERS, and
 * its standard bind allocates one per datagram, so every received batch resets the window, while
 * its mobile builds never roam and never reset it. Here it is what the reference means - one
 * window per device, which for the one-server profiles AmneziaWG is used with is per peer.
 */
static void awg_authentic(void* st, uint32_t type, size_t len, int moved)
{
    wg_awg* a = (wg_awg*)st;

    if (moved) a->udp_window = WG_AWG_UDP_WINDOW;
    if (type == WG_MSG_DATA && len >= TRANSPORT_MIN) grow(a, a->p.s[4] + len - WG_TAG_LEN);
}

const wg_codec_ops wg_codec_awg = {
    "amneziawg", awg_stamp, awg_wrap, awg_before_initiation, awg_classify, awg_padding, awg_authentic
};

void wg_awg_attach(wg_awg* a, const wg_awg_params* p, wg_device* d)
{
    memset(a, 0, sizeof(*a));
    a->p = *p;
    a->hp = !zero_key(p->hp_key);
    a->udp_window = WG_AWG_UDP_WINDOW;
    a->dev = d;
    d->codec.ops = &wg_codec_awg;
    d->codec.st = a;
}
