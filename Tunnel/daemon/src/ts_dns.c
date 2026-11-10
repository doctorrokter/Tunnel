/*
 * ts_dns - see ts_dns.h.
 */

#include "ts_dns.h"

#include <string.h>

#define DNS_HDR         12
#define T_A             1
#define T_AAAA          28
#define T_OPT           41
#define C_IN            1
#define F_QR            0x8000
#define F_OPCODE        0x7800
#define F_AA            0x0400
#define F_TC            0x0200
#define F_RD            0x0100
#define F_RA            0x0080
#define RC_NOERROR      0
#define RC_FORMERR      1
#define RC_SERVFAIL     2
#define RC_NXDOMAIN     3
#define RC_NOTIMP       4
#define NO_DEADLINE     (~0ULL)

static const uint8_t quad100_4[4] = { 100, 100, 100, 100 };
static const uint8_t quad100_6[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 };

static uint16_t rd16(const uint8_t* p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void wr16(uint8_t* p, unsigned v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint64_t fnv(const uint8_t* p, size_t n)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

/* --------------------------------------------------------------------- IP and UDP */

typedef struct {
    int            family;
    const uint8_t* src;                 /* the phone's address, in the packet */
    uint16_t       sport;
    const uint8_t* dns;                 /* the UDP payload */
    size_t         dns_len;
} udp_in;

/* An IPv4 or IPv6 packet carrying UDP to the resolver, port 53: 1 and its parts. Not taken: a
 * fragment, an IPv6 extension header (they are not walked), lengths that do not add up. */
static int udp_parse(const uint8_t* pkt, size_t len, udp_in* u)
{
    const uint8_t* udp;
    size_t ip_len, hl, udp_len, ulen;

    if (len < 1) return 0;
    if ((pkt[0] >> 4) == 4) {
        if (len < 20) return 0;
        hl = (size_t)(pkt[0] & 0x0f) * 4;
        ip_len = rd16(pkt + 2);
        if (hl < 20 || ip_len < hl + 8 || ip_len > len) return 0;
        if (pkt[9] != 17) return 0;
        if ((rd16(pkt + 6) & 0x3fff) != 0) return 0;            /* MF or an offset: a fragment */
        if (memcmp(pkt + 16, quad100_4, 4) != 0) return 0;
        u->family = 4;
        u->src = pkt + 12;
        udp = pkt + hl;
        udp_len = ip_len - hl;
    } else if ((pkt[0] >> 4) == 6) {
        if (len < 48) return 0;
        ip_len = 40 + (size_t)rd16(pkt + 4);
        if (ip_len > len || pkt[6] != 17) return 0;
        if (memcmp(pkt + 24, quad100_6, 16) != 0) return 0;
        u->family = 6;
        u->src = pkt + 8;
        udp = pkt + 40;
        udp_len = ip_len - 40;
    } else {
        return 0;
    }
    if (udp_len < 8 || rd16(udp + 2) != 53) return 0;
    ulen = rd16(udp + 4);
    if (ulen < 8 || ulen > udp_len) return 0;
    u->sport = rd16(udp);
    u->dns = udp + 8;
    u->dns_len = ulen - 8;
    return 1;
}

static uint32_t sum16(uint32_t s, const uint8_t* p, size_t n)
{
    while (n > 1) {
        s += (uint32_t)((p[0] << 8) | p[1]);
        p += 2;
        n -= 2;
    }
    if (n) s += (uint32_t)(p[0] << 8);
    return s;
}

static uint16_t fold(uint32_t s)
{
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

/* The IP packet carrying `msg` from the resolver's port 53 to the phone. 0 when it does not fit. */
static size_t udp_build(int family, const uint8_t* client, uint16_t cport, const uint8_t* msg, size_t mlen,
                        uint8_t* out, size_t cap)
{
    size_t hl = family == 4 ? 20 : 40, total = hl + 8 + mlen;
    uint8_t* udp;
    uint32_t s;
    uint16_t ck;

    if (total > cap || total > TS_DNS_PKT_MAX) return 0;
    memset(out, 0, hl + 8);
    if (family == 4) {
        out[0] = 0x45;
        wr16(out + 2, (unsigned)total);
        wr16(out + 6, 0x4000);                                  /* DF */
        out[8] = 64;
        out[9] = 17;
        memcpy(out + 12, quad100_4, 4);
        memcpy(out + 16, client, 4);
        wr16(out + 10, fold(sum16(0, out, 20)));
    } else {
        out[0] = 0x60;
        wr16(out + 4, (unsigned)(8 + mlen));
        out[6] = 17;
        out[7] = 64;
        memcpy(out + 8, quad100_6, 16);
        memcpy(out + 24, client, 16);
    }
    udp = out + hl;
    wr16(udp, 53);
    wr16(udp + 2, cport);
    wr16(udp + 4, (unsigned)(8 + mlen));
    memcpy(udp + 8, msg, mlen);
    /* the pseudo-header: both addresses, the protocol, the UDP length */
    s = family == 4 ? sum16(0, out + 12, 8) : sum16(0, out + 8, 32);
    s += 17 + (uint32_t)(8 + mlen);
    s = sum16(s, udp, 8 + mlen);
    ck = fold(s);
    wr16(udp + 6, ck ? ck : 0xffff);
    return total;
}

/* --------------------------------------------------------------------- DNS messages */

/*
 * The question's name at msg[off]: its length on the wire, and as text in lower case without the
 * trailing dot. *plain 0 when a label holds a dot, a blank or a byte beyond ASCII - no name of the
 * tailnet does; the text is then not to be looked up. 0 for a compression pointer (a question has
 * none) or a name that runs past the message or beyond TS_DNS_TEXT_MAX.
 */
static int qname(const uint8_t* msg, size_t len, size_t off, size_t* wire, char* text, size_t* tlen, int* plain)
{
    size_t p = off, t = 0, i;

    *plain = 1;
    for (;;) {
        unsigned l;
        if (p >= len) return 0;
        l = msg[p];
        if (l == 0) {
            p++;
            break;
        }
        if (l & 0xc0) return 0;
        if (p + 1 + l > len) return 0;
        if (t + (t ? 1 : 0) + l > TS_DNS_TEXT_MAX) return 0;
        if (t) text[t++] = '.';
        for (i = 0; i < l; i++) {
            uint8_t c = msg[p + 1 + i];
            if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + ('a' - 'A'));
            if (c <= ' ' || c >= 0x7f || c == '.') *plain = 0;
            text[t++] = (char)c;
        }
        p += 1 + l;
    }
    text[t] = '\0';
    *wire = p - off;
    *tlen = t;
    return 1;
}

/* Past a record's name (a pointer ends it; it is not followed). */
static int skip_name(const uint8_t* msg, size_t len, size_t* p)
{
    unsigned labels = 0;

    for (;;) {
        unsigned l;
        if (*p >= len || ++labels > 128) return 0;
        l = msg[*p];
        if (l == 0) {
            (*p)++;
            return 1;
        }
        if ((l & 0xc0) == 0xc0) {
            if (*p + 2 > len) return 0;
            *p += 2;
            return 1;
        }
        if (l & 0xc0) return 0;
        *p += 1 + l;
    }
}

/* In the copy of a query going upstream: an OPT record's UDP size cut to TS_DNS_UDP_MAX, so the answer
 * fits the tun. 0 when its records do not parse. */
static int edns_clamp(uint8_t* msg, size_t len, size_t p)
{
    unsigned an = rd16(msg + 6), ns = rd16(msg + 8), ar = rd16(msg + 10), i;

    for (i = 0; i < an + ns + ar; i++) {
        unsigned rdlen;
        if (!skip_name(msg, len, &p) || p + 10 > len) return 0;
        rdlen = rd16(msg + p + 8);
        if (i >= an + ns && rd16(msg + p) == T_OPT && rd16(msg + p + 2) > TS_DNS_UDP_MAX)
            wr16(msg + p + 2, TS_DNS_UDP_MAX);
        p += 10;
        if (p + rdlen > len) return 0;
        p += rdlen;
    }
    return 1;
}

/* A response to query `q`: its id and RD, the question when `qend` (the header and question's end;
 * 0 for none), n answers of `qtype` (4 or 16 bytes each). Into msg (512 bytes at least). */
static size_t reply(const uint8_t* q, size_t qend, int aa, unsigned rcode, unsigned qtype, int family,
                    const uint8_t (*addrs)[16], size_t n, uint8_t* msg)
{
    size_t p = DNS_HDR, i, alen = family == 4 ? 4 : 16;
    uint16_t qflags = rd16(q + 2);

    memcpy(msg, q, 2);
    wr16(msg + 2, F_QR | (qflags & (F_OPCODE | F_RD)) | (aa ? F_AA : 0) | F_RA | rcode);
    wr16(msg + 4, qend ? 1 : 0);
    wr16(msg + 6, (unsigned)n);
    wr16(msg + 8, 0);
    wr16(msg + 10, 0);
    if (qend) {
        memcpy(msg + p, q + DNS_HDR, qend - DNS_HDR);
        p = qend;
    }
    for (i = 0; i < n; i++) {
        wr16(msg + p, 0xc00c);                                  /* the question's name */
        wr16(msg + p + 2, qtype);
        wr16(msg + p + 4, C_IN);
        wr32(msg + p + 6, TS_DNS_TTL);
        wr16(msg + p + 10, (unsigned)alen);
        memcpy(msg + p + 12, addrs[i], alen);
        p += 12 + alen;
    }
    return p;
}

/* --------------------------------------------------------------------- the resolver */

void ts_dns_init(ts_dns* r, ts_dns_lookup_fn lookup, void* ctx, uint32_t seed)
{
    memset(r, 0, sizeof(*r));
    r->lookup = lookup;
    r->ctx = ctx;
    r->rng = seed ? seed : 0x9e3779b9u;
}

static uint16_t next_id(ts_dns* r)
{
    uint32_t x = r->rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    r->rng = x;
    return (uint16_t)(x ^ (x >> 16));
}

int ts_dns_is_ours(const uint8_t* pkt, size_t len)
{
    udp_in u;
    return udp_parse(pkt, len, &u);
}

ts_dns_action ts_dns_query(ts_dns* r, const uint8_t* pkt, size_t len, int can_forward, uint64_t now,
                           uint8_t* out, size_t cap, size_t* out_len, int* route)
{
    udp_in u;
    const uint8_t* m;
    uint8_t msg[600];
    uint8_t addrs[TS_DNS_ANSWERS_MAX][16];
    char text[TS_DNS_TEXT_MAX + 1];
    size_t qwire = 0, tlen = 0, qend, n = 0, mlen, i, slot;
    unsigned qtype, qclass;
    int plain = 0, family = 0, rt = -1;
    uint16_t flags;
    ts_dns_name_kind kind = TS_DNS_NAME_OTHER;

    *out_len = 0;
    if (route) *route = -1;
    if (!udp_parse(pkt, len, &u) || u.dns_len < DNS_HDR || u.dns_len > TS_DNS_PKT_MAX) {
        r->dropped++;
        return TS_DNS_DROP;
    }
    m = u.dns;
    flags = rd16(m + 2);
    if (flags & F_QR) {                                         /* a response: not for us */
        r->dropped++;
        return TS_DNS_DROP;
    }
    if (flags & F_OPCODE) {
        mlen = reply(m, 0, 0, RC_NOTIMP, 0, 4, NULL, 0, msg);
        goto answer;
    }
    if (rd16(m + 4) != 1 || !qname(m, u.dns_len, DNS_HDR, &qwire, text, &tlen, &plain) ||
        DNS_HDR + qwire + 4 > u.dns_len) {
        mlen = reply(m, 0, 0, RC_FORMERR, 0, 4, NULL, 0, msg);
        goto answer;
    }
    qend = DNS_HDR + qwire + 4;
    qtype = rd16(m + DNS_HDR + qwire);
    qclass = rd16(m + DNS_HDR + qwire + 2);
    if (plain && tlen > 0 && qclass == C_IN && r->lookup) {
        family = qtype == T_A ? 4 : qtype == T_AAAA ? 6 : 0;
        kind = r->lookup(r->ctx, text, tlen, family ? family : 4, addrs, TS_DNS_ANSWERS_MAX, &n, &rt);
        if (n > TS_DNS_ANSWERS_MAX) n = TS_DNS_ANSWERS_MAX;
        if (kind != TS_DNS_NAME_OURS || !family) n = 0;         /* another kind of record: NODATA */
    }
    if (kind == TS_DNS_NAME_OURS || kind == TS_DNS_NAME_NX) {
        mlen = reply(m, qend, 1, kind == TS_DNS_NAME_NX ? RC_NXDOMAIN : RC_NOERROR, qtype, family ? family : 4,
                     (const uint8_t (*)[16])addrs, n, msg);
        goto answer;
    }
    if (kind == TS_DNS_NAME_FAIL || (kind != TS_DNS_NAME_ROUTED && !can_forward)) {
        mlen = reply(m, qend, 0, RC_SERVFAIL, 0, 4, NULL, 0, msg);
        goto answer;
    }

    /* forwarded: a free place, an id nobody waits under, EDNS cut down */
    for (slot = 0; slot < TS_DNS_PENDING && r->wait[slot].used; slot++) {}
    if (slot == TS_DNS_PENDING || u.dns_len > cap) {
        r->dropped++;
        return TS_DNS_DROP;
    }
    memcpy(out, m, u.dns_len);
    if (!edns_clamp(out, u.dns_len, qend)) {
        mlen = reply(m, 0, 0, RC_FORMERR, 0, 4, NULL, 0, msg);
        goto answer;
    }
    {
        ts_dns_wait* w = &r->wait[slot];
        uint16_t id = 0;
        int tries, taken = 1;
        for (tries = 0; tries < 16 && taken; tries++) {
            id = next_id(r);
            taken = 0;
            for (i = 0; i < TS_DNS_PENDING; i++)
                if (r->wait[i].used && r->wait[i].id == id) taken = 1;
        }
        if (taken) {
            r->dropped++;
            return TS_DNS_DROP;
        }
        wr16(out, id);
        w->used = 1;
        w->id = id;
        w->client_id = rd16(m);
        w->family = (uint8_t)u.family;
        memset(w->client, 0, sizeof(w->client));
        memcpy(w->client, u.src, u.family == 4 ? 4 : 16);
        w->client_port = u.sport;
        w->question = fnv(m + DNS_HDR, qend - DNS_HDR);
        w->deadline = now + TS_DNS_TIMEOUT_NS;
    }
    *out_len = u.dns_len;
    if (route) *route = kind == TS_DNS_NAME_ROUTED ? rt : -1;
    r->forwarded++;
    return TS_DNS_FORWARD;

answer:
    *out_len = udp_build(u.family, u.src, u.sport, msg, mlen, out, cap);
    if (!*out_len) {
        r->dropped++;
        return TS_DNS_DROP;
    }
    r->answered++;
    return TS_DNS_ANSWER;
}

int ts_dns_answer(ts_dns* r, const uint8_t* msg, size_t len, uint8_t* out, size_t cap, size_t* out_len)
{
    uint8_t buf[TS_DNS_PKT_MAX];
    char text[TS_DNS_TEXT_MAX + 1];
    size_t qwire = 0, tlen = 0, qend, i, n, hl;
    int plain = 0;
    uint64_t h;
    ts_dns_wait* w = NULL;

    *out_len = 0;
    if (len < DNS_HDR || !(rd16(msg + 2) & F_QR) || rd16(msg + 4) != 1) return 0;
    if (!qname(msg, len, DNS_HDR, &qwire, text, &tlen, &plain) || DNS_HDR + qwire + 4 > len) return 0;
    qend = DNS_HDR + qwire + 4;
    h = fnv(msg + DNS_HDR, qend - DNS_HDR);
    for (i = 0; i < TS_DNS_PENDING; i++) {
        if (r->wait[i].used && r->wait[i].id == rd16(msg) && r->wait[i].question == h) {
            w = &r->wait[i];
            break;
        }
    }
    if (!w) return 0;
    w->used = 0;
    hl = w->family == 4 ? 20 : 40;
    if (hl + 8 + len <= TS_DNS_PKT_MAX) {
        memcpy(buf, msg, len);
        n = len;
    } else {
        /* too long for the tun: the header and the question, truncated */
        memcpy(buf, msg, qend);
        wr16(buf + 2, rd16(buf + 2) | F_TC);
        wr16(buf + 6, 0);
        wr16(buf + 8, 0);
        wr16(buf + 10, 0);
        n = qend;
    }
    wr16(buf, w->client_id);
    *out_len = udp_build(w->family, w->client, w->client_port, buf, n, out, cap);
    if (!*out_len) return 0;
    r->upstream++;
    return 1;
}

uint64_t ts_dns_expire(ts_dns* r, uint64_t now, unsigned* gone)
{
    uint64_t next = NO_DEADLINE;
    size_t i;

    if (gone) *gone = 0;
    for (i = 0; i < TS_DNS_PENDING; i++) {
        ts_dns_wait* w = &r->wait[i];
        if (!w->used) continue;
        if (now >= w->deadline) {
            w->used = 0;
            r->expired++;
            if (gone) (*gone)++;
            continue;
        }
        if (w->deadline < next) next = w->deadline;
    }
    return next;
}

void ts_dns_reset(ts_dns* r)
{
    size_t i;
    for (i = 0; i < TS_DNS_PENDING; i++) r->wait[i].used = 0;
}
