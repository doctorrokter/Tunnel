/*
 * ts_stun - see ts_stun.h.
 */

#include "ts_stun.h"

#include <string.h>

#define HEADER_LEN          20
#define ATTR_SOFTWARE       0x8022
#define ATTR_FINGERPRINT    0x8028
#define ATTR_MAPPED         0x0001
#define ATTR_XOR_MAPPED     0x0020
#define ATTR_XOR_MAPPED_ALT 0x8020
#define FINGERPRINT_XOR     0x5354554eu

static const uint8_t cookie[4] = { 0x21, 0x12, 0xa4, 0x42 };
static const char software[8] = { 't', 'a', 'i', 'l', 'n', 'o', 'd', 'e' };

static uint16_t be16(const uint8_t* p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void put16(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* CRC-32 (IEEE 802.3, reflected), bit by bit: it runs over 32 bytes per request. */
static uint32_t crc32_ieee(const uint8_t* p, size_t n)
{
    uint32_t c = 0xffffffffu;
    size_t i;
    int k;

    for (i = 0; i < n; i++) {
        c ^= p[i];
        for (k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xedb88320u : c >> 1;
    }
    return c ^ 0xffffffffu;
}

int ts_stun_is(const uint8_t* pkt, size_t len)
{
    return pkt && len >= HEADER_LEN && (pkt[0] & 0xc0) == 0 && memcmp(pkt + 4, cookie, 4) == 0;
}

size_t ts_stun_request(uint8_t* out, size_t cap, const uint8_t txid[TS_STUN_TXID_LEN])
{
    uint32_t fp;

    if (!out || cap < TS_STUN_REQUEST_LEN) return 0;
    put16(out, 0x0001);                             /* a binding request */
    put16(out + 2, 12 + 8);                         /* SOFTWARE and FINGERPRINT after the header */
    memcpy(out + 4, cookie, 4);
    memcpy(out + 8, txid, TS_STUN_TXID_LEN);
    put16(out + 20, ATTR_SOFTWARE);
    put16(out + 22, sizeof(software));
    memcpy(out + 24, software, sizeof(software));   /* 8 bytes: no padding */
    fp = crc32_ieee(out, 32) ^ FINGERPRINT_XOR;
    put16(out + 32, ATTR_FINGERPRINT);
    put16(out + 34, 4);
    out[36] = (uint8_t)(fp >> 24);
    out[37] = (uint8_t)(fp >> 16);
    out[38] = (uint8_t)(fp >> 8);
    out[39] = (uint8_t)fp;
    return TS_STUN_REQUEST_LEN;
}

/* An address attribute's value into `at`: family 1 or 2, the address whole. `xor` with the cookie
 * and the TxID, as XOR-MAPPED-ADDRESS has it. 0 when it is broken. */
static int address(const uint8_t* v, size_t vlen, int xor, const uint8_t* txid, wg_endpoint* at)
{
    size_t alen, i;
    uint8_t a[16];
    static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

    if (vlen < 4) return 0;
    if (v[1] == 0x01) alen = 4;
    else if (v[1] == 0x02) alen = 16;
    else return 0;
    if (vlen - 4 < alen) return 0;
    for (i = 0; i < alen; i++) {
        uint8_t x = 0;
        if (xor) x = i < 4 ? cookie[i] : txid[i - 4];
        a[i] = (uint8_t)(v[4 + i] ^ x);
    }
    memset(at, 0, sizeof(*at));
    at->port = be16(v + 2);
    if (xor) at->port ^= 0x2112;
    if (alen == 16 && memcmp(a, mapped, sizeof(mapped)) == 0) {     /* netip's Unmap */
        at->family = 4;
        memcpy(at->addr, a + 12, 4);
    } else {
        at->family = alen == 4 ? 4 : 6;
        memcpy(at->addr, a, alen);
    }
    return 1;
}

int ts_stun_parse_response(const uint8_t* pkt, size_t len, uint8_t txid[TS_STUN_TXID_LEN], wg_endpoint* at)
{
    const uint8_t* p;
    size_t rest, alen;
    const uint8_t* id;
    wg_endpoint xor_at, plain_at;
    int have_xor = 0, have_plain = 0;

    if (!ts_stun_is(pkt, len) || pkt[0] != 0x01 || pkt[1] != 0x01) return 0;
    id = pkt + 8;
    alen = be16(pkt + 2);
    rest = len - HEADER_LEN;
    if (alen > rest) return 0;
    rest = alen;                                    /* the datagram's tail past it: not looked at */
    p = pkt + HEADER_LEN;
    while (rest > 0) {
        uint16_t type, vlen;
        size_t padded;
        if (rest < 4) return 0;
        type = be16(p);
        vlen = be16(p + 2);
        padded = ((size_t)vlen + 3) & ~(size_t)3;
        p += 4;
        rest -= 4;
        if (padded > rest) return 0;
        if (type == ATTR_XOR_MAPPED || type == ATTR_XOR_MAPPED_ALT) {
            if (!address(p, vlen, 1, id, &xor_at)) return 0;
            have_xor = 1;
        } else if (type == ATTR_MAPPED) {
            if (!address(p, vlen, 0, id, &plain_at)) return 0;
            have_plain = 1;
        }
        p += padded;
        rest -= padded;
    }
    if (!have_xor && !have_plain) return 0;
    memcpy(txid, id, TS_STUN_TXID_LEN);
    *at = have_xor ? xor_at : plain_at;
    return 1;
}

/* --------------------------------------------------------------------- rounds */

static int ep_eq(const wg_endpoint* a, const wg_endpoint* b)
{
    return a->family == b->family && a->port == b->port && memcmp(a->addr, b->addr, a->family == 4 ? 4 : 16) == 0;
}

static void round_drop(ts_stun_state* st)
{
    memset(st->probe, 0, sizeof(st->probe));
    st->n = 0;
    st->round_end = 0;
    st->answers = 0;
    memset(&st->first, 0, sizeof(st->first));
    st->round_varies = 0;
}

void ts_stun_init(ts_stun_state* st, int family)
{
    memset(st, 0, sizeof(*st));
    st->family = (uint8_t)(family == 6 ? 6 : 4);
}

void ts_stun_want(ts_stun_state* st)
{
    st->want = 1;
}

void ts_stun_forget(ts_stun_state* st)
{
    round_drop(st);
    memset(&st->global, 0, sizeof(st->global));
    st->global_seen = 0;
    st->varies = 0;
    st->next = 0;
    st->want = 1;
}

void ts_stun_traffic(ts_stun_state* st, uint64_t now)
{
    if (st->n || st->want || st->next) return;
    if (st->last_end && now - st->last_end < TS_STUN_EVERY_NS) return;
    st->want = 1;
}

int ts_stun_due(ts_stun_state* st, uint64_t now, int active)
{
    if (st->n) return 0;
    if (st->next && now >= st->next) {
        st->next = 0;
        if (active) st->want = 1;       /* idle: no more of them until traffic asks */
    }
    return st->want;
}

void ts_stun_begin(ts_stun_state* st, const wg_endpoint* servers, const uint8_t (*txids)[TS_STUN_TXID_LEN],
                   size_t n, uint64_t now)
{
    size_t i;

    if (st->n || !n) return;            /* no servers: the wish stays */
    if (n > TS_STUN_SERVERS) n = TS_STUN_SERVERS;
    round_drop(st);
    for (i = 0; i < n; i++) {
        st->probe[i].server = servers[i];
        memcpy(st->probe[i].txid, txids[i], TS_STUN_TXID_LEN);
    }
    st->n = n;
    st->round_end = now + TS_STUN_ROUND_NS;
    st->want = 0;
    st->next = 0;
}

size_t ts_stun_sends(ts_stun_state* st, uint64_t now, wg_endpoint* to, uint8_t (*txid)[TS_STUN_TXID_LEN],
                     size_t cap)
{
    size_t i, k = 0;

    for (i = 0; i < st->n && k < cap; i++) {
        ts_stun_probe* p = &st->probe[i];
        if (p->answered || p->tries >= TS_STUN_TRIES) continue;
        if (p->tries && now < p->sent_at + TS_STUN_RETRY_NS) continue;
        p->tries++;
        p->sent_at = now;
        to[k] = p->server;
        memcpy(txid[k], p->txid, TS_STUN_TXID_LEN);
        k++;
    }
    return k;
}

int ts_stun_knows(const ts_stun_state* st, const wg_endpoint* from)
{
    size_t i;

    for (i = 0; i < st->n; i++)
        if (ep_eq(&st->probe[i].server, from)) return 1;
    return 0;
}

int ts_stun_answer(ts_stun_state* st, const wg_endpoint* from, const uint8_t* pkt, size_t len, uint64_t now)
{
    uint8_t txid[TS_STUN_TXID_LEN];
    wg_endpoint at;
    size_t i;

    (void)now;
    if (!st->n || !ts_stun_parse_response(pkt, len, txid, &at)) return 0;
    for (i = 0; i < st->n; i++) {
        ts_stun_probe* p = &st->probe[i];
        if (p->answered || !p->tries || !ep_eq(&p->server, from) || memcmp(p->txid, txid, TS_STUN_TXID_LEN) != 0)
            continue;
        p->answered = 1;
        p->seen = at;
        if (at.family != st->family) return 1;  /* ours, but a view in the other family says nothing */
        if (!st->answers) st->first = at;
        else if (!ep_eq(&st->first, &at)) st->round_varies = 1;
        st->answers++;
        return 1;
    }
    return 0;
}

int ts_stun_tick(ts_stun_state* st, uint64_t now, int active, uint32_t jitter)
{
    int changed = 0;
    size_t i, done = 0;

    if (st->n) {
        for (i = 0; i < st->n; i++)
            if (st->probe[i].answered) done++;
        if (done == st->n || now >= st->round_end) {
            if (st->answers) {
                if (!ep_eq(&st->global, &st->first)) changed = 1;
                st->global = st->first;
                st->global_seen = now;
                /* one server alone cannot tell: the finding stays as it was */
                if (st->answers >= 2 && st->varies != st->round_varies) {
                    st->varies = st->round_varies;
                    changed = 1;
                }
            }
            round_drop(st);
            st->last_end = now;
            st->next = active ? now + TS_STUN_EVERY_NS + (uint64_t)(jitter % 6001u) * 1000000ULL : 0;
        }
    }
    if (st->global.family && now - st->global_seen >= TS_STUN_KEEP_NS) {
        memset(&st->global, 0, sizeof(st->global));
        st->global_seen = 0;
        changed = 1;
    }
    return changed;
}

uint64_t ts_stun_next(const ts_stun_state* st)
{
    uint64_t next = ~0ULL;
    size_t i;

    if (st->n) {
        next = st->round_end;
        for (i = 0; i < st->n; i++) {
            const ts_stun_probe* p = &st->probe[i];
            if (!p->answered && p->tries && p->tries < TS_STUN_TRIES && p->sent_at + TS_STUN_RETRY_NS < next)
                next = p->sent_at + TS_STUN_RETRY_NS;
        }
    } else if (st->next) {
        next = st->next;
    }
    if (st->global.family && st->global_seen + TS_STUN_KEEP_NS < next) next = st->global_seen + TS_STUN_KEEP_NS;
    return next;
}
