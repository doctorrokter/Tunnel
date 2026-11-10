/*
 * ts_disco - see ts_disco.h.
 */

#include "ts_disco.h"

#include <string.h>

static const uint8_t disco_magic[TS_DISCO_MAGIC_LEN] = { 'T', 'S', 0xf0, 0x9f, 0x92, 0xac };

#define EP_WIRE_LEN     18          /* IP (16) and port (2) */
#define PONG_BODY_LEN   (TS_DISCO_TXID_LEN + EP_WIRE_LEN)

int ts_disco_is(const uint8_t* pkt, size_t len)
{
    return pkt && len >= TS_DISCO_HEADER_LEN && memcmp(pkt, disco_magic, TS_DISCO_MAGIC_LEN) == 0;
}

const uint8_t* ts_disco_sender(const uint8_t* pkt)
{
    return pkt + TS_DISCO_MAGIC_LEN;
}

int ts_disco_shared(uint8_t shared[WG_BOX_KEY_LEN], const uint8_t their_pub[TS_DISCO_KEY_LEN], const wg_key* our_priv)
{
    wg_key pub;

    memcpy(pub.b, their_pub, TS_DISCO_KEY_LEN);
    return wg_box_beforenm(shared, &pub, our_priv);
}

/* An endpoint as 18 bytes: IPv4 as v4-mapped IPv6. 0 for an endpoint of no family. */
static int ep_put(uint8_t* p, const wg_endpoint* e)
{
    if (e->family == 4) {
        memset(p, 0, 10);
        p[10] = p[11] = 0xff;
        memcpy(p + 12, e->addr, 4);
    } else if (e->family == 6) {
        memcpy(p, e->addr, 16);
    } else {
        return 0;
    }
    p[16] = (uint8_t)(e->port >> 8);
    p[17] = (uint8_t)e->port;
    return 1;
}

/* 18 bytes as an endpoint; a v4-mapped address comes out IPv4, as netip's Unmap does. */
static void ep_get(wg_endpoint* e, const uint8_t* p)
{
    static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

    memset(e, 0, sizeof(*e));
    if (memcmp(p, mapped, sizeof(mapped)) == 0) {
        e->family = 4;
        memcpy(e->addr, p + 12, 4);
    } else {
        e->family = 6;
        memcpy(e->addr, p, 16);
    }
    e->port = (uint16_t)((p[16] << 8) | p[17]);
}

/* The message inside the box: type, version 0, body. Returns its length, 0 when it cannot be. */
static size_t plain_put(uint8_t* p, size_t cap, const ts_disco_msg* m)
{
    size_t len = 2, i;

    if (cap < 2) return 0;
    p[0] = (uint8_t)m->type;
    p[1] = 0;
    switch (m->type) {
    case TS_DISCO_PING:
        if (m->padding > TS_DISCO_PLAIN_MAX ||
            len + TS_DISCO_TXID_LEN + (m->has_node_key ? TS_DISCO_KEY_LEN : 0) + m->padding > cap)
            return 0;
        memcpy(p + len, m->txid, TS_DISCO_TXID_LEN);
        len += TS_DISCO_TXID_LEN;
        if (m->has_node_key) {
            memcpy(p + len, m->node_key, TS_DISCO_KEY_LEN);
            len += TS_DISCO_KEY_LEN;
        }
        memset(p + len, 0, m->padding);
        return len + m->padding;
    case TS_DISCO_PONG:
        if (len + PONG_BODY_LEN > cap) return 0;
        memcpy(p + len, m->txid, TS_DISCO_TXID_LEN);
        len += TS_DISCO_TXID_LEN;
        if (!ep_put(p + len, &m->src)) return 0;
        return len + EP_WIRE_LEN;
    case TS_DISCO_CALL_ME_MAYBE:
        if (m->n_eps > TS_DISCO_EPS_MAX || len + m->n_eps * EP_WIRE_LEN > cap) return 0;
        for (i = 0; i < m->n_eps; i++) {
            if (!ep_put(p + len, &m->eps[i])) return 0;
            len += EP_WIRE_LEN;
        }
        return len;
    default:
        return 0;
    }
}

size_t ts_disco_seal(uint8_t* out, size_t cap, const ts_disco_msg* m, const uint8_t our_pub[TS_DISCO_KEY_LEN],
                     const uint8_t shared[WG_BOX_KEY_LEN], const uint8_t nonce[WG_BOX_NONCE_LEN])
{
    uint8_t plain[TS_DISCO_PLAIN_MAX];
    size_t len = plain_put(plain, sizeof(plain), m);

    if (!len || cap < TS_DISCO_HEADER_LEN + WG_BOX_TAG_LEN + len) return 0;
    memcpy(out, disco_magic, TS_DISCO_MAGIC_LEN);
    memcpy(out + TS_DISCO_MAGIC_LEN, our_pub, TS_DISCO_KEY_LEN);
    memcpy(out + TS_DISCO_MAGIC_LEN + TS_DISCO_KEY_LEN, nonce, WG_BOX_NONCE_LEN);
    if (!wg_secretbox_seal(out + TS_DISCO_HEADER_LEN, plain, len, nonce, shared)) return 0;
    return TS_DISCO_HEADER_LEN + WG_BOX_TAG_LEN + len;
}

/* disco.Parse on what was inside the box. */
static int plain_read(const uint8_t* p, size_t len, ts_disco_msg* m)
{
    uint8_t type, ver;
    size_t i;

    memset(m, 0, sizeof(*m));
    if (len < 2) return 0;
    type = p[0];
    ver = p[1];
    p += 2;
    len -= 2;
    switch (type) {
    case TS_DISCO_PING:
        if (len < TS_DISCO_TXID_LEN) return 0;
        m->type = TS_DISCO_PING;
        memcpy(m->txid, p, TS_DISCO_TXID_LEN);
        m->padding = len - TS_DISCO_TXID_LEN;
        if (len >= TS_DISCO_TXID_LEN + TS_DISCO_KEY_LEN) {
            /* 32 zero bytes are no key (Go's IsZero) - also when they were padding after no key */
            static const uint8_t zero[TS_DISCO_KEY_LEN];
            memcpy(m->node_key, p + TS_DISCO_TXID_LEN, TS_DISCO_KEY_LEN);
            m->has_node_key = memcmp(m->node_key, zero, TS_DISCO_KEY_LEN) != 0;
            m->padding -= TS_DISCO_KEY_LEN;
        }
        return 1;
    case TS_DISCO_PONG:
        if (len < PONG_BODY_LEN) return 0;
        m->type = TS_DISCO_PONG;
        memcpy(m->txid, p, TS_DISCO_TXID_LEN);
        ep_get(&m->src, p + TS_DISCO_TXID_LEN);
        return 1;
    case TS_DISCO_CALL_ME_MAYBE:
        m->type = TS_DISCO_CALL_ME_MAYBE;
        if (len % EP_WIRE_LEN != 0 || ver != 0 || len == 0) return 1;
        for (i = 0; i < len / EP_WIRE_LEN && m->n_eps < TS_DISCO_EPS_MAX; i++)
            ep_get(&m->eps[m->n_eps++], p + i * EP_WIRE_LEN);
        return 1;
    default:
        m->type = TS_DISCO_OTHER;
        return 1;
    }
}

int ts_disco_open(const uint8_t* pkt, size_t len, const uint8_t shared[WG_BOX_KEY_LEN], ts_disco_msg* m)
{
    uint8_t plain[TS_DISCO_PLAIN_MAX];
    size_t blen;

    memset(m, 0, sizeof(*m));
    if (!ts_disco_is(pkt, len)) return 0;
    blen = len - TS_DISCO_HEADER_LEN;
    if (blen < WG_BOX_TAG_LEN || blen - WG_BOX_TAG_LEN > sizeof(plain)) return 0;
    if (!wg_secretbox_open(plain, pkt + TS_DISCO_HEADER_LEN, blen, pkt + TS_DISCO_MAGIC_LEN + TS_DISCO_KEY_LEN, shared))
        return 0;
    return plain_read(plain, blen - WG_BOX_TAG_LEN, m);
}
