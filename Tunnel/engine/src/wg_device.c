/*
 * wg_device - see wg_device.h. The dispatch follows Linux's receive.c (wg_receive_handshake_packet,
 * wg_packet_consume_data); the per-peer work is wg_peer's.
 */

#include "wg_device.h"

#include <stddef.h>
#include <string.h>

#define PEER_OF(r) ((wg_peer*)((char*)(r) - offsetof(wg_peer, noise)))

/* The handshake states that hold a local index (see wg_noise.c). */
static int handshake_has_index(const wg_noise_handshake* hs)
{
    return hs->state == WG_HS_CREATED_INITIATION || hs->state == WG_HS_CREATED_RESPONSE
        || hs->state == WG_HS_CONSUMED_RESPONSE;
}

/* --------------------------------------------------------------------- index lookup */

/* `only`: ask that peer alone - the owner knows the sender (receive_from). NULL: every peer. */

/* The peer that sent the initiation a response answers. */
static wg_peer* peer_by_initiation(wg_device* d, wg_peer* only, uint32_t index)
{
    wg_peer* p;
    for (p = only ? only : d->peers; p; p = only ? NULL : p->next)
        if (p->noise.hs.state == WG_HS_CREATED_INITIATION && p->noise.hs.local_index == index) return p;
    return NULL;
}

static wg_peer* peer_by_keypair(wg_device* d, uint32_t index)
{
    wg_peer* p;
    for (p = d->peers; p; p = p->next)
        if (wg_session_find(&p->session, index)) return p;
    return NULL;
}

/* A cookie reply answers a handshake message; its receiver index may have become a keypair's. */
static wg_peer* peer_by_any_index(wg_device* d, wg_peer* only, uint32_t index)
{
    wg_peer* p;
    for (p = only ? only : d->peers; p; p = only ? NULL : p->next) {
        if (handshake_has_index(&p->noise.hs) && p->noise.hs.local_index == index) return p;
        if (wg_session_find(&p->session, index)) return p;
    }
    return NULL;
}

/* --------------------------------------------------------------------- wg_noise upcalls */

/* An initiation names its sender only once decrypted, in the middle of wg_noise's work - so the
 * sender the owner vouched for is checked here, before the handshake touches any peer. */
static wg_noise_remote* up_remote_get(void* ctx, const wg_key* public_key)
{
    wg_device* d = (wg_device*)ctx;
    wg_peer* p = d->rx_from;

    if (p) return memcmp(p->noise.public_key.b, public_key->b, WG_KEY_LEN) == 0 ? &p->noise : NULL;
    p = wg_device_find_peer(d, public_key);
    return p ? &p->noise : NULL;
}

/* A random index no handshake or keypair of any peer holds - of ANY peer, whoever sent the
 * datagram being answered. Nothing needs registering: the lookups above find an index wherever it
 * lives, so index_drop is not needed either. */
static int up_index_set(void* ctx, wg_noise_remote* r, uint32_t* index)
{
    wg_device* d = (wg_device*)ctx;
    uint32_t v;
    int tries;

    (void)r;
    for (tries = 0; tries < 16; tries++) {
        if (!wg_rng_bytes(&d->local.rng, &v, sizeof(v))) return 0;
        if (!peer_by_any_index(d, NULL, v)) {
            *index = v;
            return 1;
        }
    }
    return 0;
}

/* --------------------------------------------------------------------- setup */

void wg_device_init(wg_device* d)
{
    memset(d, 0, sizeof(*d));
    wg_noise_local_init(&d->local);
    d->local.ctx = d;
    d->local.remote_get = up_remote_get;
    d->local.index_set = up_index_set;
    wg_cookie_checker_init(&d->checker);
    wg_allowedips_init(&d->allowedips, NULL, 0);
    d->codec.ops = &wg_codec_wireguard;
    d->timing = wg_timing_wireguard;
    d->mtu = 1420;
}

int wg_device_set_allowedips_storage(wg_device* d, wg_allowedips_node* nodes, size_t cap)
{
    if (d->allowedips.used) return 0;
    wg_allowedips_init(&d->allowedips, nodes, cap);
    return 1;
}

int wg_device_grow_allowedips(wg_device* d, wg_allowedips_node* nodes, size_t cap,
                              wg_allowedips_node** old)
{
    return wg_allowedips_grow(&d->allowedips, nodes, cap, old);
}

void wg_device_set_timing(wg_device* d, const wg_timing* t)
{
    wg_peer* p;

    d->timing = *t;
    for (p = d->peers; p; p = p->next)
        p->session.reject_after_ns = (uint64_t)t->reject_after_time.hi * WG_NSEC_PER_SEC;
}

int wg_device_set_private_key(wg_device* d, const wg_key* private_key)
{
    wg_peer* p;

    if (!wg_noise_local_set_private_key(&d->local, private_key)) return 0;
    if (!wg_cookie_checker_set_key(&d->checker, &d->local.public_key)) return 0;
    for (p = d->peers; p; p = p->next) {
        /* as Linux's wg_noise_expire_current_peer_keypairs */
        wg_noise_remote_precompute(&p->noise);
        wg_session_expire(&p->session);
        p->has_sent_handshake = 0;
    }
    return 1;
}

wg_peer* wg_device_find_peer(wg_device* d, const wg_key* public_key)
{
    wg_peer* p;
    for (p = d->peers; p; p = p->next)
        if (memcmp(p->noise.public_key.b, public_key->b, WG_KEY_LEN) == 0) return p;
    return NULL;
}

int wg_device_add_peer(wg_device* d, wg_peer* p, const wg_key* public_key,
                       uint8_t* stage_mem, size_t stage_cap)
{
    if (wg_device_find_peer(d, public_key)) return 0;
    if (d->local.has_identity && memcmp(public_key->b, d->local.public_key.b, WG_KEY_LEN) == 0) return 0;
    wg_peer_init(p, d, public_key, stage_mem, stage_cap);
    p->next = d->peers;
    d->peers = p;
    return 1;
}

void wg_device_remove_peer(wg_device* d, wg_peer* p)
{
    wg_peer** pp;

    for (pp = &d->peers; *pp; pp = &(*pp)->next) {
        if (*pp == p) {
            *pp = p->next;
            break;
        }
    }
    wg_allowedips_remove_peer(&d->allowedips, p);
    wg_peer_reset(p);
    wg_noise_remote_wipe(&p->noise);
    wg_wipe(&p->cookie, sizeof(p->cookie));
    p->next = NULL;
}

void wg_device_up(wg_device* d, uint64_t now_ns)
{
    wg_peer* p;

    if (d->up) return;
    d->up = 1;
    for (p = d->peers; p; p = p->next) wg_peer_up(p, now_ns);
}

void wg_device_down(wg_device* d)
{
    wg_peer* p;

    d->up = 0;
    for (p = d->peers; p; p = p->next) wg_peer_reset(p);
}

/* --------------------------------------------------------------------- traffic */

static int refuse(wg_drop_reason* why, wg_drop_reason r)
{
    if (why) *why = r;
    return 0;
}

/* wg_xmit: the destination picks the peer; no peer, no packet. */
int wg_device_send(wg_device* d, const uint8_t* pkt, size_t len, uint64_t now_ns, wg_drop_reason* why)
{
    wg_peer* p;
    wg_ip ip;

    if (!d->up) return refuse(why, WG_DROP_DOWN);
    if (!wg_ip_parse(pkt, len, &ip)) return refuse(why, ip.family ? WG_DROP_BAD_LENGTH : WG_DROP_NOT_IP);
    p = wg_allowedips_lookup(&d->allowedips, ip.family, ip.dst);
    if (!p) return refuse(why, WG_DROP_NO_ROUTE);
    return wg_peer_send(p, pkt, ip.len, now_ns, why);
}

int wg_device_send_to_peer(wg_device* d, wg_peer* p, const uint8_t* pkt, size_t len, uint64_t now_ns)
{
    if (!d->up || !p) return 0;
    return wg_peer_send(p, pkt, len, now_ns, NULL);
}

/*
 * mac1 always; under load also mac2, and a message without a good one is answered with a cookie
 * reply instead (Linux adds a per-source rate limit on top - not here yet). DisableCookies turns
 * the whole of "under load" off, as amneziawg-go does. 1: go on.
 *
 * The reply answers `src`, not a peer - nobody is proven yet - so it leaves by `send` even when
 * the owner routes by peer. From a label the cookie proves nothing (a label is no address): an
 * owner that routes by peer keeps "under load" off.
 */
static int handshake_admitted(wg_device* d, const uint8_t* msg, size_t len, const wg_endpoint* src,
                              uint64_t now)
{
    uint8_t sb[18], reply[WG_COOKIE_MSG_LEN];
    size_t sn = wg_endpoint_bytes(src, sb);
    int load = d->under_load && !d->disable_cookies;
    wg_mac_state st = wg_cookie_validate(&d->checker, msg, len, sb, sn, load, now);

    if (st == WG_MAC_INVALID) return 0;
    if (load && st != WG_MAC_VALID_WITH_COOKIE) {
        if (wg_cookie_create_reply(&d->checker, reply, msg, len, sb, sn, now)) {
            wg_device_stamp(d, WG_MSG_COOKIE, reply, sizeof(reply));
            wg_device_transmit(d, NULL, src, WG_MSG_COOKIE, reply, sizeof(reply));
        }
        return 0;
    }
    return 1;
}

static int rx_initiation(wg_device* d, uint8_t* msg, const wg_endpoint* src, uint64_t now)
{
    wg_noise_remote* r;

    if (!handshake_admitted(d, msg, WG_INIT_LEN, src, now)) return 0;
    if (!wg_noise_consume_initiation(&d->local, msg, now, &r)) return 0;
    wg_peer_on_initiation(PEER_OF(r), src, WG_INIT_LEN, now);
    return 1;
}

static int rx_response(wg_device* d, wg_peer* only, uint8_t* msg, const wg_endpoint* src,
                       uint64_t now)
{
    wg_peer* p;

    if (!handshake_admitted(d, msg, WG_RESP_LEN, src, now)) return 0;
    p = peer_by_initiation(d, only, wg_load32(msg + WG_RESP_OFF_RECEIVER));
    if (!p || !wg_noise_consume_response(&p->noise, msg)) return 0;
    wg_peer_on_response(p, src, WG_RESP_LEN, now);
    return 1;
}

/* `only`: the sender the owner vouches for, NULL when unknown (then the index decides). */
static int receive(wg_device* d, wg_peer* only, uint8_t* dgram, size_t len, const wg_endpoint* src,
                   uint64_t now_ns)
{
    wg_peer* p;
    uint32_t type;
    size_t off, mlen;
    uint8_t* msg;

    if (!d->up || !src) return 0;
    if (!d->codec.ops->classify(d->codec.st, dgram, len, &type, &off, &mlen)) return 0;
    /* A codec's answer is checked, not trusted: it must point inside the datagram, at a message
     * of the right length for its type. */
    if (off > len || mlen > len - off || !wg_codec_length_ok(type, mlen)) return 0;
    msg = dgram + off;

    switch (type) {
    case WG_MSG_INITIATION:
        return rx_initiation(d, msg, src, now_ns);      /* the vouched sender: up_remote_get */
    case WG_MSG_RESPONSE:
        return rx_response(d, only, msg, src, now_ns);
    case WG_MSG_COOKIE:
        p = peer_by_any_index(d, only, wg_load32(msg + WG_COOKIE_OFF_RECEIVER));
        return p && wg_cookie_consume_reply(&p->cookie, msg, now_ns);
    default:
        /* The vouched sender's keys look for the index themselves, and say when it is not theirs. */
        p = only ? only : peer_by_keypair(d, wg_load32(msg + WG_DATA_OFF_RECEIVER));
        return p && wg_peer_on_data(p, msg, mlen, src, now_ns);
    }
}

int wg_device_receive(wg_device* d, uint8_t* dgram, size_t len, const wg_endpoint* src,
                      uint64_t now_ns)
{
    return receive(d, NULL, dgram, len, src, now_ns);
}

int wg_device_receive_from(wg_device* d, wg_peer* p, uint8_t* dgram, size_t len,
                           const wg_endpoint* src, uint64_t now_ns)
{
    int ok;

    if (!p || p->dev != d) return 0;
    d->rx_from = p;
    ok = receive(d, p, dgram, len, src, now_ns);
    d->rx_from = NULL;
    return ok;
}

/* --------------------------------------------------------------------- the wire */

void wg_device_stamp(wg_device* d, uint32_t type, uint8_t* msg, size_t len)
{
    if (d->codec.ops->stamp) d->codec.ops->stamp(d->codec.st, type, msg, len);
}

/* Whether a datagram for `p` (NULL: for no peer) has an upcall to leave by - checked before the
 * codec spends randomness on it. */
static int can_send(const wg_device* d, const wg_peer* p)
{
    return (p && d->send_peer) || d->send;
}

/* The upcall a datagram leaves by: send_peer for a peer's, when the owner routes by peer; send for
 * everything else. */
static void send_up(wg_device* d, wg_peer* p, const wg_endpoint* to, const uint8_t* dgram, size_t len)
{
    if (p && d->send_peer) d->send_peer(d->ctx, p, to, dgram, len);
    else                   d->send(d->ctx, to, dgram, len);
}

size_t wg_device_transmit(wg_device* d, wg_peer* p, const wg_endpoint* to, uint32_t type,
                          const uint8_t* msg, size_t len)
{
    const wg_codec_ops* ops = d->codec.ops;

    if (!can_send(d, p)) return 0;
    if (ops->wrap) {
        len = ops->wrap(d->codec.st, type, msg, len, d->wire, sizeof(d->wire));
        if (!len || len > sizeof(d->wire)) return 0;
        msg = d->wire;
    }
    send_up(d, p, to, msg, len);
    return len;
}

typedef struct {
    wg_device*         d;
    wg_peer*           p;
    const wg_endpoint* to;
    size_t             bytes;
} emit_ctx;

static void emit_to(void* ctx, const uint8_t* dgram, size_t len)
{
    emit_ctx* e = (emit_ctx*)ctx;
    send_up(e->d, e->p, e->to, dgram, len);
    e->bytes += len;
}

size_t wg_device_before_initiation(wg_device* d, wg_peer* p, const wg_endpoint* to)
{
    emit_ctx e;

    if (!d->codec.ops->before_initiation || !can_send(d, p)) return 0;
    e.d = d;
    e.p = p;
    e.to = to;
    e.bytes = 0;
    d->codec.ops->before_initiation(d->codec.st, d->wire, sizeof(d->wire), emit_to, &e);
    return e.bytes;
}

size_t wg_device_padding(const wg_device* d, size_t len)
{
    size_t room = WG_MAX_PACKET + WG_PADDING_MULTIPLE - len, pad;

    if (d->codec.ops->padding) pad = d->codec.ops->padding(d->codec.st, len, d->mtu);
    else                       pad = wg_data_padding(len, d->mtu);
    return pad < room ? pad : room;
}

void wg_device_authentic(wg_device* d, uint32_t type, size_t len, int moved)
{
    if (d->codec.ops->authentic) d->codec.ops->authentic(d->codec.st, type, len, moved);
}

/* --------------------------------------------------------------------- time */

uint64_t wg_device_next_deadline(const wg_device* d)
{
    const wg_peer* p;
    uint64_t next = WG_NEVER, t;

    if (!d->up) return WG_NEVER;
    for (p = d->peers; p; p = p->next) {
        t = wg_peer_next_deadline(p);
        if (t < next) next = t;
    }
    return next;
}

uint64_t wg_device_tick(wg_device* d, uint64_t now_ns)
{
    wg_peer* p;

    if (!d->up) return WG_NEVER;
    for (p = d->peers; p; p = p->next) wg_peer_tick(p, now_ns);
    return wg_device_next_deadline(d);
}
