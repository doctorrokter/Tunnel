/*
 * wg_peer - see wg_peer.h. The send and receive paths follow Linux's send.c and receive.c, the timers
 * its timers.c, event for event; each piece names the Linux function it mirrors.
 */

#include "wg_peer.h"
#include "wg_device.h"

#include <string.h>

const wg_timing wg_timing_wireguard = {
    .rekey_timeout          = { 5, 5 },
    .keepalive_timeout      = { 10, 10 },
    .rekey_after_time       = { 120, 120 },
    .reject_after_time      = { 180, 180 },
    .max_handshake_attempts = { 18, 18 },   /* REKEY_ATTEMPT_TIME / REKEY_TIMEOUT */
};

/* --------------------------------------------------------------------- endpoint */

size_t wg_endpoint_bytes(const wg_endpoint* e, uint8_t out[18])
{
    size_t n;

    if (e->family == 4)      n = 4;
    else if (e->family == 6) n = 16;
    else                     return 0;
    memcpy(out, e->addr, n);
    out[n] = (uint8_t)(e->port >> 8);
    out[n + 1] = (uint8_t)e->port;
    return n + 2;
}

int wg_endpoint_equal(const wg_endpoint* a, const wg_endpoint* b)
{
    if (a->family != b->family || a->port != b->port) return 0;
    if (a->family == 4) return memcmp(a->addr, b->addr, 4) == 0;
    if (a->family == 6) return memcmp(a->addr, b->addr, 16) == 0;
    return 1;
}

/* --------------------------------------------------------------------- staged packets */

#define RECORD_HEADER 2     /* the packet length, little-endian */

static void ring_put(wg_stage* q, size_t off, const uint8_t* src, size_t n)
{
    size_t first;

    if (!n) return;
    off %= q->cap;
    first = q->cap - off < n ? q->cap - off : n;
    memcpy(q->mem + off, src, first);
    if (n > first) memcpy(q->mem, src + first, n - first);
}

static void ring_get(const wg_stage* q, size_t off, uint8_t* dst, size_t n)
{
    size_t first;

    if (!n) return;
    off %= q->cap;
    first = q->cap - off < n ? q->cap - off : n;
    memcpy(dst, q->mem + off, first);
    if (n > first) memcpy(dst + first, q->mem, n - first);
}

static size_t oldest_len(const wg_stage* q)
{
    uint8_t h[RECORD_HEADER];
    ring_get(q, q->head, h, RECORD_HEADER);
    return (size_t)h[0] | ((size_t)h[1] << 8);
}

void wg_stage_init(wg_stage* q, uint8_t* mem, size_t cap)
{
    memset(q, 0, sizeof(*q));
    q->mem = mem;
    q->cap = mem ? cap : 0;
}

void wg_stage_drop(wg_stage* q)
{
    size_t n;

    if (!q->count) return;
    n = RECORD_HEADER + oldest_len(q);
    q->head = (q->head + n) % q->cap;
    q->used -= n;
    if (--q->count == 0) q->head = 0;
}

int wg_stage_push(wg_stage* q, const uint8_t* pkt, size_t len)
{
    uint8_t h[RECORD_HEADER];
    size_t need = RECORD_HEADER + len;

    if (len > WG_MAX_PACKET || need > q->cap) return 0;
    while (q->cap - q->used < need) {
        wg_stage_drop(q);
        q->dropped++;
    }
    h[0] = (uint8_t)len;
    h[1] = (uint8_t)(len >> 8);
    ring_put(q, q->head + q->used, h, RECORD_HEADER);
    ring_put(q, q->head + q->used + RECORD_HEADER, pkt, len);
    q->used += need;
    q->count++;
    return 1;
}

size_t wg_stage_peek(const wg_stage* q, uint8_t* out)
{
    size_t len = oldest_len(q);
    ring_get(q, q->head + RECORD_HEADER, out, len);
    return len;
}

void wg_stage_clear(wg_stage* q)
{
    if (q->mem) wg_wipe(q->mem, q->cap);     /* staged packets are the user's plaintext */
    q->head = q->used = q->count = 0;
}

/* --------------------------------------------------------------------- times */

/* A value of the range, both ends included; a single value costs no randomness. */
static uint32_t draw(wg_peer* p, wg_range r)
{
    return r.hi > r.lo ? r.lo + wg_rng_below(&p->dev->local.rng, r.hi - r.lo + 1) : r.lo;
}

static uint64_t draw_s(wg_peer* p, wg_range r)
{
    return (uint64_t)draw(p, r) * WG_NSEC_PER_SEC;
}

static uint64_t lo_s(wg_range r)
{
    return (uint64_t)r.lo * WG_NSEC_PER_SEC;
}

static uint64_t hi_s(wg_range r)
{
    return (uint64_t)r.hi * WG_NSEC_PER_SEC;
}

static int keepalive_on(const wg_peer* p)
{
    return p->persistent_keepalive.lo || p->persistent_keepalive.hi;
}

/* --------------------------------------------------------------------- timers (timers.c) */

/* A random extra delay for the handshake timers, so two peers do not retry in lockstep. */
static uint64_t jitter(wg_peer* p)
{
    uint32_t r = 0;

    if (!wg_rng_bytes(&p->dev->local.rng, &r, sizeof(r))) return 0;
    return (uint64_t)r % WG_REKEY_JITTER_NS;
}

/* wg_timers_data_sent; newHandshakeTimeout: the keepalive range's top plus a drawn rekey timeout */
static void timers_data_sent(wg_peer* p, uint64_t now)
{
    const wg_timing* t = &p->dev->timing;
    uint64_t wait;

    if (p->t_new_handshake == WG_NEVER) {
        wait = hi_s(t->keepalive_timeout) + draw_s(p, t->rekey_timeout);
        p->t_new_handshake = now + wait + jitter(p);
    }
}

/* wg_timers_data_received */
static void timers_data_received(wg_peer* p, uint64_t now)
{
    if (p->t_send_keepalive == WG_NEVER)
        p->t_send_keepalive = now + draw_s(p, p->dev->timing.keepalive_timeout);
    else
        p->need_another_keepalive = 1;
}

/* wg_timers_any_authenticated_packet_sent: whatever we sent answers the peer, no keepalive needed */
static void timers_any_authenticated_packet_sent(wg_peer* p)
{
    p->t_send_keepalive = WG_NEVER;
}

/* wg_timers_any_authenticated_packet_received: the peer is alive */
static void timers_any_authenticated_packet_received(wg_peer* p)
{
    p->t_new_handshake = WG_NEVER;
}

/* wg_timers_handshake_initiated; retransmitHandshakeTimeout: a drawn rekey timeout */
static void timers_handshake_initiated(wg_peer* p, uint64_t now)
{
    uint64_t wait = draw_s(p, p->dev->timing.rekey_timeout);
    p->t_retransmit_handshake = now + wait + jitter(p);
}

/* wg_timers_handshake_complete: a response consumed, or a responder's keys confirmed */
static void timers_handshake_complete(wg_peer* p, uint64_t now)
{
    p->t_retransmit_handshake = WG_NEVER;
    p->handshake_attempts = 0;
    p->max_handshake_attempts = draw(p, p->dev->timing.max_handshake_attempts);
    p->sent_lastminute_handshake = 0;
    p->last_handshake_ns = now;
    p->has_handshake = 1;
}

/* wg_timers_session_derived; keychainExpireTime: the top of the reject range */
static void timers_session_derived(wg_peer* p, uint64_t now)
{
    p->t_zero_key_material = now + 3 * hi_s(p->dev->timing.reject_after_time);
}

/* wg_timers_any_authenticated_packet_traversal: either way, sent or received */
static void timers_any_authenticated_packet_traversal(wg_peer* p, uint64_t now)
{
    if (keepalive_on(p))
        p->t_persistent_keepalive = now + draw_s(p, p->persistent_keepalive);
}

/* --------------------------------------------------------------------- sending (send.c) */

/* Onto the wire through the device's codec, to wherever the peer is - or to the owner, with the
 * peer named, when it routes by peer (a label is an endpoint too). */
static void transmit(wg_peer* p, uint32_t type, const uint8_t* msg, size_t len)
{
    if (!p->endpoint.family) return;
    p->tx_bytes += wg_device_transmit(p->dev, p, &p->endpoint, type, msg, len);
}

/* wg_packet_send_handshake_initiation, with the rate limit of its queued variant */
static void send_initiation(wg_peer* p, uint64_t now, int is_retry)
{
    wg_device* d = p->dev;
    uint8_t msg[WG_INIT_LEN], ts[WG_TIMESTAMP_LEN];
    uint64_t sec = 0;
    uint32_t nsec = 0;

    if (!is_retry) {
        p->handshake_attempts = 0;
        p->max_handshake_attempts = draw(p, d->timing.max_handshake_attempts);
    }
    /* rekeyMinTimeout: the bottom of the rekey range */
    if (p->has_sent_handshake && now - p->last_sent_handshake_ns < lo_s(d->timing.rekey_timeout)) return;
    p->last_sent_handshake_ns = now;
    p->has_sent_handshake = 1;

    if (d->wall_clock) d->wall_clock(d->ctx, &sec, &nsec);
    wg_tai64n(ts, sec, nsec);
    if (!wg_noise_create_initiation(&p->noise, ts, msg)) return;
    wg_device_stamp(d, WG_MSG_INITIATION, msg, sizeof(msg));   /* before the macs: they cover it */
    if (!wg_cookie_add_macs(&p->cookie, msg, sizeof(msg), now)) return;

    timers_any_authenticated_packet_traversal(p, now);
    timers_any_authenticated_packet_sent(p);
    if (p->endpoint.family) p->tx_bytes += wg_device_before_initiation(d, p, &p->endpoint);
    transmit(p, WG_MSG_INITIATION, msg, sizeof(msg));
    timers_handshake_initiated(p, now);
}

/* wg_packet_send_handshake_response: answer, and derive the session right away */
static void send_response(wg_peer* p, uint64_t now)
{
    uint8_t msg[WG_RESP_LEN];
    wg_noise_keys keys;

    p->last_sent_handshake_ns = now;
    p->has_sent_handshake = 1;
    if (!wg_noise_create_response(&p->noise, msg)) return;
    wg_device_stamp(p->dev, WG_MSG_RESPONSE, msg, sizeof(msg));
    if (!wg_cookie_add_macs(&p->cookie, msg, sizeof(msg), now)) return;
    if (!wg_noise_begin_session(&p->noise, &keys)) return;
    wg_session_add(&p->session, &keys, now);
    wg_wipe(&keys, sizeof(keys));

    timers_session_derived(p, now);
    timers_any_authenticated_packet_traversal(p, now);
    timers_any_authenticated_packet_sent(p);
    transmit(p, WG_MSG_RESPONSE, msg, sizeof(msg));
}

/* keep_key_fresh after sending: a rekey by message count, or by age when we were the initiator
 * (keyRefreshTimeoutSending: a rekey-after time drawn at every check) */
static void keep_key_fresh_send(wg_peer* p, uint64_t now)
{
    wg_keypair* kp = p->session.current;

    if (kp && kp->send_valid
        && (kp->send_counter > WG_REKEY_AFTER_MESSAGES
            || (kp->initiator && now - kp->birth_ns >= draw_s(p, p->dev->timing.rekey_after_time))))
        send_initiation(p, now, 0);
}

/* keep_key_fresh after receiving: an initiator whose keys are about to be rejected renews them
 * once, even if it has nothing to send (keyRefreshTimeoutReceiving: a drawn reject time less the
 * bottoms of the keepalive and rekey ranges, never below 0) */
static void keep_key_fresh_receive(wg_peer* p, uint64_t now)
{
    const wg_timing* t = &p->dev->timing;
    wg_keypair* kp = p->session.current;
    uint64_t reject, margin;

    if (p->sent_lastminute_handshake) return;
    if (!kp || !kp->send_valid || !kp->initiator) return;
    reject = draw_s(p, t->reject_after_time);
    margin = lo_s(t->keepalive_timeout) + lo_s(t->rekey_timeout);
    if (now - kp->birth_ns >= (reject > margin ? reject - margin : 0)) {
        p->sent_lastminute_handshake = 1;
        send_initiation(p, now, 0);
    }
}

/* Seals one packet with the current keys and sends it (wg_packet_create_data_done); 0 when there
 * is no usable key. `pkt` may be the scratch buffer's payload area: sealed in place. */
static int seal_and_send(wg_peer* p, const uint8_t* pkt, size_t len, uint64_t now)
{
    wg_device* d = p->dev;
    size_t n = 0;

    if (!wg_session_encrypt(&p->session, d->scratch, &n, pkt, len, wg_device_padding(d, len), now))
        return 0;
    wg_device_stamp(d, WG_MSG_DATA, d->scratch, n);         /* the header is not authenticated */
    timers_any_authenticated_packet_traversal(p, now);
    timers_any_authenticated_packet_sent(p);
    transmit(p, WG_MSG_DATA, d->scratch, n);
    if (len) timers_data_sent(p, now);
    keep_key_fresh_send(p, now);
    return 1;
}

/* wg_packet_send_staged_packets: in order, until done or out of keys - then handshake for more */
static void send_staged(wg_peer* p, uint64_t now)
{
    uint8_t* payload = p->dev->scratch + WG_DATA_HEADER_LEN;
    size_t len;

    while (p->staged.count) {
        len = wg_stage_peek(&p->staged, payload);
        if (!seal_and_send(p, payload, len, now)) {
            send_initiation(p, now, 0);
            return;
        }
        wg_stage_drop(&p->staged);
    }
}

/* wg_packet_send_keepalive: what is staged goes out and confirms the session; with nothing staged,
 * an empty packet does - staged itself when there is no key yet, behind a handshake */
static void send_keepalive(wg_peer* p, uint64_t now)
{
    if (p->staged.count) {
        send_staged(p, now);
    } else if (!seal_and_send(p, NULL, 0, now)) {
        wg_stage_push(&p->staged, NULL, 0);
        send_initiation(p, now, 0);
    }
}

int wg_peer_send(wg_peer* p, const uint8_t* pkt, size_t len, uint64_t now_ns, wg_drop_reason* why)
{
    wg_drop_reason r = WG_DROP_NONE;

    if (!p->endpoint.family) {
        r = WG_DROP_NO_ENDPOINT;            /* Linux drops these before queueing, too */
    } else if (len > WG_MAX_PACKET) {
        r = WG_DROP_NO_ROOM;
    } else if (p->staged.count || !seal_and_send(p, pkt, len, now_ns)) {
        /* No key, or packets already waiting (order matters): queue it behind them. */
        if (wg_stage_push(&p->staged, pkt, len)) send_staged(p, now_ns);
        else r = WG_DROP_NO_ROOM;
    }
    if (why) *why = r;
    return r == WG_DROP_NONE;
}

/* --------------------------------------------------------------------- receiving (receive.c) */

/* An authentic message: the peer is wherever it came from (roaming), and the codec may learn
 * from it - before anything is sent back. From the owner's label to the same label nothing moves:
 * where such a peer really is, only the owner knows. */
static void heard(wg_peer* p, uint32_t type, size_t len, const wg_endpoint* src)
{
    int moved = !wg_endpoint_equal(&p->endpoint, src);

    p->endpoint = *src;
    wg_device_authentic(p->dev, type, len, moved);
}

void wg_peer_on_initiation(wg_peer* p, const wg_endpoint* src, size_t len, uint64_t now_ns)
{
    heard(p, WG_MSG_INITIATION, len, src);
    send_response(p, now_ns);
    p->rx_bytes += len;
    timers_any_authenticated_packet_received(p);
    timers_any_authenticated_packet_traversal(p, now_ns);
}

void wg_peer_on_response(wg_peer* p, const wg_endpoint* src, size_t len, uint64_t now_ns)
{
    wg_noise_keys keys;

    heard(p, WG_MSG_RESPONSE, len, src);
    if (wg_noise_begin_session(&p->noise, &keys)) {
        wg_session_add(&p->session, &keys, now_ns);
        wg_wipe(&keys, sizeof(keys));
        timers_session_derived(p, now_ns);
        timers_handshake_complete(p, now_ns);
        /* Confirm the session at once: the responder may not send until it hears from us. */
        send_keepalive(p, now_ns);
    }
    p->rx_bytes += len;
    timers_any_authenticated_packet_received(p);
    timers_any_authenticated_packet_traversal(p, now_ns);
}

int wg_peer_on_data(wg_peer* p, uint8_t* msg, size_t len, const wg_endpoint* src, uint64_t now_ns)
{
    wg_device* d = p->dev;
    uint8_t* pkt = msg + WG_DATA_HEADER_LEN;
    wg_recv rv;
    wg_ip ip;

    if (!wg_session_decrypt(&p->session, pkt, msg, len, now_ns, &rv)) {
        p->last_drop = rv.drop;
        return 0;
    }
    /* Roaming: the peer is wherever its last AUTHENTIC packet came from. */
    heard(p, WG_MSG_DATA, len, src);
    if (rv.confirmed) {
        timers_handshake_complete(p, now_ns);
        send_staged(p, now_ns);
    }
    keep_key_fresh_receive(p, now_ns);
    timers_any_authenticated_packet_received(p);
    timers_any_authenticated_packet_traversal(p, now_ns);

    if (!rv.len || pkt[0] == 0) {                       /* a keepalive, padded or not */
        p->rx_bytes += len;
        return 1;
    }
    timers_data_received(p, now_ns);

    /* wg_packet_consume_data_done: authentic is not enough. The packet must be IP, whole, and
     * from an address this peer may send from - or a peer could inject traffic as any other. */
    if (!wg_ip_parse(pkt, rv.len, &ip)) {
        p->last_drop = ip.family ? WG_DROP_BAD_LENGTH : WG_DROP_NOT_IP;
        return 0;
    }
    if (wg_allowedips_lookup(&d->allowedips, ip.family, ip.src) != p) {
        p->last_drop = WG_DROP_WRONG_SOURCE;
        return 0;
    }
    p->rx_bytes += len;
    if (d->deliver) d->deliver(d->ctx, p, pkt, ip.len);
    return 1;
}

/* --------------------------------------------------------------------- timer expiry */

/* wg_expired_retransmit_handshake */
static void expired_retransmit_handshake(wg_peer* p, uint64_t now)
{
    if (p->handshake_attempts > p->max_handshake_attempts) {
        /* Given up: drop what waited for keys, and wipe whatever is left of the exchange later. */
        p->t_send_keepalive = WG_NEVER;
        wg_stage_clear(&p->staged);
        if (p->t_zero_key_material == WG_NEVER)
            p->t_zero_key_material = now + 3 * hi_s(p->dev->timing.reject_after_time);
    } else {
        p->handshake_attempts++;
        send_initiation(p, now, 1);
    }
}

/* wg_expired_send_keepalive */
static void expired_send_keepalive(wg_peer* p, uint64_t now)
{
    send_keepalive(p, now);
    if (p->need_another_keepalive) {
        p->need_another_keepalive = 0;
        p->t_send_keepalive = now + draw_s(p, p->dev->timing.keepalive_timeout);
    }
}

/* wg_expired_zero_key_material */
static void expired_zero_key_material(wg_peer* p)
{
    wg_noise_remote_clear(&p->noise);
    wg_session_clear(&p->session);
}

void wg_peer_tick(wg_peer* p, uint64_t now_ns)
{
    /* Each handler re-arms only into the future, so nothing fires twice in one tick. */
    if (p->t_retransmit_handshake <= now_ns) {
        p->t_retransmit_handshake = WG_NEVER;
        expired_retransmit_handshake(p, now_ns);
    }
    if (p->t_send_keepalive <= now_ns) {
        p->t_send_keepalive = WG_NEVER;
        expired_send_keepalive(p, now_ns);
    }
    if (p->t_new_handshake <= now_ns) {
        /* wg_expired_new_handshake: we sent data and heard nothing back */
        p->t_new_handshake = WG_NEVER;
        send_initiation(p, now_ns, 0);
    }
    if (p->t_zero_key_material <= now_ns) {
        p->t_zero_key_material = WG_NEVER;
        expired_zero_key_material(p);
    }
    if (p->t_persistent_keepalive <= now_ns) {
        p->t_persistent_keepalive = WG_NEVER;
        if (keepalive_on(p)) send_keepalive(p, now_ns);
    }
}

uint64_t wg_peer_next_deadline(const wg_peer* p)
{
    uint64_t next = p->t_retransmit_handshake;

    if (p->t_send_keepalive < next) next = p->t_send_keepalive;
    if (p->t_new_handshake < next) next = p->t_new_handshake;
    if (p->t_zero_key_material < next) next = p->t_zero_key_material;
    if (p->t_persistent_keepalive < next) next = p->t_persistent_keepalive;
    return next;
}

/* --------------------------------------------------------------------- life cycle and config */

static void timers_stop(wg_peer* p)
{
    p->t_retransmit_handshake = WG_NEVER;
    p->t_send_keepalive = WG_NEVER;
    p->t_new_handshake = WG_NEVER;
    p->t_zero_key_material = WG_NEVER;
    p->t_persistent_keepalive = WG_NEVER;
    p->handshake_attempts = 0;
    p->max_handshake_attempts = p->dev->timing.max_handshake_attempts.hi;  /* drawn before use */
    p->need_another_keepalive = 0;
    p->sent_lastminute_handshake = 0;
}

void wg_peer_init(wg_peer* p, wg_device* dev, const wg_key* public_key,
                  uint8_t* stage_mem, size_t stage_cap)
{
    memset(p, 0, sizeof(*p));
    p->dev = dev;
    wg_noise_remote_init(&p->noise, &dev->local, public_key);
    wg_cookie_maker_init(&p->cookie, public_key);
    wg_session_init(&p->session, &dev->local);
    p->session.reject_after_ns = hi_s(dev->timing.reject_after_time);  /* keychainExpireTime */
    wg_stage_init(&p->staged, stage_mem, stage_cap);
    timers_stop(p);
}

void wg_peer_reset(wg_peer* p)
{
    timers_stop(p);
    wg_stage_clear(&p->staged);
    wg_noise_remote_clear(&p->noise);
    wg_session_clear(&p->session);
    p->has_sent_handshake = 0;
}

void wg_peer_up(wg_peer* p, uint64_t now_ns)
{
    send_staged(p, now_ns);
    if (keepalive_on(p)) send_keepalive(p, now_ns);
}

void wg_peer_set_psk(wg_peer* p, const uint8_t psk[WG_KEY_LEN])
{
    wg_noise_remote_set_psk(&p->noise, psk);
}

void wg_peer_set_endpoint(wg_peer* p, const wg_endpoint* ep)
{
    p->endpoint = *ep;
}

void wg_peer_set_persistent_keepalive_range(wg_peer* p, wg_range seconds, uint64_t now_ns)
{
    int was_on = keepalive_on(p);

    p->persistent_keepalive = seconds;
    if (!keepalive_on(p)) p->t_persistent_keepalive = WG_NEVER;
    else if (!was_on && p->dev->up) send_keepalive(p, now_ns);
}

void wg_peer_set_persistent_keepalive(wg_peer* p, uint16_t seconds, uint64_t now_ns)
{
    wg_range r;
    r.lo = r.hi = seconds;
    wg_peer_set_persistent_keepalive_range(p, r, now_ns);
}

void wg_peer_initiate(wg_peer* p, uint64_t now_ns)
{
    if (p->dev->up) send_initiation(p, now_ns, 0);
}

int wg_peer_allow(wg_peer* p, int family, const uint8_t* addr, uint8_t cidr)
{
    return wg_allowedips_insert(&p->dev->allowedips, family, addr, cidr, p);
}

int wg_peer_disallow(wg_peer* p, int family, const uint8_t* addr, uint8_t cidr)
{
    return wg_allowedips_remove(&p->dev->allowedips, family, addr, cidr, p);
}

void wg_peer_disallow_all(wg_peer* p)
{
    wg_allowedips_remove_peer(&p->dev->allowedips, p);
}
