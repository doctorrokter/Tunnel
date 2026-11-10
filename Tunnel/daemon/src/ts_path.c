/*
 * ts_path - see ts_path.h.
 */

#include "ts_path.h"

#include <string.h>

static int ep_same(const wg_endpoint* a, const wg_endpoint* b)
{
    return a->family == b->family && a->port == b->port &&
           memcmp(a->addr, b->addr, a->family == 4 ? 4 : 16) == 0;
}

void ts_path_init(ts_path* p)
{
    memset(p, 0, sizeof(*p));
}

int ts_path_usable(const wg_endpoint* e)
{
    static const uint8_t zero[16];
    static const uint8_t tailnet6[6] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0 };
    const uint8_t* a = e->addr;

    if (!e->port) return 0;
    if (e->family == 4) {
        if (memcmp(a, zero, 4) == 0) return 0;
        if (a[0] == 100 && (a[1] & 0xc0) == 64) return 0;      /* 100.64.0.0/10 */
        if ((a[0] & 0xf0) == 224 || (a[0] == 255 && a[1] == 255 && a[2] == 255 && a[3] == 255)) return 0;
        return 1;
    }
    if (e->family == 6) {
        if (memcmp(a, zero, 16) == 0) return 0;
        if (memcmp(a, tailnet6, sizeof(tailnet6)) == 0) return 0;
        if (a[0] == 0xff) return 0;
        return 1;
    }
    return 0;
}

/* --------------------------------------------------------------------- what an address is worth */

static int is_loopback(const wg_endpoint* e)
{
    static const uint8_t one[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    return e->family == 4 ? e->addr[0] == 127 : memcmp(e->addr, one, 16) == 0;
}

static int is_link_local(const wg_endpoint* e)
{
    return e->family == 4 ? e->addr[0] == 169 && e->addr[1] == 254 : e->addr[0] == 0xfe && (e->addr[1] & 0xc0) == 0x80;
}

static int is_private(const wg_endpoint* e)
{
    const uint8_t* a = e->addr;
    if (e->family == 4) return a[0] == 10 || (a[0] == 172 && (a[1] & 0xf0) == 16) || (a[0] == 192 && a[1] == 168);
    return (a[0] & 0xfe) == 0xfc;
}

static int bonus(const wg_endpoint* e)
{
    int points = 0;
    if (is_loopback(e)) points += 50;
    else if (is_link_local(e)) points += 30;
    else if (is_private(e)) points += 20;
    if (e->family == 6) points += 10;
    return points;
}

/* magicsock's betterAddr: is `a` (latency `al`) a better path than `b` (latency `bl`; family 0: none)? */
static int better(const wg_endpoint* a, uint64_t al, const wg_endpoint* b, uint64_t bl)
{
    int ap = 0, bp = 0;

    if (b->family && ep_same(a, b)) return 0;
    if (!b->family) return 1;
    if (!a->family) return 0;
    /* how much faster than the slower one, in percent */
    if (al > bl && al > 0) bp = (int)(100 - (bl * 100) / al);
    else if (bl > 0) ap = (int)(100 - (al * 100) / bl);
    ap += bonus(a);
    bp += bonus(b);
    if (ap <= 1 && bp == 0) return 0;               /* less than 1 %: no flapping */
    return ap > bp;
}

/* --------------------------------------------------------------------- candidates */

static int cand_find(const ts_path* p, const wg_endpoint* e)
{
    size_t i;
    for (i = 0; i < p->n; i++)
        if (ep_same(&p->cand[i].ep, e)) return (int)i;
    return -1;
}

static void best_clear(ts_path* p)
{
    memset(&p->best, 0, sizeof(p->best));
    p->best_latency = 0;
    p->trust_until = 0;
}

/* Candidates nothing names any longer go; the best with them. */
static void cand_prune(ts_path* p)
{
    size_t i = 0;

    while (i < p->n) {
        if (p->cand[i].from) {
            i++;
            continue;
        }
        if (p->best.family && ep_same(&p->best, &p->cand[i].ep)) best_clear(p);
        memmove(&p->cand[i], &p->cand[i + 1], (p->n - i - 1) * sizeof(p->cand[0]));
        p->n--;
    }
}

/* One more source for an address; a full table makes room by the one only a ping named, heard of
 * longest ago - unless the new one is only that too. */
static void cand_add(ts_path* p, const wg_endpoint* e, unsigned from, uint64_t now)
{
    int i = cand_find(p, e);
    size_t k, victim = p->n;

    if (!ts_path_usable(e)) return;
    if (i >= 0) {
        p->cand[i].from |= from;
        if (from & TS_PATH_PINGED) p->cand[i].heard = now;
        return;
    }
    if (p->n == TS_PATH_CANDS) {
        for (k = 0; k < p->n; k++)
            if (p->cand[k].from == TS_PATH_PINGED && (victim == p->n || p->cand[k].heard < p->cand[victim].heard))
                victim = k;
        if (victim == p->n || (from == TS_PATH_PINGED && p->cand[victim].heard >= now)) return;
        p->cand[victim].from = 0;
        cand_prune(p);
    }
    memset(&p->cand[p->n], 0, sizeof(p->cand[0]));
    p->cand[p->n].ep = *e;
    p->cand[p->n].from = from;
    if (from & TS_PATH_PINGED) p->cand[p->n].heard = now;
    p->n++;
}

/* A source's set replaced: the bit off everywhere, back on for the new set. */
static void cand_set(ts_path* p, unsigned from, const wg_endpoint* eps, size_t n, uint64_t now)
{
    size_t i;

    for (i = 0; i < p->n; i++) p->cand[i].from &= ~from;
    cand_prune(p);
    for (i = 0; i < n; i++) cand_add(p, &eps[i], from, now);
}

void ts_path_netmap(ts_path* p, const wg_endpoint* eps, size_t n)
{
    cand_set(p, TS_PATH_NETMAP, eps, n, 0);
}

void ts_path_call_me_maybe(ts_path* p, const wg_endpoint* eps, size_t n, uint64_t now)
{
    size_t i;

    cand_set(p, TS_PATH_CMM, eps, n, now);
    /* It sent to us, its firewall is open now: every candidate at once, no CallMeMaybe back. */
    for (i = 0; i < p->n; i++) p->cand[i].last_ping = 0;
    p->ping_all = 1;
}

void ts_path_pinged_from(ts_path* p, const wg_endpoint* src, uint64_t now)
{
    cand_add(p, src, TS_PATH_PINGED, now);
}

/* --------------------------------------------------------------------- pings */

/* Pings that waited 5 s are let go; candidates only a ping named go 45 s after it. */
static void expire(ts_path* p, uint64_t now)
{
    size_t i;

    for (i = 0; i < TS_PATH_INFLIGHT; i++)
        if (p->inflight[i].sent && now - p->inflight[i].sent >= TS_PATH_PING_TIMEOUT) p->inflight[i].sent = 0;
    for (i = 0; i < p->n; i++)
        if ((p->cand[i].from & TS_PATH_PINGED) && now - p->cand[i].heard > TS_PATH_ACTIVE)
            p->cand[i].from &= ~TS_PATH_PINGED;
    cand_prune(p);
}

/* A ping in flight to `e`: the oldest one makes room when all are taken. */
static void ping_start(ts_path* p, const wg_endpoint* e, const uint8_t txid[TS_PATH_TXID_LEN], uint64_t now)
{
    size_t i, slot = 0;
    int c = cand_find(p, e);

    for (i = 0; i < TS_PATH_INFLIGHT; i++) {
        if (!p->inflight[i].sent) {
            slot = i;
            break;
        }
        if (p->inflight[i].sent < p->inflight[slot].sent) slot = i;
    }
    memcpy(p->inflight[slot].txid, txid, TS_PATH_TXID_LEN);
    p->inflight[slot].to = *e;
    p->inflight[slot].sent = now ? now : 1;
    if (c >= 0) p->cand[c].last_ping = now ? now : 1;
}

/* Every candidate not pinged for 5 s. */
static size_t round_all(ts_path* p, uint64_t now, wg_endpoint* to, const uint8_t (*txid)[TS_PATH_TXID_LEN], size_t cap,
                        size_t k, int then_cmm)
{
    size_t i, first = k;

    p->last_full = now ? now : 1;
    for (i = 0; i < p->n && k < cap; i++) {
        ts_path_cand* c = &p->cand[i];
        if (c->last_ping && now - c->last_ping < TS_PATH_PING_EVERY) continue;
        ping_start(p, &c->ep, txid[k], now);
        to[k++] = c->ep;
    }
    if (k > first && then_cmm) p->cmm_due = 1;
    return k;
}

static int want_full(const ts_path* p, uint64_t now)
{
    if (!p->best.family || !p->last_full) return 1;
    if (now >= p->trust_until) return 1;
    if (p->best_latency <= TS_PATH_GOOD_ENOUGH) return 0;
    return now - p->last_full >= TS_PATH_UPGRADE;
}

static int active(const ts_path* p, uint64_t now)
{
    return p->last_send && now - p->last_send <= TS_PATH_ACTIVE;
}

int ts_path_direct(const ts_path* p, uint64_t now, wg_endpoint* to)
{
    if (!p->best.family || now >= p->trust_until) return 0;
    if (to) *to = p->best;
    return 1;
}

size_t ts_path_send(ts_path* p, uint64_t now, wg_endpoint* to, const uint8_t (*txid)[TS_PATH_TXID_LEN], size_t cap)
{
    size_t k = 0;

    expire(p, now);
    if (!active(p, now)) p->last_heartbeat = now;      /* a session starts: heartbeats from now on */
    p->last_send = now ? now : 1;
    if (!ts_path_direct(p, now, NULL)) k = round_all(p, now, to, txid, cap, 0, 1);
    return k;
}

size_t ts_path_tick(ts_path* p, uint64_t now, wg_endpoint* to, const uint8_t (*txid)[TS_PATH_TXID_LEN], size_t cap)
{
    size_t k = 0;

    expire(p, now);
    /* the session is over: no more heartbeats - and none left in ts_path_next to wake for */
    if (p->last_send && !active(p, now)) p->last_send = 0;
    /* a CallMeMaybe came: every candidate, no CallMeMaybe back */
    if (p->ping_all) {
        p->ping_all = 0;
        k = round_all(p, now, to, txid, cap, k, 0);
    }
    if (active(p, now) && now - p->last_heartbeat >= TS_PATH_HEARTBEAT) {
        p->last_heartbeat = now;
        if (p->best.family && k < cap) {
            ping_start(p, &p->best, txid[k], now);
            to[k++] = p->best;
        }
        if (want_full(p, now)) k = round_all(p, now, to, txid, cap, k, 1);
    }
    return k;
}

int ts_path_take_cmm(ts_path* p)
{
    int due = p->cmm_due;
    p->cmm_due = 0;
    return due;
}

int ts_path_pong(ts_path* p, const uint8_t txid[TS_PATH_TXID_LEN], uint64_t now)
{
    size_t i;
    wg_endpoint to;
    uint64_t latency;

    for (i = 0; i < TS_PATH_INFLIGHT; i++)
        if (p->inflight[i].sent && memcmp(p->inflight[i].txid, txid, TS_PATH_TXID_LEN) == 0) break;
    if (i == TS_PATH_INFLIGHT) return 0;
    to = p->inflight[i].to;
    latency = now > p->inflight[i].sent ? now - p->inflight[i].sent : 0;
    p->inflight[i].sent = 0;
    if (cand_find(p, &to) < 0 && !(p->best.family && ep_same(&p->best, &to))) return 1;   /* no longer ours */
    if (better(&to, latency, &p->best, p->best_latency) || now >= p->trust_until) {
        p->best = to;
        p->best_latency = latency;
    }
    if (ep_same(&p->best, &to)) {
        p->best_latency = latency;
        p->trust_until = now + TS_PATH_TRUST;
    }
    return 1;
}

int ts_path_knows(const ts_path* p, const wg_endpoint* src)
{
    return cand_find(p, src) >= 0 || (p->best.family && ep_same(&p->best, src));
}

uint64_t ts_path_next(const ts_path* p)
{
    uint64_t next = TS_PATH_NEVER, t;
    size_t i;

    for (i = 0; i < TS_PATH_INFLIGHT; i++) {
        t = p->inflight[i].sent + TS_PATH_PING_TIMEOUT;
        if (p->inflight[i].sent && t < next) next = t;
    }
    for (i = 0; i < p->n; i++) {
        t = p->cand[i].heard + TS_PATH_ACTIVE + 1;
        if ((p->cand[i].from & TS_PATH_PINGED) && t < next) next = t;
    }
    if (p->ping_all) next = 0;
    if (p->last_send) {
        t = p->last_heartbeat + TS_PATH_HEARTBEAT;
        if (t <= p->last_send + TS_PATH_ACTIVE && t < next) next = t;
    }
    return next;
}

void ts_path_reset(ts_path* p)
{
    size_t i;

    best_clear(p);
    memset(p->inflight, 0, sizeof(p->inflight));
    for (i = 0; i < p->n; i++) p->cand[i].last_ping = 0;
    p->last_full = 0;
    p->cmm_due = 0;
    p->ping_all = 0;
}
