/*
 * bt_ts_relay - see bt_ts_relay.h.
 */

#include "bt_ts_relay.h"
#include "bt_log.h"
#include "bt_tls.h"
#include "ts_derp.h"
#include "ts_http1.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SEC                 1000000000ULL
#define QUEUE_MAX           (16 * 1024)             /* packets waiting for a login, per connection */
#define DEAD_NS             (125ULL * SEC)          /* two server keepalives (60 s) and a margin */
#define RETRY_MIN_NS        (1ULL * SEC)
#define RETRY_MAX_NS        (30ULL * SEC)
#define MEASURE_NS          (3ULL * SEC)
#define CONNECT_MS          10000                   /* derphttp: DNS + TCP + TLS + upgrade in 10 s */
#define LOGIN_NS            (15ULL * SEC)           /* ... and the DERP login after it: ServerInfo */
#define TLS_OUT_MAX         (512 * 1024)
#define READ_CHUNK          16384

typedef enum {
    R_FREE = 0,
    R_CONNECTING,           /* TCP and TLS; the upgrade request is queued already */
    R_UPGRADE,              /* the HTTP response to it */
    R_DERP,                 /* ts_derp: the login, then packets */
    R_WAIT                  /* home, after a failure: again at retry_at */
} rstate;

typedef struct {
    struct bt_relays* set;
    rstate          st;
    int             region;
    size_t          node;                   /* which of the region's nodes */
    int             v6;                     /* its IPv6 address this time */
    bt_tls          tls;
    ts_http1_resp*  http;                   /* while the upgrade is read */
    ts_derp*        derp;
    uint64_t        since;                  /* this attempt began */
    uint64_t        last_rx, last_tx;
    uint64_t        retry_at;
    unsigned        fails;
    uint8_t*        queue;                  /* records: 2-byte length, 32-byte key, the packet */
    size_t          queue_len;
    int             ready_told;             /* home: io.home(1) said for this connection */
    int             busy;                   /* inside ts_derp_input: not to be freed now */
    int             in_poll;                /* its fd went into the last poll (a new one's did not) */
    uint32_t        restart_ms;             /* the server said it restarts: wait this long */
} relay;

/* One region's measurement: a TLS handshake, closed as soon as it is over (or failed). */
typedef struct {
    int      region;
    bt_tls   tls;                           /* idle once done */
    uint64_t start;
    uint64_t tcp_at;                        /* the TCP connect made: the handshake starts; 0 = not yet */
    uint64_t ns;                            /* the answer; 0 = none */
    int      done;
    int      in_poll;                       /* its fd went into the last poll (see relay) */
} probe;

struct bt_relays {
    wg_key          priv, pub;
    int             plain;
    char            tag[48];
    bt_relay_io     io;
    bt_relay_region map[BT_RELAY_REGIONS];
    size_t          n_map;
    int             home;
    relay           c[BT_RELAY_CONNS];
    probe           probes[BT_RELAY_REGIONS];
    size_t          n_probes;
    uint64_t        probe_until;
    int             early_told;             /* this round's first answer went up already */
    uint64_t        packets_in, packets_out, dropped;
    const char*     drop_why;               /* the reason of the drops since the last packet sent */
    uint64_t        drop_streak;            /* ... and how many */
};

/* One frame at a time goes to TLS, header and all in one piece (bt_tls_write is all or nothing). */
static uint8_t frame[TS_DERP_HDR_LEN + TS_DERP_KEY_LEN + TS_DERP_MAX_PACKET];
static uint8_t rbuf[READ_CHUNK];

/* --------------------------------------------------------------------- helpers */

static const bt_relay_region* find_region(const bt_relays* rs, int id)
{
    size_t i;
    for (i = 0; i < rs->n_map; i++)
        if (rs->map[i].id == id) return &rs->map[i];
    return NULL;
}

static relay* find_conn(bt_relays* rs, int region)
{
    int i;
    for (i = 0; i < BT_RELAY_CONNS; i++)
        if (rs->c[i].st != R_FREE && rs->c[i].region == region) return &rs->c[i];
    return NULL;
}

static int logged_in(const relay* r)
{
    return r->st == R_DERP && r->derp &&
           (r->derp->state == TS_DERP_WAIT_INFO || r->derp->state == TS_DERP_READY);
}

static uint16_t node_port(const bt_relays* rs, const bt_relay_node* n)
{
    return n->port ? n->port : (uint16_t)(rs->plain ? 80 : 443);
}

/* Drops the connection's socket and buffers; the slot stays for WAIT, or is freed. */
static void conn_close(bt_relays* rs, relay* r, int keep_slot)
{
    int was_home_up = r->region == rs->home && r->ready_told;

    bt_tls_free(&r->tls);
    free(r->http);
    r->http = NULL;
    if (r->derp) {
        ts_derp_clear(r->derp);
        free(r->derp);
        r->derp = NULL;
    }
    free(r->queue);
    r->queue = NULL;
    r->queue_len = 0;
    r->ready_told = 0;
    if (!keep_slot) {
        memset(r, 0, sizeof(*r));
        r->st = R_FREE;
    }
    if (was_home_up && rs->io.home) rs->io.home(rs->io.ctx, 0);
}

/* A connection failed: home waits and tries again (the next node, the other family); another
 * region is simply let go - traffic brings it back. */
static void conn_fail(bt_relays* rs, relay* r, const char* why, uint64_t now)
{
    const bt_relay_region* g = find_region(rs, r->region);
    uint64_t wait;

    BT_W("%s: relay %d: %s", rs->tag, r->region, why);
    if (r->region != rs->home || !g) {
        conn_close(rs, r, 0);
        return;
    }
    conn_close(rs, r, 1);
    r->fails++;
    wait = RETRY_MIN_NS << (r->fails > 5 ? 5 : r->fails - 1);
    if (wait > RETRY_MAX_NS) wait = RETRY_MAX_NS;
    if (r->restart_ms) {
        wait = (uint64_t)r->restart_ms * 1000000ULL;
        r->restart_ms = 0;
    }
    r->retry_at = now + wait;
    r->st = R_WAIT;
    /* Another node of the region, or the other family of this one, next time. */
    if (!r->v6 && g->nodes[r->node].v6.family) r->v6 = 1;
    else {
        r->v6 = 0;
        r->node = (r->node + 1) % (g->n_nodes ? g->n_nodes : 1);
    }
}

/* --------------------------------------------------------------------- ts_derp's upcalls */

static int up_write(void* ctx, const uint8_t* a, size_t alen, const uint8_t* b, size_t blen)
{
    relay* r = (relay*)ctx;
    if (alen + blen > sizeof(frame)) return 0;
    memcpy(frame, a, alen);
    if (blen) memcpy(frame + alen, b, blen);
    return bt_tls_write(&r->tls, frame, alen + blen);
}

static void up_packet(void* ctx, const uint8_t src[32], uint8_t* data, size_t len)
{
    relay* r = (relay*)ctx;
    r->set->packets_in++;
    if (r->set->io.packet) r->set->io.packet(r->set->io.ctx, r->region, src, data, len);
}

static void up_ready(void* ctx, const char* json, size_t len)
{
    relay* r = (relay*)ctx;
    BT_D("%s: relay %d: logged in, %.*s", r->set->tag, r->region, (int)(len > 120 ? 120 : len), json);
}

static void up_gone(void* ctx, const uint8_t key[32], int reason)
{
    relay* r = (relay*)ctx;
    (void)reason;
    if (r->set->io.peer_gone) r->set->io.peer_gone(r->set->io.ctx, r->region, key);
}

static void up_health(void* ctx, const char* text, size_t len)
{
    relay* r = (relay*)ctx;
    if (len) BT_W("%s: relay %d says: %.*s", r->set->tag, r->region, (int)(len > 200 ? 200 : len), text);
}

static void up_restarting(void* ctx, uint32_t in_ms, uint32_t for_ms)
{
    relay* r = (relay*)ctx;
    (void)for_ms;
    BT_I("%s: relay %d restarts: again in %u ms", r->set->tag, r->region, in_ms);
    /* The server goes after this frame; asking again sooner than it says only meets a closed door. */
    r->restart_ms = in_ms;
}

/* --------------------------------------------------------------------- connecting */

static int conn_start(bt_relays* rs, relay* r, uint64_t now)
{
    const bt_relay_region* g = find_region(rs, r->region);
    const bt_relay_node* n;
    bt_tls_params p;
    char req[1024];
    size_t len;
    ts_derp_io io;

    if (!g || !g->n_nodes) return 0;
    if (r->node >= g->n_nodes) r->node = 0;
    n = &g->nodes[r->node];
    if (r->v6 && !n->v6.family) r->v6 = 0;
    if (!r->v6 && !n->v4.family) r->v6 = 1;
    if (r->v6 && !n->v6.family) return 0;

    memset(&p, 0, sizeof(p));
    p.addr = r->v6 ? n->v6 : n->v4;
    p.port = node_port(rs, n);
    p.host = n->host;
    p.pin = n->pin[0] ? n->pin : NULL;
    p.plain = rs->plain;
    p.timeout_ms = CONNECT_MS;
    p.out_max = TLS_OUT_MAX;

    r->http = (ts_http1_resp*)malloc(sizeof(*r->http));
    r->derp = (ts_derp*)malloc(sizeof(*r->derp));
    if (!r->http || !r->derp) return 0;
    ts_http1_resp_init(r->http, NULL, 0);
    memset(&io, 0, sizeof(io));
    io.ctx = r;
    io.write = up_write;
    io.packet = up_packet;
    io.ready = up_ready;
    io.peer_gone = up_gone;
    io.health = up_health;
    io.restarting = up_restarting;
    ts_derp_init(r->derp, &rs->priv, &rs->pub, r->region == rs->home, NULL, &io);

    r->set = rs;
    r->since = now;
    r->last_rx = r->last_tx = now;
    r->in_poll = 0;
    r->st = R_CONNECTING;
    if (!bt_tls_connect(&r->tls, &p, -1, now)) return 0;
    /* The upgrade goes into the queue now: bt_tls sends it once the connection is open. The ideal
     * node is named when this is not it, for the server's statistics, as derphttp does. */
    len = ts_http1_derp_request(req, sizeof(req), n->host, p.port, !rs->plain,
                                r->node ? g->nodes[0].name : NULL);
    if (!len || !bt_tls_write(&r->tls, (const uint8_t*)req, len)) return 0;
    BT_D("%s: relay %d: connecting to %s (%s)", rs->tag, r->region, r->tls.peer, n->host);
    return 1;
}

/* A connection to `region`, made if there is none (and there is room). */
static relay* conn_get(bt_relays* rs, int region, uint64_t now)
{
    relay* r = find_conn(rs, region);
    int i, oldest = -1;

    if (r) return r;
    if (!find_region(rs, region)) return NULL;
    for (i = 0; i < BT_RELAY_CONNS && rs->c[i].st != R_FREE; i++) {}
    if (i == BT_RELAY_CONNS) {
        /* Full: the least used connection that is not home makes room. */
        for (i = 0; i < BT_RELAY_CONNS; i++) {
            relay* o = &rs->c[i];
            uint64_t last = o->last_rx > o->last_tx ? o->last_rx : o->last_tx;
            uint64_t best;
            if (o->region == rs->home || o->busy) continue;
            if (oldest < 0) {
                oldest = i;
                continue;
            }
            best = rs->c[oldest].last_rx > rs->c[oldest].last_tx ? rs->c[oldest].last_rx : rs->c[oldest].last_tx;
            if (last < best) oldest = i;
        }
        if (oldest < 0) return NULL;
        conn_close(rs, &rs->c[oldest], 0);
        i = oldest;
    }
    r = &rs->c[i];
    memset(r, 0, sizeof(*r));
    r->region = region;
    if (!conn_start(rs, r, now)) {
        conn_fail(rs, r, r->tls.error[0] ? r->tls.error : "cannot start a connection", now);
        return find_conn(rs, region);
    }
    return r;
}

/* The login went out: what waited goes now. */
static void flush_queue(bt_relays* rs, relay* r)
{
    size_t off = 0;

    while (off + 2 + TS_DERP_KEY_LEN <= r->queue_len) {
        size_t len = (size_t)r->queue[off] << 8 | r->queue[off + 1];
        const uint8_t* key = r->queue + off + 2;
        if (!ts_derp_send(r->derp, key, key + TS_DERP_KEY_LEN, len)) rs->dropped++;
        else rs->packets_out++;
        off += 2 + TS_DERP_KEY_LEN + len;
    }
    free(r->queue);
    r->queue = NULL;
    r->queue_len = 0;
}

/* --------------------------------------------------------------------- reading */

static void conn_read(bt_relays* rs, relay* r, uint64_t now)
{
    for (;;) {
        size_t n = bt_tls_read(&r->tls, rbuf, sizeof(rbuf)), off = 0;

        if (!n) break;
        r->last_rx = now;
        if (r->st == R_CONNECTING) r->st = R_UPGRADE;
        if (r->st == R_UPGRADE) {
            size_t used = 0;
            ts_http1_state s = ts_http1_resp_feed(r->http, rbuf, n, &used);
            if (s == TS_HTTP1_MORE) continue;
            if (s != TS_HTTP1_UPGRADED || !ts_http1_resp_upgraded(r->http, "DERP")) {
                char why[160];
                if (s == TS_HTTP1_FAILED) snprintf(why, sizeof(why), "not HTTP: %s", ts_http1_error_text(r->http->error));
                else snprintf(why, sizeof(why), "no DERP upgrade: HTTP %d", r->http->status);
                conn_fail(rs, r, why, now);
                return;
            }
            free(r->http);
            r->http = NULL;
            r->st = R_DERP;
            off = used;
        }
        if (off < n) {
            int ok;
            r->busy = 1;
            ok = ts_derp_input(r->derp, rbuf + off, n - off);
            r->busy = 0;
            if (!ok) {
                char why[160];
                snprintf(why, sizeof(why), "DERP: %s", r->derp->error ? r->derp->error : "broken");
                conn_fail(rs, r, why, now);
                return;
            }
        }
        if (logged_in(r) && r->queue) flush_queue(rs, r);
        if (r->st == R_DERP && r->derp->state == TS_DERP_READY) {
            r->fails = 0;
            if (r->region == rs->home && !r->ready_told) {
                r->ready_told = 1;
                BT_I("%s: home relay %d up (%s)", rs->tag, r->region, r->tls.peer);
                if (rs->io.home) rs->io.home(rs->io.ctx, 1);
            }
        }
    }
    if (r->tls.state == BT_TLS_FAILED || r->tls.state == BT_TLS_CLOSED) {
        conn_fail(rs, r, r->tls.error[0] ? r->tls.error : "closed by the server", now);
    }
}

/* --------------------------------------------------------------------- the set */

bt_relays* bt_relays_new(const wg_key* node_priv, const wg_key* node_pub, int plain, const char* tag,
                         const bt_relay_io* io)
{
    bt_relays* rs = (bt_relays*)calloc(1, sizeof(*rs));

    if (!rs) return NULL;
    rs->priv = *node_priv;
    rs->pub = *node_pub;
    rs->plain = plain;
    snprintf(rs->tag, sizeof(rs->tag), "%s", tag);
    if (io) rs->io = *io;
    return rs;
}

static void probes_close(bt_relays* rs)
{
    size_t i;
    for (i = 0; i < rs->n_probes; i++) bt_tls_free(&rs->probes[i].tls);
    rs->n_probes = 0;
    rs->probe_until = 0;
}

void bt_relays_free(bt_relays* rs)
{
    int i;
    if (!rs) return;
    rs->io.home = NULL;                     /* going away: nobody to tell */
    for (i = 0; i < BT_RELAY_CONNS; i++)
        if (rs->c[i].st != R_FREE) conn_close(rs, &rs->c[i], 0);
    probes_close(rs);
    wg_wipe(&rs->priv, sizeof(rs->priv));
    free(rs);
}

static int node_same(const bt_relay_node* a, const bt_relay_node* b)
{
    return strcmp(a->host, b->host) == 0 && a->port == b->port && strcmp(a->pin, b->pin) == 0 &&
           bt_addr_equal(&a->v4, &b->v4) && bt_addr_equal(&a->v6, &b->v6);
}

void bt_relays_set_map(bt_relays* rs, const bt_relay_region* regions, size_t n, uint64_t now)
{
    int i;
    size_t k;

    if (n > BT_RELAY_REGIONS) n = BT_RELAY_REGIONS;
    /* A connection stays only where its node is still there as it was. */
    for (i = 0; i < BT_RELAY_CONNS; i++) {
        relay* r = &rs->c[i];
        const bt_relay_region* old;
        const bt_relay_region* now_g = NULL;
        if (r->st == R_FREE) continue;
        old = find_region(rs, r->region);
        for (k = 0; k < n; k++)
            if (regions[k].id == r->region) now_g = &regions[k];
        if (!old || !now_g || r->node >= now_g->n_nodes || r->node >= old->n_nodes ||
            !node_same(&old->nodes[r->node], &now_g->nodes[r->node])) {
            BT_I("%s: relay %d changed in the DERP map", rs->tag, r->region);
            conn_close(rs, r, 0);
        }
    }
    memcpy(rs->map, regions, n * sizeof(*regions));
    rs->n_map = n;
    if (rs->home && !find_region(rs, rs->home)) {
        BT_W("%s: home relay %d left the DERP map", rs->tag, rs->home);
        rs->home = 0;
    }
    if (rs->home) conn_get(rs, rs->home, now);
}

const bt_relay_region* bt_relays_region(const bt_relays* rs, int id)
{
    return find_region(rs, id);
}

void bt_relays_set_home(bt_relays* rs, int region, uint64_t now)
{
    relay* old;
    relay* r;

    if (region == rs->home) {
        if (region) conn_get(rs, region, now);
        return;
    }
    old = rs->home ? find_conn(rs, rs->home) : NULL;
    if (old && old->ready_told) {
        old->ready_told = 0;
        if (rs->io.home) rs->io.home(rs->io.ctx, 0);
    }
    if (old && logged_in(old)) ts_derp_note_preferred(old->derp, 0);
    if (old && old->st == R_WAIT) conn_close(rs, old, 0);
    rs->home = region;
    if (!region) return;
    BT_I("%s: home relay: %d", rs->tag, region);
    r = conn_get(rs, region, now);
    if (r && r->derp && r->derp->state != TS_DERP_BROKEN) ts_derp_note_preferred(r->derp, 1);
    if (r && r->st == R_DERP && r->derp && r->derp->state == TS_DERP_READY && !r->ready_told) {
        r->ready_told = 1;
        if (rs->io.home) rs->io.home(rs->io.ctx, 1);
    }
}

int bt_relays_home(const bt_relays* rs)
{
    return rs->home;
}

int bt_relays_home_up(const bt_relays* rs)
{
    int i;
    for (i = 0; i < BT_RELAY_CONNS; i++)
        if (rs->c[i].st == R_DERP && rs->c[i].region == rs->home && rs->c[i].ready_told) return 1;
    return 0;
}

int bt_relays_open(const bt_relays* rs, int region)
{
    int i;
    for (i = 0; i < BT_RELAY_CONNS; i++)
        if (rs->c[i].region == region && logged_in(&rs->c[i])) return 1;
    return 0;
}

/* A packet not sent. The debug log gets the first of a run of drops with its reason, and the
 * run's end (sent) - not a line per packet. */
static int drop(bt_relays* rs, int region, const char* why)
{
    rs->dropped++;
    if (rs->drop_why != why) {
        BT_D("%s: relay %d: a packet not sent: %s", rs->tag, region, why);
        rs->drop_why = why;
    }
    rs->drop_streak++;
    return 0;
}

int bt_relays_send(bt_relays* rs, int region, const uint8_t dst[32], const uint8_t* pkt, size_t len,
                   uint64_t now)
{
    relay* r;

    if (len > TS_DERP_MAX_PACKET) return drop(rs, region, "too big for a relay");
    r = conn_get(rs, region, now);
    if (!r) return drop(rs, region, "no connection to the region (not in the DERP map, or no room)");
    r->last_tx = now;
    if (r->st == R_WAIT) return drop(rs, region, "its connection waits to try again");
    if (rs->drop_why) {
        BT_D("%s: relay %d: sending again after %llu packet(s) not sent", rs->tag, region,
             (unsigned long long)rs->drop_streak);
        rs->drop_why = NULL;
        rs->drop_streak = 0;
    }
    if (!logged_in(r)) {
        uint8_t* q;
        if (r->queue_len + 2 + TS_DERP_KEY_LEN + len > QUEUE_MAX) return drop(rs, region, "the queue for the login is full");
        q = (uint8_t*)realloc(r->queue, r->queue_len + 2 + TS_DERP_KEY_LEN + len);
        if (!q) return drop(rs, region, "out of memory");
        r->queue = q;
        q += r->queue_len;
        q[0] = (uint8_t)(len >> 8);
        q[1] = (uint8_t)len;
        memcpy(q + 2, dst, TS_DERP_KEY_LEN);
        memcpy(q + 2 + TS_DERP_KEY_LEN, pkt, len);
        r->queue_len += 2 + TS_DERP_KEY_LEN + len;
        return 1;
    }
    /* A full TLS queue (a slow link) drops this packet rather than the connection - WireGuard
     * copes with loss, and ts_derp breaks on a refused write. */
    if (bt_tls_queued(&r->tls) + TS_DERP_HDR_LEN + TS_DERP_KEY_LEN + len > TLS_OUT_MAX)
        return drop(rs, region, "the TLS queue is full (a slow link)");
    if (!ts_derp_send(r->derp, dst, pkt, len)) {
        /* Inside its own input (a reply from an upcall) it is failed when that returns. */
        if (!r->busy) conn_fail(rs, r, "cannot queue a packet", now);
        return drop(rs, region, "the relay refused it");
    }
    rs->packets_out++;
    return 1;
}

/* --------------------------------------------------------------------- measuring home */

void bt_relays_measure(bt_relays* rs, const int64_t* regions, size_t count, uint64_t now)
{
    size_t i;

    probes_close(rs);
    rs->early_told = 0;
    for (i = 0; i < count && rs->n_probes < BT_RELAY_REGIONS; i++) {
        const bt_relay_region* g = find_region(rs, (int)regions[i]);
        const bt_relay_node* n;
        bt_tls_params params;
        probe* p;

        if (!g || !g->n_nodes) continue;
        n = &g->nodes[0];
        if (!n->v4.family && !n->v6.family) continue;
        memset(&params, 0, sizeof(params));
        params.addr = n->v4.family ? n->v4 : n->v6;
        params.port = node_port(rs, n);
        params.host = n->host;
        params.pin = n->pin[0] ? n->pin : NULL;
        params.plain = rs->plain;
        params.timeout_ms = (uint32_t)(MEASURE_NS / 1000000ULL);
        p = &rs->probes[rs->n_probes];
        p->region = g->id;
        p->start = now;
        p->tcp_at = 0;
        p->ns = 0;
        p->done = 0;
        p->in_poll = 0;
        if (!bt_tls_connect(&p->tls, &params, -1, now)) {
            BT_D("%s: relay %d not measured: %s", rs->tag, g->id, p->tls.error);
            bt_tls_free(&p->tls);
            continue;
        }
        rs->n_probes++;
    }
    rs->probe_until = rs->n_probes ? now + MEASURE_NS : 0;
    if (!rs->n_probes && rs->io.measured) rs->io.measured(rs->io.ctx, NULL, NULL, 0);
}

static void measure_done(bt_relays* rs)
{
    int64_t region[BT_RELAY_REGIONS];
    uint64_t ns[BT_RELAY_REGIONS];
    char text[400];
    size_t i, n = rs->n_probes, used = 0, answered = 0;

    text[0] = '\0';
    for (i = 0; i < n; i++) {
        region[i] = rs->probes[i].region;
        ns[i] = rs->probes[i].ns;
        if (ns[i] == 0) continue;
        answered++;
        if (used < sizeof(text)) {
            int k = snprintf(text + used, sizeof(text) - used, " %d:%llu", (int)region[i],
                             (unsigned long long)(ns[i] / 1000000ULL));
            if (k > 0) used += (size_t)k;
        }
    }
    probes_close(rs);
    BT_D("%s: home measured: %u region(s), %u answered, ms:%s", rs->tag, (unsigned)n, (unsigned)answered, text);
    if (rs->io.measured) rs->io.measured(rs->io.ctx, region, ns, n);
}

/*
 * Where a probe stands after a step or a tick: the TCP connect made (the handshake's clock starts
 * there), the handshake over (the answer: the time since the connect - about one round trip to the
 * server, whatever proxy answered the connect), or failed (no answer). A done probe holds nothing.
 */
static void probe_check(bt_relays* rs, probe* p, uint64_t now)
{
    if (p->done) return;
    if (!p->tcp_at && p->tls.state != BT_TLS_CONNECTING) p->tcp_at = now;
    if (p->tls.state == BT_TLS_OPEN) {
        /* Plain (the stand) has no handshake to time: the connect is all there is. */
        uint64_t from = rs->plain ? p->start : p->tcp_at;
        p->ns = now > from ? now - from : 1;
    } else if (p->tls.state == BT_TLS_FAILED || p->tls.state == BT_TLS_CLOSED) {
        BT_D("%s: relay %d not measured: %s", rs->tag, p->region, p->tls.error);
    } else {
        return;                             /* still on its way */
    }
    p->done = 1;
    bt_tls_free(&p->tls);
}

static int probes_all_done(const bt_relays* rs)
{
    size_t i;
    for (i = 0; i < rs->n_probes; i++)
        if (!rs->probes[i].done) return 0;
    return 1;
}

/* The first answer is the nearest region: with no home yet it goes up at once, so the tunnel need
 * not wait for the slowest region (or 3 s) to come up; the whole round may still move home. */
static void probe_answered(bt_relays* rs, const probe* p)
{
    int64_t region = p->region;
    uint64_t ns = p->ns;

    if (rs->early_told || rs->home || !rs->io.measured) return;
    rs->early_told = 1;
    rs->io.measured(rs->io.ctx, &region, &ns, 1);
}

static void probe_step(bt_relays* rs, probe* p, short revents, uint64_t now)
{
    bt_tls_step(&p->tls, revents);
    probe_check(rs, p, now);
    if (p->ns) probe_answered(rs, p);
    if (probes_all_done(rs)) measure_done(rs);
}

/* --------------------------------------------------------------------- the loop */

void bt_relays_reconnect(bt_relays* rs, uint64_t now)
{
    int i;

    for (i = 0; i < BT_RELAY_CONNS; i++) {
        relay* r = &rs->c[i];
        if (r->st == R_FREE) continue;
        if (r->region == rs->home) {
            conn_close(rs, r, 1);
            r->fails = 0;
            r->st = R_WAIT;
            r->retry_at = now;                  /* at once, in the next tick */
        } else {
            conn_close(rs, r, 0);
        }
    }
    if (rs->home && !find_conn(rs, rs->home)) conn_get(rs, rs->home, now);
}

int bt_relays_pollfds(bt_relays* rs, struct pollfd* out, int cap)
{
    int n = 0, i;
    size_t k;

    for (i = 0; i < BT_RELAY_CONNS && n < cap; i++) {
        relay* r = &rs->c[i];
        int fd = r->st == R_FREE || r->st == R_WAIT ? -1 : bt_tls_fd(&r->tls);
        if (fd < 0) continue;
        r->in_poll = 1;
        out[n].fd = fd;
        out[n].events = bt_tls_events(&r->tls);
        out[n++].revents = 0;
    }
    for (k = 0; k < rs->n_probes && n < cap; k++) {
        probe* p = &rs->probes[k];
        int fd = p->done ? -1 : bt_tls_fd(&p->tls);
        if (fd < 0) continue;
        p->in_poll = 1;
        out[n].fd = fd;
        out[n].events = bt_tls_events(&p->tls);
        out[n++].revents = 0;
    }
    return n;
}

int bt_relays_owns(const bt_relays* rs, int fd)
{
    int i;
    size_t k;

    if (fd < 0) return 0;
    for (i = 0; i < BT_RELAY_CONNS; i++)
        if (rs->c[i].st != R_FREE && rs->c[i].st != R_WAIT && bt_tls_fd(&rs->c[i].tls) == fd) return 1;
    for (k = 0; k < rs->n_probes; k++)
        if (!rs->probes[k].done && bt_tls_fd(&rs->probes[k].tls) == fd) return 1;
    return 0;
}

void bt_relays_io(bt_relays* rs, const struct pollfd* pfd, uint64_t now)
{
    int i;
    size_t k;

    for (i = 0; i < BT_RELAY_CONNS; i++) {
        relay* r = &rs->c[i];
        if (r->st == R_FREE || r->st == R_WAIT || bt_tls_fd(&r->tls) != pfd->fd) continue;
        /* A connection made while this round's results are handed out may have got a closed
         * one's fd number: those results are not its. */
        if (!r->in_poll) return;
        bt_tls_step(&r->tls, pfd->revents);
        conn_read(rs, r, now);
        return;
    }
    for (k = 0; k < rs->n_probes; k++) {
        probe* p = &rs->probes[k];
        if (p->done || bt_tls_fd(&p->tls) != pfd->fd) continue;
        if (!p->in_poll) return;            /* a new probe on a closed fd's number: not its results */
        probe_step(rs, p, pfd->revents, now);
        return;
    }
}

uint64_t bt_relays_tick(bt_relays* rs, uint64_t now)
{
    uint64_t next = BT_NEVER;
    int i;

    for (i = 0; i < BT_RELAY_CONNS; i++) {
        relay* r = &rs->c[i];
        uint64_t d, last;

        if (r->st == R_FREE) continue;
        if (r->st == R_WAIT) {
            if (r->region != rs->home) {
                conn_close(rs, r, 0);
                continue;
            }
            if (now >= r->retry_at) {
                if (!conn_start(rs, r, now)) {
                    conn_fail(rs, r, r->tls.error[0] ? r->tls.error : "cannot start a connection", now);
                    if (r->st == R_WAIT && r->retry_at < next) next = r->retry_at;
                    continue;
                }
            } else {
                if (r->retry_at < next) next = r->retry_at;
                continue;
            }
        }
        d = bt_tls_tick(&r->tls, now);
        if (r->tls.state == BT_TLS_FAILED || r->tls.state == BT_TLS_CLOSED) {
            conn_fail(rs, r, r->tls.error[0] ? r->tls.error : "closed", now);
            if (r->st == R_WAIT && r->retry_at < next) next = r->retry_at;
            continue;
        }
        if (d < next) next = d;
        if (!(r->st == R_DERP && r->derp && r->derp->state == TS_DERP_READY)) {
            if (now - r->since >= LOGIN_NS) {
                conn_fail(rs, r, "no DERP login within 15 s", now);
                if (r->st == R_WAIT && r->retry_at < next) next = r->retry_at;
                continue;
            }
            if (r->since + LOGIN_NS < next) next = r->since + LOGIN_NS;
        }
        /* A server that said nothing for two keepalive periods is gone, whatever TCP thinks. */
        if (r->st == R_DERP && now - r->last_rx >= DEAD_NS) {
            conn_fail(rs, r, "no word from the server for two minutes", now);
            if (r->st == R_WAIT && r->retry_at < next) next = r->retry_at;
            continue;
        }
        if (r->st == R_DERP && r->last_rx + DEAD_NS < next) next = r->last_rx + DEAD_NS;
        /* Not home: a minute without traffic either way and it goes. */
        last = r->last_rx > r->last_tx ? r->last_rx : r->last_tx;
        if (r->region != rs->home) {
            if (now - last >= BT_RELAY_IDLE_NS) {
                BT_D("%s: relay %d idle, closed", rs->tag, r->region);
                conn_close(rs, r, 0);
                continue;
            }
            if (last + BT_RELAY_IDLE_NS < next) next = last + BT_RELAY_IDLE_NS;
        }
        /* bt_tls may hold decrypted bytes poll cannot see. */
        if (bt_tls_pending(&r->tls)) conn_read(rs, r, now);
    }
    if (rs->n_probes) {
        size_t k;
        for (k = 0; k < rs->n_probes; k++) {
            probe* p = &rs->probes[k];
            uint64_t d;
            if (p->done) continue;
            d = bt_tls_tick(&p->tls, now);
            probe_check(rs, p, now);
            if (p->ns) probe_answered(rs, p);
            if (!p->done && d < next) next = d;
        }
        if (probes_all_done(rs) || now >= rs->probe_until) measure_done(rs);
        else if (rs->probe_until < next) next = rs->probe_until;
    }
    return next;
}

void bt_relays_stats(const bt_relays* rs, bt_relay_stats* st)
{
    int i;

    memset(st, 0, sizeof(*st));
    st->home = rs->home;
    st->home_up = bt_relays_home_up(rs);
    for (i = 0; i < BT_RELAY_CONNS; i++)
        if (logged_in(&rs->c[i])) st->open++;
    st->packets_in = rs->packets_in;
    st->packets_out = rs->packets_out;
    st->dropped = rs->dropped;
}
