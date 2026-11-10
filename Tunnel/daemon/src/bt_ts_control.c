/*
 * bt_ts_control - see bt_ts_control.h.
 */

#include "bt_ts_control.h"
#include "bt_log.h"
#include "bt_plat.h"
#include "bt_tls.h"
#include "ts_h2.h"
#include "ts_http1.h"
#include "ts_json.h"
#include "ts_netmap.h"
#include "ts_noise.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SEC                 1000000000ULL
#define STEP_NS             (30ULL * SEC)       /* name, /key, upgrade and handshake: all of it */
#define WATCHDOG_NS         (120ULL * SEC)      /* direct.go: a map stream silent this long is dead */
#define RETRY_MIN_NS        (1ULL * SEC)
#define RETRY_MAX_NS        (60ULL * SEC)
#define STREAM_WINDOW       (256u * 1024)       /* per stream: the first netmap comes at once */
#define TLS_OUT_MAX         (256 * 1024)
#define BODY_MAX            TS_NM_REGISTER_MSG_MAX
#define ERROR_BODY_MAX      512                 /* of a failed response, for the log */
#define READ_CHUNK          16384

typedef enum {
    C_IDLE = 0,             /* not started */
    C_WAIT,                 /* after a failure, until retry_at */
    C_RESOLVE,              /* the server's name */
    C_KEY,                  /* GET /key, a connection of its own */
    C_UPGRADE,              /* POST /ts2021, waiting for the 101 */
    C_NOISE,                /* the handshake's response */
    C_OPEN                  /* HTTP/2 inside the Noise records */
} cstate;

typedef struct {
    int         id;                     /* the caller's number; 0 = a free slot */
    uint32_t    stream;
    bt_tsc_mode mode;
    int         status;
    uint64_t    retry_after;
    uint8_t*    buf;                    /* BODY and error bodies: the body; STREAM: one message */
    size_t      len, cap;
    size_t      need;                   /* STREAM: the message's length once its 4 bytes are in */
    uint8_t     lenb[4];
    size_t      lenb_got;
    uint64_t    last;                   /* STREAM: when data last came (the watchdog) */
} creq;

struct bt_tsc {
    ts_url      url;
    char        tag[24];
    bt_tsc_calls io;
    uint16_t    capver;
    wg_key      machine;
    wg_key      server;
    int         has_server;
    int         server_cached;          /* the key came from the profile, not this run's /key */
    bt_addr     addr;                   /* where the name led (or the cache) */
    int         has_addr;

    cstate      st;
    int         was_open;
    bt_tls      tls;
    int         in_poll;
    bt_lookup   lookup;
    int         dns_fd[2];
    ts_http1_resp* http;
    uint8_t*    key_body;
    ts_noise*   noise;
    ts_h2*      h2;
    creq        reqs[TS_H2_MAX_STREAMS];
    int         next_id;
    uint64_t    step_until;
    uint64_t    retry_at;
    unsigned    fails;
    char        error[160];

    /* A drop asked for from inside an upcall waits until the upcall returns: the objects the
     * upcall's caller still holds must stay. `gen` tells a loop that the connection it was
     * reading is gone. */
    int         in_upcall;
    int         drop_pending;
    char        drop_why[160];
    uint64_t    drop_delay;
    unsigned    gen;
};

static uint8_t rbuf[READ_CHUNK];
static uint8_t plain[TS_NOISE_MAX_PLAINTEXT];
static uint8_t sealed[64 * 1024];

static void close_all(bt_tsc* c);
static void fail(bt_tsc* c, uint64_t now, const char* fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 3, 4)))
#endif
    ;

/* --------------------------------------------------------------------- requests' slots */

static creq* req_by_stream(bt_tsc* c, uint32_t stream)
{
    int i;
    for (i = 0; i < TS_H2_MAX_STREAMS; i++)
        if (c->reqs[i].id && c->reqs[i].stream == stream) return &c->reqs[i];
    return NULL;
}

static void req_free(creq* r)
{
    free(r->buf);
    memset(r, 0, sizeof(*r));
}

static int append(creq* r, const uint8_t* p, size_t n, size_t max)
{
    if (r->len + n > max) return 0;
    if (r->len + n > r->cap) {
        size_t cap = r->cap ? r->cap : 4096;
        uint8_t* b;
        while (cap < r->len + n) cap *= 2;
        if (cap > max) cap = max;
        b = (uint8_t*)realloc(r->buf, cap);
        if (!b) return 0;
        r->buf = b;
        r->cap = cap;
    }
    memcpy(r->buf + r->len, p, n);
    r->len += n;
    return 1;
}

/* --------------------------------------------------------------------- upcalls, guarded */

static void up_open(bt_tsc* c)
{
    if (!c->io.open) return;
    c->in_upcall++;
    c->io.open(c->io.ctx);
    c->in_upcall--;
}

static void up_response(bt_tsc* c, creq* r)
{
    int id = r->id, status = r->status;
    uint64_t ra = r->retry_after;
    uint8_t* body = r->buf;
    size_t len = r->len;

    r->buf = NULL;
    req_free(r);                        /* the slot is free for a request the upcall makes */
    if (c->io.response) {
        c->in_upcall++;
        c->io.response(c->io.ctx, id, status, body, len, ra);
        c->in_upcall--;
    }
    free(body);
}

static void up_message(bt_tsc* c, creq* r)
{
    if (!c->io.message) return;
    c->in_upcall++;
    c->io.message(c->io.ctx, r->id, (char*)r->buf, r->len);
    c->in_upcall--;
}

/* --------------------------------------------------------------------- the bytes out */

/* What HTTP/2 has for the server, sealed into Noise records, into TLS - only as much as TLS takes
 * at once: a sealed record must go out (its nonce is spent), so nothing is sealed that cannot. */
static void flush_out(bt_tsc* c, uint64_t now)
{
    while (c->st == C_OPEN) {
        size_t len, used = 0, out_len = 0, room;
        const uint8_t* out = ts_h2_output(c->h2, &len);

        if (!len) return;
        room = TLS_OUT_MAX - bt_tls_queued(&c->tls);
        if (room > sizeof(sealed)) room = sizeof(sealed);
        if (room < TS_NOISE_RECORD_OVERHEAD + 1) return;    /* POLLOUT brings us back */
        if (!ts_noise_seal(c->noise, out, len, &used, sealed, room, &out_len)) {
            fail(c, now, "Noise: %s", ts_noise_error_text(c->noise->err));
            return;
        }
        if (!used) return;
        if (!bt_tls_write(&c->tls, sealed, out_len)) {
            fail(c, now, "cannot queue %u bytes for control", (unsigned)out_len);
            return;
        }
        ts_h2_output_done(c->h2, used);
    }
}

/* --------------------------------------------------------------------- HTTP/2 events */

static void stream_data(bt_tsc* c, creq* r, const uint8_t* p, size_t n, uint64_t now)
{
    unsigned gen = c->gen;

    if (r->status != 200 || r->mode == BT_TSC_DISCARD) {
        if (r->status != 200 && r->len < ERROR_BODY_MAX) {
            size_t k = n < ERROR_BODY_MAX - r->len ? n : ERROR_BODY_MAX - r->len;
            append(r, p, k, ERROR_BODY_MAX);
        }
        return;
    }
    if (r->mode == BT_TSC_BODY) {
        if (!append(r, p, n, BODY_MAX)) fail(c, now, "a response over %u bytes", (unsigned)BODY_MAX);
        return;
    }
    /* STREAM: each message is its length (32 bits, little-endian), then that much JSON. */
    r->last = now;
    while (n) {
        if (r->lenb_got < 4) {
            r->lenb[r->lenb_got++] = *p++;
            n--;
            if (r->lenb_got == 4) {
                r->need = (size_t)r->lenb[0] | (size_t)r->lenb[1] << 8 | (size_t)r->lenb[2] << 16 |
                          (size_t)r->lenb[3] << 24;
                r->len = 0;
                if (!r->need || r->need > TS_NM_MSG_MAX) {
                    fail(c, now, "a map message of %u bytes", (unsigned)r->need);
                    return;
                }
            }
            continue;
        }
        {
            size_t k = r->need - r->len < n ? r->need - r->len : n;
            if (!append(r, p, k, TS_NM_MSG_MAX)) {
                fail(c, now, "out of memory for a map message");
                return;
            }
            p += k;
            n -= k;
            if (r->len == r->need) {
                c->fails = 0;           /* a map message: the server works, the delays start over */
                up_message(c, r);
                if (c->gen != gen || !r->id) return;
                r->len = 0;
                r->lenb_got = 0;
            }
        }
    }
}

static void h2_event(bt_tsc* c, const ts_h2_event* ev, uint64_t now)
{
    creq* r = ev->stream ? req_by_stream(c, ev->stream) : NULL;

    switch (ev->type) {
    case TS_H2_EV_EARLY:
        BT_D("%s: EarlyNoise, %u bytes", c->tag, (unsigned)ev->len);
        break;
    case TS_H2_EV_HEADERS:
        if (!r) break;
        r->status = ev->status;
        {
            size_t vl;
            const char* v = ts_h2_field_value(ev, "retry-after", &vl);
            uint64_t s, sec = 0;
            /* As tailscaled: a value of 0 or over an hour is none - the caller picks its own delay. */
            if (v && ts_http_retry_after(v, vl, (uint64_t)time(NULL), &s) && s > 0 && s <= 3600) sec = s;
            r->retry_after = sec;
        }
        r->len = 0;
        break;
    case TS_H2_EV_DATA:
        if (r) stream_data(c, r, ev->data, ev->len, now);
        if (c->st == C_OPEN) ts_h2_consume(c->h2, ev->stream, ev->len);
        break;
    case TS_H2_EV_END:
        if (r) up_response(c, r);
        break;
    case TS_H2_EV_RESET:
        if (r) {
            BT_D("%s: stream %u reset: %s", c->tag, ev->stream, ts_h2_error_text(ev->error));
            r->status = 0;
            up_response(c, r);
        }
        break;
    case TS_H2_EV_GOAWAY:
        BT_I("%s: control is going away (%s)", c->tag, ts_h2_error_text(ev->error));
        break;
    case TS_H2_EV_CLOSED:
        fail(c, now, "HTTP/2: %s", ev->error == TS_H2_ERR_EOF ? "the connection closed" : ts_h2_error_text(ev->error));
        break;
    case TS_H2_EV_NONE:
        break;
    }
}

/* Plaintext from the records into HTTP/2, every event handled; 0 when the connection went. */
static int h2_feed(bt_tsc* c, const uint8_t* p, size_t n, uint64_t now)
{
    unsigned gen = c->gen;
    size_t off = 0;

    for (;;) {
        ts_h2_event ev;
        off += ts_h2_input(c->h2, p + off, n - off, &ev);
        if (ev.type == TS_H2_EV_NONE) break;
        h2_event(c, &ev, now);
        if (c->gen != gen || c->st != C_OPEN) return 0;
    }
    return 1;
}

/* --------------------------------------------------------------------- the steps */

static void dns_close(bt_tsc* c)
{
    int k;
    for (k = 0; k < 2; k++) {
        if (c->dns_fd[k] >= 0) close(c->dns_fd[k]);
        c->dns_fd[k] = -1;
    }
}

static void close_all(bt_tsc* c)
{
    int i;

    c->gen++;
    bt_tls_free(&c->tls);
    dns_close(c);
    free(c->http);
    c->http = NULL;
    free(c->key_body);
    c->key_body = NULL;
    if (c->noise) {
        ts_noise_wipe(c->noise);
        free(c->noise);
        c->noise = NULL;
    }
    free(c->h2);
    c->h2 = NULL;
    for (i = 0; i < TS_H2_MAX_STREAMS; i++)
        if (c->reqs[i].id) req_free(&c->reqs[i]);
}

/* Down until retry_at; `delay` 0 grows with the failures in a row. */
static void go_wait(bt_tsc* c, uint64_t delay, uint64_t now)
{
    int was_open = c->st == C_OPEN;

    close_all(c);
    if (!delay) {
        c->fails++;
        delay = RETRY_MIN_NS << (c->fails > 7 ? 6 : c->fails - 1);
        if (delay > RETRY_MAX_NS) delay = RETRY_MAX_NS;
    }
    c->retry_at = now + delay;
    c->st = C_WAIT;
    if (was_open && c->io.lost) {
        c->in_upcall++;
        c->io.lost(c->io.ctx, c->error);
        c->in_upcall--;
    }
}

static void fail(bt_tsc* c, uint64_t now, const char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(c->error, sizeof(c->error), fmt, ap);
    va_end(ap);
    if (c->in_upcall) {
        /* Inside an upcall from deeper down: the drop happens when it returns. */
        if (!c->drop_pending) {
            c->drop_pending = 1;
            c->drop_delay = 0;
            snprintf(c->drop_why, sizeof(c->drop_why), "%s", c->error);
        }
        c->gen++;
        return;
    }
    BT_W("%s: control: %s", c->tag, c->error);
    go_wait(c, 0, now);
}

static int connect_to(bt_tsc* c, cstate next, uint64_t now)
{
    bt_tls_params p;
    char req[1536];
    size_t len = 0;

    bt_tls_free(&c->tls);
    memset(&p, 0, sizeof(p));
    p.addr = c->addr;
    p.port = c->url.port;
    p.host = c->url.host;
    p.plain = !c->url.tls;
    p.timeout_ms = (uint32_t)(STEP_NS / 1000000ULL);
    p.out_max = TLS_OUT_MAX;
    c->in_poll = 0;
    if (!bt_tls_connect(&c->tls, &p, -1, now)) {
        fail(c, now, "%s", c->tls.error[0] ? c->tls.error : "cannot connect");
        return 0;
    }
    free(c->http);
    c->http = (ts_http1_resp*)malloc(sizeof(*c->http));
    if (!c->http) {
        fail(c, now, "out of memory");
        return 0;
    }
    if (next == C_KEY) {
        if (!c->key_body) c->key_body = (uint8_t*)malloc(TS_NM_KEY_MSG_MAX);
        if (!c->key_body) {
            fail(c, now, "out of memory");
            return 0;
        }
        ts_http1_resp_init(c->http, c->key_body, TS_NM_KEY_MSG_MAX);
        len = ts_http1_key_request(req, sizeof(req), c->url.host, c->url.port, c->url.tls, c->capver);
    } else {
        uint8_t init[TS_NOISE_INIT_LEN];
        if (!c->noise) c->noise = (ts_noise*)calloc(1, sizeof(*c->noise));
        if (!c->noise || !ts_noise_init(c->noise, &c->machine, &c->server, c->capver, NULL) ||
            !ts_noise_initiation(c->noise, init)) {
            fail(c, now, "cannot begin the Noise handshake");
            return 0;
        }
        ts_http1_resp_init(c->http, NULL, 0);
        len = ts_http1_ts2021_request(req, sizeof(req), c->url.host, c->url.port, init, sizeof(init));
        wg_wipe(init, sizeof(init));
    }
    if (!len || !bt_tls_write(&c->tls, (const uint8_t*)req, len)) {
        fail(c, now, "cannot send the request");
        return 0;
    }
    c->st = next;
    BT_D("%s: %s to %s", c->tag, next == C_KEY ? "key" : "ts2021", c->tls.peer);
    return 1;
}

static void have_address(bt_tsc* c, uint64_t now)
{
    dns_close(c);
    connect_to(c, c->has_server ? C_UPGRADE : C_KEY, now);
}

static void dns_send(void* ctx, const bt_addr* server, const uint8_t* q, size_t len)
{
    bt_tsc* c = (bt_tsc*)ctx;
    int k = server->family == 6 ? 1 : 0;
    struct sockaddr_storage ss;
    socklen_t sl;

    if (c->dns_fd[k] < 0) {
        c->dns_fd[k] = socket(server->family == 6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
        if (c->dns_fd[k] < 0) return;
        fcntl(c->dns_fd[k], F_SETFL, fcntl(c->dns_fd[k], F_GETFL) | O_NONBLOCK);
        fcntl(c->dns_fd[k], F_SETFD, FD_CLOEXEC);
    }
    memset(&ss, 0, sizeof(ss));
    if (server->family == 6) {
        struct sockaddr_in6* s = (struct sockaddr_in6*)&ss;
        s->sin6_family = AF_INET6;
        s->sin6_port = htons(BT_DNS_PORT);
        memcpy(&s->sin6_addr, server->addr, 16);
        sl = sizeof(*s);
    } else {
        struct sockaddr_in* s = (struct sockaddr_in*)&ss;
        s->sin_family = AF_INET;
        s->sin_port = htons(BT_DNS_PORT);
        memcpy(&s->sin_addr, server->addr, 4);
        sl = sizeof(*s);
    }
    sendto(c->dns_fd[k], q, len, 0, (struct sockaddr*)&ss, sl);
}

/* The lookup ended: its first address (IPv4 first); failed, the last one known if there is one. */
static void dns_done(bt_tsc* c, uint64_t now)
{
    if (c->lookup.state == BT_LOOKUP_DONE && c->lookup.n) {
        if (!c->has_addr || !bt_addr_equal(&c->addr, &c->lookup.addrs[0])) {
            c->addr = c->lookup.addrs[0];
            c->has_addr = 1;
            if (c->io.address) {
                c->in_upcall++;
                c->io.address(c->io.ctx, &c->addr);
                c->in_upcall--;
            }
        }
        have_address(c, now);
        return;
    }
    if (c->has_addr) {
        BT_W("%s: %s: %s - the address it had last time", c->tag, c->url.host, bt_lookup_error_text(c->lookup.error));
        have_address(c, now);
        return;
    }
    fail(c, now, "%s: %s", c->url.host, bt_lookup_error_text(c->lookup.error));
}

static void start(bt_tsc* c, uint64_t now)
{
    bt_addr servers[BT_LOOKUP_SERVERS];
    size_t n;

    close_all(c);
    c->step_until = now + STEP_NS;      /* the last error stays for the screens until it opens */
    if (c->url.literal) {
        int family;
        memset(&c->addr, 0, sizeof(c->addr));
        if (!ts_addr_parse(c->url.host, strlen(c->url.host), &family, c->addr.addr)) {
            fail(c, now, "a control address that is not one: %s", c->url.host);
            return;
        }
        c->addr.family = (uint8_t)family;
        c->has_addr = 1;
        have_address(c, now);
        return;
    }
    n = c->io.resolvers ? c->io.resolvers(c->io.ctx, servers, BT_LOOKUP_SERVERS) : bt_dns_system(servers, BT_LOOKUP_SERVERS);
    if (!bt_lookup_start(&c->lookup, c->url.host, servers, n, 1, 1, NULL, now)) {
        dns_done(c, now);
        return;
    }
    c->st = C_RESOLVE;
}

/* The bytes after the 101 and everything after them: the handshake, then records. */
static void noise_feed(bt_tsc* c, const uint8_t* p, size_t n, uint64_t now)
{
    size_t off = 0;
    unsigned gen = c->gen;

    while (off < n) {
        const uint8_t* pt;
        size_t used = 0, pt_len = 0;

        if (!ts_noise_receive(c->noise, p + off, n - off, &used, &pt, &pt_len)) {
            if (c->noise->err == TS_NOISE_ERR_SERVER) fail(c, now, "control refused the handshake: %s", c->noise->err_text);
            else fail(c, now, "Noise: %s", ts_noise_error_text(c->noise->err));
            return;
        }
        off += used;
        if (c->st == C_NOISE && c->noise->state == TS_NOISE_OPEN) {
            c->h2 = (ts_h2*)calloc(1, sizeof(*c->h2));
            if (!c->h2) {
                fail(c, now, "out of memory");
                return;
            }
            ts_h2_init(c->h2, STREAM_WINDOW, 1);
            c->st = C_OPEN;
            c->was_open = 1;
            c->error[0] = '\0';
            BT_I("%s: control open (%s%s%s)", c->tag, c->tls.peer, c->url.tls ? ", " : ", plain",
                 c->url.tls ? bt_tls_version(&c->tls) : "");
            flush_out(c, now);
            up_open(c);
            if (c->gen != gen || c->st != C_OPEN) return;
            flush_out(c, now);
        }
        if (pt_len) {
            /* Out of ts_noise's buffer first: sealing our answers is a call on it too. */
            memcpy(plain, pt, pt_len);
            if (!h2_feed(c, plain, pt_len, now)) return;
            flush_out(c, now);
            if (c->gen != gen) return;
        }
    }
}

static void got_key(bt_tsc* c, uint64_t now)
{
    ts_json doc;
    jsmntok_t tok[64];
    ts_server_keys keys;
    ts_netmap_err err;

    if (c->http->status != 200) {
        fail(c, now, "GET /key: HTTP %d", c->http->status);
        return;
    }
    if (!ts_json_parse(&doc, (const char*)c->key_body, c->http->body_len, tok, 64) ||
        !ts_server_keys_parse(&doc, &keys, &err)) {
        fail(c, now, "GET /key: an answer that is not a key");
        return;
    }
    c->server = keys.public_key;
    c->has_server = 1;
    c->server_cached = 0;
    if (c->io.server_key) {
        c->in_upcall++;
        c->io.server_key(c->io.ctx, &c->server);
        c->in_upcall--;
    }
    BT_D("%s: the server's key from /key", c->tag);
    connect_to(c, C_UPGRADE, now);                  /* a connection of its own, as tailscaled */
}

static void conn_read(bt_tsc* c, uint64_t now)
{
    unsigned gen = c->gen;

    for (;;) {
        size_t n = bt_tls_read(&c->tls, rbuf, sizeof(rbuf)), used = 0;
        ts_http1_state s;

        if (!n) break;
        switch (c->st) {
        case C_KEY:
            s = ts_http1_resp_feed(c->http, rbuf, n, &used);
            if (s == TS_HTTP1_DONE) {
                got_key(c, now);
                return;
            }
            if (s != TS_HTTP1_MORE) {
                fail(c, now, "GET /key: %s", ts_http1_error_text(c->http->error));
                return;
            }
            break;
        case C_UPGRADE:
            s = ts_http1_resp_feed(c->http, rbuf, n, &used);
            if (s == TS_HTTP1_MORE) break;
            if (s != TS_HTTP1_UPGRADED || !ts_http1_resp_upgraded(c->http, "tailscale-control-protocol")) {
                if (s == TS_HTTP1_FAILED) fail(c, now, "ts2021: %s", ts_http1_error_text(c->http->error));
                else fail(c, now, "ts2021: HTTP %d (the server's capability floor above %u?)", c->http->status, c->capver);
                return;
            }
            c->st = C_NOISE;
            noise_feed(c, rbuf + used, n - used, now);
            if (c->gen != gen) return;
            break;
        case C_NOISE:
        case C_OPEN:
            noise_feed(c, rbuf, n, now);
            if (c->gen != gen) return;
            break;
        default:
            return;
        }
    }
    if (c->tls.state != BT_TLS_FAILED && c->tls.state != BT_TLS_CLOSED) return;
    /* The connection ended. */
    switch (c->st) {
    case C_KEY:
        if (ts_http1_resp_eof(c->http) == TS_HTTP1_DONE) got_key(c, now);
        else fail(c, now, "GET /key: %s", c->tls.error[0] ? c->tls.error : "the connection closed");
        break;
    case C_NOISE:
        /* Go's server sends no error frame after the 101 - it just closes: the handshake was
         * refused. With a key from the cache, the key is the likely culprit: /key again. */
        if (c->server_cached) {
            c->has_server = 0;
            c->server_cached = 0;
        }
        fail(c, now, "control closed the connection during the handshake");
        break;
    case C_OPEN:
        ts_h2_eof(c->h2);
        if (h2_feed(c, NULL, 0, now)) fail(c, now, "control closed the connection");
        break;
    default:
        fail(c, now, "%s", c->tls.error[0] ? c->tls.error : "the connection closed");
        break;
    }
}

/* --------------------------------------------------------------------- the interface */

bt_tsc* bt_tsc_new(const ts_url* url, const wg_key* machine_priv, const wg_key* server_key,
                   const bt_addr* addr, uint16_t capver, const char* tag, const bt_tsc_calls* io)
{
    bt_tsc* c = (bt_tsc*)calloc(1, sizeof(*c));

    if (!c) return NULL;
    c->url = *url;
    c->machine = *machine_priv;
    if (server_key) {
        c->server = *server_key;
        c->has_server = 1;
        c->server_cached = 1;
    }
    if (addr && addr->family) {
        c->addr = *addr;
        c->has_addr = 1;
    }
    c->capver = capver;
    snprintf(c->tag, sizeof(c->tag), "%s", tag);
    if (io) c->io = *io;
    c->dns_fd[0] = c->dns_fd[1] = -1;
    return c;
}

void bt_tsc_free(bt_tsc* c)
{
    if (!c) return;
    close_all(c);
    wg_wipe(c, sizeof(*c));
    free(c);
}

void bt_tsc_connect(bt_tsc* c, uint64_t now)
{
    if (c->st != C_IDLE && c->st != C_WAIT) return;
    c->fails = 0;
    start(c, now);
}

void bt_tsc_drop(bt_tsc* c, const char* why, uint64_t delay, uint64_t now)
{
    if (c->in_upcall) {
        if (!c->drop_pending) {
            c->drop_pending = 1;
            c->drop_delay = delay;
            snprintf(c->drop_why, sizeof(c->drop_why), "%s", why);
        }
        c->gen++;
        return;
    }
    if (c->st == C_IDLE || c->st == C_WAIT) {
        if (delay && c->st == C_WAIT) c->retry_at = now + delay;
        return;
    }
    snprintf(c->error, sizeof(c->error), "%s", why);
    BT_I("%s: control: %s", c->tag, why);
    go_wait(c, delay, now);
}

/* A drop asked for inside an upcall, now that the upcall is over. */
static void drop_now(bt_tsc* c, uint64_t now)
{
    if (!c->drop_pending || c->in_upcall) return;
    c->drop_pending = 0;
    if (c->st == C_IDLE || c->st == C_WAIT) return;
    snprintf(c->error, sizeof(c->error), "%s", c->drop_why);
    BT_I("%s: control: %s", c->tag, c->drop_why);
    go_wait(c, c->drop_delay, now);
}

int bt_tsc_is_open(const bt_tsc* c)
{
    return c->st == C_OPEN && !c->drop_pending && ts_h2_usable(c->h2);
}

const char* bt_tsc_error(const bt_tsc* c)
{
    return c->error;
}

int bt_tsc_post(bt_tsc* c, const char* path, const char* json, size_t len, const char* lb_key,
                bt_tsc_mode mode, uint64_t now)
{
    ts_h2_pair fields[1];
    ts_h2_req req;
    uint32_t stream;
    int i;

    if (!bt_tsc_is_open(c)) return 0;
    for (i = 0; i < TS_H2_MAX_STREAMS && c->reqs[i].id; i++) {}
    if (i == TS_H2_MAX_STREAMS) return 0;
    memset(&req, 0, sizeof(req));
    req.method = "POST";
    req.scheme = "https";               /* tailscaled's URL is https:// even inside Noise */
    req.authority = c->url.host;
    req.path = path;
    if (lb_key) {
        fields[0].name = "ts-lb";
        fields[0].value = lb_key;
        req.fields = fields;
        req.n_fields = 1;
    }
    req.body = (const uint8_t*)json;
    req.body_len = len;
    stream = ts_h2_request(c->h2, &req);
    if (!stream) return 0;
    memset(&c->reqs[i], 0, sizeof(c->reqs[i]));
    if (++c->next_id <= 0) c->next_id = 1;
    c->reqs[i].id = c->next_id;
    c->reqs[i].stream = stream;
    c->reqs[i].mode = mode;
    c->reqs[i].last = now;
    flush_out(c, now);
    return c->reqs[i].id ? c->reqs[i].id : 0;
}

int bt_tsc_pollfds(bt_tsc* c, struct pollfd* out, int cap)
{
    int n = 0, k, fd = bt_tls_fd(&c->tls);

    if (fd >= 0 && n < cap && c->st >= C_KEY) {
        c->in_poll = 1;
        out[n].fd = fd;
        out[n].events = bt_tls_events(&c->tls);
        out[n++].revents = 0;
    }
    for (k = 0; k < 2 && n < cap; k++) {
        if (c->dns_fd[k] < 0) continue;
        out[n].fd = c->dns_fd[k];
        out[n].events = POLLIN;
        out[n++].revents = 0;
    }
    return n;
}

int bt_tsc_owns(const bt_tsc* c, int fd)
{
    return fd >= 0 && (fd == bt_tls_fd(&c->tls) || fd == c->dns_fd[0] || fd == c->dns_fd[1]);
}

void bt_tsc_io(bt_tsc* c, const struct pollfd* pfd, uint64_t now)
{
    if (pfd->fd == c->dns_fd[0] || pfd->fd == c->dns_fd[1]) {
        for (;;) {
            struct sockaddr_storage ss;
            socklen_t sl = sizeof(ss);
            bt_addr from;
            uint16_t port;
            ssize_t n = recvfrom(pfd->fd, rbuf, BT_DNS_MSG_MAX, 0, (struct sockaddr*)&ss, &sl);
            if (n < 0) break;
            memset(&from, 0, sizeof(from));
            if (ss.ss_family == AF_INET6) {
                from.family = 6;
                memcpy(from.addr, &((struct sockaddr_in6*)&ss)->sin6_addr, 16);
                port = ntohs(((struct sockaddr_in6*)&ss)->sin6_port);
            } else {
                from.family = 4;
                memcpy(from.addr, &((struct sockaddr_in*)&ss)->sin_addr, 4);
                port = ntohs(((struct sockaddr_in*)&ss)->sin_port);
            }
            if (c->st != C_RESOLVE) break;
            if (bt_lookup_receive(&c->lookup, &from, port, rbuf, (size_t)n, now) &&
                (c->lookup.state == BT_LOOKUP_DONE || c->lookup.state == BT_LOOKUP_FAILED)) {
                dns_done(c, now);
                break;
            }
        }
        drop_now(c, now);
        return;
    }
    if (pfd->fd != bt_tls_fd(&c->tls) || !c->in_poll) return;
    bt_tls_step(&c->tls, pfd->revents);
    if (c->st == C_OPEN) flush_out(c, now);         /* room in TLS again: what HTTP/2 holds */
    conn_read(c, now);
    drop_now(c, now);
}

uint64_t bt_tsc_tick(bt_tsc* c, uint64_t now)
{
    uint64_t next = BT_NEVER, d;
    int i;

    drop_now(c, now);
    switch (c->st) {
    case C_IDLE:
        return BT_NEVER;
    case C_WAIT:
        if (now < c->retry_at) return c->retry_at;
        start(c, now);
        return now;
    case C_RESOLVE:
        d = bt_lookup_tick(&c->lookup, now, dns_send, c);
        if (c->lookup.state == BT_LOOKUP_DONE || c->lookup.state == BT_LOOKUP_FAILED) {
            dns_done(c, now);
            return now;
        }
        next = d;
        break;
    default:
        d = bt_tls_tick(&c->tls, now);
        if (d < next) next = d;
        if (c->tls.state == BT_TLS_FAILED || c->tls.state == BT_TLS_CLOSED) {
            conn_read(c, now);
            drop_now(c, now);
            return now;
        }
        if (bt_tls_pending(&c->tls)) conn_read(c, now);
        break;
    }
    if (c->st != C_OPEN && c->st != C_WAIT && c->st != C_IDLE) {
        if (now >= c->step_until) {
            fail(c, now, "control did not answer within %u s", (unsigned)(STEP_NS / SEC));
            return now;
        }
        if (c->step_until < next) next = c->step_until;
    }
    if (c->st == C_OPEN) {
        /* Go's watchdog: a map stream with nothing for two minutes is a dead connection. */
        for (i = 0; i < TS_H2_MAX_STREAMS; i++) {
            creq* r = &c->reqs[i];
            if (!r->id || r->mode != BT_TSC_STREAM) continue;
            if (now - r->last >= WATCHDOG_NS) {
                bt_tsc_drop(c, "no word on the map stream for two minutes", 0, now);
                return now;
            }
            if (r->last + WATCHDOG_NS < next) next = r->last + WATCHDOG_NS;
        }
        flush_out(c, now);
    }
    drop_now(c, now);
    return next;
}
