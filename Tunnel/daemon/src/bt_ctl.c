/*
 * bt_ctl - see bt_ctl.h.
 */

#define _GNU_SOURCE                     /* struct ucred */

#include "bt_ctl.h"
#include "bt_log.h"
#include "bt_tailscale.h"
#include "ts_profile.h"
#include "wg_conf.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL    0               /* SIGPIPE is ignored by the daemon anyway */
#endif

#define OUT_MAX         (8 * 1024 * 1024)       /* a client this far behind is dropped */
#define STATS_NS        BT_NSEC_PER_SEC
#define ALLOWED_SHOWN   64
#define DEBUG_SECONDS   (30 * 60)       /* log.debug on=1: then back to INFO by itself */
#define DEBUG_MAX       (60 * 60)

typedef struct {
    int        fd;
    char*      rbuf;
    bt_reader  reader;
    char*      out;
    size_t     out_len, out_cap;
    int        watch;
    int        stats;
} client;

static int listen_fd = -1;
static char sock_path[108];
static client C[BT_CTL_CLIENTS];
static bt_ctl_opts O;
static uint64_t next_stats_ns = BT_NEVER;
/* log.debug: the debug lines go until then (BT_NEVER: not switched on here, or switched off). Not
 * kept anywhere: a restart starts at INFO again (--debug aside). */
static uint64_t debug_until_ns = BT_NEVER;

static char resp[BT_BLOCK_MAX + 8192];
/* Events have their own buffer: a command may cause one (tunnel.down: event=tunnel) while its
 * reply is half built in resp. */
static char evbuf[16384];
static bt_block req;

/* --------------------------------------------------------------------- clients */

static void drop(client* c)
{
    if (c->fd >= 0) close(c->fd);
    free(c->rbuf);
    free(c->out);
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

static void queue(client* c, const char* data, size_t len)
{
    if (c->fd < 0) return;
    if (c->out_len + len > OUT_MAX) {
        BT_W("ctl: a client is not reading, dropped");
        drop(c);
        return;
    }
    if (c->out_len + len > c->out_cap) {
        size_t cap = c->out_cap ? c->out_cap : 8192;
        char* p;
        while (cap < c->out_len + len) cap *= 2;
        p = (char*)realloc(c->out, cap);
        if (!p) {
            drop(c);
            return;
        }
        c->out = p;
        c->out_cap = cap;
    }
    memcpy(c->out + c->out_len, data, len);
    c->out_len += len;
}

static void flush(client* c)
{
    while (c->fd >= 0 && c->out_len) {
        ssize_t w = send(c->fd, c->out, c->out_len, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (w <= 0) {
            drop(c);
            return;
        }
        memmove(c->out, c->out + w, c->out_len - (size_t)w);
        c->out_len -= (size_t)w;
    }
}

static void send_block(client* c, bt_writer* w)
{
    if (!bt_end(w)) {
        BT_E("ctl: a response did not fit");
        return;
    }
    queue(c, w->buf, w->len);
}

static void broadcast(bt_writer* w, int stats_only)
{
    int i;

    if (!bt_end(w)) return;
    for (i = 0; i < BT_CTL_CLIENTS; i++) {
        client* c = &C[i];
        if (c->fd < 0 || !c->watch || (stats_only && !c->stats)) continue;
        queue(c, w->buf, w->len);
        flush(c);
    }
}

/* --------------------------------------------------------------------- replies */

static void begin(bt_writer* w, const char* kind, const char* what)
{
    const char* id = bt_get(&req, "id");

    bt_writer_init(w, resp, sizeof(resp));
    bt_put(w, kind, what);
    if (id) bt_put(w, "id", id);
}

static void reply_ok(client* c, bt_writer* w)
{
    bt_put_u64(w, "errno", BT_ERR_OK);
    send_block(c, w);
}

static void reply_err(client* c, const char* cmd, int code, const char* error, int line)
{
    bt_writer w;

    begin(&w, "reply", cmd);
    bt_put_u64(&w, "errno", (uint64_t)code);
    bt_put(&w, "error", error);
    if (line > 0) bt_put_u64(&w, "line", (uint64_t)line);
    send_block(c, &w);
}

/* --------------------------------------------------------------------- .conf checks */

/* Parses a .conf the way bt_tunnel will, into malloc'd arrays; free with conf_free. */
typedef struct {
    wg_conf       conf;
    wg_conf_peer* peers;
    wg_prefix*    allowed;
} parsed;

static int conf_parse(parsed* p, const char* text, size_t len)
{
    size_t i, cap_peers = 1, cap_items = 1;

    for (i = 0; i < len; i++) {
        if (text[i] == ',' || text[i] == '\n') cap_items++;
        if (text[i] == '[') cap_peers++;
    }
    p->peers = (wg_conf_peer*)calloc(cap_peers, sizeof(*p->peers));
    p->allowed = (wg_prefix*)calloc(cap_items, sizeof(*p->allowed));
    if (!p->peers || !p->allowed) {
        memset(&p->conf, 0, sizeof(p->conf));
        snprintf(p->conf.error, sizeof(p->conf.error), "out of memory");
        return 0;
    }
    wg_conf_init(&p->conf, p->peers, cap_peers, p->allowed, cap_items);
    return wg_conf_parse(&p->conf, text, len);
}

static void conf_free(parsed* p)
{
    if (p->peers) wg_wipe(p->peers, sizeof(*p->peers) * p->conf.cap_peers);
    wg_wipe(&p->conf, sizeof(p->conf));
    free(p->peers);
    free(p->allowed);
    p->peers = NULL;
    p->allowed = NULL;
}

/* 1 when the text is a .conf the daemon will take; else a reply has gone out. */
static int conf_acceptable(client* c, const char* cmd, const char* text, size_t len, int* awg)
{
    parsed p;
    wg_awg_params ap;
    char err[128];
    int ok;

    memset(&p, 0, sizeof(p));
    if (len > BT_CONF_MAX) {
        reply_err(c, cmd, BT_ERR_CONF, "the file is too large", 0);
        return 0;
    }
    ok = conf_parse(&p, text, len);
    if (!ok) {
        reply_err(c, cmd, BT_ERR_CONF, p.conf.error, p.conf.error_line);
    } else if (!p.conf.n_peers) {
        reply_err(c, cmd, BT_ERR_CONF, "no [Peer]", 0);
        ok = 0;
    } else if (p.conf.awg && !wg_conf_awg_params(&p.conf, &ap, err, sizeof(err))) {
        reply_err(c, cmd, BT_ERR_CONF, err, 0);
        ok = 0;
    }
    if (ok && awg) *awg = p.conf.awg;
    conf_free(&p);
    return ok;
}

static const char* arg_profile(client* c, const char* cmd, bt_meta* m)
{
    const char* id = bt_get(&req, "profile");

    if (!id || !bt_id_valid(id)) {
        reply_err(c, cmd, BT_ERR_REQUEST, "profile= missing or malformed", 0);
        return NULL;
    }
    if (!bt_store_load_meta(O.store, id, m)) {
        reply_err(c, cmd, BT_ERR_PROFILE, "no such profile", 0);
        return NULL;
    }
    return id;
}

/* --------------------------------------------------------------------- commands */

static void cmd_hello(client* c)
{
    bt_writer w;

    begin(&w, "reply", "hello");
    bt_put(&w, "daemon", O.version);
    bt_put_u64(&w, "proto", BT_PROTO_VERSION);
    reply_ok(c, &w);
}

static uint32_t next_order(void)
{
    static bt_meta list[64];
    size_t n = 0, i;
    uint32_t top = 0;

    if (!bt_store_list(O.store, list, 64, &n, NULL)) return 0;
    for (i = 0; i < n && i < 64; i++)
        if (list[i].order >= top) top = list[i].order + 1;
    return top;
}

/* --------------------------------------------------------------------- Tailscale profiles */

static void put_summary(bt_writer* w, const bt_meta* m);

static int is_tailscale(const bt_meta* m)
{
    return strcmp(m->type, BT_TYPE_TAILSCALE) == 0;
}

/* The profile text of a Tailscale profile: its keys, so the buffer is wiped after every use. */
static char ts_text[4096];

/* A Tailscale profile's .conf, parsed; 1 when it is there and sound, else a reply has gone out. */
static int ts_load(client* c, const char* cmd, const char* id, ts_profile* p)
{
    size_t len;
    char* text = bt_store_load_conf(O.store, id, &len);
    int ok = text && ts_profile_parse(p, text, len);

    if (text) bt_store_free_conf(text, len);
    if (!ok) reply_err(c, cmd, BT_ERR_SYSTEM, "the profile's Tailscale keys cannot be read", 0);
    return ok;
}

/* Writes the profile back: its .meta and the profile text as its .conf. */
static int ts_save(client* c, const char* cmd, const bt_meta* m, const ts_profile* p)
{
    size_t len = ts_profile_format(p, ts_text, sizeof(ts_text));
    int ok = len && bt_store_save(O.store, m, ts_text, len);

    wg_wipe(ts_text, sizeof(ts_text));
    if (!ok) reply_err(c, cmd, BT_ERR_SYSTEM, len ? strerror(errno) : "the profile does not fit", 0);
    return ok;
}

/*
 * How a Tailscale profile logs in: authkey=<key>, or login=link - by a link the user opens on another
 * device (docs/TAILSCALE.md, section 11b). One of the two; 1 when the request says which, `*link` set
 * for a link.
 */
static int login_kind(client* c, const char* cmd, const char* key, size_t alen, int* link)
{
    const char* login = bt_get(&req, "login");

    *link = 0;
    if (login && strcmp(login, "link") != 0) {
        reply_err(c, cmd, BT_ERR_REQUEST, "login= is link, or nothing", 0);
        return 0;
    }
    if (login && key) {
        reply_err(c, cmd, BT_ERR_REQUEST, "authkey= or login=link, not both", 0);
        return 0;
    }
    if (login) {
        *link = 1;
        return 1;
    }
    if (!key || !ts_authkey_valid(key, alen)) {
        reply_err(c, cmd, BT_ERR_REQUEST, "authkey= missing or not an auth key (or login=link)", 0);
        return 0;
    }
    return 1;
}

/*
 * profile.import type=tailscale: fresh machine and node keys, and the auth key to register the node
 * with when it first comes up (docs/TAILSCALE.md, section 3) - or login=link, no key: the first
 * connection asks control for a login link (section 11b). control= only on the stand: the app never
 * sends it, and the official server is the default.
 */
static void import_tailscale(client* c, const char* cmd, const char* name, size_t nlen)
{
    size_t alen, ulen, hlen;
    const char* key = bt_get_len(&req, "authkey", &alen);
    const char* control = bt_get_len(&req, "control", &ulen);
    const char* host = bt_get_len(&req, "hostname", &hlen);
    ts_profile p;
    ts_url u;
    bt_meta m;
    bt_writer w;
    uint64_t sec;
    uint32_t nsec;
    int ok, link;

    if (!login_kind(c, cmd, key, alen, &link)) return;
    if (control && !ts_url_parse(control, ulen, &u)) {
        reply_err(c, cmd, BT_ERR_REQUEST, "control= is not an http(s)://host[:port] address", 0);
        return;
    }
    if (host && !ts_hostname_valid(host, hlen)) {
        reply_err(c, cmd, BT_ERR_REQUEST, "hostname= is not one DNS label (1-63 of A-Z, a-z, 0-9, -)", 0);
        return;
    }
    memset(&m, 0, sizeof(m));
    if (!bt_store_new_id(O.store, NULL, m.id)) {
        reply_err(c, cmd, BT_ERR_SYSTEM, "no id", 0);
        return;
    }
    if (!ts_profile_new(&p, control, link ? NULL : key, NULL)) {
        reply_err(c, cmd, BT_ERR_SYSTEM, "no keys", 0);
        return;
    }
    if (host) memcpy(p.hostname, host, hlen + 1);
    memcpy(m.name, name, nlen + 1);
    snprintf(m.type, sizeof(m.type), "%s", BT_TYPE_TAILSCALE);
    bt_wall(&sec, &nsec);
    m.created = sec;
    m.order = next_order();
    ok = ts_save(c, cmd, &m, &p);
    ts_profile_wipe(&p);
    if (!ok) return;
    BT_I("profile %s imported (%s, %s, %s)", m.id, m.type, control ? "another control server" : "the official server",
         link ? "a login by a link" : "an auth key");
    begin(&w, "reply", cmd);
    bt_put(&w, "profile", m.id);
    reply_ok(c, &w);
    bt_ctl_event_profile(m.id, "added");
}

/* profile.get of a Tailscale profile: what the screens show, never a private key. */
static void get_tailscale(client* c, const char* cmd, const bt_meta* m)
{
    ts_profile p;
    wg_key pub;
    char hex[65], key[80];
    size_t i;
    bt_writer w;

    if (!ts_load(c, cmd, m->id, &p)) return;
    begin(&w, "reply", cmd);
    put_summary(&w, m);
    bt_put(&w, "control", p.control);
    /* not logged in yet: with the key it keeps, or by a link */
    bt_put(&w, "login", p.registered ? "ok" : (p.auth_key[0] ? "pending" : "link"));
    bt_put(&w, "hostname", p.hostname[0] ? p.hostname : TS_HOSTNAME_DEFAULT);
    if (wg_key_public(&p.node, &pub)) {
        ts_hex32(hex, pub.b);
        snprintf(key, sizeof(key), "nodekey:%s", hex);
        bt_put(&w, "node_key", key);
    }
    if (p.tailnet[0]) bt_put(&w, "tailnet", p.tailnet);
    if (p.node_name[0]) bt_put(&w, "node_name", p.node_name);
    for (i = 0; i < p.n_address; i++) bt_put(&w, "address", p.address[i]);
    ts_profile_wipe(&p);
    reply_ok(c, &w);
}

/* profile.update authkey= (or login=link, `key` NULL): logging in again - a new node key, the old one
 * named (section 3). */
static int relogin_tailscale(client* c, const char* cmd, const bt_meta* m, const char* key, size_t alen)
{
    ts_profile p;
    char k[TS_AUTHKEY_MAX + 1] = "";
    int ok;

    if (key && !ts_authkey_valid(key, alen)) {
        reply_err(c, cmd, BT_ERR_REQUEST, "authkey= is not an auth key", 0);
        return 0;
    }
    if (!ts_load(c, cmd, m->id, &p)) return 0;
    if (key) memcpy(k, key, alen + 1);
    if (!ts_profile_relogin(&p, k, NULL)) {
        ts_profile_wipe(&p);
        reply_err(c, cmd, BT_ERR_SYSTEM, "no keys", 0);
        return 0;
    }
    ok = ts_save(c, cmd, m, &p);
    ts_profile_wipe(&p);
    wg_wipe(k, sizeof(k));
    if (ok) BT_I("profile %s: %s, a new node key", m->id, key ? "a new auth key" : "a login by a link");
    return ok;
}

/* --------------------------------------------------------------------- profiles */

static void cmd_profile_import(client* c)
{
    const char* cmd = "profile.import";
    size_t nlen, clen;
    const char* name = bt_get_len(&req, "name", &nlen);
    const char* conf = bt_get_len(&req, "conf", &clen);
    const char* type = bt_get(&req, "type");
    bt_meta m;
    bt_writer w;
    uint64_t sec;
    uint32_t nsec;
    int awg = 0;

    if (!name || !bt_name_valid(name, nlen)) {
        reply_err(c, cmd, BT_ERR_REQUEST, "name= missing or not a valid name (1-64 bytes of text)", 0);
        return;
    }
    if (type && strcmp(type, BT_TYPE_TAILSCALE) == 0) {
        import_tailscale(c, cmd, name, nlen);
        return;
    }
    if (type && strcmp(type, BT_TYPE_WIREGUARD) != 0 && strcmp(type, BT_TYPE_AMNEZIAWG) != 0) {
        reply_err(c, cmd, BT_ERR_REQUEST, "type= is wireguard, amneziawg (both: as the .conf says) or tailscale", 0);
        return;
    }
    if (!conf) {
        reply_err(c, cmd, BT_ERR_REQUEST, "conf= missing", 0);
        return;
    }
    if (!conf_acceptable(c, cmd, conf, clen, &awg)) return;

    memset(&m, 0, sizeof(m));
    if (!bt_store_new_id(O.store, NULL, m.id)) {
        reply_err(c, cmd, BT_ERR_SYSTEM, "no id", 0);
        return;
    }
    memcpy(m.name, name, nlen + 1);
    snprintf(m.type, sizeof(m.type), "%s", awg ? BT_TYPE_AMNEZIAWG : BT_TYPE_WIREGUARD);
    bt_wall(&sec, &nsec);
    m.created = sec;
    m.order = next_order();
    if (!bt_store_save(O.store, &m, conf, clen)) {
        reply_err(c, cmd, BT_ERR_SYSTEM, strerror(errno), 0);
        return;
    }
    BT_I("profile %s imported (%s)", m.id, m.type);
    begin(&w, "reply", cmd);
    bt_put(&w, "profile", m.id);
    reply_ok(c, &w);
    bt_ctl_event_profile(m.id, "added");
}

static void put_summary(bt_writer* w, const bt_meta* m)
{
    bt_tunnel* t = bt_tunnel_find(m->id);
    bt_settings st;

    bt_put(w, "profile", m->id);
    bt_put(w, "name", m->name);
    bt_put(w, "type", m->type);
    bt_put_u64(w, "created", m->created);
    bt_put_u64(w, "order", m->order);
    bt_put(w, "state", t ? bt_tstate_name(bt_tunnel_state(t)) : "down");
    bt_store_load_settings(O.store, &st);
    bt_put(w, "always_on", strcmp(st.always_on, m->id) == 0 || strcmp(st.always_on_tailscale, m->id) == 0 ? "1" : "0");
}

/* The profile is not always on any more. 1 when it was. */
static int always_on_clear(bt_settings* st, const char* id)
{
    int was_on = 0;

    if (strcmp(st->always_on, id) == 0) {
        st->always_on[0] = '\0';
        was_on = 1;
    }
    if (strcmp(st->always_on_tailscale, id) == 0) {
        st->always_on_tailscale[0] = '\0';
        was_on = 1;
    }
    return was_on;
}

static void put_always_on(bt_writer* w, const bt_settings* st)
{
    bt_put(w, "always_on", st->always_on);
    bt_put(w, "always_on_tailscale", st->always_on_tailscale);
}

static void cmd_profile_list(client* c)
{
    static bt_meta list[256];
    size_t n = 0, i;
    bt_writer w;

    if (!bt_store_list(O.store, list, 256, &n, NULL)) {
        reply_err(c, "profile.list", BT_ERR_SYSTEM, strerror(errno), 0);
        return;
    }
    for (i = 0; i < n && i < 256; i++) {
        begin(&w, "item", "profile");
        put_summary(&w, &list[i]);
        send_block(c, &w);
    }
    begin(&w, "reply", "profile.list");
    bt_put_u64(&w, "count", n < 256 ? n : 256);
    reply_ok(c, &w);
}

static void put_prefix(bt_writer* w, const char* key, const wg_prefix* p, int with_cidr)
{
    char a[64], s[80];
    inet_ntop(p->family == 6 ? AF_INET6 : AF_INET, p->addr, a, sizeof(a));
    if (with_cidr) snprintf(s, sizeof(s), "%s/%u", a, p->cidr);
    else snprintf(s, sizeof(s), "%s", a);
    bt_put(w, key, s);
}

static void cmd_profile_get(client* c)
{
    const char* cmd = "profile.get";
    bt_meta m;
    const char* id = arg_profile(c, cmd, &m);
    char* text;
    size_t len, i;
    parsed p;
    bt_writer w;

    if (!id) return;
    if (is_tailscale(&m)) {
        get_tailscale(c, cmd, &m);
        return;
    }
    text = bt_store_load_conf(O.store, id, &len);
    if (!text) {
        reply_err(c, cmd, BT_ERR_SYSTEM, "the profile's .conf cannot be read", 0);
        return;
    }
    memset(&p, 0, sizeof(p));
    begin(&w, "reply", cmd);
    put_summary(&w, &m);
    if (conf_parse(&p, text, len)) {
        wg_key pub;
        char b64[45];
        if (p.conf.has_private_key && wg_key_public(&p.conf.private_key, &pub)) {
            wg_key_to_base64(b64, &pub);
            bt_put(&w, "public_key", b64);
        }
        for (i = 0; i < p.conf.n_address; i++) put_prefix(&w, "address", &p.conf.address[i], 1);
        for (i = 0; i < p.conf.n_dns; i++) put_prefix(&w, "dns", &p.conf.dns[i], 0);
        if (p.conf.dns_search[0]) bt_put(&w, "dns_search", p.conf.dns_search);
        if (p.conf.mtu) bt_put_u64(&w, "mtu", p.conf.mtu);
        if (p.conf.listen_port) bt_put_u64(&w, "listen_port", p.conf.listen_port);
        bt_put_u64(&w, "peers", p.conf.n_peers);
        for (i = 0; i < p.conf.n_peers; i++) {
            char ep[WG_CONF_TEXT_MAX + 16];
            const wg_conf_peer* cp = &p.peers[i];
            if (!cp->endpoint_host[0]) continue;
            snprintf(ep, sizeof(ep), strchr(cp->endpoint_host, ':') ? "[%s]:%u" : "%s:%u", cp->endpoint_host,
                     cp->endpoint_port);
            bt_put(&w, "endpoint", ep);
        }
        bt_put_u64(&w, "allowed_count", p.conf.n_allowed);
        for (i = 0; i < p.conf.n_allowed && i < ALLOWED_SHOWN; i++) put_prefix(&w, "allowed", &p.allowed[i], 1);
    }
    conf_free(&p);
    bt_store_free_conf(text, len);
    reply_ok(c, &w);
}

static void cmd_profile_update(client* c)
{
    const char* cmd = "profile.update";
    bt_meta m;
    const char* id = arg_profile(c, cmd, &m);
    size_t nlen, clen, alen;
    const char* name;
    const char* conf;
    const char* authkey;
    uint64_t order;
    int r, awg = 0, relogin = 0, link = 0;
    bt_writer w;

    if (!id) return;
    name = bt_get_len(&req, "name", &nlen);
    conf = bt_get_len(&req, "conf", &clen);
    authkey = bt_get_len(&req, "authkey", &alen);
    if (is_tailscale(&m) && conf) {
        reply_err(c, cmd, BT_ERR_REQUEST, "a Tailscale profile has no .conf: log in again with authkey= or login=link", 0);
        return;
    }
    if (!is_tailscale(&m) && (authkey || bt_get(&req, "login"))) {
        reply_err(c, cmd, BT_ERR_REQUEST, "authkey= and login= are for Tailscale profiles", 0);
        return;
    }
    /* logging in again: with a new key, or by a link */
    if (authkey || bt_get(&req, "login")) {
        if (!login_kind(c, cmd, authkey, alen, &link)) return;
        relogin = 1;
    }
    if (name) {
        if (!bt_name_valid(name, nlen)) {
            reply_err(c, cmd, BT_ERR_REQUEST, "name= is not a valid name", 0);
            return;
        }
        memcpy(m.name, name, nlen + 1);
    }
    r = bt_get_u64(&req, "order", 0xffffffffULL, &order);
    if (r < 0) {
        reply_err(c, cmd, BT_ERR_REQUEST, "order= is not a number", 0);
        return;
    }
    if (r > 0) m.order = (uint32_t)order;
    if (conf) {
        if (!conf_acceptable(c, cmd, conf, clen, &awg)) return;
        snprintf(m.type, sizeof(m.type), "%s", awg ? BT_TYPE_AMNEZIAWG : BT_TYPE_WIREGUARD);
        m.n_resolved = 0;                   /* the endpoints may be other names now */
    }
    if (relogin) {
        if (!relogin_tailscale(c, cmd, &m, link ? NULL : authkey, alen)) return;    /* saves the .meta too */
    } else if (!bt_store_save(O.store, &m, conf, conf ? clen : 0)) {
        reply_err(c, cmd, BT_ERR_SYSTEM, strerror(errno), 0);
        return;
    }
    begin(&w, "reply", cmd);
    bt_put(&w, "profile", m.id);
    if (conf && bt_tunnel_find(m.id)) bt_put(&w, "note", "the tunnel uses the new .conf from its next start");
    if (relogin && bt_tunnel_find(m.id))
        bt_put(&w, "note", link ? "the tunnel asks for a login link from its next start"
                                : "the tunnel logs in with it from its next start");
    reply_ok(c, &w);
    bt_ctl_event_profile(m.id, "updated");
}

static void cmd_profile_delete(client* c)
{
    const char* cmd = "profile.delete";
    bt_meta m;
    const char* id = arg_profile(c, cmd, &m);
    bt_settings st;
    bt_writer w;

    if (!id) return;
    bt_tunnel_down(m.id);
    if (!bt_store_delete(O.store, m.id)) {
        reply_err(c, cmd, BT_ERR_SYSTEM, strerror(errno), 0);
        return;
    }
    bt_store_load_settings(O.store, &st);
    if (always_on_clear(&st, m.id)) {
        bt_store_save_settings(O.store, &st);
    }
    BT_I("profile %s deleted", m.id);
    begin(&w, "reply", cmd);
    bt_put(&w, "profile", m.id);
    reply_ok(c, &w);
    bt_ctl_event_profile(m.id, "deleted");
}

static void cmd_tunnel_up(client* c)
{
    const char* cmd = "tunnel.up";
    bt_meta m;
    const char* id = arg_profile(c, cmd, &m);
    char err[160] = "";
    bt_writer w;
    bt_tunnel* t;

    if (!id) return;
    if (!bt_tunnel_up(m.id, err, sizeof(err)) && err[0]) {
        reply_err(c, cmd, BT_ERR_BUSY, err, 0);
        return;
    }
    t = bt_tunnel_find(m.id);
    begin(&w, "reply", cmd);
    if (t) bt_tunnel_describe(t, &w);
    if (t && bt_tunnel_state(t) == BT_TS_ERROR) {
        bt_put_u64(&w, "errno", BT_ERR_SYSTEM);
        bt_put(&w, "error", "the tunnel did not come up: see reason and detail");
        send_block(c, &w);
        return;
    }
    reply_ok(c, &w);
}

static void cmd_tunnel_down(client* c)
{
    const char* cmd = "tunnel.down";
    const char* id = bt_get(&req, "profile");
    bt_writer w;

    if (!id || !bt_id_valid(id)) {
        reply_err(c, cmd, BT_ERR_REQUEST, "profile= missing or malformed", 0);
        return;
    }
    begin(&w, "reply", cmd);
    bt_put(&w, "profile", id);
    bt_put(&w, "was_up", bt_tunnel_down(id) ? "1" : "0");
    reply_ok(c, &w);
}

/* The netmap's nodes of a Tailscale tunnel that is up: the profile page's list. */
static void cmd_tailscale_nodes(client* c)
{
    const char* cmd = "tailscale.nodes";
    bt_meta m;
    const char* id = arg_profile(c, cmd, &m);
    bt_tunnel* t;
    bt_ts* ts;
    bt_writer w;
    size_t i, n;

    if (!id) return;
    if (!is_tailscale(&m)) {
        reply_err(c, cmd, BT_ERR_REQUEST, "not a Tailscale profile", 0);
        return;
    }
    t = bt_tunnel_find(id);
    ts = t ? bt_tunnel_ts(t) : NULL;
    if (!ts) {
        reply_err(c, cmd, BT_ERR_BUSY, "the tunnel is not up: no netmap", 0);
        return;
    }
    n = bt_ts_node_count(ts);
    for (i = 0; i < n; i++) {
        begin(&w, "item", "node");
        bt_ts_node_put(ts, i, &w);
        send_block(c, &w);
    }
    begin(&w, "reply", cmd);
    bt_put_u64(&w, "count", (uint64_t)n);
    reply_ok(c, &w);
}

static void cmd_status(client* c)
{
    bt_writer w;
    int i, n = 0;

    for (i = 0; i < BT_TUNNELS_MAX; i++) {
        bt_tunnel* t = bt_tunnel_at(i);
        if (!t) continue;
        begin(&w, "item", "tunnel");
        bt_tunnel_describe(t, &w);
        bt_tunnel_stats(t, &w);
        send_block(c, &w);
        n++;
    }
    begin(&w, "reply", "status");
    bt_put_u64(&w, "count", (uint64_t)n);
    reply_ok(c, &w);
}

static void cmd_watch(client* c)
{
    int stats = 0;
    bt_writer w;

    if (bt_get_bool(&req, "stats", &stats) < 0) {
        reply_err(c, "watch", BT_ERR_REQUEST, "stats= is 0 or 1", 0);
        return;
    }
    c->watch = 1;
    c->stats = stats;
    if (stats && next_stats_ns == BT_NEVER) next_stats_ns = bt_now_ns() + STATS_NS;
    begin(&w, "reply", "watch");
    reply_ok(c, &w);
}

static void cmd_settings_get(client* c)
{
    bt_settings st;
    bt_writer w;

    bt_store_load_settings(O.store, &st);
    begin(&w, "reply", "settings.get");
    put_always_on(&w, &st);
    bt_put_u64(&w, "kill_switch", (uint64_t)st.kill_switch);
    reply_ok(c, &w);
}

static void cmd_settings_set(client* c)
{
    const char* cmd = "settings.set";
    bt_settings st;
    const char* ao = bt_get(&req, "always_on");
    const char* off = bt_get(&req, "always_off");
    int ks = 0, r;
    bt_writer w;

    bt_store_load_settings(O.store, &st);
    if (ao && !*ao) {
        st.always_on[0] = '\0';
        st.always_on_tailscale[0] = '\0';
    } else if (ao) {
        /* one of each kind: it takes the place of the one of its kind, the other kind's stays */
        bt_meta m;
        if (!bt_id_valid(ao) || !bt_store_load_meta(O.store, ao, &m)) {
            reply_err(c, cmd, BT_ERR_PROFILE, "always_on= names no profile", 0);
            return;
        }
        if (is_tailscale(&m)) snprintf(st.always_on_tailscale, sizeof(st.always_on_tailscale), "%s", ao);
        else snprintf(st.always_on, sizeof(st.always_on), "%s", ao);
    }
    if (off) always_on_clear(&st, off);
    r = bt_get_bool(&req, "kill_switch", &ks);
    if (r < 0) {
        reply_err(c, cmd, BT_ERR_REQUEST, "kill_switch= is 0 or 1", 0);
        return;
    }
    if (r > 0) st.kill_switch = ks;
    if (!bt_store_save_settings(O.store, &st)) {
        reply_err(c, cmd, BT_ERR_SYSTEM, strerror(errno), 0);
        return;
    }
    begin(&w, "reply", cmd);
    put_always_on(&w, &st);
    bt_put_u64(&w, "kill_switch", (uint64_t)st.kill_switch);
    if (st.kill_switch) bt_put(&w, "note", "the kill switch is stored; this version does not enforce it yet");
    reply_ok(c, &w);
}

static void cmd_log_tail(client* c)
{
    static char text[BT_LOG_RING + 1];
    uint64_t lines = 100;
    bt_writer w;

    if (bt_get_u64(&req, "lines", 5000, &lines) < 0) {
        reply_err(c, "log.tail", BT_ERR_REQUEST, "lines= is a number up to 5000", 0);
        return;
    }
    bt_log_tail(text, sizeof(text), (unsigned)lines);
    begin(&w, "reply", "log.tail");
    bt_put(&w, "text", text);
    reply_ok(c, &w);
}

/* The debug lines for a while (docs/DAEMON.md, section 3): on=1 for seconds= (DEBUG_SECONDS when
 * not given), then INFO again by itself (bt_ctl_tick); on=0 at once; without on= only the state.
 * The log stays within its two files whatever the level (bt_log_open's cap). */
static void cmd_log_debug(client* c)
{
    const char* cmd = "log.debug";
    uint64_t seconds = DEBUG_SECONDS, now = bt_now_ns();
    int on = 0, r;
    bt_writer w;

    r = bt_get_bool(&req, "on", &on);
    if (r < 0) {
        reply_err(c, cmd, BT_ERR_REQUEST, "on= is 0 or 1", 0);
        return;
    }
    if (bt_get_u64(&req, "seconds", DEBUG_MAX, &seconds) < 0 || seconds == 0) {
        reply_err(c, cmd, BT_ERR_REQUEST, "seconds= is a number from 1 to 3600", 0);
        return;
    }
    if (r > 0 && on) {
        bt_log_set_level(BT_LOG_DEBUG);
        debug_until_ns = now + seconds * BT_NSEC_PER_SEC;
        BT_I("debug lines on for %u min (log.debug)", (unsigned)((seconds + 59) / 60));
    } else if (r > 0) {
        if (bt_log_get_level() == BT_LOG_DEBUG) BT_I("debug lines off (log.debug)");
        bt_log_set_level(BT_LOG_INFO);
        debug_until_ns = BT_NEVER;
    }
    begin(&w, "reply", cmd);
    bt_put(&w, "debug", bt_log_get_level() == BT_LOG_DEBUG ? "1" : "0");
    /* 0 while off, and while on by --debug: no end then */
    bt_put_u64(&w, "left", debug_until_ns == BT_NEVER || debug_until_ns <= now ? 0
                           : (debug_until_ns - now + BT_NSEC_PER_SEC - 1) / BT_NSEC_PER_SEC);
    reply_ok(c, &w);
}

static void cmd_daemon_restart(client* c)
{
    bt_writer w;

    begin(&w, "reply", "daemon.restart");
    reply_ok(c, &w);
    BT_I("restart asked for");
    if (O.restart) O.restart();
}

static void handle(client* c)
{
    static const struct {
        const char* name;
        void (*fn)(client*);
    } table[] = {
        { "hello", cmd_hello },
        { "profile.import", cmd_profile_import },
        { "profile.list", cmd_profile_list },
        { "profile.get", cmd_profile_get },
        { "profile.update", cmd_profile_update },
        { "profile.delete", cmd_profile_delete },
        { "tunnel.up", cmd_tunnel_up },
        { "tunnel.down", cmd_tunnel_down },
        { "tailscale.nodes", cmd_tailscale_nodes },
        { "status", cmd_status },
        { "watch", cmd_watch },
        { "settings.get", cmd_settings_get },
        { "settings.set", cmd_settings_set },
        { "log.tail", cmd_log_tail },
        { "log.debug", cmd_log_debug },
        { "daemon.restart", cmd_daemon_restart },
    };
    const char* kind = bt_block_kind(&req);
    size_t i;

    if (!kind || strcmp(kind, "cmd") != 0) {
        reply_err(c, "?", BT_ERR_REQUEST, "a request starts with cmd=", 0);
        return;
    }
    for (i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (strcmp(req.kv[0].val, table[i].name) == 0) {
            BT_D("ctl: %s", table[i].name);
            table[i].fn(c);
            return;
        }
    }
    reply_err(c, req.kv[0].val, BT_ERR_COMMAND, "no such command", 0);
}

/* --------------------------------------------------------------------- the socket */

int bt_ctl_listen(const char* path, const bt_ctl_opts* o)
{
    struct sockaddr_un sa;
    int i;

    O = *o;
    for (i = 0; i < BT_CTL_CLIENTS; i++) {
        memset(&C[i], 0, sizeof(C[i]));
        C[i].fd = -1;
    }
    if (strlen(path) >= sizeof(sa.sun_path)) {
        errno = ENAMETOOLONG;
        return 0;
    }
    snprintf(sock_path, sizeof(sock_path), "%s", path);
    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) return 0;
    fcntl(listen_fd, F_SETFL, fcntl(listen_fd, F_GETFL) | O_NONBLOCK);
    fcntl(listen_fd, F_SETFD, FD_CLOEXEC);
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, path);
    unlink(path);                           /* a stale one from before */
    if (bind(listen_fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) return 0;
    if (chmod(path, 0600) < 0) return 0;
    if ((O.owner_uid >= 0 || O.owner_gid >= 0) && chown(path, (uid_t)O.owner_uid, (gid_t)O.owner_gid) < 0) return 0;
    return listen(listen_fd, 8) == 0;
}

void bt_ctl_close(void)
{
    int i;
    for (i = 0; i < BT_CTL_CLIENTS; i++)
        if (C[i].fd >= 0) {
            flush(&C[i]);
            drop(&C[i]);
        }
    if (listen_fd >= 0) {
        close(listen_fd);
        unlink(sock_path);
    }
    listen_fd = -1;
}

static int peer_allowed(int fd)
{
#if defined(__linux__)
    struct ucred cr;
    socklen_t len = sizeof(cr);

    if (O.owner_uid < 0) return 1;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len) < 0) return 0;
    return cr.uid == 0 || cr.uid == (uid_t)O.owner_uid;
#else
    (void)fd;                               /* the socket file's mode is the guard */
    return 1;
#endif
}

static void accept_one(void)
{
    int fd = accept(listen_fd, NULL, NULL), i;

    if (fd < 0) return;
    if (!peer_allowed(fd)) {
        BT_W("ctl: a client of another uid refused");
        close(fd);
        return;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    for (i = 0; i < BT_CTL_CLIENTS && C[i].fd >= 0; i++) {}
    if (i == BT_CTL_CLIENTS) {
        BT_W("ctl: %d clients already, one more refused", BT_CTL_CLIENTS);
        close(fd);
        return;
    }
    C[i].rbuf = (char*)malloc(BT_BLOCK_MAX + 4);
    if (!C[i].rbuf) {
        close(fd);
        return;
    }
    C[i].fd = fd;
    bt_reader_init(&C[i].reader, C[i].rbuf, BT_BLOCK_MAX + 4);
    BT_D("ctl: client %d connected", i);
}

static void read_client(client* c)
{
    char err[64];

    for (;;) {
        size_t room;
        char* p = bt_reader_space(&c->reader, &room);
        ssize_t n;
        int rc;

        if (!room) {
            drop(c);
            return;
        }
        n = recv(c->fd, p, room, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (n <= 0) {
            flush(c);
            drop(c);
            return;
        }
        bt_reader_commit(&c->reader, (size_t)n);
        while ((rc = bt_reader_next(&c->reader, &req, err, sizeof(err))) == 1) {
            handle(c);
            if (c->fd < 0) return;
        }
        if (rc < 0) {
            BT_W("ctl: a client broke the protocol (%s), dropped", err);
            drop(c);
            return;
        }
    }
}

int bt_ctl_pollfds(struct pollfd* out, int cap)
{
    int n = 0, i;

    if (listen_fd >= 0 && n < cap) {
        out[n].fd = listen_fd;
        out[n].events = POLLIN;
        out[n++].revents = 0;
    }
    for (i = 0; i < BT_CTL_CLIENTS && n < cap; i++) {
        if (C[i].fd < 0) continue;
        out[n].fd = C[i].fd;
        out[n].events = (short)(POLLIN | (C[i].out_len ? POLLOUT : 0));
        out[n++].revents = 0;
    }
    return n;
}

void bt_ctl_io(const struct pollfd* pfd)
{
    int i;

    if (pfd->fd == listen_fd) {
        if (pfd->revents & POLLIN) accept_one();
        return;
    }
    for (i = 0; i < BT_CTL_CLIENTS; i++) {
        client* c = &C[i];
        if (c->fd != pfd->fd) continue;
        if (pfd->revents & POLLOUT) flush(c);
        if (c->fd >= 0 && (pfd->revents & (POLLIN | POLLHUP | POLLERR))) read_client(c);
        if (c->fd >= 0) flush(c);
        return;
    }
}

int bt_ctl_idle(void)
{
    int i;
    for (i = 0; i < BT_CTL_CLIENTS; i++)
        if (C[i].fd >= 0 && C[i].out_len) return 0;
    return 1;
}

/* --------------------------------------------------------------------- events */

void bt_ctl_event_tunnel(bt_tunnel* t)
{
    bt_writer w;

    bt_writer_init(&w, evbuf, sizeof(evbuf));
    bt_put(&w, "event", "tunnel");
    bt_tunnel_describe(t, &w);
    broadcast(&w, 0);
}

void bt_ctl_event_profile(const char* id, const char* action)
{
    bt_writer w;

    bt_writer_init(&w, evbuf, sizeof(evbuf));
    bt_put(&w, "event", "profile");
    bt_put(&w, "profile", id);
    bt_put(&w, "action", action);
    broadcast(&w, 0);
}

void bt_ctl_event_network(void)
{
    char dev[BT_IFNAME_MAX];
    bt_writer w;

    bt_writer_init(&w, evbuf, sizeof(evbuf));
    bt_put(&w, "event", "network");
    bt_put(&w, "ipv4", bt_default_if(4, dev) ? dev : "");
    bt_put(&w, "ipv6", bt_default_if(6, dev) ? dev : "");
    broadcast(&w, 0);
}

uint64_t bt_ctl_tick(uint64_t now)
{
    int i, any = 0;

    if (debug_until_ns != BT_NEVER && now >= debug_until_ns) {
        debug_until_ns = BT_NEVER;
        bt_log_set_level(BT_LOG_INFO);
        BT_I("debug lines off: their time is over (log.debug)");
    }
    for (i = 0; i < BT_CTL_CLIENTS; i++)
        if (C[i].fd >= 0 && C[i].watch && C[i].stats) any = 1;
    if (!any) {
        next_stats_ns = BT_NEVER;
        return debug_until_ns;
    }
    if (now < next_stats_ns) return next_stats_ns < debug_until_ns ? next_stats_ns : debug_until_ns;
    for (i = 0; i < BT_TUNNELS_MAX; i++) {
        bt_tunnel* t = bt_tunnel_at(i);
        bt_writer w;
        if (!t) continue;
        bt_writer_init(&w, evbuf, sizeof(evbuf));
        bt_put(&w, "event", "stats");
        bt_tunnel_stats(t, &w);
        broadcast(&w, 1);
    }
    next_stats_ns = now + STATS_NS;
    return next_stats_ns < debug_until_ns ? next_stats_ns : debug_until_ns;
}
