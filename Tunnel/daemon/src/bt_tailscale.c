/*
 * bt_tailscale - see bt_tailscale.h.
 */

#include "bt_tailscale.h"
#include "bt_log.h"
#include "bt_plat.h"
#include "bt_ts_control.h"
#include "bt_ts_relay.h"
#include "bt_tunnel.h"
#include "ts_disco.h"
#include "ts_dns.h"
#include "ts_json.h"
#include "ts_netmap.h"
#include "ts_path.h"
#include "ts_profile.h"
#include "ts_stun.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SEC                 1000000000ULL
#define PEERS_MAX           64          /* nodes that are engine peers at once: the ones in use */
#define STAGE               (8 * 1024)  /* a new peer's packets while its handshake runs */
#define POOL_FIRST          256         /* AllowedIPs nodes to start with; doubled when short */
#define POOL_MAX            (1u << 20)
#define PEER_IDLE_NS        (300ULL * SEC)  /* silent this long, a peer may make room for another */
#define VIA_FRESH_NS        (30ULL * SEC)   /* the relay a peer last spoke through, as a way back */
#define DNS_SEARCH_MAX      512             /* MagicDNS's search domains as text */
#define DNS_UPSTREAM_MAX    8
#define DNS_READ_BURST      16
#define NODE_ROUTES_MAX     64          /* one peer's AllowedIPs in the engine */
#define OS_ROUTES_MAX       256         /* subnet routes handed to the tun */
#define REQ_MAX             4096        /* a register or map request's JSON */
#define LITE_RETRY_NS       (30ULL * SEC)
#define BUSY_DELAY_NS       (10ULL * SEC)   /* 429 / 503 without Retry-After: tailscaled waits 5-10 s */
#define LINK_WAIT_NS        (120ULL * SEC)  /* the wait at a login link unanswered this long: the connection anew */
#define LINK_PAUSE_MAX_NS   (30ULL * SEC)   /* the same link again: the next wait after n^2 x 10 ms, at most this */
#define LOCAL4_MAX          4           /* our local endpoints: the default interface's IPv4 addresses */
#define LOCAL6_MAX          2           /* ... and its global IPv6 ones (magicsock: two per subnet) */
#define LOCAL_MAX           (LOCAL4_MAX + LOCAL6_MAX)
#define EPS_MAX             (LOCAL_MAX + 2)     /* ... and the ones STUN found outside, IPv4 and IPv6 */
#define EP_TYPE_LOCAL       1           /* tailcfg.EndpointLocal */
#define EP_TYPE_STUN        2           /* tailcfg.EndpointSTUN */
#define UDP_READ_BURST      64          /* datagrams read from the direct-path socket per wakeup */

/* A pong's source for a ping that came over DERP: magicsock's DerpMagicIPAddr, the region as the port. */
static const uint8_t derp_magic_ip[4] = { 127, 3, 3, 40 };

typedef struct {
    wg_peer  p;                         /* first: the engine's send_peer hands this pointer back */
    int64_t  node;                      /* its NodeID */
    int      via;                       /* the region its last packet came through: a way back */
    uint64_t via_at;                    /* ... when, monotonic */
    int      sent_via;                  /* the region we last sent it through (-1: nowhere), for the log */
    uint64_t last;                      /* traffic either way, monotonic */
    char     name[96];                  /* for the log: ts_node_display_name's */

    /* The direct path (TAILSCALE.md section 11a). */
    ts_path  path;
    uint8_t  disco_shared[WG_BOX_KEY_LEN];
    uint8_t  disco_for[32];             /* the node's disco key the shared key is for; zero: none yet */
    wg_endpoint direct_logged;          /* the direct address last logged; family 0: the relays */

    uint8_t  stage[STAGE];
} ts_peer;

struct bt_ts {
    char        id[BT_ID_LEN + 1];
    char        tag[24];                /* "ts <id>", at the start of the log lines */
    bt_store*   store;
    ts_profile  prof;
    ts_url      url;
    bt_ts_hooks hooks;
    wg_device*  dev;
    wg_key      node_pub;
    wg_key      disco_priv, disco_pub;  /* new every start: in the requests, and the disco messages' key */
    char        nodekey[80];            /* "nodekey:<hex>", for the requests and the Ts-Lb header */
    char        discokey[80];

    /* control */
    bt_tsc*     ctl;
    int         req_register, req_map;
    int         checking;               /* req_register asks why control refused the map: no login */
    char        check_why[160];         /* ... that refusal, for when the answer explains nothing */

    /* The login by a link (TAILSCALE.md section 11b): in memory only, never on disk or in the log. */
    char        auth_url[TS_REG_URL_MAX + 1];   /* the link control gave; "" - none */
    int         link_wait;              /* req_register is the wait at it (a register with Followup) */
    uint64_t    link_sent;              /* ... sent then, monotonic */
    uint64_t    link_at;                /* the next wait at this time; 0 - none planned */
    unsigned    link_same;              /* control gave the same link this many times in a row */
    int         link_anew;              /* a refused wait asked for a new link already */
    int         map_up;                 /* this map session's first netmap is in */
    int         ever_up;
    int         stopped;                /* the login was refused or expired */
    char        reason[16];
    char        detail[160];

    /* the netmap */
    ts_netmap   nm;
    ts_node*    nm_nodes;
    uint16_t*   nm_index;
    uint8_t*    nm_arena;
    jsmntok_t*  tok;
    size_t      tok_cap;
    int64_t     skew;                   /* control's clock minus ours, seconds (ControlTime) */
    int         approval;               /* in the tailnet, an admin has not approved the node yet */

    /* relays and our home */
    bt_relays*  relays;
    int64_t     home;
    int         lite_pending;           /* control has yet to hear our PreferredDERP */
    uint64_t    lite_at;
    uint64_t    home_heard;             /* when home last brought a packet */

    /* peers */
    ts_peer*    peers[PEERS_MAX];
    wg_allowedips_node* pool;
    size_t      pool_cap;

    /* MagicDNS (TAILSCALE.md section 8a) */
    ts_dns      dns;
    int         dns_fd[2];              /* to upstream, IPv4 / IPv6; -1 until a query needs it */
    int         magic;                  /* on: the tailnet has it and our node's name gives its domain */
    char        suffix[TS_DNS_TEXT_MAX + 1];
    char        search[DNS_SEARCH_MAX];
    size_t      dns_turn;               /* which upstream server: the next one after one let a query go */
    char        dns_problem[96];        /* the socket trouble logged last: logged once */
    char        routes_said[256];       /* split DNS's routes as the log last said them */

    /* Direct paths (section 11a): one UDP socket for disco and WireGuard, following the routes. */
    int         udp;                    /* -1: none - the relays only */
    uint16_t    udp_port;
    int         udp6;                   /* the same for IPv6; -1: none - IPv4 only */
    uint16_t    udp6_port;
    wg_endpoint local[LOCAL_MAX];       /* the default interfaces' addresses with our ports, IPv4 first */
    size_t      n_local;
    wg_endpoint eps[EPS_MAX];           /* ours, as control and our CallMeMaybe tell the nodes */
    uint8_t     ep_type[EPS_MAX];       /* each one's EndpointType */
    size_t      n_eps;
    ts_stun_state stun;                 /* our IPv4 address outside every NAT (stage 2) */
    ts_stun_state stun6;                /* ... and IPv6's (no NAT on the way, mostly: the local one) */
    int64_t     measured_region[TS_DERPMAP_REGIONS_MAX];    /* the last home measurement, for STUN */
    uint64_t    measured_ns[TS_DERPMAP_REGIONS_MAX];
    size_t      n_measured;
    uint8_t     txid_base[TS_PATH_TXID_LEN];
    uint64_t    txid_count;
    char        udp_problem[96];        /* the socket trouble logged last: logged once */
    char        udp6_problem[96];       /* ... the IPv6 socket's, apart: no IPv6 must not flood the log */
};

static uint8_t scratch[REQ_MAX];

/* --------------------------------------------------------------------- small helpers */

static ts_time wall_now(const bt_ts* ts)
{
    uint64_t sec;
    uint32_t nsec;
    ts_time t;

    bt_wall(&sec, &nsec);
    t.sec = (int64_t)sec + ts->skew;
    t.nsec = (int32_t)nsec;
    return t;
}

static void key_text(char* out, size_t cap, const char* prefix, const wg_key* k)
{
    char hex[65];
    ts_hex32(hex, k->b);
    snprintf(out, cap, "%s%s", prefix, hex);
}

/* `s` for inside the quotes of a JSON string. 0 when it does not fit. */
static size_t json_escape(char* out, size_t cap, const char* s)
{
    size_t n = 0;

    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        const char* esc = NULL;
        char u[8];
        if (c == '"') esc = "\\\"";
        else if (c == '\\') esc = "\\\\";
        else if (c < 0x20) {
            snprintf(u, sizeof(u), "\\u%04x", c);
            esc = u;
        }
        if (esc) {
            size_t l = strlen(esc);
            if (n + l >= cap) return 0;
            memcpy(out + n, esc, l);
            n += l;
        } else {
            if (n + 1 >= cap) return 0;
            out[n++] = (char)c;
        }
    }
    out[n] = '\0';
    return n;
}

static void dns_refresh(bt_ts* ts);

static void stop(bt_ts* ts, const char* reason, const char* fmt, ...)
{
    va_list ap;

    if (ts->stopped) return;
    ts->stopped = 1;
    snprintf(ts->reason, sizeof(ts->reason), "%s", reason);
    va_start(ap, fmt);
    vsnprintf(ts->detail, sizeof(ts->detail), fmt, ap);
    va_end(ap);
    BT_W("%s: stopped (%s): %s", ts->tag, ts->reason, ts->detail);
    /* a login link of a stopped login is no link to open */
    wg_wipe(ts->auth_url, sizeof(ts->auth_url));
    /* MagicDNS off with it: the system's DNS goes back at once */
    if (ts->magic) dns_refresh(ts);
}

/* --------------------------------------------------------------------- the profile on disk */

/*
 * Reads the profile again, lets `fn` copy what the tunnel learned into it, writes it back - unless
 * another login replaced the node key meanwhile (profile.update authkey=): then this tunnel's copy
 * is the old one and writing it would undo that login.
 */
static void profile_update(bt_ts* ts, void (*fn)(const bt_ts* ts, ts_profile* p))
{
    static char out[4096];
    bt_meta m;
    ts_profile p;
    char* text;
    size_t len, n;
    int ok;

    if (!bt_store_load_meta(ts->store, ts->id, &m)) return;
    text = bt_store_load_conf(ts->store, ts->id, &len);
    if (!text) return;
    ok = ts_profile_parse(&p, text, len);
    bt_store_free_conf(text, len);
    if (!ok) return;
    if (memcmp(p.node.b, ts->prof.node.b, WG_KEY_LEN) == 0) {
        fn(ts, &p);
        n = ts_profile_format(&p, out, sizeof(out));
        if (!n || !bt_store_save(ts->store, &m, out, n)) BT_W("%s: cannot save the profile", ts->tag);
        wg_wipe(out, sizeof(out));
    }
    ts_profile_wipe(&p);
}

static void fn_registered(const bt_ts* ts, ts_profile* p)
{
    p->registered = 1;
    p->has_old_node = 0;
    wg_wipe(&p->old_node, sizeof(p->old_node));
    wg_wipe(p->auth_key, sizeof(p->auth_key));          /* sent once, never kept */
    (void)ts;
}

static void fn_server(const bt_ts* ts, ts_profile* p)
{
    p->server = ts->prof.server;
    p->has_server = ts->prof.has_server;
    memcpy(p->control_addr, ts->prof.control_addr, sizeof(p->control_addr));
}

static void fn_netmap(const bt_ts* ts, ts_profile* p)
{
    memcpy(p->tailnet, ts->prof.tailnet, sizeof(p->tailnet));
    memcpy(p->node_name, ts->prof.node_name, sizeof(p->node_name));
    memcpy(p->address, ts->prof.address, sizeof(p->address));
    p->n_address = ts->prof.n_address;
}

/* --------------------------------------------------------------------- requests */

static size_t hostinfo(const bt_ts* ts, char* out, size_t cap)
{
    char net[64] = "";
    int n;

    if (ts->home > 0) snprintf(net, sizeof(net), ",\"NetInfo\":{\"PreferredDERP\":%lld}", (long long)ts->home);
    /* What microlink sends to the official server, which takes it: Linux as the OS family. */
    n = snprintf(out, cap,
                 "{\"OS\":\"linux\",\"OSVersion\":\"BlackBerry 10\",\"DeviceModel\":\"BlackBerry 10\","
                 "\"Hostname\":\"%s\",\"GoArch\":\"arm\",\"App\":\"bbtunnel\"%s}",
                 ts->prof.hostname[0] ? ts->prof.hostname : TS_HOSTNAME_DEFAULT, net);
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

/*
 * A login: with the auth key; without one - by a link: control answers with the link, and the same
 * request with Followup = the link waits there until the user has logged in (section 11b). Or, `check`,
 * a register with our node key alone: control's answer says whether it still knows the node and its
 * login holds, as Go's client asks at every start.
 */
static void send_register(bt_ts* ts, int check, uint64_t now)
{
    static char follow[2 * TS_REG_URL_MAX + 32];
    char hi[512], auth[2 * TS_AUTHKEY_MAX + 32] = "", old[96] = "", key[2 * TS_AUTHKEY_MAX + 8];
    int n;

    ts->req_register = 0;
    ts->link_wait = 0;
    follow[0] = '\0';
    if (!hostinfo(ts, hi, sizeof(hi))) return;
    if (ts->prof.auth_key[0] && !check) {
        if (!json_escape(key, sizeof(key), ts->prof.auth_key)) return;
        snprintf(auth, sizeof(auth), "\"Auth\":{\"AuthKey\":\"%s\"},", key);
        wg_wipe(key, sizeof(key));
    } else if (!check && ts->auth_url[0]) {
        static char url[2 * TS_REG_URL_MAX + 8];
        if (!json_escape(url, sizeof(url), ts->auth_url)) return;
        snprintf(follow, sizeof(follow), "\"Followup\":\"%s\",", url);
        wg_wipe(url, sizeof(url));
    }
    if (ts->prof.has_old_node && !check) {
        wg_key pub;
        char k[80];
        if (wg_key_public(&ts->prof.old_node, &pub)) {
            key_text(k, sizeof(k), "nodekey:", &pub);
            snprintf(old, sizeof(old), "\"OldNodeKey\":\"%s\",", k);
        }
    }
    n = snprintf((char*)scratch, sizeof(scratch), "{\"Version\":%d,\"NodeKey\":\"%s\",%s%s%s\"Hostinfo\":%s}",
                 BT_TS_CAPVER, ts->nodekey, old, auth, follow, hi);
    wg_wipe(auth, sizeof(auth));
    if (n <= 0 || (size_t)n >= sizeof(scratch)) {
        wg_wipe(follow, sizeof(follow));
        return;
    }
    ts->req_register = bt_tsc_post(ts->ctl, "/machine/register", (const char*)scratch, (size_t)n, ts->nodekey,
                                   BT_TSC_BODY, now);
    wg_wipe(scratch, (size_t)n);
    if (follow[0]) {
        wg_wipe(follow, sizeof(follow));
        if (ts->req_register) {
            ts->link_wait = 1;
            ts->link_sent = now;
        }
        BT_D("%s: waiting at the login link", ts->tag);
    } else if (check) {
        BT_I("%s: asking control whether it still knows the node (a register without an auth key)", ts->tag);
    } else {
        BT_I("%s: registering the node%s%s", ts->tag, ts->prof.auth_key[0] ? "" : " (a login by a link)",
             ts->prof.has_old_node ? " (a new key for an old one)" : "");
    }
}

/* "login.tailscale.com" of "https://login.tailscale.com/a/...": the link's host, for the log - the link
 * itself logs a device in, and the log is a file anyone may be sent. */
static void link_host(char* out, size_t cap, const char* url)
{
    const char* h = strstr(url, "://");
    size_t n = 0;

    h = h ? h + 3 : url;
    while (h[n] && h[n] != '/' && h[n] != '?' && h[n] != '#' && n + 1 < cap) n++;
    memcpy(out, h, n);
    out[n] = '\0';
}

static void link_forget(bt_ts* ts)
{
    int had = ts->auth_url[0] != '\0';

    wg_wipe(ts->auth_url, sizeof(ts->auth_url));
    ts->link_wait = 0;
    ts->link_at = 0;
    ts->link_same = 0;
    if (had && ts->hooks.login_link) ts->hooks.login_link(ts->hooks.ctx);
}

/*
 * Control's answer to a login by a link: log in there. A new link is kept for the clients (status,
 * event=tunnel - they show it, and its QR code) and waited at at once; the same one again - the wait
 * again after a pause, n^2 x 10 ms up to 30 s, as Go's client.
 */
static void on_link(bt_ts* ts, const char* url, uint64_t now)
{
    ts->link_anew = 0;
    if (strcmp(url, ts->auth_url) != 0) {
        char host[96];
        snprintf(ts->auth_url, sizeof(ts->auth_url), "%s", url);
        ts->link_same = 0;
        ts->link_at = 0;
        link_host(host, sizeof(host), url);
        BT_I("%s: control gave a login link (%s) - waiting for the login there", ts->tag, host);
        if (ts->hooks.login_link) ts->hooks.login_link(ts->hooks.ctx);
        send_register(ts, 0, now);
        if (!ts->req_register) bt_tsc_drop(ts->ctl, "the wait at the login link could not go", 0, now);
        return;
    }
    {
        uint64_t pause;
        ts->link_same++;
        pause = (uint64_t)ts->link_same * ts->link_same * 10000000ULL;
        if (pause > LINK_PAUSE_MAX_NS) pause = LINK_PAUSE_MAX_NS;
        ts->link_at = now + pause;
        BT_D("%s: the same login link again - the next wait in %llu ms", ts->tag,
             (unsigned long long)(pause / 1000000ULL));
    }
}

/*
 * Control refused the map: it is asked why, by a register with our node key alone. The official
 * server's map says only "404 node not found" for a node gone from the tailnet - deleted by an admin,
 * or an ephemeral one 30-60 minutes after it fell quiet (the phone, 2026-10-22); the register's
 * answer tells that from an expired login. Not sent: as before, the map again after the growing delay.
 */
static void check_login(bt_ts* ts, const char* why, uint64_t now)
{
    BT_I("%s: control refused the map - %s", ts->tag, why);
    snprintf(ts->check_why, sizeof(ts->check_why), "%s", why);
    ts->checking = 1;
    send_register(ts, 1, now);
    if (!ts->req_register) {
        ts->checking = 0;
        bt_tsc_drop(ts->ctl, why, 0, now);
    }
}

/* Our endpoints for a short map request: "Endpoints":[...],"EndpointTypes":[...], - local ones (type
 * 1: an interface's address with our socket's port) and the one from STUN (type 2). "" without any. */
static void ep_text(char* out, size_t cap, const wg_endpoint* e);

static void endpoints_json(const bt_ts* ts, char* out, size_t cap)
{
    size_t len = 0, i;

    out[0] = '\0';
    if (!ts->n_eps) return;
    len += (size_t)snprintf(out + len, cap - len, "\"Endpoints\":[");
    for (i = 0; i < ts->n_eps && len < cap; i++) {
        char a[64];
        ep_text(a, sizeof(a), &ts->eps[i]);         /* netip.AddrPort's form: IPv6 in brackets */
        len += (size_t)snprintf(out + len, cap - len, "%s\"%s\"", i ? "," : "", a);
    }
    if (len < cap) len += (size_t)snprintf(out + len, cap - len, "],\"EndpointTypes\":[");
    for (i = 0; i < ts->n_eps && len < cap; i++)
        len += (size_t)snprintf(out + len, cap - len, "%s%u", i ? "," : "", (unsigned)ts->ep_type[i]);
    if (len < cap) len += (size_t)snprintf(out + len, cap - len, "],");
    if (len >= cap) out[0] = '\0';                  /* cut short: better none than half */
}

/* The streaming map, or the short one that tells control our Hostinfo (PreferredDERP) and our
 * endpoints: a stream takes neither since capver 68. */
static int send_map(bt_ts* ts, int stream, uint64_t now)
{
    char hi[512], eps[64 * EPS_MAX + 64];   /* an IPv6 endpoint takes up to 56 with its quotes */
    int n;

    if (!hostinfo(ts, hi, sizeof(hi))) return 0;
    if (stream) eps[0] = '\0';
    else endpoints_json(ts, eps, sizeof(eps));
    n = snprintf((char*)scratch, sizeof(scratch),
                 "{\"Version\":%d,\"KeepAlive\":true,\"NodeKey\":\"%s\",\"DiscoKey\":\"%s\",%s%s\"Hostinfo\":%s}",
                 BT_TS_CAPVER, ts->nodekey, ts->discokey, stream ? "\"Stream\":true," : "\"OmitPeers\":true,", eps, hi);
    if (n <= 0 || (size_t)n >= sizeof(scratch)) return 0;
    return bt_tsc_post(ts->ctl, "/machine/map", (const char*)scratch, (size_t)n, ts->nodekey,
                       stream ? BT_TSC_STREAM : BT_TSC_DISCARD, now);
}

static void start_map(bt_ts* ts, uint64_t now)
{
    ts_netmap_session_start(&ts->nm);
    ts->map_up = 0;
    ts->req_map = send_map(ts, 1, now);
    if (ts->home) {
        ts->lite_pending = 1;           /* a new session: tell our home again once it runs */
        ts->lite_at = now;
    }
}

/* --------------------------------------------------------------------- peers */

static int pool_grow(bt_ts* ts)
{
    size_t cap = ts->pool_cap * 2;
    wg_allowedips_node* bigger;
    wg_allowedips_node* old = NULL;

    if (cap > POOL_MAX) return 0;
    bigger = (wg_allowedips_node*)calloc(cap, sizeof(*bigger));
    if (!bigger) return 0;
    if (!wg_device_grow_allowedips(ts->dev, bigger, cap, &old)) {
        free(bigger);
        return 0;
    }
    free(old);
    ts->pool = bigger;
    ts->pool_cap = cap;
    BT_D("%s: AllowedIPs pool now %u nodes", ts->tag, (unsigned)cap);
    return 1;
}

/* A peer's AllowedIPs in the engine, as the netmap routes them to its node now. */
static void peer_allow(bt_ts* ts, ts_peer* tp, const ts_node* n)
{
    wg_prefix r[NODE_ROUTES_MAX];
    size_t cnt = ts_netmap_node_routes(&ts->nm, n, TS_ROUTE_SUBNETS, 0, wall_now(ts), r, NODE_ROUTES_MAX), k;

    if (cnt > NODE_ROUTES_MAX) cnt = NODE_ROUTES_MAX;
    wg_peer_disallow_all(&tp->p);
    for (k = 0; k < cnt; k++) {
        if (!r[k].family) continue;
        if (wg_peer_allow(&tp->p, r[k].family, r[k].addr, r[k].cidr)) continue;
        if (pool_grow(ts) && wg_peer_allow(&tp->p, r[k].family, r[k].addr, r[k].cidr)) continue;
        BT_W("%s: a route of node %lld left out of the engine", ts->tag, (long long)n->id);
    }
}

static void peer_drop(bt_ts* ts, int i)
{
    ts_peer* tp = ts->peers[i];

    if (!tp) return;
    wg_device_remove_peer(ts->dev, &tp->p);
    wg_wipe(tp, sizeof(*tp));
    free(tp);
    ts->peers[i] = NULL;
}

static ts_peer* peer_find(const bt_ts* ts, const uint8_t key[32])
{
    int i;
    for (i = 0; i < PEERS_MAX; i++)
        if (ts->peers[i] && memcmp(ts->peers[i]->p.noise.public_key.b, key, WG_KEY_LEN) == 0) return ts->peers[i];
    return NULL;
}

/* The node as an engine peer, made now if it is not one yet. NULL: it cannot be one - expired, no
 * key, or every slot busy with traffic. */
static ts_peer* peer_get(bt_ts* ts, const ts_node* n, uint64_t now)
{
    static const uint8_t zero[WG_KEY_LEN];
    ts_peer* tp = peer_find(ts, n->key.b);
    wg_endpoint label;
    int i, slot = -1;
    char name[96], at[64] = "";

    if (tp) return tp;
    if (memcmp(n->key.b, zero, WG_KEY_LEN) == 0 || ts_node_expired(n, wall_now(ts))) return NULL;
    for (i = 0; i < PEERS_MAX; i++) {
        if (!ts->peers[i]) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        /* Full: the one silent longest makes room, if it has been silent a while. */
        for (i = 0; i < PEERS_MAX; i++)
            if (now - ts->peers[i]->last >= PEER_IDLE_NS && (slot < 0 || ts->peers[i]->last < ts->peers[slot]->last))
                slot = i;
        if (slot < 0) {
            BT_W("%s: %d nodes in use already, node %lld waits", ts->tag, PEERS_MAX, (long long)n->id);
            return NULL;
        }
        peer_drop(ts, slot);
    }
    tp = (ts_peer*)calloc(1, sizeof(*tp));
    if (!tp) return NULL;
    if (!wg_device_add_peer(ts->dev, &tp->p, &n->key, tp->stage, STAGE)) {
        free(tp);
        return NULL;
    }
    memset(&label, 0, sizeof(label));
    label.family = WG_EP_OWNER;
    wg_peer_set_endpoint(&tp->p, &label);
    if (ts->hooks.peer_added) ts->hooks.peer_added(ts->hooks.ctx, &tp->p);
    tp->node = n->id;
    tp->last = now;
    ts->peers[slot] = tp;
    peer_allow(ts, tp, n);
    ts_node_display_name(&ts->nm, n, name, sizeof(name));
    snprintf(tp->name, sizeof(tp->name), "%s", name[0] ? name : "?");
    if (n->n_addrs) {
        const wg_prefix* a = ts_node_addrs(&ts->nm, n);
        inet_ntop(a[0].family == 6 ? AF_INET6 : AF_INET, a[0].addr, at, sizeof(at));
    }
    BT_I("%s: peer %s %s (home relay %lld)", ts->tag, name[0] ? name : "?", at, (long long)n->home_derp);
    return tp;
}

/* The netmap changed: peers whose node left, expired or took another key go; the rest follow
 * their node's routes. */
static void peers_sync(bt_ts* ts)
{
    ts_time now = wall_now(ts);
    int i;

    for (i = 0; i < PEERS_MAX; i++) {
        ts_peer* tp = ts->peers[i];
        const ts_node* n;
        if (!tp) continue;
        n = ts_netmap_find_key(&ts->nm, tp->p.noise.public_key.b);
        if (!n || ts_node_expired(n, now)) {
            BT_I("%s: node %lld gone from the netmap (or expired): its peer goes", ts->tag, (long long)tp->node);
            peer_drop(ts, i);
            continue;
        }
        tp->node = n->id;
        peer_allow(ts, tp, n);
    }
}

/* --------------------------------------------------------------------- relays */

static void relay_node_from(bt_ts* ts, const ts_derpmap_node* dn, bt_relay_node* rn)
{
    const char* host = ts_derpmap_str(&ts->nm, dn->host);
    const char* cert = ts_derpmap_str(&ts->nm, dn->cert);
    int family;
    uint8_t a[16];

    memset(rn, 0, sizeof(*rn));
    snprintf(rn->host, sizeof(rn->host), "%s", host);
    snprintf(rn->name, sizeof(rn->name), "%s", ts_derpmap_str(&ts->nm, dn->name));
    if (dn->v4.mode == TS_DERPMAP_IP_ADDR) rn->v4 = dn->v4.addr;
    if (dn->v6.mode == TS_DERPMAP_IP_ADDR) rn->v6 = dn->v6.addr;
    /* No address given, but the host name is one (a stand's IP): that is where to go. */
    if (!rn->v4.family && !rn->v6.family && ts_addr_parse(host, strlen(host), &family, a)) {
        bt_addr* to = family == 4 ? &rn->v4 : &rn->v6;
        to->family = (uint8_t)family;
        memcpy(to->addr, a, 16);
    }
    rn->port = ts->url.tls || dn->derp_port ? ts_derpmap_port(dn) : 80;
    if (strncmp(cert, "sha256-raw:", 11) == 0) snprintf(rn->pin, sizeof(rn->pin), "%s", cert);
}

static void home_set(bt_ts* ts, int64_t region, uint64_t now);

/* Our home from what the regions answered (netcheck's rules, in ts_netmap). Nobody answering keeps
 * home; without one, control's idea of it (our node's HomeDERP), else the first candidate. */
static void on_measured(void* ctx, const int64_t* region, const uint64_t* ns, size_t n)
{
    bt_ts* ts = (bt_ts*)ctx;
    uint64_t now = bt_now_ns();
    uint64_t heard = ts->home_heard ? now - ts->home_heard : ~0ULL;
    int64_t best = ts_derpmap_pick_home(&ts->nm, region, ns, n, ts->home, heard);

    /* kept: STUN asks the fastest regions after home, as netcheck's probe plan does */
    ts->n_measured = n < TS_DERPMAP_REGIONS_MAX ? n : TS_DERPMAP_REGIONS_MAX;
    memcpy(ts->measured_region, region, ts->n_measured * sizeof(region[0]));
    memcpy(ts->measured_ns, ns, ts->n_measured * sizeof(ns[0]));
    if (!best) {
        const ts_node* self = ts_netmap_self(&ts->nm);
        int64_t cand[1];
        if (self && self->home_derp && ts_derpmap_find(&ts->nm, self->home_derp)) best = self->home_derp;
        else if (ts_derpmap_home_candidates(&ts->nm, 0, cand, 1)) best = cand[0];
    }
    if (best) home_set(ts, best, now);
}

static void measure(bt_ts* ts, uint64_t now)
{
    int64_t cand[TS_DERPMAP_REGIONS_MAX];
    size_t n = ts_derpmap_home_candidates(&ts->nm, ts->home, cand, TS_DERPMAP_REGIONS_MAX);

    if (n > TS_DERPMAP_REGIONS_MAX) n = TS_DERPMAP_REGIONS_MAX;
    if (n == 1) home_set(ts, cand[0], now);                 /* one region (a stand): no question */
    else if (n > 1) bt_relays_measure(ts->relays, cand, n, now);
}

static void home_set(bt_ts* ts, int64_t region, uint64_t now)
{
    if (region == ts->home && bt_relays_home(ts->relays) == (int)region) return;
    ts->home = region;
    bt_relays_set_home(ts->relays, (int)region, now);
    ts->lite_pending = 1;
    ts->lite_at = now;
}

/* The DERP map into the relays' own form: what it says about reaching each region. */
static void relays_map(bt_ts* ts, uint64_t now)
{
    static bt_relay_region regions[BT_RELAY_REGIONS];
    size_t i, n = 0;

    for (i = 0; i < ts->nm.derp.n_regions && n < BT_RELAY_REGIONS; i++) {
        const ts_derpmap_region* r = &ts->nm.derp.regions[i];
        const ts_derpmap_node* nodes = ts_derpmap_nodes(&ts->nm, r);
        bt_relay_region* g = &regions[n];
        size_t k;

        memset(g, 0, sizeof(*g));
        g->id = (int)r->id;
        snprintf(g->code, sizeof(g->code), "%s", ts_derpmap_str(&ts->nm, r->code));
        g->no_home = r->no_measure_no_home || r->avoid;
        for (k = 0; k < r->n_nodes && g->n_nodes < BT_RELAY_NODES; k++) {
            if (nodes[k].stun_only || !ts_derpmap_port(&nodes[k])) continue;
            relay_node_from(ts, &nodes[k], &g->nodes[g->n_nodes]);
            if (g->nodes[g->n_nodes].v4.family || g->nodes[g->n_nodes].v6.family) g->n_nodes++;
            else BT_W("%s: relay %d node %s has no address", ts->tag, g->id, g->nodes[g->n_nodes].host);
        }
        if (g->n_nodes) n++;
    }
    bt_relays_set_map(ts->relays, regions, n, now);
    if (!ts->home || !bt_relays_region(ts->relays, (int)ts->home)) {
        ts->home = 0;
        measure(ts, now);
    }
    ts_stun_want(&ts->stun);            /* a map: STUN servers to ask */
    ts_stun_want(&ts->stun6);
}

/* The relay a node is reached through now, as magicsock picks it: its home's connection if one is
 * open; else the one we last heard it on, while it is fresh; else connect to its home. Fresh:
 * VIA_FRESH_NS since its last packet there - a node closes a relay that is not its home a minute
 * after it last wrote there, and a relay of several servers may not say PeerGone when it does: our
 * packets then went on into nothing (the phone's browser to the NAS, 2026-10-16: its SYNs through
 * relay 4 eight minutes on). 0: nothing says where it is. */
static int relay_for(bt_ts* ts, const ts_peer* tp, const ts_node* n, uint64_t now)
{
    int home = n ? (int)n->home_derp : 0;

    if (home && bt_relays_open(ts->relays, home)) return home;
    if (tp->via && now - tp->via_at < VIA_FRESH_NS && bt_relays_open(ts->relays, tp->via)) return tp->via;
    return home ? home : tp->via;
}

static void disco_in(bt_ts* ts, const uint8_t* frame, size_t len, const wg_endpoint* udp_src, int region,
                     const uint8_t* derp_src, uint64_t now);

static void on_relay_packet(void* ctx, int region, const uint8_t src[32], uint8_t* data, size_t len)
{
    bt_ts* ts = (bt_ts*)ctx;
    uint64_t now = bt_now_ns();
    ts_peer* tp;
    wg_endpoint label;
    uint64_t handshake;
    int had_handshake;

    if (ts_disco_is(data, len)) {
        disco_in(ts, data, len, NULL, region, src, now);
        return;
    }
    tp = peer_find(ts, src);
    if (!tp) {
        /* A node starting a handshake with us: it becomes a peer, if the netmap knows it. */
        const ts_node* n = ts_netmap_find_key(&ts->nm, src);
        if (!n) {
            BT_D("%s: relay %d: a packet from a key the netmap does not know - dropped", ts->tag, region);
            return;
        }
        if (!(tp = peer_get(ts, n, now))) return;
    }
    if (region != tp->via) BT_D("%s: %s speaks through relay %d", ts->tag, tp->name, region);
    tp->via = region;
    tp->via_at = now;
    tp->last = now;
    if (region == ts->home) ts->home_heard = now;
    memset(&label, 0, sizeof(label));
    label.family = WG_EP_OWNER;
    had_handshake = tp->p.has_handshake;
    handshake = tp->p.last_handshake_ns;
    wg_device_receive_from(ts->dev, &tp->p, data, len, &label, now);
    if (tp->p.has_handshake && (!had_handshake || tp->p.last_handshake_ns != handshake))
        BT_D("%s: handshake with %s done (relay %d)", ts->tag, tp->name, region);
}

static void on_relay_gone(void* ctx, int region, const uint8_t key[32])
{
    bt_ts* ts = (bt_ts*)ctx;
    ts_peer* tp = peer_find(ts, key);
    if (tp && tp->via == region) tp->via = 0;
}

static void on_relay_home(void* ctx, int up)
{
    bt_ts* ts = (bt_ts*)ctx;
    if (up) ts->home_heard = bt_now_ns();
}

/* --------------------------------------------------------------------- direct paths (section 11a) */

static void udp_trouble(bt_ts* ts, const char* what)
{
    char line[96];

    snprintf(line, sizeof(line), "%s: %s", what, strerror(errno));
    if (strcmp(line, ts->udp_problem) == 0) return;
    snprintf(ts->udp_problem, sizeof(ts->udp_problem), "%s", line);
    BT_W("%s: direct paths: %s", ts->tag, line);
}

static void udp_trouble6(bt_ts* ts, const char* what)
{
    char line[96];

    snprintf(line, sizeof(line), "%s: %s", what, strerror(errno));
    if (strcmp(line, ts->udp6_problem) == 0) return;
    snprintf(ts->udp6_problem, sizeof(ts->udp6_problem), "%s", line);
    BT_W("%s: direct paths: %s", ts->tag, line);
}

/* A UDP socket of `family` on `port` (0: the kernel's choice), any address, non-blocking; IPv6 only
 * IPv6 (V6ONLY: IPv4 has its own). -1 with errno when it cannot be had; the port it got in *got. */
static int udp_bind(int family, uint16_t port, uint16_t* got)
{
    struct sockaddr_storage ss;
    socklen_t sl;
    int fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0), fl, one = 1, saved;

    if (fd < 0) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    fl = fcntl(fd, F_GETFL, 0);
    memset(&ss, 0, sizeof(ss));
    if (family == 6) {
        struct sockaddr_in6* s6 = (struct sockaddr_in6*)&ss;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port);
        sl = (socklen_t)sizeof(*s6);
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) < 0) goto fail;
    } else {
        struct sockaddr_in* s4 = (struct sockaddr_in*)&ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        sl = (socklen_t)sizeof(*s4);
    }
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0 || bind(fd, (struct sockaddr*)&ss, sl) < 0 ||
        getsockname(fd, (struct sockaddr*)&ss, &sl) < 0)
        goto fail;
    *got = ntohs(family == 6 ? ((struct sockaddr_in6*)&ss)->sin6_port : ((struct sockaddr_in*)&ss)->sin_port);
    return fd;
fail:
    saved = errno;
    close(fd);
    errno = saved;
    return -1;
}

/* The sockets for disco, STUN and WireGuard to nodes directly: IPv4 on a port of the kernel's
 * choosing, IPv6 on the same one when it is free (else its own), not bound to an interface - they
 * follow the routes, as the rest of Tailscale's transport (section 9). No IPv4 one: the relays only,
 * as before; no IPv6 one: IPv4 only. */
static void udp_open(bt_ts* ts)
{
    ts->udp = udp_bind(4, 0, &ts->udp_port);
    if (ts->udp < 0) {
        udp_trouble(ts, "no socket");
        return;
    }
    ts->udp6 = udp_bind(6, ts->udp_port, &ts->udp6_port);
    if (ts->udp6 < 0) ts->udp6 = udp_bind(6, 0, &ts->udp6_port);
    if (ts->udp6 < 0) {
        BT_I("%s: direct paths: UDP port %u (IPv4 only: no IPv6 socket - %s)", ts->tag, (unsigned)ts->udp_port,
             strerror(errno));
    } else if (ts->udp6_port == ts->udp_port) {
        BT_I("%s: direct paths: UDP port %u (IPv4 and IPv6)", ts->tag, (unsigned)ts->udp_port);
    } else {
        BT_I("%s: direct paths: UDP port %u, IPv6 %u", ts->tag, (unsigned)ts->udp_port, (unsigned)ts->udp6_port);
    }
}

static int ep_same(const wg_endpoint* a, const wg_endpoint* b)
{
    return a->family == b->family && a->port == b->port && memcmp(a->addr, b->addr, a->family == 4 ? 4 : 16) == 0;
}

static void ep_text(char* out, size_t cap, const wg_endpoint* e)
{
    char a[INET6_ADDRSTRLEN] = "?";
    inet_ntop(e->family == 6 ? AF_INET6 : AF_INET, e->addr, a, sizeof(a));
    snprintf(out, cap, e->family == 6 ? "[%s]:%u" : "%s:%u", a, (unsigned)e->port);
}

/*
 * Our endpoints as the nodes are told them: the local ones, then the address STUN found outside
 * every NAT when it is not one of them (no NAT on the way: it is) - magicsock's determineEndpoints
 * without port mapping. Told to control in the short map request, and to the nodes in our
 * CallMeMaybe, when they change.
 */
static void eps_compose(bt_ts* ts, uint64_t now)
{
    wg_endpoint eps[EPS_MAX];
    uint8_t type[EPS_MAX];
    size_t n = 0, i, k;
    const wg_endpoint* g[2];

    g[0] = &ts->stun.global;
    g[1] = &ts->stun6.global;
    memset(eps, 0, sizeof(eps));
    memset(type, 0, sizeof(type));
    for (i = 0; i < ts->n_local && n < EPS_MAX; i++) {
        eps[n] = ts->local[i];
        type[n++] = EP_TYPE_LOCAL;
    }
    for (k = 0; k < 2; k++) {
        if (!g[k]->family || !ts_path_usable(g[k]) || n >= EPS_MAX) continue;
        for (i = 0; i < n && !ep_same(&eps[i], g[k]); i++) {}
        if (i == n) {
            eps[n] = *g[k];
            type[n++] = EP_TYPE_STUN;
        }
    }
    if (n == ts->n_eps) {
        for (i = 0; i < n && ep_same(&eps[i], &ts->eps[i]) && type[i] == ts->ep_type[i]; i++) {}
        if (i == n) return;
    }
    memcpy(ts->eps, eps, sizeof(eps));
    memcpy(ts->ep_type, type, sizeof(type));
    ts->n_eps = n;
    if (n) {
        char line[200] = "", e[64];
        size_t len = 0;
        for (i = 0; i < n && len < sizeof(line); i++) {
            ep_text(e, sizeof(e), &eps[i]);
            len += (size_t)snprintf(line + len, sizeof(line) - len, "%s%s%s", i ? " " : "", e,
                                    type[i] == EP_TYPE_STUN ? " (STUN)" : "");
        }
        BT_I("%s: direct paths: our endpoints %s", ts->tag, line);
    } else {
        BT_I("%s: direct paths: no endpoint of ours", ts->tag);
    }
    ts->lite_pending = 1;               /* control - and through it the nodes - hear of them */
    ts->lite_at = now;
}

/*
 * Our local endpoints: the IPv4 addresses of the interface the IPv4 default route leaves through, and
 * the global IPv6 ones of the interface IPv6's leaves through (not link-local, not ULA - magicsock's
 * LocalAddresses leaves those out while there is anything else; two at most, as it takes per subnet),
 * each with its socket's port - where a node in the same network reaches us (a NAS at home). 1 when
 * they changed; the caller composes the endpoints (eps_compose).
 */
static int eps_refresh(bt_ts* ts)
{
    wg_endpoint local[LOCAL_MAX];
    size_t n = 0, n6 = 0, i;
    char if4[BT_IFNAME_MAX], if6[BT_IFNAME_MAX];
    int have4 = ts->udp >= 0 && bt_default_if(4, if4), have6 = ts->udp6 >= 0 && bt_default_if(6, if6);
    struct ifaddrs* list = NULL;
    struct ifaddrs* ifa;

    memset(local, 0, sizeof(local));
    if ((have4 || have6) && getifaddrs(&list) == 0) {
        for (ifa = list; ifa && have4 && n < LOCAL4_MAX; ifa = ifa->ifa_next) {
            const struct sockaddr_in* s = (const struct sockaddr_in*)ifa->ifa_addr;
            if (!s || s->sin_family != AF_INET || strcmp(ifa->ifa_name, if4) != 0) continue;
            if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK)) continue;
            local[n].family = 4;
            memcpy(local[n].addr, &s->sin_addr, 4);
            local[n].port = ts->udp_port;
            if (ts_path_usable(&local[n]) && !(local[n].addr[0] == 169 && local[n].addr[1] == 254)) n++;
            else memset(&local[n], 0, sizeof(local[n]));
        }
        for (ifa = list; ifa && have6 && n6 < LOCAL6_MAX; ifa = ifa->ifa_next) {
            const struct sockaddr_in6* s = (const struct sockaddr_in6*)ifa->ifa_addr;
            if (!s || s->sin6_family != AF_INET6 || strcmp(ifa->ifa_name, if6) != 0) continue;
            if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK)) continue;
            if ((s->sin6_addr.s6_addr[0] & 0xe0) != 0x20) continue;     /* global unicast, 2000::/3 */
            local[n].family = 6;
            memcpy(local[n].addr, &s->sin6_addr, 16);
            local[n].port = ts->udp6_port;
            if (ts_path_usable(&local[n])) {
                n++;
                n6++;
            } else {
                memset(&local[n], 0, sizeof(local[n]));
            }
        }
        freeifaddrs(list);
    }
    if (n == ts->n_local) {
        for (i = 0; i < n && ep_same(&local[i], &ts->local[i]); i++) {}
        if (i == n) return 0;
    }
    memcpy(ts->local, local, sizeof(local));
    ts->n_local = n;
    return 1;
}

/* --- STUN (stage 2): rounds by ts_stun, the I/O here */

static int udp_send(bt_ts* ts, const wg_endpoint* to, const uint8_t* msg, size_t len);

/* Traffic to a node in the last TS_STUN_ACTIVE_NS: periodic rounds go on (magicsock's idle check). */
static int stun_active(const bt_ts* ts, uint64_t now)
{
    int i;
    for (i = 0; i < PEERS_MAX; i++)
        if (ts->peers[i] && ts->peers[i]->last && now - ts->peers[i]->last < TS_STUN_ACTIVE_NS) return 1;
    return 0;
}

/* A region's STUN server in `family` (4 or 6): its first node that answers STUN at an address of that
 * family we know (given, or a host name that is one); 0 when none does. */
static int stun_server_of(const bt_ts* ts, const ts_derpmap_region* r, int family, wg_endpoint* out)
{
    const ts_derpmap_node* nodes = ts_derpmap_nodes(&ts->nm, r);
    size_t k, alen = family == 6 ? 16 : 4;

    for (k = 0; k < r->n_nodes; k++) {
        const ts_derpmap_node* dn = &nodes[k];
        const ts_derpmap_ip* ip = family == 6 ? &dn->v6 : &dn->v4;
        const char* host = ts_derpmap_str(&ts->nm, dn->host);
        int f;
        uint8_t a[16];

        if (dn->stun_port < 0 || dn->stun_port > 65535) continue;
        memset(out, 0, sizeof(*out));
        if (ip->mode == TS_DERPMAP_IP_ADDR && ip->addr.family == family) {
            memcpy(out->addr, ip->addr.addr, alen);
        } else if (ip->mode == TS_DERPMAP_IP_DNS && ts_addr_parse(host, strlen(host), &f, a) && f == family) {
            memcpy(out->addr, a, alen);
        } else {
            continue;               /* a name to look up, or "none": not for STUN (the official map gives both) */
        }
        out->family = (uint8_t)family;
        out->port = dn->stun_port ? (uint16_t)dn->stun_port : TS_STUN_PORT_DEFAULT;
        return 1;
    }
    return 0;
}

/* The servers of a round in `family`: home's first, then the fastest others the last measurement saw,
 * then the rest of the map in its order - as netcheck plans its incremental probes (home and the
 * fastest). */
static size_t stun_servers(const bt_ts* ts, int family, wg_endpoint* out, size_t cap)
{
    int64_t order[2 * TS_DERPMAP_REGIONS_MAX + 1];  /* regions in the order to ask; repeats skipped */
    uint8_t used[TS_DERPMAP_REGIONS_MAX];
    size_t n_order = 0, n = 0, i, k;

    if (cap > TS_STUN_SERVERS) cap = TS_STUN_SERVERS;
    if (ts->home) order[n_order++] = ts->home;
    /* the measured ones that answered, the fastest first */
    memset(used, 0, sizeof(used));
    for (;;) {
        size_t best = ts->n_measured;
        for (i = 0; i < ts->n_measured; i++) {
            if (used[i] || !ts->measured_ns[i]) continue;
            if (best == ts->n_measured || ts->measured_ns[i] < ts->measured_ns[best]) best = i;
        }
        if (best == ts->n_measured) break;
        used[best] = 1;
        order[n_order++] = ts->measured_region[best];
    }
    for (i = 0; i < ts->nm.derp.n_regions; i++)
        if (!ts->nm.derp.regions[i].no_measure_no_home) order[n_order++] = ts->nm.derp.regions[i].id;

    for (i = 0; i < n_order && n < cap; i++) {
        const ts_derpmap_region* r;
        for (k = 0; k < i && order[k] != order[i]; k++) {}
        if (k < i) continue;
        r = ts_derpmap_find(&ts->nm, order[i]);
        if (r && stun_server_of(ts, r, family, &out[n])) n++;
    }
    return n;
}

/* What a round found, said once: where we are seen from outside, and (IPv4: netcheck tracks it for
 * IPv4 only) whether the NAT is hard. */
static void stun_report(bt_ts* ts, const ts_stun_state* st, const wg_endpoint* was, int was_varies)
{
    char at[64];

    if (!ep_same(&st->global, was)) {
        if (st->global.family) {
            ep_text(at, sizeof(at), &st->global);
            BT_I("%s: direct paths: seen from outside at %s (STUN)", ts->tag, at);
        } else {
            BT_I("%s: direct paths: no IPv%d address from outside any more (STUN has not answered for 5 min)",
                 ts->tag, (int)st->family);
        }
    }
    if (st->family == 4 && st->varies != was_varies) {
        if (st->varies)
            BT_I("%s: direct paths: the NAT maps us anew for each server (a hard NAT) - directly only to nodes "
                 "whose own side is open", ts->tag);
        else
            BT_I("%s: direct paths: the NAT keeps one mapping for every server again", ts->tag);
    }
}

/* One family's STUN on the clock: a round when one is due, its requests and second tries, its end.
 * The next time it has work. */
static uint64_t stun_step_family(bt_ts* ts, ts_stun_state* st, int active, uint64_t now)
{
    wg_endpoint to[TS_STUN_SERVERS], was;
    uint8_t txid[TS_STUN_SERVERS][TS_STUN_TXID_LEN], req[TS_STUN_REQUEST_LEN];
    uint32_t jitter = 0;
    size_t n, i;
    int was_varies;

    if (ts_stun_due(st, now, active)) {
        n = stun_servers(ts, st->family, to, TS_STUN_SERVERS);
        if (n && wg_random(txid, sizeof(txid))) {
            ts_stun_begin(st, to, (const uint8_t(*)[TS_STUN_TXID_LEN])txid, n, now);
            BT_D("%s: direct paths: STUN round (IPv%d), %u server(s)", ts->tag, (int)st->family, (unsigned)n);
        }
    }
    n = ts_stun_sends(st, now, to, txid, TS_STUN_SERVERS);
    for (i = 0; i < n; i++)
        if (ts_stun_request(req, sizeof(req), txid[i])) udp_send(ts, &to[i], req, sizeof(req));
    if (st->n) wg_random(&jitter, sizeof(jitter));
    was = st->global;
    was_varies = st->varies;
    if (ts_stun_tick(st, now, active, jitter)) {
        stun_report(ts, st, &was, was_varies);
        eps_compose(ts, now);
    }
    return ts_stun_next(st);
}

/* Whether we have a global IPv6 address: only then is IPv6 asked about (netcheck's HaveV6) - a phone
 * without IPv6 (home Wi-Fi often) would only collect "no route" every round. */
static int have_local6(const bt_ts* ts)
{
    size_t i;
    for (i = 0; i < ts->n_local; i++)
        if (ts->local[i].family == 6) return 1;
    return 0;
}

/* STUN's share of the clock, both families. */
static uint64_t stun_step(bt_ts* ts, uint64_t now)
{
    uint64_t next = BT_NEVER, d;
    int active;

    if (ts->udp < 0) return BT_NEVER;
    active = stun_active(ts, now);
    next = stun_step_family(ts, &ts->stun, active, now);
    if (ts->udp6 >= 0 && have_local6(ts)) {
        d = stun_step_family(ts, &ts->stun6, active, now);
        if (d < next) next = d;
    }
    return next;
}

/* TxIDs for pings: unguessable at the start, then counted - they only have to match pongs. */
static void txids_fill(bt_ts* ts, uint8_t (*rows)[TS_PATH_TXID_LEN], size_t n)
{
    size_t i, k;

    for (i = 0; i < n; i++) {
        uint64_t c = ++ts->txid_count;
        memcpy(rows[i], ts->txid_base, TS_PATH_TXID_LEN);
        for (k = 0; k < 8; k++) rows[i][TS_PATH_TXID_LEN - 1 - k] ^= (uint8_t)(c >> (8 * k));
    }
}

/* The key we seal to the node's disco key with: made when first needed, again when the key changes.
 * 0: the node has no disco key (or a bad one) - no direct path to it. */
static int peer_disco(bt_ts* ts, ts_peer* tp, const ts_node* n)
{
    static const uint8_t zero[32];

    if (memcmp(n->disco.b, zero, 32) == 0) return 0;
    if (memcmp(tp->disco_for, n->disco.b, 32) == 0) return 1;
    memset(tp->disco_for, 0, sizeof(tp->disco_for));
    if (!ts_disco_shared(tp->disco_shared, n->disco.b, &ts->disco_priv)) return 0;
    memcpy(tp->disco_for, n->disco.b, 32);
    return 1;
}

static int udp_send(bt_ts* ts, const wg_endpoint* to, const uint8_t* msg, size_t len)
{
    if (to->family == 6) {
        struct sockaddr_in6 sa6;
        if (ts->udp6 < 0) return 0;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons(to->port);
        memcpy(&sa6.sin6_addr, to->addr, 16);
        if (sendto(ts->udp6, msg, len, 0, (struct sockaddr*)&sa6, sizeof(sa6)) == (ssize_t)len) {
            ts->udp6_problem[0] = '\0';
            return 1;
        }
        udp_trouble6(ts, "send over IPv6");
        return 0;
    } else {
        struct sockaddr_in sa;
        if (ts->udp < 0 || to->family != 4) return 0;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(to->port);
        memcpy(&sa.sin_addr, to->addr, 4);
        if (sendto(ts->udp, msg, len, 0, (struct sockaddr*)&sa, sizeof(sa)) == (ssize_t)len) {
            ts->udp_problem[0] = '\0';
            return 1;
        }
        udp_trouble(ts, "send");
        return 0;
    }
}

/* A disco message to the node: over UDP to `to`, or over DERP when `to` is NULL. */
static void disco_send(bt_ts* ts, ts_peer* tp, const ts_node* n, const ts_disco_msg* m, const wg_endpoint* to,
                       uint64_t now)
{
    uint8_t frame[TS_DISCO_FRAME_MAX], nonce[WG_BOX_NONCE_LEN];
    size_t len;
    int region;

    if (!wg_random(nonce, sizeof(nonce))) return;
    len = ts_disco_seal(frame, sizeof(frame), m, ts->disco_pub.b, tp->disco_shared, nonce);
    if (!len) return;
    if (to) {
        udp_send(ts, to, frame, len);
        return;
    }
    region = relay_for(ts, tp, n, now);
    if (region) bt_relays_send(ts->relays, region, n->key.b, frame, len, now);
}

/* The pings ts_path asked for, and the CallMeMaybe after a round - over DERP, with our endpoints. */
static void pings_out(bt_ts* ts, ts_peer* tp, const ts_node* n, const wg_endpoint* to,
                      const uint8_t (*txid)[TS_PATH_TXID_LEN], size_t k, uint64_t now)
{
    ts_disco_msg m;
    size_t i;

    memset(&m, 0, sizeof(m));
    m.type = TS_DISCO_PING;
    m.has_node_key = 1;
    memcpy(m.node_key, ts->node_pub.b, 32);
    for (i = 0; i < k; i++) {
        memcpy(m.txid, txid[i], TS_PATH_TXID_LEN);
        disco_send(ts, tp, n, &m, &to[i], now);
    }
    if (k && bt_log_get_level() >= BT_LOG_DEBUG) {
        char line[160], e[64];
        size_t len = 0;
        line[0] = '\0';
        for (i = 0; i < k && len < sizeof(line); i++) {
            ep_text(e, sizeof(e), &to[i]);
            len += (size_t)snprintf(line + len, sizeof(line) - len, "%s%s", i ? " " : "", e);
        }
        BT_D("%s: pinging %s at %s", ts->tag, tp->name, line);
    }
    if (ts_path_take_cmm(&tp->path) && ts->n_eps) {
        memset(&m, 0, sizeof(m));
        m.type = TS_DISCO_CALL_ME_MAYBE;
        m.n_eps = ts->n_eps;
        memcpy(m.eps, ts->eps, ts->n_eps * sizeof(ts->eps[0]));
        disco_send(ts, tp, n, &m, NULL, now);
        BT_D("%s: asked %s to call us (%u endpoint(s), over DERP)", ts->tag, tp->name, (unsigned)ts->n_eps);
    }
}

/* A change of the way to the node, logged once: directly where, or the relays again. */
static void path_log(bt_ts* ts, ts_peer* tp, uint64_t now)
{
    wg_endpoint to;
    char at[64];

    if (ts_path_direct(&tp->path, now, &to)) {
        if (ep_same(&to, &tp->direct_logged)) return;
        ep_text(at, sizeof(at), &to);
        BT_I("%s: %s directly at %s (%llu ms)", ts->tag, tp->name, at,
             (unsigned long long)(tp->path.best_latency / 1000000ULL));
        tp->direct_logged = to;
    } else if (tp->direct_logged.family) {
        BT_I("%s: %s through the relays again", ts->tag, tp->name);
        memset(&tp->direct_logged, 0, sizeof(tp->direct_logged));
    }
}

/* WireGuard to the node: directly when a path is trusted (1); 0 - the relays. Pings go out first,
 * as ts_path asks: this send is what starts and keeps the search for a path. */
static int direct_send(bt_ts* ts, ts_peer* tp, const ts_node* n, const uint8_t* msg, size_t len, uint64_t now)
{
    uint8_t txid[TS_PATH_INFLIGHT][TS_PATH_TXID_LEN];
    wg_endpoint pings[TS_PATH_INFLIGHT], to;
    size_t k;

    if (ts->udp < 0 || !peer_disco(ts, tp, n)) return 0;
    txids_fill(ts, txid, TS_PATH_INFLIGHT);
    k = ts_path_send(&tp->path, now, pings, (const uint8_t(*)[TS_PATH_TXID_LEN])txid, TS_PATH_INFLIGHT);
    if (k || tp->path.cmm_due) pings_out(ts, tp, n, pings, (const uint8_t(*)[TS_PATH_TXID_LEN])txid, k, now);
    path_log(ts, tp, now);
    if (!ts_path_direct(&tp->path, now, &to)) return 0;
    return udp_send(ts, &to, msg, len);
}

/* The node whose disco key sent a message; NULL: none in the netmap - not ours to answer. */
static const ts_node* node_by_disco(const bt_ts* ts, const uint8_t* key)
{
    size_t i, count = ts_netmap_count(&ts->nm);

    for (i = 0; i < count; i++) {
        const ts_node* n = ts_netmap_at(&ts->nm, i);
        if (memcmp(n->disco.b, key, 32) == 0) return n;
    }
    return NULL;
}

/*
 * A disco message - over UDP from `udp_src`, or over DERP through `region` from node key `derp_src`.
 * Ping: a Pong back the same way, with the address it came from (and over UDP that address becomes a
 * candidate); Pong: the path may change; CallMeMaybe (over DERP only): the node's endpoints, pinged at
 * once. From a disco key no node of the netmap has - or over DERP from another node's key - nothing.
 */
static void disco_in(bt_ts* ts, const uint8_t* frame, size_t len, const wg_endpoint* udp_src, int region,
                     const uint8_t* derp_src, uint64_t now)
{
    static const uint8_t zero[32];
    const ts_node* n = node_by_disco(ts, ts_disco_sender(frame));
    ts_peer* tp;
    ts_disco_msg m, reply;

    if (!n || memcmp(n->disco.b, zero, 32) == 0) return;
    if (derp_src && memcmp(n->key.b, derp_src, 32) != 0) return;
    if (!(tp = peer_get(ts, n, now)) || !peer_disco(ts, tp, n)) return;
    if (!ts_disco_open(frame, len, tp->disco_shared, &m)) return;
    switch (m.type) {
    case TS_DISCO_PING:
        if (m.has_node_key && memcmp(m.node_key, n->key.b, 32) != 0) return;   /* not who it says */
        memset(&reply, 0, sizeof(reply));
        reply.type = TS_DISCO_PONG;
        memcpy(reply.txid, m.txid, TS_DISCO_TXID_LEN);
        if (udp_src) {
            char at[64];
            ep_text(at, sizeof(at), udp_src);
            BT_D("%s: %s pings us directly from %s", ts->tag, tp->name, at);
            reply.src = *udp_src;
            ts_path_pinged_from(&tp->path, udp_src, now);
            disco_send(ts, tp, n, &reply, udp_src, now);
        } else {
            reply.src.family = 4;
            memcpy(reply.src.addr, derp_magic_ip, 4);
            reply.src.port = (uint16_t)region;
            disco_send(ts, tp, n, &reply, NULL, now);
        }
        break;
    case TS_DISCO_PONG:
        if (udp_src && ts_path_pong(&tp->path, m.txid, now)) path_log(ts, tp, now);
        break;
    case TS_DISCO_CALL_ME_MAYBE:
        if (!udp_src) {
            if (bt_log_get_level() >= BT_LOG_DEBUG) {
                char line[200], e[64];
                size_t len = 0, i;
                line[0] = '\0';
                for (i = 0; i < m.n_eps && len < sizeof(line); i++) {
                    ep_text(e, sizeof(e), &m.eps[i]);
                    len += (size_t)snprintf(line + len, sizeof(line) - len, "%s%s", i ? " " : "", e);
                }
                BT_D("%s: %s asks us to call it at %s", ts->tag, tp->name, m.n_eps ? line : "(nothing)");
            }
            ts_path_call_me_maybe(&tp->path, m.eps, m.n_eps, now);
        }
        break;
    default:
        break;                          /* peer relays and the like: not ours */
    }
}

/* Datagrams on a direct-path socket (`fd`: the IPv4 one or the IPv6 one): a STUN answer from a server
 * of the running round, disco, or WireGuard from a node - the engine finds which, asked of the node
 * the address belongs to when we know it. */
static void udp_receive(bt_ts* ts, int fd)
{
    static uint8_t buf[2048];
    uint64_t now = bt_now_ns();
    wg_endpoint label;
    int burst, i, stun = 0;

    memset(&label, 0, sizeof(label));
    label.family = WG_EP_OWNER;
    for (burst = 0; burst < UDP_READ_BURST; burst++) {
        struct sockaddr_storage ss;
        socklen_t sl = (socklen_t)sizeof(ss);
        wg_endpoint src;
        ts_peer* tp = NULL;
        ts_stun_state* st;
        ssize_t r = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&ss, &sl);

        if (r < 0) break;
        memset(&src, 0, sizeof(src));
        if (ss.ss_family == AF_INET) {
            const struct sockaddr_in* s4 = (const struct sockaddr_in*)&ss;
            src.family = 4;
            memcpy(src.addr, &s4->sin_addr, 4);
            src.port = ntohs(s4->sin_port);
            st = &ts->stun;
        } else if (ss.ss_family == AF_INET6) {
            const struct sockaddr_in6* s6 = (const struct sockaddr_in6*)&ss;
            src.family = 6;
            memcpy(src.addr, &s6->sin6_addr, 16);
            src.port = ntohs(s6->sin6_port);
            st = &ts->stun6;
        } else {
            continue;
        }
        /* STUN only from a server we asked this round: a WireGuard packet may carry the cookie too */
        if (ts_stun_is(buf, (size_t)r) && ts_stun_knows(st, &src)) {
            if (ts_stun_answer(st, &src, buf, (size_t)r, now)) stun = 1;
            continue;
        }
        if (ts_disco_is(buf, (size_t)r)) {
            disco_in(ts, buf, (size_t)r, &src, 0, NULL, now);
            continue;
        }
        for (i = 0; i < PEERS_MAX && !tp; i++)
            if (ts->peers[i] && ts_path_knows(&ts->peers[i]->path, &src)) tp = ts->peers[i];
        if (tp) {
            tp->last = now;
            wg_device_receive_from(ts->dev, &tp->p, buf, (size_t)r, &label, now);
        } else {
            wg_device_receive(ts->dev, buf, (size_t)r, &label, now);
        }
    }
    if (stun) stun_step(ts, now);       /* the round may be over: say what it found at once */
}

/* The clock: heartbeats and the pings they bring, the end of trust - for every peer. */
static uint64_t direct_tick(bt_ts* ts, uint64_t now)
{
    uint64_t next = BT_NEVER;
    int i;

    if (ts->udp < 0) return next;
    for (i = 0; i < PEERS_MAX; i++) {
        ts_peer* tp = ts->peers[i];
        const ts_node* n;
        uint8_t txid[TS_PATH_INFLIGHT][TS_PATH_TXID_LEN];
        wg_endpoint pings[TS_PATH_INFLIGHT];
        size_t k;
        uint64_t t;

        if (!tp) continue;
        n = ts_netmap_find_key(&ts->nm, tp->p.noise.public_key.b);
        if (!n || !peer_disco(ts, tp, n)) continue;
        txids_fill(ts, txid, TS_PATH_INFLIGHT);
        k = ts_path_tick(&tp->path, now, pings, (const uint8_t(*)[TS_PATH_TXID_LEN])txid, TS_PATH_INFLIGHT);
        if (k || tp->path.cmm_due) pings_out(ts, tp, n, pings, (const uint8_t(*)[TS_PATH_TXID_LEN])txid, k, now);
        path_log(ts, tp, now);
        t = ts_path_next(&tp->path);
        if (t < next) next = t;
        /* the trust's end is no work for ts_path_tick, but the log should say it when it comes */
        if (tp->direct_logged.family && tp->path.trust_until && tp->path.trust_until < next) next = tp->path.trust_until;
    }
    return next;
}

/* --------------------------------------------------------------------- MagicDNS (section 8a) */

static const uint8_t quad100_4[4] = { 100, 100, 100, 100 };
static const uint8_t quad100_6[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 };

/* `a` (len bytes, lower case) is `b` (blen bytes) but for ASCII case and one trailing dot on b. */
static int name_is(const char* a, size_t len, const char* b, size_t blen)
{
    size_t i;

    if (blen && b[blen - 1] == '.') blen--;
    if (blen != len) return 0;
    for (i = 0; i < len; i++) {
        char c = b[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c + ('a' - 'A'));
        if (c != a[i]) return 0;
    }
    return 1;
}

/* A name that can go into the system's search list as it is: letters, digits, dots and hyphens -
 * on the phone "_" separates the words of _CS_RESOLVE. Lower case is made here. */
static int search_word(char* s)
{
    size_t i;

    if (!s[0]) return 0;
    for (i = 0; s[i]; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') s[i] = c = (char)(c + ('a' - 'A'));
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) return 0;
    }
    return 1;
}

static size_t node_addrs_of(const bt_ts* ts, const ts_node* n, int family, uint8_t (*out)[16], size_t cap)
{
    const wg_prefix* a = ts_node_addrs(&ts->nm, n);
    size_t i, k = 0;

    for (i = 0; i < n->n_addrs && k < cap; i++)
        if (a[i].family == family) memcpy(out[k++], a[i].addr, 16);
    return k;
}

/*
 * The tailnet's view of a name (ts_dns_lookup_fn): our node and the peers by their Name, the
 * ExtraRecords; a bare name as the node of that name in our domain (none - forwarded as it is: a
 * LAN may answer single names); under our domain and nobody's - NXDOMAIN. Then split DNS: under a
 * route (the longest suffix that fits, as Go's forwarder picks it) - its servers; a route without
 * servers is MagicDNS's own (NXDOMAIN for what is not a name of ours), one we cannot follow SERVFAIL.
 */
static ts_dns_name_kind dns_lookup(void* ctx, const char* name, size_t len, int family, uint8_t (*out)[16],
                                   size_t cap, size_t* n, int* route)
{
    bt_ts* ts = (bt_ts*)ctx;
    const ts_dnsconf* c = ts_netmap_dns(&ts->nm);
    const ts_node* self = ts_netmap_self(&ts->nm);
    char full[TS_DNS_TEXT_MAX + 1];
    size_t sl = strlen(ts->suffix), i, count = ts_netmap_count(&ts->nm);
    int found = 0, bare = memchr(name, '.', len) == NULL;

    *n = 0;
    if (!ts->magic) return TS_DNS_NAME_OTHER;
    if (bare) {
        if (len + 1 + sl > TS_DNS_TEXT_MAX) return TS_DNS_NAME_OTHER;
        memcpy(full, name, len);
        full[len] = '.';
        memcpy(full + len + 1, ts->suffix, sl + 1);
        name = full;
        len += 1 + sl;
    }
    if (self && name_is(name, len, ts_node_name(&ts->nm, self), self->name_len)) {
        *n += node_addrs_of(ts, self, family, out, cap);
        found = 1;
    }
    for (i = 0; i < count && !found; i++) {
        const ts_node* p = ts_netmap_at(&ts->nm, i);
        if (name_is(name, len, ts_node_name(&ts->nm, p), p->name_len)) {
            *n += node_addrs_of(ts, p, family, out, cap);
            found = 1;
        }
    }
    for (i = 0; i < c->n_extra; i++) {
        if (!name_is(name, len, c->extra[i].name, strlen(c->extra[i].name))) continue;
        found = 1;
        if (c->extra[i].family == family && *n < cap) memcpy(out[(*n)++], c->extra[i].addr, 16);
    }
    if (found) return TS_DNS_NAME_OURS;
    if (bare) return TS_DNS_NAME_OTHER;
    if (sl && len >= sl && memcmp(name + len - sl, ts->suffix, sl) == 0 && (len == sl || name[len - sl - 1] == '.'))
        return TS_DNS_NAME_NX;
    {
        int best = -1;
        size_t best_len = 0;
        for (i = 0; i < c->n_routes; i++) {
            const char* s = c->routes[i].suffix;
            size_t rl = strlen(s);
            if (rl > len || (best >= 0 && rl <= best_len)) continue;
            if (memcmp(name + len - rl, s, rl) == 0 && (len == rl || name[len - rl - 1] == '.')) {
                best = (int)i;
                best_len = rl;
            }
        }
        if (best < 0) return TS_DNS_NAME_OTHER;
        if (c->routes[best].unusable) return TS_DNS_NAME_FAIL;
        if (!c->routes[best].n_servers) return TS_DNS_NAME_NX;
        *route = best;
        return TS_DNS_NAME_ROUTED;
    }
}

/* `s` onto the text in `out` (`*len` long, `cap` the room): what does not fit is left out, the text
 * always ends in a NUL. */
static void text_add(char* out, size_t cap, size_t* len, const char* s)
{
    size_t n = strlen(s);

    if (*len + 1 >= cap) return;
    if (n > cap - 1 - *len) n = cap - 1 - *len;
    memcpy(out + *len, s, n);
    *len += n;
    out[*len] = '\0';
}

/*
 * MagicDNS on or off, its domain and search list, after a netmap: on when the tailnet has it
 * (DNSConfig.Proxied) and our node's name gives the domain. The tunnel is told when any of it
 * changed - it sets the system's DNS.
 */
static void dns_refresh(bt_ts* ts)
{
    const ts_dnsconf* c = ts_netmap_dns(&ts->nm);
    char suffix[TS_DNS_TEXT_MAX + 1], search[DNS_SEARCH_MAX], word[TS_DNS_NAME_MAX + 1];
    size_t used = 0, i;
    int magic;

    ts_netmap_magic_suffix(&ts->nm, suffix, sizeof(suffix));
    magic = !ts->stopped && c->present && c->proxied && search_word(suffix);
    search[0] = '\0';
    if (magic) {
        used = strlen(suffix);
        memcpy(search, suffix, used + 1);
        for (i = 0; i < c->n_domains; i++) {
            size_t dl;
            snprintf(word, sizeof(word), "%s", c->domains[i]);
            if (!search_word(word) || strcmp(word, suffix) == 0) continue;
            dl = strlen(word);
            if (used + 1 + dl >= sizeof(search)) break;
            search[used++] = ' ';
            memcpy(search + used, word, dl + 1);
            used += dl;
        }
    } else {
        suffix[0] = '\0';
    }
    {   /* split DNS: the routes with servers of their own, said when they change (control's own
         * reverse zones, MagicDNS's, only counted) */
        char routes[sizeof(ts->routes_said)], count[48];
        size_t len = 0, k, own = 0, listed = 0;
        routes[0] = '\0';
        for (i = 0; magic && i < c->n_routes; i++) {
            const ts_dns_route* r = &c->routes[i];
            if (!r->n_servers && !r->unusable) {
                own++;
                continue;
            }
            text_add(routes, sizeof(routes), &len, listed++ ? ", " : "");
            text_add(routes, sizeof(routes), &len, r->suffix);
            text_add(routes, sizeof(routes), &len, " ->");
            if (r->unusable) text_add(routes, sizeof(routes), &len, " SERVFAIL (DoH only)");
            for (k = 0; k < r->n_servers; k++) {
                char a[INET6_ADDRSTRLEN] = "?";
                inet_ntop(r->servers[k].family == 6 ? AF_INET6 : AF_INET, r->servers[k].addr, a, sizeof(a));
                text_add(routes, sizeof(routes), &len, " ");
                text_add(routes, sizeof(routes), &len, a);
            }
        }
        if (own) {
            snprintf(count, sizeof(count), "%s%u MagicDNS's own", listed ? "; " : "", (unsigned)own);
            text_add(routes, sizeof(routes), &len, count);
        }
        if (strcmp(routes, ts->routes_said) != 0) {
            if (routes[0]) BT_I("%s: split DNS: %s", ts->tag, routes);
            else if (ts->routes_said[0]) BT_I("%s: split DNS: none", ts->tag);
            snprintf(ts->routes_said, sizeof(ts->routes_said), "%s", routes);
        }
    }
    if (magic == ts->magic && strcmp(suffix, ts->suffix) == 0 && strcmp(search, ts->search) == 0) return;
    if (magic != ts->magic) {
        if (magic) BT_I("%s: MagicDNS on, domain %s", ts->tag, suffix);
        else BT_I("%s: MagicDNS off", ts->tag);
    }
    ts->magic = magic;
    snprintf(ts->suffix, sizeof(ts->suffix), "%s", suffix);
    snprintf(ts->search, sizeof(ts->search), "%s", search);
    if (!magic) ts_dns_reset(&ts->dns);
    if (ts->hooks.dns_changed) ts->hooks.dns_changed(ts->hooks.ctx);
}

/* Where forwarded queries go: the "Override local DNS" servers when control gave some, else those
 * the phone would use without Tailscale (the tunnel's hook: a full tunnel's DNS=, else the
 * network's). Never the resolver's own addresses. */
static size_t dns_upstream(bt_ts* ts, bt_addr* out, size_t cap)
{
    const ts_dnsconf* c = ts_netmap_dns(&ts->nm);
    bt_addr got[DNS_UPSTREAM_MAX];
    size_t n = 0, k = 0, i;

    if (c->n_resolvers) {
        n = c->n_resolvers < DNS_UPSTREAM_MAX ? c->n_resolvers : DNS_UPSTREAM_MAX;
        memcpy(got, c->resolvers, n * sizeof(*got));
    } else if (ts->hooks.resolvers) {
        n = ts->hooks.resolvers(ts->hooks.ctx, got, DNS_UPSTREAM_MAX);
        if (n > DNS_UPSTREAM_MAX) n = DNS_UPSTREAM_MAX;
    }
    for (i = 0; i < n && k < cap; i++) {
        if (got[i].family == 4 && memcmp(got[i].addr, quad100_4, 4) == 0) continue;
        if (got[i].family == 6 && memcmp(got[i].addr, quad100_6, 16) == 0) continue;
        if (got[i].family != 4 && got[i].family != 6) continue;
        out[k++] = got[i];
    }
    return k;
}

static void dns_trouble(bt_ts* ts, const char* what)
{
    char line[96];

    snprintf(line, sizeof(line), "%s: %s", what, strerror(errno));
    if (strcmp(line, ts->dns_problem) == 0) return;
    snprintf(ts->dns_problem, sizeof(ts->dns_problem), "%s", line);
    BT_W("%s: MagicDNS: %s", ts->tag, line);
}

/* The socket to upstream of a family, made at the first query that needs it. Not bound to any
 * interface: it follows the routes, as the phone's own DNS would - into a full tunnel when one is up. */
static int dns_socket(bt_ts* ts, int family)
{
    int i = family == 6 ? 1 : 0, fd, fl;

    if (ts->dns_fd[i] >= 0) return ts->dns_fd[i];
    fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }
    ts->dns_fd[i] = fd;
    return fd;
}

static void dns_send(bt_ts* ts, const bt_addr* to, const uint8_t* msg, size_t len)
{
    struct sockaddr_storage ss;
    socklen_t sl;
    int fd = dns_socket(ts, to->family);

    if (fd < 0) {
        dns_trouble(ts, "no socket");
        return;
    }
    memset(&ss, 0, sizeof(ss));
    if (to->family == 4) {
        struct sockaddr_in* s = (struct sockaddr_in*)&ss;
        s->sin_family = AF_INET;
        s->sin_port = htons(53);
        memcpy(&s->sin_addr, to->addr, 4);
        sl = (socklen_t)sizeof(*s);
    } else {
        struct sockaddr_in6* s = (struct sockaddr_in6*)&ss;
        s->sin6_family = AF_INET6;
        s->sin6_port = htons(53);
        memcpy(&s->sin6_addr, to->addr, 16);
        sl = (socklen_t)sizeof(*s);
    }
    if (sendto(fd, msg, len, 0, (struct sockaddr*)&ss, sl) < 0) dns_trouble(ts, "send upstream");
    else ts->dns_problem[0] = '\0';
}

/* Whether `a` is a server of one of the split-DNS routes. */
static int route_server(const bt_ts* ts, const bt_addr* a)
{
    const ts_dnsconf* c = ts_netmap_dns(&ts->nm);
    size_t i, k;

    for (i = 0; i < c->n_routes; i++)
        for (k = 0; k < c->routes[i].n_servers; k++) {
            const bt_addr* s = &c->routes[i].servers[k];
            if (s->family == a->family && memcmp(s->addr, a->addr, a->family == 4 ? 4 : 16) == 0) return 1;
        }
    return 0;
}

/* Answers from upstream: only from a server we send to, from its port 53. */
static void dns_receive(bt_ts* ts, int fd)
{
    uint8_t msg[1500], pkt[TS_DNS_PKT_MAX];
    bt_addr up[DNS_UPSTREAM_MAX];
    size_t n_up = dns_upstream(ts, up, DNS_UPSTREAM_MAX), out_len = 0, i;
    int burst;

    for (burst = 0; burst < DNS_READ_BURST; burst++) {
        struct sockaddr_storage ss;
        socklen_t sl = (socklen_t)sizeof(ss);
        bt_addr from;
        unsigned port = 0;
        int known = 0;
        ssize_t r = recvfrom(fd, msg, sizeof(msg), 0, (struct sockaddr*)&ss, &sl);

        if (r < 0) break;
        memset(&from, 0, sizeof(from));
        if (ss.ss_family == AF_INET) {
            const struct sockaddr_in* s = (const struct sockaddr_in*)&ss;
            from.family = 4;
            memcpy(from.addr, &s->sin_addr, 4);
            port = ntohs(s->sin_port);
        } else if (ss.ss_family == AF_INET6) {
            const struct sockaddr_in6* s = (const struct sockaddr_in6*)&ss;
            from.family = 6;
            memcpy(from.addr, &s->sin6_addr, 16);
            port = ntohs(s->sin6_port);
        } else {
            continue;
        }
        if (port != 53) continue;
        for (i = 0; i < n_up && !known; i++)
            if (up[i].family == from.family && memcmp(up[i].addr, from.addr, from.family == 4 ? 4 : 16) == 0) known = 1;
        known = known || route_server(ts, &from);
        if (!known) continue;
        if (ts_dns_answer(&ts->dns, msg, (size_t)r, pkt, sizeof(pkt), &out_len) && ts->hooks.to_tun)
            ts->hooks.to_tun(ts->hooks.ctx, pkt, out_len);
    }
}

/* --------------------------------------------------------------------- the netmap */

static void cache_netmap(bt_ts* ts)
{
    const ts_node* self = ts_netmap_self(&ts->nm);
    const wg_prefix* a;
    size_t i;

    if (!self) return;
    snprintf(ts->prof.tailnet, sizeof(ts->prof.tailnet), "%s", ts_netmap_domain(&ts->nm));
    snprintf(ts->prof.node_name, sizeof(ts->prof.node_name), "%s", ts_node_name(&ts->nm, self));
    a = ts_node_addrs(&ts->nm, self);
    ts->prof.n_address = 0;
    for (i = 0; i < self->n_addrs && ts->prof.n_address < TS_PROFILE_ADDRS; i++) {
        char t[INET6_ADDRSTRLEN];
        if (!a[i].family) continue;
        inet_ntop(a[i].family == 6 ? AF_INET6 : AF_INET, a[i].addr, t, sizeof(t));
        snprintf(ts->prof.address[ts->prof.n_address++], TS_ADDR_TEXT_MAX, "%s/%d", t, a[i].cidr);
    }
    profile_update(ts, fn_netmap);
}

static void netmap_applied(bt_ts* ts, const ts_netmap_result* res, uint64_t now)
{
    const ts_node* self = ts_netmap_self(&ts->nm);
    unsigned ch = res->changed;

    if (!self) return;
    if (ch & (TS_NM_CHANGED_SELF | TS_NM_CHANGED_RESET)) {
        if (ts_node_expired(self, wall_now(ts))) {
            stop(ts, "expired", "the node's login expired: log in again with a new auth key");
            return;
        }
        ts->approval = !(self->flags & TS_NODE_AUTHORIZED);
        if (ts->hooks.addresses) ts->hooks.addresses(ts->hooks.ctx, ts_node_addrs(&ts->nm, self), self->n_addrs);
    }
    if (ch & (TS_NM_CHANGED_DERP | TS_NM_CHANGED_RESET)) relays_map(ts, now);
    if (ch & (TS_NM_CHANGED_PEERS | TS_NM_CHANGED_RESET | TS_NM_CHANGED_SELF)) {
        static wg_prefix routes[OS_ROUTES_MAX];
        size_t n = ts_netmap_os_routes(&ts->nm, TS_ROUTE_SUBNETS, 0, wall_now(ts), routes, OS_ROUTES_MAX);
        peers_sync(ts);
        if (ts->hooks.routes) ts->hooks.routes(ts->hooks.ctx, routes, n < OS_ROUTES_MAX ? n : OS_ROUTES_MAX);
    }
    if (ch & (TS_NM_CHANGED_SELF | TS_NM_CHANGED_DOMAIN | TS_NM_CHANGED_RESET)) cache_netmap(ts);
    if (ch & (TS_NM_CHANGED_DNS | TS_NM_CHANGED_SELF | TS_NM_CHANGED_RESET)) dns_refresh(ts);
}

/* One message of the map stream: parsed, applied; a refused one ends the session, as in Go. */
static void on_message(void* ctx, int req, char* json, size_t len)
{
    bt_ts* ts = (bt_ts*)ctx;
    uint64_t now = bt_now_ns();
    ts_netmap_result res;
    ts_json doc;
    long need;

    if (req != ts->req_map || ts->stopped) return;
    need = ts_json_count(json, len);
    if (need <= 0 || need > TS_NM_TOKENS_MAX) {
        bt_tsc_drop(ts->ctl, "a map message too large or not JSON", 0, now);
        return;
    }
    if ((size_t)need > ts->tok_cap) {
        jsmntok_t* t = (jsmntok_t*)realloc(ts->tok, (size_t)need * sizeof(*t));
        if (!t) {
            bt_tsc_drop(ts->ctl, "out of memory for a map message", 0, now);
            return;
        }
        ts->tok = t;
        ts->tok_cap = (size_t)need;
    }
    if (!ts_json_parse(&doc, json, len, ts->tok, ts->tok_cap)) {
        char why[96];
        snprintf(why, sizeof(why), "a map message is not JSON: %s", ts_json_err_text(doc.err));
        bt_tsc_drop(ts->ctl, why, 0, now);
        return;
    }
    if (!ts_netmap_apply(&ts->nm, &doc, wall_now(ts), &res)) {
        char why[96];
        snprintf(why, sizeof(why), "a map message refused: %s", ts_netmap_err_text(res.err));
        bt_tsc_drop(ts->ctl, why, 0, now);
        return;
    }
    if (res.has_control_time) {
        uint64_t sec;
        uint32_t nsec;
        bt_wall(&sec, &nsec);
        ts->skew = res.control_time.sec - (int64_t)sec;
    }
    if (res.keepalive) return;
    if (!ts->map_up) {
        ts->map_up = 1;
        BT_I("%s: netmap: %u node(s), tailnet %s%s", ts->tag, (unsigned)ts_netmap_count(&ts->nm),
             ts_netmap_domain(&ts->nm)[0] ? ts_netmap_domain(&ts->nm) : "?",
             ts->nm.incomplete ? " (not all kept)" : "");
    }
    netmap_applied(ts, &res, now);
}

/* --------------------------------------------------------------------- control */

static void on_open(void* ctx)
{
    bt_ts* ts = (bt_ts*)ctx;
    uint64_t now = bt_now_ns();

    if (ts->stopped) return;
    ts->req_register = ts->req_map = 0;
    ts->checking = 0;
    ts->link_at = 0;            /* the wait at a login link goes now: with the register */
    if (!ts->prof.registered) send_register(ts, 0, now);
    else start_map(ts, now);
}

static void on_lost(void* ctx, const char* why)
{
    bt_ts* ts = (bt_ts*)ctx;
    ts->map_up = 0;
    ts->req_register = ts->req_map = 0;
    ts->checking = 0;
    ts->link_wait = 0;
    BT_I("%s: control lost: %s", ts->tag, why);
}

static int register_answer(bt_ts* ts, const uint8_t* body, size_t len, ts_register* r)
{
    ts_json doc;
    ts_netmap_err err;
    long need = ts_json_count((const char*)body, len);

    if (need <= 0 || (size_t)need > 4096) return 0;
    if ((size_t)need > ts->tok_cap) {
        jsmntok_t* t = (jsmntok_t*)realloc(ts->tok, (size_t)need * sizeof(*t));
        if (!t) return 0;
        ts->tok = t;
        ts->tok_cap = (size_t)need;
    }
    return ts_json_parse(&doc, (const char*)body, len, ts->tok, ts->tok_cap) && ts_register_parse(&doc, r, &err);
}

static void on_register(bt_ts* ts, int status, const uint8_t* body, size_t len, uint64_t retry_after, uint64_t now)
{
    static ts_register r;
    int check = ts->checking, waited = ts->link_wait;

    ts->checking = 0;
    ts->link_wait = 0;
    if (status == 429 || status == 503) {
        bt_tsc_drop(ts->ctl, "control is busy", retry_after ? retry_after * SEC : BUSY_DELAY_NS, now);
        return;
    }
    if (status >= 500 || status <= 0) {
        bt_tsc_drop(ts->ctl, check ? ts->check_why : "control failed the login", 0, now);
        return;
    }
    if (status != 200 && waited && !ts->link_anew) {
        /* The wait at the link ended with no node in the answer: the official server's 410 the moment the
         * user has logged in (the phone, build 31), Headscale's "registration timed out", a link of the
         * past. A register again says which: logged in - registered; else a new link. A second such
         * end in a row stops it. */
        BT_I("%s: control ended the wait at the login link (HTTP %d) - registering again: logged in there, "
             "or a new link", ts->tag, status);
        link_forget(ts);
        ts->link_anew = 1;
        send_register(ts, 0, now);
        if (!ts->req_register) bt_tsc_drop(ts->ctl, "the login could not go", 0, now);
        return;
    }
    if (status != 200) {
        if (check)
            stop(ts, status == 404 ? "removed" : "login", "control refused the map, then the check (HTTP %d): %.80s",
                 status, len ? (const char*)body : "");
        else
            stop(ts, "login", "control refused the login (HTTP %d): %.100s", status, len ? (const char*)body : "");
        return;
    }
    if (!register_answer(ts, body, len, &r)) {
        bt_tsc_drop(ts->ctl, "a register answer that is not one", 0, now);
        return;
    }
    if (check)
        BT_I("%s: control's answer: nodeKeyExpired=%d, machineAuthorized=%d, authURL=%d%s%.100s", ts->tag,
             r.node_key_expired ? 1 : 0, r.machine_authorized ? 1 : 0, r.auth_url[0] ? 1 : 0,
             r.error[0] ? ", error: " : "", r.error);
    if (r.error[0]) stop(ts, "login", "%s", r.error);
    else if (r.node_key_signature) stop(ts, "login", "the tailnet is locked (tailnet lock): not supported");
    else if (r.node_key_expired) stop(ts, "expired", "the node key expired: log in again with a new auth key");
    else if (r.auth_url[0] && check)
        stop(ts, "removed", "control does not know this device any more: an admin removed it from the tailnet, "
                            "or it was an ephemeral node and fell quiet");
    else if (r.auth_url[0] && ts->prof.auth_key[0])
        stop(ts, "login", "the auth key was not accepted: control asks for an interactive login");
    else if (r.auth_url[0]) {
        on_link(ts, r.auth_url, now);
        return;
    }
    if (ts->stopped) return;
    if (check) {
        /* Control knows the node and its login holds: the refusal stays unexplained - the map again
         * after the growing delay, as Go's client retries its map. */
        BT_I("%s: control still knows the node - the map again later", ts->tag);
        bt_tsc_drop(ts->ctl, ts->check_why, 0, now);
        return;
    }
    BT_I("%s: registered%s%s%s%s", ts->tag, r.login_name[0] ? " as " : "", r.login_name,
         ts->auth_url[0] ? " (logged in at the link)" : "",
         r.machine_authorized ? "" : " - waiting for an admin to approve the device");
    link_forget(ts);
    ts->link_anew = 0;
    ts->prof.registered = 1;
    fn_registered(ts, &ts->prof);
    profile_update(ts, fn_registered);
    start_map(ts, now);
}

static void on_response(void* ctx, int req, int status, const uint8_t* body, size_t len, uint64_t retry_after)
{
    bt_ts* ts = (bt_ts*)ctx;
    uint64_t now = bt_now_ns();

    if (ts->stopped) return;
    if (req == ts->req_register) {
        ts->req_register = 0;
        on_register(ts, status, body, len, retry_after, now);
    } else if (req == ts->req_map) {
        char why[160];
        ts->req_map = 0;
        ts->map_up = 0;
        if (status == 200) snprintf(why, sizeof(why), "control ended the map stream");
        else snprintf(why, sizeof(why), "map: HTTP %d %.100s", status, len ? (const char*)body : "");
        /* Refused, not busy: control is asked why (check_login) - a node gone from the tailnet or an
         * expired login is mended by a login, not by a reconnect. */
        if (status >= 400 && status < 500 && status != 429) check_login(ts, why, now);
        else bt_tsc_drop(ts->ctl, why, (status == 429 || status == 503) ? (retry_after ? retry_after * SEC : BUSY_DELAY_NS) : 0, now);
    } else if (status != 200) {
        /* The short map with our home: again later. */
        ts->lite_pending = 1;
        ts->lite_at = now + (retry_after ? retry_after * SEC : LITE_RETRY_NS);
    }
}

static void on_server_key(void* ctx, const wg_key* key)
{
    bt_ts* ts = (bt_ts*)ctx;
    ts->prof.server = *key;
    ts->prof.has_server = 1;
    profile_update(ts, fn_server);
}

static void on_address(void* ctx, const bt_addr* a)
{
    bt_ts* ts = (bt_ts*)ctx;
    inet_ntop(a->family == 6 ? AF_INET6 : AF_INET, a->addr, ts->prof.control_addr, sizeof(ts->prof.control_addr));
    profile_update(ts, fn_server);
}

static size_t on_resolvers(void* ctx, bt_addr* out, size_t cap)
{
    bt_ts* ts = (bt_ts*)ctx;
    return ts->hooks.resolvers ? ts->hooks.resolvers(ts->hooks.ctx, out, cap) : bt_dns_system(out, cap);
}

/* --------------------------------------------------------------------- start and stop */

/* The addresses the last netmap gave: on the tun at once, before control answers. */
static void cached_addresses(bt_ts* ts)
{
    wg_prefix a[TS_PROFILE_ADDRS];
    size_t i, n = 0;

    for (i = 0; i < ts->prof.n_address; i++)
        if (wg_prefix_parse(ts->prof.address[i], strlen(ts->prof.address[i]), &a[n])) n++;
    if (n && ts->hooks.addresses) ts->hooks.addresses(ts->hooks.ctx, a, n);
}

bt_ts* bt_ts_start(const char* id, bt_store* store, wg_device* dev, const bt_ts_hooks* hooks,
                   uint64_t now, char* err, size_t errlen)
{
    bt_ts* ts = (bt_ts*)calloc(1, sizeof(*ts));
    bt_relay_io rio;
    bt_tsc_calls cio;
    bt_addr caddr;
    int family;
    char* text;
    size_t len;
    int ok;

    if (!ts) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    /* before any way out through bt_ts_stop: calloc's 0 is stdin's fd */
    ts->dns_fd[0] = ts->dns_fd[1] = -1;
    ts->udp = ts->udp6 = -1;
    snprintf(ts->id, sizeof(ts->id), "%s", id);
    snprintf(ts->tag, sizeof(ts->tag), "ts %s", id);
    ts->store = store;
    ts->dev = dev;
    if (hooks) ts->hooks = *hooks;

    text = bt_store_load_conf(store, id, &len);
    ok = text && ts_profile_parse(&ts->prof, text, len);
    if (text) bt_store_free_conf(text, len);
    if (!ok || !ts_url_parse(ts->prof.control, strlen(ts->prof.control), &ts->url)) {
        snprintf(err, errlen, "the profile's Tailscale keys cannot be read");
        bt_ts_stop(ts);
        return NULL;
    }
    if (!wg_key_public(&ts->prof.node, &ts->node_pub) || !wg_key_generate(&ts->disco_priv, &ts->disco_pub) ||
        !wg_device_set_private_key(dev, &ts->prof.node)) {
        snprintf(err, errlen, "no keys");
        bt_ts_stop(ts);
        return NULL;
    }
    key_text(ts->nodekey, sizeof(ts->nodekey), "nodekey:", &ts->node_pub);
    key_text(ts->discokey, sizeof(ts->discokey), "discokey:", &ts->disco_pub);

    ts->pool_cap = POOL_FIRST;
    ts->pool = (wg_allowedips_node*)calloc(ts->pool_cap, sizeof(*ts->pool));
    ts->nm_nodes = (ts_node*)calloc(TS_NM_PEERS, sizeof(*ts->nm_nodes));
    ts->nm_index = (uint16_t*)calloc(2 * TS_NM_PEERS, sizeof(*ts->nm_index));
    ts->nm_arena = (uint8_t*)malloc(TS_NM_ARENA);
    if (!ts->pool || !ts->nm_nodes || !ts->nm_index || !ts->nm_arena ||
        !wg_device_set_allowedips_storage(dev, ts->pool, ts->pool_cap)) {
        snprintf(err, errlen, "out of memory");
        bt_ts_stop(ts);
        return NULL;
    }
    ts_netmap_init(&ts->nm, ts->nm_nodes, ts->nm_index, TS_NM_PEERS, ts->nm_arena, TS_NM_ARENA);
    {
        uint32_t seed = 0;
        wg_random(&seed, sizeof(seed));             /* the ids upstream sees: not guessable */
        ts_dns_init(&ts->dns, dns_lookup, ts, seed);
    }
    wg_random(ts->txid_base, sizeof(ts->txid_base));
    ts_stun_init(&ts->stun, 4);         /* a round once the DERP map names the servers */
    ts_stun_init(&ts->stun6, 6);
    udp_open(ts);
    eps_refresh(ts);
    eps_compose(ts, now);
    wg_device_up(dev, now);

    memset(&rio, 0, sizeof(rio));
    rio.ctx = ts;
    rio.packet = on_relay_packet;
    rio.peer_gone = on_relay_gone;
    rio.home = on_relay_home;
    rio.measured = on_measured;
    ts->relays = bt_relays_new(&ts->prof.node, &ts->node_pub, !ts->url.tls, ts->tag, &rio);

    memset(&cio, 0, sizeof(cio));
    cio.ctx = ts;
    cio.open = on_open;
    cio.lost = on_lost;
    cio.response = on_response;
    cio.message = on_message;
    cio.server_key = on_server_key;
    cio.address = on_address;
    cio.resolvers = on_resolvers;
    memset(&caddr, 0, sizeof(caddr));
    if (ts->prof.control_addr[0] &&
        wg_addr_parse(ts->prof.control_addr, strlen(ts->prof.control_addr), &family, caddr.addr))
        caddr.family = (uint8_t)family;
    ts->ctl = bt_tsc_new(&ts->url, &ts->prof.machine, ts->prof.has_server ? &ts->prof.server : NULL,
                         caddr.family ? &caddr : NULL, BT_TS_CAPVER, ts->tag, &cio);
    if (!ts->relays || !ts->ctl) {
        snprintf(err, errlen, "out of memory");
        bt_ts_stop(ts);
        return NULL;
    }

    cached_addresses(ts);
    bt_tsc_connect(ts->ctl, now);
    BT_I("%s: %s, node %.16s..., %s", ts->tag, ts->prof.control, ts->nodekey + 8,
         ts->prof.registered ? "logged in before"
                             : (ts->prof.auth_key[0] ? "logging in with an auth key" : "logging in by a link"));
    return ts;
}

void bt_ts_stop(bt_ts* ts)
{
    int i;

    if (!ts) return;
    for (i = 0; i < 2; i++)
        if (ts->dns_fd[i] >= 0) close(ts->dns_fd[i]);
    if (ts->udp >= 0) close(ts->udp);
    if (ts->udp6 >= 0) close(ts->udp6);
    for (i = 0; i < PEERS_MAX; i++) peer_drop(ts, i);
    bt_tsc_free(ts->ctl);
    bt_relays_free(ts->relays);
    free(ts->pool);                     /* the table is empty: every peer left it */
    free(ts->nm_nodes);
    free(ts->nm_index);
    free(ts->nm_arena);
    free(ts->tok);
    ts_profile_wipe(&ts->prof);
    wg_wipe(ts, sizeof(*ts));
    free(ts);
}

/* --------------------------------------------------------------------- the engine and the tun */

void bt_ts_send_peer(bt_ts* ts, wg_peer* p, const uint8_t* msg, size_t len)
{
    ts_peer* tp = (ts_peer*)p;
    const ts_node* n = ts_netmap_find_key(&ts->nm, p->noise.public_key.b);
    uint64_t now = bt_now_ns();
    int home = n ? (int)n->home_derp : 0, region;

    /* traffic after an idle spell: our address outside the NATs asked again before the pings need it */
    ts_stun_traffic(&ts->stun, now);
    ts_stun_traffic(&ts->stun6, now);
    /* A direct path the node answered on lately: that way (section 11a). Without one this is also
     * what pings its candidates and asks it to call back. */
    if (n && direct_send(ts, tp, n, msg, len, now)) {
        tp->last = now;
        return;
    }
    region = relay_for(ts, tp, n, now);
    if (!region) {                      /* nothing says where it is */
        if (tp->sent_via != -1) BT_D("%s: to %s: no relay known for it - not sent", ts->tag, tp->name);
        tp->sent_via = -1;
        return;
    }
    if (region != tp->sent_via) {
        BT_D("%s: to %s through relay %d (%s)", ts->tag, tp->name, region,
             region == home ? "its home" : region == tp->via ? "the one it last spoke through" : "connecting to it");
        tp->sent_via = region;
    }
    tp->last = now;
    bt_relays_send(ts->relays, region, p->noise.public_key.b, msg, len, now);
}

int bt_ts_no_route(bt_ts* ts, const uint8_t* pkt, size_t len, uint64_t now)
{
    wg_ip ip;
    const ts_node* n;
    ts_peer* tp;

    if (ts->stopped || !wg_ip_parse(pkt, len, &ip) || !ip.family) return 0;
    n = ts_netmap_route(&ts->nm, ip.family, ip.dst, TS_ROUTE_SUBNETS, 0, wall_now(ts));
    if (!n) {
        /* once per address in a row, not per packet; not for multicast - the kernel's own IPv6
         * neighbour and router messages on the tun, every few seconds */
        static uint8_t last_dst[16];
        uint8_t dst[16] = { 0 };
        int multicast;
        memcpy(dst, ip.dst, ip.family == 6 ? 16 : 4);
        multicast = ip.family == 6 ? dst[0] == 0xff : (dst[0] & 0xf0) == 0xe0;
        if (!multicast && memcmp(last_dst, dst, sizeof(dst)) != 0) {
            char at[64] = "";
            inet_ntop(ip.family == 6 ? AF_INET6 : AF_INET, dst, at, sizeof(at));
            BT_D("%s: a packet to %s: no node of the netmap has it - dropped", ts->tag, at);
            memcpy(last_dst, dst, sizeof(dst));
        }
        return 0;
    }
    tp = peer_find(ts, n->key.b);
    if (tp) {
        peer_allow(ts, tp, n);          /* a peer already: its routes were behind the netmap's */
        return 1;
    }
    return peer_get(ts, n, now) != NULL;
}

int bt_ts_dns(bt_ts* ts, const uint8_t* pkt, size_t len, uint64_t now)
{
    uint8_t out[TS_DNS_PKT_MAX];
    bt_addr up[DNS_UPSTREAM_MAX];
    size_t n_up, out_len = 0;
    ts_dns_action a;

    int route = -1;

    if (!ts->magic || ts->stopped || !ts_dns_is_ours(pkt, len)) return 0;
    n_up = dns_upstream(ts, up, DNS_UPSTREAM_MAX);
    a = ts_dns_query(&ts->dns, pkt, len, n_up > 0, now, out, sizeof(out), &out_len, &route);
    if (a == TS_DNS_ANSWER && ts->hooks.to_tun) {
        ts->hooks.to_tun(ts->hooks.ctx, out, out_len);
    } else if (a == TS_DNS_FORWARD && route >= 0) {
        /* split DNS: the route's own servers (they may be in the tailnet - the socket follows the routes) */
        const ts_dns_route* r = &ts_netmap_dns(&ts->nm)->routes[route];
        if (r->n_servers) dns_send(ts, &r->servers[ts->dns_turn % r->n_servers], out, out_len);
    } else if (a == TS_DNS_FORWARD && n_up) {
        dns_send(ts, &up[ts->dns_turn % n_up], out, out_len);
    }
    return 1;
}

int bt_ts_magic_dns(const bt_ts* ts, char* search, size_t cap)
{
    if (!ts->magic || ts->stopped) return 0;
    if (cap) snprintf(search, cap, "%s", ts->search);
    return 1;
}

/* --------------------------------------------------------------------- the loop */

int bt_ts_pollfds(bt_ts* ts, struct pollfd* out, int cap)
{
    int n = bt_tsc_pollfds(ts->ctl, out, cap), i;

    n += bt_relays_pollfds(ts->relays, out + n, cap - n);
    for (i = 0; i < 2; i++) {
        if (ts->dns_fd[i] < 0 || n >= cap) continue;
        out[n].fd = ts->dns_fd[i];
        out[n].events = POLLIN;
        out[n].revents = 0;
        n++;
    }
    if (ts->udp >= 0 && n < cap) {
        out[n].fd = ts->udp;
        out[n].events = POLLIN;
        out[n].revents = 0;
        n++;
    }
    if (ts->udp6 >= 0 && n < cap) {
        out[n].fd = ts->udp6;
        out[n].events = POLLIN;
        out[n].revents = 0;
        n++;
    }
    return n;
}

int bt_ts_owns(const bt_ts* ts, int fd)
{
    return bt_tsc_owns(ts->ctl, fd) || bt_relays_owns(ts->relays, fd) ||
           (fd >= 0 && (fd == ts->dns_fd[0] || fd == ts->dns_fd[1] || fd == ts->udp || fd == ts->udp6));
}

void bt_ts_io(bt_ts* ts, const struct pollfd* pfd)
{
    uint64_t now = bt_now_ns();
    if (pfd->fd >= 0 && (pfd->fd == ts->udp || pfd->fd == ts->udp6)) udp_receive(ts, pfd->fd);
    else if (pfd->fd >= 0 && (pfd->fd == ts->dns_fd[0] || pfd->fd == ts->dns_fd[1])) dns_receive(ts, pfd->fd);
    else if (bt_tsc_owns(ts->ctl, pfd->fd)) bt_tsc_io(ts->ctl, pfd, now);
    else bt_relays_io(ts->relays, pfd, now);
}

uint64_t bt_ts_tick(bt_ts* ts, uint64_t now)
{
    uint64_t next, d;
    unsigned gone = 0;

    if (ts->stopped) return BT_NEVER;
    next = bt_tsc_tick(ts->ctl, now);
    d = bt_relays_tick(ts->relays, now);
    if (d < next) next = d;
    /* MagicDNS: queries upstream let go at their time; the next one goes to the next server */
    d = ts_dns_expire(&ts->dns, now, &gone);
    if (gone) ts->dns_turn++;
    if (d < next) next = d;
    /* Our home to control, in a short map beside the stream. */
    if (ts->lite_pending && ts->map_up && bt_tsc_is_open(ts->ctl)) {
        if (now >= ts->lite_at) {
            if (send_map(ts, 0, now)) {
                ts->lite_pending = 0;
                BT_D("%s: told control home relay %lld", ts->tag, (long long)ts->home);
            } else {
                ts->lite_at = now + LITE_RETRY_NS;
            }
        }
        if (ts->lite_pending && ts->lite_at < next) next = ts->lite_at;
    }
    /* The login by a link: the next wait after its pause; a wait with no answer for two minutes - the
     * connection anew (on its way to control a NAT may have forgotten it), and the wait again. */
    if (ts->link_at && bt_tsc_is_open(ts->ctl) && !ts->req_register) {
        if (now >= ts->link_at) {
            ts->link_at = 0;
            send_register(ts, 0, now);
            if (!ts->req_register) bt_tsc_drop(ts->ctl, "the wait at the login link could not go", 0, now);
        } else if (ts->link_at < next) {
            next = ts->link_at;
        }
    }
    if (ts->link_wait && ts->req_register) {
        uint64_t end = ts->link_sent + LINK_WAIT_NS;
        if (now >= end) {
            ts->link_wait = 0;
            bt_tsc_drop(ts->ctl, "no word on the wait at the login link for two minutes", SEC, now);
        } else if (end < next) {
            next = end;
        }
    }
    /* Direct paths: heartbeats, pings, trust running out; STUN rounds. */
    d = direct_tick(ts, now);
    if (d < next) next = d;
    d = stun_step(ts, now);
    if (d < next) next = d;
    return next;
}

/* Every direct path found so far is gone: they are searched for again from scratch. */
static void paths_reset(bt_ts* ts)
{
    int i;
    for (i = 0; i < PEERS_MAX; i++)
        if (ts->peers[i]) ts_path_reset(&ts->peers[i]->path);
}

void bt_ts_net_changed(bt_ts* ts, uint64_t now)
{
    if (ts->stopped) return;
    bt_tsc_drop(ts->ctl, "the network changed", 1, now);
    bt_tsc_connect(ts->ctl, now);
    bt_relays_reconnect(ts->relays, now);
    if (ts->nm.derp.n_regions) measure(ts, now);
    paths_reset(ts);
    ts_stun_forget(&ts->stun);          /* what STUN saw was the old network's */
    ts_stun_forget(&ts->stun6);
    eps_refresh(ts);
    eps_compose(ts, now);
}

void bt_ts_net_event(bt_ts* ts, uint64_t now)
{
    if (ts->stopped) return;
    if (!eps_refresh(ts)) return;
    /* our local addresses moved: the paths and what STUN saw belong to the old network */
    ts_stun_forget(&ts->stun);
    ts_stun_forget(&ts->stun6);
    eps_compose(ts, now);
    paths_reset(ts);
}

/* --------------------------------------------------------------------- for the tunnel and clients */

bt_ts_status bt_ts_state(const bt_ts* ts, const char** reason, const char** detail)
{
    int ctl = bt_tsc_is_open(ts->ctl), home = bt_relays_home_up(ts->relays);

    *reason = "";
    *detail = NULL;
    if (ts->stopped) {
        *reason = ts->reason;
        *detail = ts->detail;
        return BT_TAIL_STOPPED;
    }
    /* a login link to open: what the user must do, whatever the connection does meanwhile */
    if (ts->auth_url[0]) {
        *reason = "browser";
        *detail = "waiting for a login at the link";
        return ts->ever_up ? BT_TAIL_LOST : BT_TAIL_STARTING;
    }
    if (ctl && ts->map_up && home && !ts->approval) {
        ((bt_ts*)ts)->ever_up = 1;
        return BT_TAIL_RUNNING;
    }
    if (!ctl) {
        *reason = "control";
        *detail = bt_tsc_error(ts->ctl)[0] ? bt_tsc_error(ts->ctl) : NULL;
    } else if (ts->map_up && ts->approval) {
        *reason = "approval";
        *detail = "waiting for an admin to approve the device";
    } else if (ts->map_up && !home) {
        *reason = "relay";
    }
    return ts->ever_up ? BT_TAIL_LOST : BT_TAIL_STARTING;
}

void bt_ts_describe(const bt_ts* ts, bt_writer* w)
{
    const ts_node* self = ts_netmap_self(&ts->nm);
    const bt_relay_region* g;
    bt_relay_stats st;
    size_t i;
    int active = 0;

    if (ts_netmap_domain(&ts->nm)[0]) bt_put(w, "tailnet", ts_netmap_domain(&ts->nm));
    else if (ts->prof.tailnet[0]) bt_put(w, "tailnet", ts->prof.tailnet);
    if (self) {
        const wg_prefix* a = ts_node_addrs(&ts->nm, self);
        for (i = 0; i < self->n_addrs; i++) {
            char t[64];
            if (!a[i].family) continue;
            inet_ntop(a[i].family == 6 ? AF_INET6 : AF_INET, a[i].addr, t, sizeof(t));
            bt_put(w, "ts_address", t);
        }
        bt_put(w, "ts_name", ts_node_name(&ts->nm, self));
    }
    bt_relays_stats(ts->relays, &st);
    g = st.home ? bt_relays_region(ts->relays, st.home) : NULL;
    if (g) bt_put(w, "relay", g->code[0] ? g->code : "?");
    bt_put(w, "relay_up", st.home_up ? "1" : "0");
    if (ts->auth_url[0]) bt_put(w, "auth_url", ts->auth_url);      /* to open, and its QR code */
    if (ts->stun6.global.family) {      /* where STUN sees us from outside over IPv6 */
        char at[64];
        ep_text(at, sizeof(at), &ts->stun6.global);
        bt_put(w, "outside", at);
    }
    if (ts->stun.global.family) {       /* ... and over IPv4, and whether the NAT is hard */
        char at[64];
        ep_text(at, sizeof(at), &ts->stun.global);
        bt_put(w, "outside", at);
        if (ts->stun.varies) bt_put(w, "hard_nat", "1");
    }
    for (i = 0; i < PEERS_MAX; i++)
        if (ts->peers[i]) active++;
    bt_put_u64(w, "nodes", ts_netmap_count(&ts->nm));
    bt_put_u64(w, "nodes_active", (uint64_t)active);
    bt_put_u64(w, "relay_in", st.packets_in);
    bt_put_u64(w, "relay_out", st.packets_out);
    bt_put_u64(w, "relay_dropped", st.dropped);
}

size_t bt_ts_node_count(const bt_ts* ts)
{
    return ts_netmap_count(&ts->nm);
}

void bt_ts_node_put(const bt_ts* ts, size_t i, bt_writer* w)
{
    const ts_node* node = ts_netmap_at(&ts->nm, i);
    const wg_prefix* a;
    const ts_peer* tp;
    char name[TS_NODE_NAME_MAX + 1];
    int k, online;

    if (!node) return;
    a = ts_node_addrs(&ts->nm, node);
    tp = peer_find(ts, node->key.b);
    online = ts_node_online(node);
    ts_node_display_name(&ts->nm, node, name, sizeof(name));
    bt_put(w, "name", name);
    for (k = 0; k < node->n_addrs; k++) {
        char t[INET6_ADDRSTRLEN];
        if (!a[k].family) continue;
        inet_ntop(a[k].family == 6 ? AF_INET6 : AF_INET, a[k].addr, t, sizeof(t));
        bt_put(w, "address", t);
    }
    bt_put(w, "online", online < 0 ? "" : online ? "1" : "0");
    if (ts_node_expired(node, wall_now(ts))) bt_put(w, "expired", "1");
    if (node->home_derp > 0) bt_put_i64(w, "relay", node->home_derp);
    bt_put(w, "active", tp && tp->p.has_handshake ? "1" : "0");
    if (tp) {
        wg_endpoint to;
        bt_put_u64(w, "rx_bytes", tp->p.rx_bytes);
        bt_put_u64(w, "tx_bytes", tp->p.tx_bytes);
        /* reached directly now (section 11a): where */
        if (ts_path_direct(&tp->path, bt_now_ns(), &to)) {
            char at[64];
            ep_text(at, sizeof(at), &to);
            bt_put(w, "direct", at);
        }
    }
}
