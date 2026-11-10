/*
 * bt_tunnel - see bt_tunnel.h.
 */

#include "bt_tunnel.h"
#include "bt_log.h"
#include "bt_tailscale.h"
#include "wg_conf.h"
#include "wg_device.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define STAGE_PER_PEER      (32 * 1024)
#define DEFAULT_MTU         1420
#define STALL_NS            (15 * BT_NSEC_PER_SEC)      /* connecting this long: say "handshake" */
#define NUDGE_NS            (20 * BT_NSEC_PER_SEC)      /* not up: initiate again this often */
#define REJECT_NS           (180 * BT_NSEC_PER_SEC)
#define BURST               64                          /* packets per fd per loop turn */
/* The tun's own: as many as its send queue holds (NetBSD tun, 256), so that a turn takes all the
 * system put there. With 64 the queue ran full in a burst and the system threw packets away - the
 * phone, 2026-10-16: `netstat -d` Drops 111 on Tailscale's tun, most likely the name lookups at boot
 * (all of them go to MagicDNS's resolver) while the daemon was bringing Tailscale up. */
#define TUN_BURST           256

struct bt_tunnel {
    int                 used;
    char                id[BT_ID_LEN + 1];
    bt_meta             meta;
    bt_tstate           state;
    char                reason[16];
    char                detail[160];
    unsigned            up_seq;             /* order of coming up, for who owns DNS */

    /* the configuration; the text stays while up (the conf points into it) */
    char*               text;
    size_t              text_len;
    wg_conf             conf;
    wg_conf_peer*       cpeers;
    wg_prefix*          callowed;

    /* the engine */
    wg_device*          dev;
    wg_awg*             awg;
    wg_peer*            peers;
    uint8_t*            stage;
    wg_allowedips_node* nodes;
    size_t              n_peers;

    /* the system */
    char                ifname[BT_IFNAME_MAX];
    int                 tun_fd;
    int                 udp[2];             /* [0] IPv4, [1] IPv6: the peers */
    int                 dnsfd[2];           /* the same, for looking up the peers' names */
    char                egress[2][BT_IFNAME_MAX];
    int                 routes_in;
    int                 full[2];            /* holds the default route of the family */
    int                 mtu;
    int                 engine;             /* the .conf went into the device */

    bt_lookup*          lookups;            /* one per peer; IDLE for a literal endpoint */

    uint64_t            since_ns;           /* connecting / reconnecting since */
    uint64_t            rx_since;           /* the peers' bytes in at that moment */
    uint64_t            next_nudge_ns;

    /* A Tailscale profile: its other half (bt_tailscale), which brings the peers; the addresses
     * and routes it asked for, as applied; where a new peer's handshake timestamps start. */
    bt_ts*              ts;
    wg_prefix           ts_addr[4];
    size_t              n_ts_addr;
    wg_prefix*          ts_routes;
    size_t              n_ts_routes;
    uint8_t             ts_start[WG_TIMESTAMP_LEN];
};

static bt_tunnel T[BT_TUNNELS_MAX];
static bt_store* S;
static bt_tunnel_hooks H;
static unsigned up_counter;
static int dns_owner = -1;                  /* the tunnel whose DNS= is in: index into T, or -1 */
static int dns_magic = -1;                  /* the Tailscale tunnel whose MagicDNS is in front, or -1 */
static const char* status_icon_shown;       /* what the status bar's VPN key was last set to, NULL before that */
static uint8_t pkt[WG_MAX_PACKET + 64];

static void bypass_sync(int recheck);
static int  bypass_known(int family, const uint8_t* addr);

int64_t bt_clock_offset_sec;

/* --------------------------------------------------------------------- clocks */

uint64_t bt_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * BT_NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

void bt_wall(uint64_t* sec, uint32_t* nsec)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    *sec = (uint64_t)((int64_t)tv.tv_sec + bt_clock_offset_sec);
    *nsec = (uint32_t)tv.tv_usec * 1000u;
}

const char* bt_tstate_name(bt_tstate s)
{
    switch (s) {
    case BT_TS_DOWN:         return "down";
    case BT_TS_CONNECTING:   return "connecting";
    case BT_TS_UP:           return "up";
    case BT_TS_RECONNECTING: return "reconnecting";
    case BT_TS_ERROR:        return "error";
    }
    return "?";
}

/* --------------------------------------------------------------------- small helpers */

static int fam_index(int family)
{
    return family == 6 ? 1 : 0;
}

/* The engine's peers: a WireGuard profile's from its .conf, a Tailscale profile's as bt_tailscale
 * added them - the device's list holds both. */
static const wg_peer* first_peer(const bt_tunnel* t)
{
    return t->dev && t->engine ? t->dev->peers : NULL;
}

static uint64_t rx_total(const bt_tunnel* t)
{
    uint64_t n = 0;
    const wg_peer* p;

    for (p = first_peer(t); p; p = p->next) n += p->rx_bytes;
    return n;
}

/*
 * The status bar's VPN key shows the tunnels as a whole (docs/DAEMON.md, section 10a): connected
 * while any is up; on while none is up and one is getting back after a network change, so that the
 * key does not blink; off otherwise, a first connection included.
 */
static const char* status_icon_wanted(void)
{
    int reconnecting = 0;
    int i;

    for (i = 0; i < BT_TUNNELS_MAX; i++) {
        if (!T[i].used) continue;
        if (T[i].state == BT_TS_UP) return "connected";
        if (T[i].state == BT_TS_RECONNECTING) reconnecting = 1;
    }
    if (reconnecting) return "on";
    return "off";
}

/* Written only when it changes: the navigator redraws on it. After a failed write the next change
 * tries again. */
static void status_icon_update(void)
{
    const char* wanted = status_icon_wanted();

    if (status_icon_shown && strcmp(status_icon_shown, wanted) == 0) return;
    if (!bt_status_icon(wanted)) {
        BT_W("status bar: cannot set the VPN icon to %s: %s", wanted, strerror(errno));
        return;
    }
    status_icon_shown = wanted;
    BT_I("status bar: VPN icon %s", wanted);
}

static void set_state(bt_tunnel* t, bt_tstate s, const char* reason, const char* detail)
{
    int changed = t->state != s || strcmp(t->reason, reason ? reason : "") != 0;

    if (t->state != s && (s == BT_TS_CONNECTING || s == BT_TS_RECONNECTING)) {
        t->since_ns = bt_now_ns();
        t->rx_since = rx_total(t);
    }
    t->state = s;
    snprintf(t->reason, sizeof(t->reason), "%s", reason ? reason : "");
    if (detail) snprintf(t->detail, sizeof(t->detail), "%s", detail);
    else if (changed) t->detail[0] = '\0';
    if (changed) {
        BT_I("tunnel %s: %s%s%s%s%s%s", t->id, bt_tstate_name(s), t->reason[0] ? " (" : "", t->reason,
             t->detail[0] ? ": " : "", t->detail, t->reason[0] ? ")" : "");
        if (H.changed) H.changed(t);
        status_icon_update();
    }
}

static void addr_text(int family, const uint8_t* addr, char* out, size_t cap)
{
    if (!inet_ntop(family == 6 ? AF_INET6 : AF_INET, addr, out, (socklen_t)cap)) snprintf(out, cap, "?");
}

static void close_fd(int* fd)
{
    if (*fd >= 0) close(*fd);
    *fd = -1;
}

static size_t to_sockaddr(const wg_endpoint* e, struct sockaddr_storage* ss)
{
    memset(ss, 0, sizeof(*ss));
    if (e->family == 4) {
        struct sockaddr_in* s = (struct sockaddr_in*)ss;
        s->sin_family = AF_INET;
        s->sin_port = htons(e->port);
        memcpy(&s->sin_addr, e->addr, 4);
        return sizeof(*s);
    }
    {
        struct sockaddr_in6* s = (struct sockaddr_in6*)ss;
        s->sin6_family = AF_INET6;
        s->sin6_port = htons(e->port);
        memcpy(&s->sin6_addr, e->addr, 16);
        return sizeof(*s);
    }
}

static int from_sockaddr(const struct sockaddr_storage* ss, wg_endpoint* e)
{
    memset(e, 0, sizeof(*e));
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in* s = (const struct sockaddr_in*)ss;
        e->family = 4;
        memcpy(e->addr, &s->sin_addr, 4);
        e->port = ntohs(s->sin_port);
        return 1;
    }
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6* s = (const struct sockaddr_in6*)ss;
        e->family = 6;
        memcpy(e->addr, &s->sin6_addr, 16);
        e->port = ntohs(s->sin6_port);
        return 1;
    }
    return 0;
}

/* --------------------------------------------------------------------- engine upcalls */

static void up_send(void* ctx, const wg_endpoint* to, const uint8_t* msg, size_t len)
{
    bt_tunnel* t = (bt_tunnel*)ctx;
    struct sockaddr_storage ss;
    int fd = t->udp[fam_index(to->family)];
    socklen_t sl;

    if (fd < 0) return;                 /* no network of that family now: the timers retry */
    /* A new address (the peer roamed): its host route first, if the backend works that way. */
    if (!bypass_known(to->family, to->addr)) bypass_sync(0);
    sl = (socklen_t)to_sockaddr(to, &ss);
    sendto(fd, msg, len, 0, (struct sockaddr*)&ss, sl);
}

static void up_deliver(void* ctx, wg_peer* from, uint8_t* p, size_t len)
{
    bt_tunnel* t = (bt_tunnel*)ctx;
    (void)from;
    if (t->tun_fd >= 0) bt_tun_write(t->tun_fd, p, len);
}

/* Tailscale: what goes to a peer goes through the relay its node is reached by. */
static void up_send_peer(void* ctx, wg_peer* p, const wg_endpoint* to, const uint8_t* msg, size_t len)
{
    bt_tunnel* t = (bt_tunnel*)ctx;
    (void)to;
    if (t->ts) bt_ts_send_peer(t->ts, p, msg, len);
}

static void up_wall_clock(void* ctx, uint64_t* sec, uint32_t* nsec)
{
    (void)ctx;
    bt_wall(sec, nsec);
}

/* --------------------------------------------------------------------- the handshake timestamp ceiling */

#define TAI64_EPOCH_OFFSET  0x400000000000000aULL

static uint64_t tai_seconds(const uint8_t ts[WG_TIMESTAMP_LEN])
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v = (v << 8) | ts[i];
    return v >= TAI64_EPOCH_OFFSET ? v - TAI64_EPOCH_OFFSET : 0;
}

/*
 * The daemon's floor (settings.ts_floor): the highest ceiling any profile has had. It outlives a
 * deleted profile, whose key may come back in a new one.
 */
static void floor_raise(uint64_t ceiling)
{
    bt_settings st;

    if (!bt_store_load_settings(S, &st) || st.ts_floor >= ceiling) return;
    st.ts_floor = ceiling;
    if (!bt_store_save_settings(S, &st)) BT_W("cannot save the timestamp floor");
}

/*
 * Every timestamp ever sent stays below meta.ts_ceiling, which is on disk: after a restart the
 * first one sent is above it, whatever the clock says (section 9). The ceiling runs
 * BT_TS_MARGIN_SEC ahead and is raised only when a timestamp gets there.
 */
static void ceiling_check(bt_tunnel* t)
{
    uint64_t top = 0, sec;
    uint32_t nsec;
    const wg_peer* p;

    for (p = first_peer(t); p; p = p->next) {
        uint64_t s = tai_seconds(p->noise.sent_timestamp);
        if (s > top) top = s;
    }
    if (top + 60 < t->meta.ts_ceiling) return;         /* far enough below */
    bt_wall(&sec, &nsec);
    if (sec > top) top = sec;
    t->meta.ts_ceiling = top + BT_TS_MARGIN_SEC;
    if (!bt_store_save(S, &t->meta, NULL, 0)) BT_W("tunnel %s: cannot save the timestamp ceiling", t->id);
    floor_raise(t->meta.ts_ceiling);
}

/*
 * Within one run of the daemon the newest timestamp a profile sent is known exactly, so coming up
 * again starts from it; only after a restart is the ceiling the best there is. (Starting from the
 * ceiling on every up would push it another margin ahead each time.)
 */
static struct {
    char    id[BT_ID_LEN + 1];
    uint8_t ts[WG_TIMESTAMP_LEN];
} sent_seen[16];
/* The newest any profile sent in this run, deleted ones too. */
static uint8_t sent_max[WG_TIMESTAMP_LEN];

static void sent_remember(const bt_tunnel* t)
{
    uint8_t top[WG_TIMESTAMP_LEN];
    size_t i, slot = 0;
    const wg_peer* p;

    memset(top, 0, sizeof(top));
    for (p = first_peer(t); p; p = p->next)
        if (memcmp(p->noise.sent_timestamp, top, WG_TIMESTAMP_LEN) > 0)
            memcpy(top, p->noise.sent_timestamp, WG_TIMESTAMP_LEN);
    if (memcmp(top, sent_max, WG_TIMESTAMP_LEN) > 0) memcpy(sent_max, top, WG_TIMESTAMP_LEN);
    for (i = 0; i < sizeof(sent_seen) / sizeof(sent_seen[0]); i++) {
        if (strcmp(sent_seen[i].id, t->id) == 0) {
            slot = i;
            break;
        }
        if (!sent_seen[i].id[0]) slot = i;
    }
    snprintf(sent_seen[slot].id, sizeof(sent_seen[slot].id), "%s", t->id);
    if (memcmp(top, sent_seen[slot].ts, WG_TIMESTAMP_LEN) > 0) memcpy(sent_seen[slot].ts, top, WG_TIMESTAMP_LEN);
}

/* Where this tunnel's handshake timestamps start; every peer gets it now, a Tailscale peer added
 * later gets it then (ts_start). */
static void ceiling_start(bt_tunnel* t)
{
    static const uint8_t zero[WG_TIMESTAMP_LEN];
    uint8_t from[WG_TIMESTAMP_LEN], floor[WG_TIMESTAMP_LEN];
    bt_settings st;
    size_t i;
    const wg_peer* q;
    wg_peer* p;
    int j;

    memset(from, 0, sizeof(from));
    if (t->meta.ts_ceiling) wg_tai64n(from, t->meta.ts_ceiling, 0);
    for (i = 0; i < sizeof(sent_seen) / sizeof(sent_seen[0]); i++)
        if (strcmp(sent_seen[i].id, t->id) == 0) memcpy(from, sent_seen[i].ts, WG_TIMESTAMP_LEN);
    /* And above anything any other profile sent: a key may be in two profiles - imported twice, or
     * deleted and imported again - and its server remembers the newest timestamp it saw. In this
     * run that is known (the tunnels up and those gone); after a restart the floor is the best
     * there is. */
    memcpy(floor, sent_max, WG_TIMESTAMP_LEN);
    for (j = 0; j < BT_TUNNELS_MAX; j++) {
        const bt_tunnel* o = &T[j];
        if (o == t || !o->used) continue;
        for (q = first_peer(o); q; q = q->next)
            if (memcmp(q->noise.sent_timestamp, floor, WG_TIMESTAMP_LEN) > 0)
                memcpy(floor, q->noise.sent_timestamp, WG_TIMESTAMP_LEN);
    }
    if (memcmp(floor, zero, WG_TIMESTAMP_LEN) == 0 && bt_store_load_settings(S, &st) && st.ts_floor)
        wg_tai64n(floor, st.ts_floor, 0);
    if (memcmp(floor, from, WG_TIMESTAMP_LEN) > 0) memcpy(from, floor, WG_TIMESTAMP_LEN);
    memcpy(t->ts_start, from, WG_TIMESTAMP_LEN);
    if (memcmp(from, zero, WG_TIMESTAMP_LEN) == 0) return;
    for (p = t->dev ? t->dev->peers : NULL; p; p = p->next) memcpy(p->noise.sent_timestamp, from, WG_TIMESTAMP_LEN);
}

/* --------------------------------------------------------------------- sockets out of the tunnels */

/* (Re)opens the family's sockets when the physical interface changed or they are missing. 1 when
 * they are (now) open. `moved` tells whether new ones were made. */
static int egress_ensure(bt_tunnel* t, int family, int* moved)
{
    int k = fam_index(family);
    char dev[BT_IFNAME_MAX];

    if (!bt_default_if(family, dev)) {
        if (t->udp[k] >= 0) BT_I("tunnel %s: no IPv%d network any more", t->id, family);
        close_fd(&t->udp[k]);
        close_fd(&t->dnsfd[k]);
        t->egress[k][0] = '\0';
        return 0;
    }
    if (t->udp[k] >= 0 && t->dnsfd[k] >= 0 && strcmp(dev, t->egress[k]) == 0) return 1;

    close_fd(&t->udp[k]);
    close_fd(&t->dnsfd[k]);
    t->udp[k] = bt_udp_open(family, family == 4 ? t->conf.listen_port : 0);
    if (t->udp[k] < 0 && family == 4 && t->conf.listen_port) t->udp[k] = bt_udp_open(family, 0);
    t->dnsfd[k] = bt_udp_open(family, 0);
    if (t->udp[k] < 0 || t->dnsfd[k] < 0) {
        BT_W("tunnel %s: IPv%d socket via %s: %s", t->id, family, dev, strerror(errno));
        close_fd(&t->udp[k]);
        close_fd(&t->dnsfd[k]);
        t->egress[k][0] = '\0';
        return 0;
    }
    BT_I("tunnel %s: IPv%d out via %s", t->id, family, dev);
    snprintf(t->egress[k], sizeof(t->egress[k]), "%s", dev);
    if (moved) *moved = 1;
    return 1;
}

/* --------------------------------------------------------------------- host routes to the servers */

/*
 * Where the backend keeps our sockets out of the tunnels by host routes (section 5, the third
 * way), it has to know every remote address they send to that a tunnel would catch. The set is
 * worked out again wherever it may change - and before a packet goes to an address not in it.
 */
static bt_addr bypass_seen[BT_BYPASS_MAX];      /* every address our sockets talk to, last time */
static size_t  n_bypass_seen;
static bt_addr bypass_need[BT_BYPASS_MAX];      /* ... of them, the ones a tunnel catches */
static size_t  n_bypass_need;
static bt_addr bypass_in[BT_BYPASS_MAX];        /* the host routes in, as the journal has them */
static size_t  n_bypass_in;

static int addr_listed(const bt_addr* set, size_t n, int family, const uint8_t* addr)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (set[i].family == family && memcmp(set[i].addr, addr, family == 4 ? 4 : 16) == 0) return 1;
    return 0;
}

static void addr_collect(bt_addr* set, size_t* n, int family, const uint8_t* addr)
{
    if (*n == BT_BYPASS_MAX || addr_listed(set, *n, family, addr)) return;
    memset(&set[*n], 0, sizeof(set[*n]));
    set[*n].family = (uint8_t)family;
    memcpy(set[*n].addr, addr, family == 4 ? 4 : 16);
    (*n)++;
}

static int same_addrs(const bt_addr* a, size_t na, const bt_addr* b, size_t nb)
{
    size_t i;
    if (na != nb) return 0;
    for (i = 0; i < na; i++)
        if (!addr_listed(b, nb, a[i].family, a[i].addr)) return 0;
    return 1;
}

static int bypass_known(int family, const uint8_t* addr)
{
    return addr_listed(bypass_seen, n_bypass_seen, family, addr);
}

/* Whether the routes of a tunnel take `addr` in (its AllowedIPs are its routes). */
static int caught(int family, const uint8_t* addr)
{
    int i;
    for (i = 0; i < BT_TUNNELS_MAX; i++) {
        const bt_tunnel* t = &T[i];
        if (t->used && t->engine && t->routes_in && wg_allowedips_lookup(&t->dev->allowedips, family, addr))
            return 1;
    }
    return 0;
}

static void bypass_sync(int recheck)
{
    bt_addr all[BT_BYPASS_MAX], need[BT_BYPASS_MAX], in[BT_BYPASS_MAX];
    size_t n_all = 0, n_need = 0, n_in, i, k;
    int j;

    for (j = 0; j < BT_TUNNELS_MAX; j++) {
        const bt_tunnel* t = &T[j];
        if (!t->used || !t->engine) continue;
        for (i = 0; i < t->n_peers; i++) {
            const wg_endpoint* e = &t->peers[i].endpoint;
            const bt_lookup* l = &t->lookups[i];
            if (e->family) addr_collect(all, &n_all, e->family, e->addr);
            if (l->state == BT_LOOKUP_RUNNING)
                for (k = 0; k < l->n_servers; k++) addr_collect(all, &n_all, l->servers[k].family, l->servers[k].addr);
        }
    }
    for (i = 0; i < n_all; i++)
        if (caught(all[i].family, all[i].addr)) need[n_need++] = all[i];
    memcpy(bypass_seen, all, sizeof(all[0]) * n_all);
    n_bypass_seen = n_all;
    if (!recheck && same_addrs(need, n_need, bypass_need, n_bypass_need)) return;

    memcpy(bypass_need, need, sizeof(need[0]) * n_need);
    n_bypass_need = n_need;
    if (!bt_bypass_set(need, n_need, recheck)) BT_W("host routes: %s", strerror(errno));
    n_in = bt_bypass_list(in, BT_BYPASS_MAX);
    if (!same_addrs(in, n_in, bypass_in, n_bypass_in)) {
        memcpy(bypass_in, in, sizeof(in[0]) * n_in);
        n_bypass_in = n_in;
        if (H.applied) H.applied();
    }
}

/* --------------------------------------------------------------------- endpoint names */

static void lookup_send(void* ctx, const bt_addr* server, const uint8_t* q, size_t len)
{
    bt_tunnel* t = (bt_tunnel*)ctx;
    wg_endpoint e;
    struct sockaddr_storage ss;
    int fd = t->dnsfd[fam_index(server->family)];

    if (fd < 0) return;
    if (!bypass_known(server->family, server->addr)) bypass_sync(0);
    memset(&e, 0, sizeof(e));
    e.family = server->family;
    memcpy(e.addr, server->addr, 16);
    e.port = BT_DNS_PORT;
    sendto(fd, q, len, 0, (struct sockaddr*)&ss, (socklen_t)to_sockaddr(&e, &ss));
}

/* The last address a name had (meta), so a restart does not wait for DNS. */
static int cached_endpoint(const bt_tunnel* t, const char* host, wg_endpoint* e)
{
    size_t i;
    for (i = 0; i < t->meta.n_resolved; i++) {
        int family;
        if (strcmp(t->meta.resolved[i].host, host) != 0) continue;
        if (wg_addr_parse(t->meta.resolved[i].addr, strlen(t->meta.resolved[i].addr), &family, e->addr)) {
            e->family = (uint8_t)family;
            return 1;
        }
    }
    return 0;
}

static void remember_resolved(bt_tunnel* t, const char* host, const bt_addr* a)
{
    char text[BT_ADDR_TEXT_MAX];
    size_t i, j;

    addr_text(a->family, a->addr, text, sizeof(text));
    for (i = 0; i < t->meta.n_resolved; i++) {
        if (strcmp(t->meta.resolved[i].host, host) == 0) {
            if (strcmp(t->meta.resolved[i].addr, text) == 0) return;
            break;
        }
    }
    if (i == t->meta.n_resolved) {
        if (i == BT_META_RESOLVED) {                /* full: drop the oldest */
            for (j = 1; j < BT_META_RESOLVED; j++) t->meta.resolved[j - 1] = t->meta.resolved[j];
            i = BT_META_RESOLVED - 1;
        } else {
            t->meta.n_resolved++;
        }
    }
    snprintf(t->meta.resolved[i].host, sizeof(t->meta.resolved[i].host), "%.*s", BT_HOST_MAX, host);
    snprintf(t->meta.resolved[i].addr, sizeof(t->meta.resolved[i].addr), "%s", text);
    bt_store_save(S, &t->meta, NULL, 0);
}

static void lookups_start(bt_tunnel* t, uint64_t now)
{
    bt_addr servers[BT_LOOKUP_SERVERS];
    size_t n = bt_dns_system(servers, BT_LOOKUP_SERVERS), i;

    for (i = 0; i < t->n_peers; i++) {
        const wg_conf_peer* cp = &t->cpeers[i];
        if (!cp->endpoint_host[0] || cp->endpoint.family) continue;     /* none, or a literal */
        if (!bt_lookup_start(&t->lookups[i], cp->endpoint_host, servers, n, 1, 1, NULL, now))
            BT_W("tunnel %s: cannot look up %s: %s", t->id, cp->endpoint_host,
                 bt_lookup_error_text(t->lookups[i].error));
    }
    bypass_sync(0);                     /* the resolvers, while the lookups run */
}

static void lookup_done(bt_tunnel* t, size_t i, uint64_t now)
{
    bt_lookup* l = &t->lookups[i];
    const wg_conf_peer* cp = &t->cpeers[i];
    size_t k;

    if (l->state == BT_LOOKUP_FAILED) {
        wg_endpoint e;
        BT_W("tunnel %s: %s: %s", t->id, cp->endpoint_host, bt_lookup_error_text(l->error));
        if (!t->peers[i].endpoint.family && !cached_endpoint(t, cp->endpoint_host, &e) &&
            t->state != BT_TS_UP) {
            char d[160];
            snprintf(d, sizeof(d), "%.100s: %s", cp->endpoint_host, bt_lookup_error_text(l->error));
            set_state(t, t->state, "resolve", d);
        }
        l->state = BT_LOOKUP_IDLE;
        return;
    }
    /* The first address of a family we can reach (IPv4 first, as the lookup orders them). */
    for (k = 0; k < l->n; k++) {
        if (t->udp[fam_index(l->addrs[k].family)] >= 0) break;
    }
    if (k == l->n) {
        BT_W("tunnel %s: %s has no address we can reach now", t->id, cp->endpoint_host);
        l->state = BT_LOOKUP_IDLE;
        return;
    }
    {
        wg_endpoint e;
        char text[BT_ADDR_TEXT_MAX];
        memset(&e, 0, sizeof(e));
        e.family = l->addrs[k].family;
        memcpy(e.addr, l->addrs[k].addr, 16);
        e.port = cp->endpoint_port;
        addr_text(e.family, e.addr, text, sizeof(text));
        if (!wg_endpoint_equal(&e, &t->peers[i].endpoint)) {
            BT_I("tunnel %s: %s is %s", t->id, cp->endpoint_host, text);
            wg_peer_set_endpoint(&t->peers[i], &e);
            bypass_sync(0);             /* the new address's host route before the handshake */
            wg_peer_initiate(&t->peers[i], now);
        }
        remember_resolved(t, cp->endpoint_host, &l->addrs[k]);
        if (strcmp(t->reason, "resolve") == 0) set_state(t, t->state, "", NULL);
    }
    l->state = BT_LOOKUP_IDLE;
    bypass_sync(0);                     /* the resolvers are done with */
}

/* --------------------------------------------------------------------- routes and DNS */

/* The routes into a tunnel: a WireGuard profile's AllowedIPs, or the tailnet's ranges and the
 * subnet routes bt_tailscale asked for. */
static size_t route_list(const bt_tunnel* t, const wg_prefix** out)
{
    if (t->ts_routes) {
        *out = t->ts_routes;
        return t->n_ts_routes;
    }
    *out = t->callowed;
    return t->conf.n_allowed;
}

static int route_one(const bt_tunnel* t, int add, const wg_prefix* p)
{
    static const uint8_t zero[16] = { 0 };
    static const uint8_t half4[16] = { 0x80 };
    static const uint8_t half6[16] = { 0x80 };

    if (p->cidr == 0) {
        int ok = bt_route(add, t->ifname, p->family, zero, 1);
        return bt_route(add, t->ifname, p->family, p->family == 4 ? half4 : half6, 1) && ok;
    } else {
        uint8_t net[16];
        int bits = p->cidr, b;
        memcpy(net, p->addr, 16);
        for (b = bits; b < (p->family == 4 ? 32 : 128); b++) net[b / 8] &= (uint8_t)~(0x80 >> (b % 8));
        return bt_route(add, t->ifname, p->family, net, p->cidr);
    }
}

static void routes_apply(bt_tunnel* t, int add)
{
    const wg_prefix* list;
    size_t n = route_list(t, &list), i;

    for (i = 0; i < n; i++) {
        if (!route_one(t, add, &list[i]) && add) {
            char at[BT_ADDR_TEXT_MAX];
            addr_text(list[i].family, list[i].addr, at, sizeof(at));
            BT_W("tunnel %s: route %s/%d did not go in: %s", t->id, at, list[i].cidr, strerror(errno));
        }
    }
    t->routes_in = add;
    bypass_sync(0);                     /* what the tunnels catch has changed */
    if (H.applied) H.applied();
}

/* Ours into the system. Refused with the search domains - the servers alone: they are what the
 * phone needs, and MagicDNS answers a short name without a search list too. */
static int dns_apply_servers(const char* who, const bt_addr* servers, size_t n, const char* search)
{
    if (bt_dns_apply(servers, n, search)) return 1;
    if (!search[0]) return 0;
    BT_W("DNS: %s's search domains refused (%s): %s - the servers without them", who, search, strerror(errno));
    return bt_dns_apply(servers, n, "");
}

/* The resolvers the phone would use without MagicDNS: those of the tunnel that owns DNS (`owner`),
 * else the network's. */
static size_t dns_base(int owner, bt_addr* out, size_t cap)
{
    size_t n = 0, k;

    if (owner >= 0 && T[owner].used) {
        const bt_tunnel* o = &T[owner];
        for (k = 0; k < o->conf.n_dns && n < cap; k++) {
            memset(&out[n], 0, sizeof(out[n]));
            out[n].family = o->conf.dns[k].family;
            memcpy(out[n].addr, o->conf.dns[k].addr, 16);
            n++;
        }
        if (n) return n;
    }
    return bt_dns_system(out, cap);
}

/* Whole words of `list` (space- or comma-separated) onto the search list `out`, while they fit
 * what the phone's resolver reads: DNS_SEARCH_WORDS names, DNS_SEARCH_CHARS in all. A word cut in
 * half there would be a domain nobody has. */
#define DNS_SEARCH_WORDS    6
#define DNS_SEARCH_CHARS    255
#define DNS_MAGIC_SERVERS   3           /* the resolver asks the first three */

static void search_join(char* out, size_t* used, int* words, const char* list)
{
    const char* p = list;

    while (*p) {
        size_t len = 0;
        while (*p == ' ' || *p == ',') p++;
        while (p[len] && p[len] != ' ' && p[len] != ',') len++;
        if (!len) break;
        if (*words < DNS_SEARCH_WORDS && *used + (*used ? 1 : 0) + len <= DNS_SEARCH_CHARS) {
            if (*used) out[(*used)++] = ' ';
            memcpy(out + *used, p, len);
            *used += len;
            out[*used] = '\0';
            (*words)++;
        }
        p += len;
    }
}

/*
 * MagicDNS of tunnel `magic` in front (TAILSCALE.md section 8a): its resolver 100.100.100.100
 * first, then what the phone would use without it - so that names still resolve if the daemon goes
 * away - and its domains before those of the tunnel that owns DNS (`owner`, may be -1).
 */
static int dns_apply_magic(int magic, int owner)
{
    static const uint8_t resolver[16] = { 100, 100, 100, 100 };
    bt_addr servers[DNS_MAGIC_SERVERS], base[BT_LOOKUP_SERVERS];
    char ours[512], search[DNS_SEARCH_CHARS + 1];
    size_t n = 0, nb = dns_base(owner, base, BT_LOOKUP_SERVERS), used = 0, k;
    int words = 0;

    memset(&servers[0], 0, sizeof(servers[0]));
    servers[0].family = 4;
    memcpy(servers[0].addr, resolver, 4);
    n = 1;
    for (k = 0; k < nb && n < DNS_MAGIC_SERVERS; k++) {
        if (base[k].family == 4 && memcmp(base[k].addr, resolver, 4) == 0) continue;
        servers[n++] = base[k];
    }
    search[0] = '\0';
    if (!bt_ts_magic_dns(T[magic].ts, ours, sizeof(ours))) ours[0] = '\0';
    search_join(search, &used, &words, ours);
    if (owner >= 0) search_join(search, &used, &words, T[owner].conf.dns_search);
    return dns_apply_servers(T[magic].id, servers, n, search);
}

/* Who owns DNS: the tunnel with a default route, else the one up last; only a tunnel whose .conf
 * has DNS= and which is not in error. A Tailscale tunnel with MagicDNS on (the one up last) puts its
 * resolver in front of that (dns_apply_magic). Applies the change. */
static void dns_reconcile(void)
{
    int best = -1, magic = -1, i;

    for (i = 0; i < BT_TUNNELS_MAX; i++) {
        bt_tunnel* t = &T[i];
        if (!t->used || t->state == BT_TS_ERROR) continue;
        if (t->ts && bt_ts_magic_dns(t->ts, NULL, 0) && (magic < 0 || t->up_seq > T[magic].up_seq)) magic = i;
        if (!t->conf.n_dns) continue;
        if (best < 0) best = i;
        else {
            int tf = t->full[0] || t->full[1], bf = T[best].full[0] || T[best].full[1];
            if (tf > bf || (tf == bf && t->up_seq > T[best].up_seq)) best = i;
        }
    }
    if (magic >= 0) {
        if (!dns_apply_magic(magic, best)) BT_W("DNS: cannot apply %s's MagicDNS: %s", T[magic].id, strerror(errno));
        else if (dns_magic != magic || dns_owner != best) {
            if (best >= 0) BT_I("DNS: %s's MagicDNS, then %s's servers", T[magic].id, T[best].id);
            else BT_I("DNS: %s's MagicDNS, then the network's servers", T[magic].id);
        }
    } else if (best >= 0) {
        bt_tunnel* t = &T[best];
        bt_addr servers[WG_CONF_MAX_DNS];
        char search[WG_CONF_TEXT_MAX];
        size_t k, j;

        for (k = 0; k < t->conf.n_dns; k++) {
            servers[k].family = t->conf.dns[k].family;
            memcpy(servers[k].addr, t->conf.dns[k].addr, 16);
        }
        /* dns_search is comma-separated; resolv.conf wants spaces */
        snprintf(search, sizeof(search), "%s", t->conf.dns_search);
        for (j = 0; search[j]; j++)
            if (search[j] == ',') search[j] = ' ';
        if (!dns_apply_servers(t->id, servers, t->conf.n_dns, search)) BT_W("DNS: cannot apply %s's: %s", t->id, strerror(errno));
        else if (dns_owner != best || dns_magic >= 0) BT_I("DNS: %s's servers", t->id);
    } else if (dns_owner >= 0 || dns_magic >= 0) {
        if (!bt_dns_restore()) BT_W("DNS: cannot restore the system's: %s", strerror(errno));
        else BT_I("DNS: the system's again");
    }
    dns_owner = best;
    dns_magic = magic;
    if (H.applied) H.applied();
}

/* --------------------------------------------------------------------- up and down */

static void release(bt_tunnel* t)
{
    size_t i;

    if (t->dev && t->engine) sent_remember(t);
    if (t->ts) {
        bt_ts_stop(t->ts);              /* its peers leave the device, its connections close */
        t->ts = NULL;
    }
    if (t->dev) {
        if (t->engine) {
            wg_device_down(t->dev);
            for (i = 0; i < t->n_peers; i++) wg_device_remove_peer(t->dev, &t->peers[i]);
        }
        wg_wipe(t->dev, sizeof(*t->dev));                   /* a failed apply: just thrown away */
    }
    if (t->peers) wg_wipe(t->peers, sizeof(*t->peers) * (t->n_peers ? t->n_peers : 1));
    t->engine = 0;
    if (t->routes_in && t->ifname[0]) routes_apply(t, 0);
    if (t->tun_fd >= 0) bt_tun_close(t->tun_fd, t->ifname);
    t->tun_fd = -1;
    close_fd(&t->udp[0]);
    close_fd(&t->udp[1]);
    close_fd(&t->dnsfd[0]);
    close_fd(&t->dnsfd[1]);
    if (t->awg) wg_wipe(t->awg, sizeof(*t->awg));
    if (t->text) wg_wipe(t->text, t->text_len + 1);
    if (t->cpeers) wg_wipe(t->cpeers, sizeof(*t->cpeers) * t->conf.cap_peers);
    wg_wipe(&t->conf, sizeof(t->conf));
    free(t->dev);
    free(t->awg);
    free(t->peers);
    free(t->stage);
    free(t->nodes);
    free(t->lookups);
    free(t->text);
    free(t->cpeers);
    free(t->callowed);
    free(t->ts_routes);
    t->ts_routes = NULL;
    t->n_ts_routes = 0;
    t->n_ts_addr = 0;
    t->dev = NULL;
    t->awg = NULL;
    t->peers = NULL;
    t->stage = NULL;
    t->nodes = NULL;
    t->lookups = NULL;
    t->text = NULL;
    t->cpeers = NULL;
    t->callowed = NULL;
    t->n_peers = 0;
    t->ifname[0] = '\0';
    t->full[0] = t->full[1] = 0;
    t->egress[0][0] = t->egress[1][0] = '\0';
    bypass_sync(0);                     /* its servers' host routes go */
}

/* Counts that bound what the parser can find: [Peer] headers and list items. */
static void count_caps(const char* text, size_t len, size_t* peers, size_t* items)
{
    size_t i;
    *peers = 1;
    *items = 1;
    for (i = 0; i < len; i++) {
        if (text[i] == ',' || text[i] == '\n') (*items)++;
        if (text[i] == '[') (*peers)++;
    }
}

static void fail(bt_tunnel* t, const char* reason, const char* detail)
{
    release(t);
    set_state(t, BT_TS_ERROR, reason, detail);
    dns_reconcile();
}

void bt_tunnels_init(bt_store* store, const bt_tunnel_hooks* hooks)
{
    int i;
    S = store;
    if (hooks) H = *hooks;
    for (i = 0; i < BT_TUNNELS_MAX; i++) {
        memset(&T[i], 0, sizeof(T[i]));
        T[i].tun_fd = T[i].udp[0] = T[i].udp[1] = T[i].dnsfd[0] = T[i].dnsfd[1] = -1;
    }
    status_icon_update();               /* off: a daemon that died may have left the key lit */
}

bt_tunnel* bt_tunnel_find(const char* id)
{
    int i;
    for (i = 0; i < BT_TUNNELS_MAX; i++)
        if (T[i].used && strcmp(T[i].id, id) == 0) return &T[i];
    return NULL;
}

bt_tunnel* bt_tunnel_at(int i)
{
    return i >= 0 && i < BT_TUNNELS_MAX && T[i].used ? &T[i] : NULL;
}

struct bt_ts* bt_tunnel_ts(const bt_tunnel* t)
{
    return t->ts;
}

const char* bt_tunnel_id(const bt_tunnel* t)
{
    return t->id;
}

bt_tstate bt_tunnel_state(const bt_tunnel* t)
{
    return t->state;
}

/* --------------------------------------------------------------------- Tailscale */

static int prefix_same(const wg_prefix* a, const wg_prefix* b)
{
    return a->family == b->family && a->cidr == b->cidr && memcmp(a->addr, b->addr, a->family == 4 ? 4 : 16) == 0;
}

static int prefix_listed(const wg_prefix* list, size_t n, const wg_prefix* p)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (prefix_same(&list[i], p)) return 1;
    return 0;
}

/* The node's addresses on the tun: whatever the netmap gives goes on; one it no longer gives comes
 * off when another of its family has taken its place (ts_hook_addresses). */
static int ts_has_family(const bt_tunnel* t, int family)
{
    size_t i;
    for (i = 0; i < t->n_ts_addr; i++)
        if (t->ts_addr[i].family == family) return 1;
    return 0;
}

/* The tailnet's routes of a family again, now that the tun has an address of it. On the BSDs a route
 * keeps the interface address it found when it went in: one put in before the tun had an IPv4
 * address leaves TCP no source address - connect() fails with "network unreachable" and sends
 * nothing (the phone's browser, 2026-10-16; ping still went). Out and in again, it takes the new
 * address. Before the first address of the family, when nothing can have been sent yet; and when an
 * address the routes may hold came off (ts_addresses_prune) - for that moment a packet to the tailnet
 * may go past the tunnel, once in a node's life. */
static void ts_routes_rebind(bt_tunnel* t, int family)
{
    size_t i;
    for (i = 0; i < t->n_ts_routes; i++) {
        if (t->ts_routes[i].family != family) continue;
        route_one(t, 0, &t->ts_routes[i]);
        if (!route_one(t, 1, &t->ts_routes[i])) BT_W("tunnel %s: a route did not go in again: %s", t->id, strerror(errno));
    }
}

/* 1 when `list` has an address of `family`. */
static int listed_family(const wg_prefix* list, size_t n, int family)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (list[i].family == family) return 1;
    return 0;
}

/*
 * An address on the tun that the node no longer has - an admin gave the node another, or a login
 * made it a new node - comes off, once one of the same family from `a` is there to take its place:
 * left on, the tailnet's routes could keep it as their source, and every node drops what comes from
 * an address that is not ours (the phone after a new login, 2026-10-22). The routes of that family
 * then go out and in again, to take the address that stays. A list without any address of a family
 * takes nothing of that family off: a tun without an address helps no one.
 */
static void ts_addresses_prune(bt_tunnel* t, const wg_prefix* a, size_t n)
{
    size_t i = 0;
    int gone4 = 0, gone6 = 0;

    while (i < t->n_ts_addr) {
        const wg_prefix* p = &t->ts_addr[i];
        char at[BT_ADDR_TEXT_MAX];
        if (prefix_listed(a, n, p) || !listed_family(a, n, p->family)) {
            i++;
            continue;
        }
        addr_text(p->family, p->addr, at, sizeof(at));
        if (!bt_if_addr_del(t->ifname, p->family, p->addr, p->cidr)) {
            BT_W("tunnel %s: address %s/%d is no longer the node's, but stays: %s", t->id, at, p->cidr, strerror(errno));
            i++;
            continue;
        }
        BT_I("tunnel %s: address %s/%d is no longer the node's - off the tun", t->id, at, p->cidr);
        if (p->family == 4) gone4 = 1;
        else gone6 = 1;
        memmove(&t->ts_addr[i], &t->ts_addr[i + 1], (t->n_ts_addr - i - 1) * sizeof(t->ts_addr[0]));
        t->n_ts_addr--;
    }
    if (t->routes_in && gone4 && ts_has_family(t, 4)) ts_routes_rebind(t, 4);
    if (t->routes_in && gone6 && ts_has_family(t, 6)) ts_routes_rebind(t, 6);
}

static void ts_hook_addresses(void* ctx, const wg_prefix* a, size_t n)
{
    bt_tunnel* t = (bt_tunnel*)ctx;
    size_t i;
    int had4 = ts_has_family(t, 4), had6 = ts_has_family(t, 6);

    for (i = 0; i < n; i++) {
        char at[BT_ADDR_TEXT_MAX];
        if (prefix_listed(t->ts_addr, t->n_ts_addr, &a[i])) continue;
        addr_text(a[i].family, a[i].addr, at, sizeof(at));
        if (t->n_ts_addr == sizeof(t->ts_addr) / sizeof(t->ts_addr[0])) {
            BT_W("tunnel %s: no room for address %s", t->id, at);
            continue;
        }
        if (!bt_if_addr(t->ifname, a[i].family, a[i].addr, a[i].cidr)) {
            BT_W("tunnel %s: address %s/%d: %s", t->id, at, a[i].cidr, strerror(errno));
            continue;
        }
        BT_I("tunnel %s: address %s/%d", t->id, at, a[i].cidr);
        t->ts_addr[t->n_ts_addr++] = a[i];
    }
    if (t->routes_in && !had4 && ts_has_family(t, 4)) ts_routes_rebind(t, 4);
    if (t->routes_in && !had6 && ts_has_family(t, 6)) ts_routes_rebind(t, 6);
    ts_addresses_prune(t, a, n);
}

/* The tailnet's own ranges stay first; the subnet routes after them change as the netmap does.
 * Only the difference goes to the system: a route taken out and put back would let packets out
 * past the tunnel for that moment. */
static void ts_hook_routes(void* ctx, const wg_prefix* r, size_t n)
{
    bt_tunnel* t = (bt_tunnel*)ctx;
    wg_prefix* list;
    size_t i, keep = 2, total;

    if (!t->ts_routes || t->n_ts_routes < keep) return;
    total = keep;
    for (i = 0; i < n; i++)
        if (!prefix_listed(t->ts_routes, keep, &r[i])) total++;
    list = (wg_prefix*)calloc(total, sizeof(*list));
    if (!list) return;
    memcpy(list, t->ts_routes, keep * sizeof(*list));
    total = keep;
    for (i = 0; i < n; i++)
        if (!prefix_listed(list, total, &r[i])) list[total++] = r[i];
    if (t->routes_in) {
        for (i = keep; i < t->n_ts_routes; i++)
            if (!prefix_listed(list, total, &t->ts_routes[i])) route_one(t, 0, &t->ts_routes[i]);
        for (i = keep; i < total; i++)
            if (!prefix_listed(t->ts_routes, t->n_ts_routes, &list[i]) && !route_one(t, 1, &list[i]))
                BT_W("tunnel %s: a subnet route did not go in: %s", t->id, strerror(errno));
    }
    if (total != t->n_ts_routes) BT_I("tunnel %s: %u subnet route(s)", t->id, (unsigned)(total - keep));
    free(t->ts_routes);
    t->ts_routes = list;
    t->n_ts_routes = total;
    bypass_sync(0);
    if (H.applied) H.applied();
}

static void evaluate(bt_tunnel* t, uint64_t now);

/* The resolvers the phone uses now - never MagicDNS's own: those of the tunnel that owns DNS, else
 * the network's. */
static size_t ts_hook_resolvers(void* ctx, bt_addr* out, size_t cap)
{
    (void)ctx;
    return dns_base(dns_owner, out, cap);
}

static void ts_hook_peer_added(void* ctx, wg_peer* p)
{
    static const uint8_t zero[WG_TIMESTAMP_LEN];
    bt_tunnel* t = (bt_tunnel*)ctx;
    if (memcmp(t->ts_start, zero, WG_TIMESTAMP_LEN) != 0) memcpy(p->noise.sent_timestamp, t->ts_start, WG_TIMESTAMP_LEN);
}

/* MagicDNS's answers go back to the phone through the tun, as a peer's packets do. */
static void ts_hook_to_tun(void* ctx, const uint8_t* p, size_t len)
{
    bt_tunnel* t = (bt_tunnel*)ctx;
    if (t->tun_fd >= 0) bt_tun_write(t->tun_fd, p, len);
}

static void ts_hook_dns_changed(void* ctx)
{
    (void)ctx;
    dns_reconcile();
}

/* A new login link (or none any more): the clients hear of it now, as of any change of the tunnel - the
 * reason stays "browser" while one link follows another. */
static void ts_hook_login_link(void* ctx)
{
    bt_tunnel* t = (bt_tunnel*)ctx;
    if (H.changed) H.changed(t);
}

/*
 * A Tailscale profile up: a device with no peers yet - bt_tailscale brings them from the netmap as
 * traffic needs them - the tun with Tailscale's MTU, and the tailnet's two ranges routed into it
 * from the start (TAILSCALE.md, section 8). The addresses come from bt_tailscale: the last netmap's
 * at once, control's when it answers.
 */
static int ts_up(bt_tunnel* t, uint64_t now)
{
    static const uint8_t cgnat[16] = { 100, 64 };
    static const uint8_t ula[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0 };
    bt_ts_hooks h;
    char e[160];

    t->dev = (wg_device*)calloc(1, sizeof(*t->dev));
    t->ts_routes = (wg_prefix*)calloc(2, sizeof(*t->ts_routes));
    if (!t->dev || !t->ts_routes) {
        fail(t, "conf", "out of memory");
        return 0;
    }
    wg_device_init(t->dev);
    t->dev->ctx = t;
    /* No `send`: it would get only cookie replies, to a label - the engine works without it. */
    t->dev->send_peer = up_send_peer;
    t->dev->deliver = up_deliver;
    t->dev->wall_clock = up_wall_clock;
    t->mtu = BT_TS_MTU;
    t->dev->mtu = BT_TS_MTU;
    if (!bt_default_if(4, t->egress[0])) t->egress[0][0] = '\0';   /* the way out, to see it move */
    if (!bt_default_if(6, t->egress[1])) t->egress[1][0] = '\0';
    t->ts_routes[0].family = 4;
    memcpy(t->ts_routes[0].addr, cgnat, 16);
    t->ts_routes[0].cidr = 10;
    t->ts_routes[1].family = 6;
    memcpy(t->ts_routes[1].addr, ula, 16);
    t->ts_routes[1].cidr = 48;
    t->n_ts_routes = 2;
    ceiling_start(t);

    t->tun_fd = bt_tun_open(t->ifname);
    if (t->tun_fd < 0) {
        snprintf(e, sizeof(e), "%s", strerror(errno));
        fail(t, "tun", e);
        return 0;
    }
    if (!bt_if_mtu(t->ifname, t->mtu) || !bt_if_up(t->ifname)) {
        snprintf(e, sizeof(e), "%s up: %s", t->ifname, strerror(errno));
        fail(t, "tun", e);
        return 0;
    }

    memset(&h, 0, sizeof(h));
    h.ctx = t;
    h.addresses = ts_hook_addresses;
    h.routes = ts_hook_routes;
    h.resolvers = ts_hook_resolvers;
    h.peer_added = ts_hook_peer_added;
    h.to_tun = ts_hook_to_tun;
    h.dns_changed = ts_hook_dns_changed;
    h.login_link = ts_hook_login_link;
    t->engine = 1;
    t->ts = bt_ts_start(t->id, S, t->dev, &h, now, e, sizeof(e));
    if (!t->ts) {
        fail(t, "conf", e);
        return 0;
    }
    /* After the start: the last netmap's addresses are on the tun by now, and the routes take them
     * (ts_routes_rebind). A first login gets its addresses later, and its routes are put in again
     * then. */
    routes_apply(t, 1);
    BT_I("tunnel %s: %s, mtu %d, Tailscale", t->id, t->ifname, t->mtu);
    set_state(t, BT_TS_CONNECTING, "", NULL);
    evaluate(t, now);
    dns_reconcile();
    return t->state != BT_TS_ERROR;
}

/* Tailscale's transport follows the routes (section 9): a full tunnel coming or going moves it, as
 * a network change does. */
static void ts_transport_moved(const bt_tunnel* except, uint64_t now)
{
    int i;
    for (i = 0; i < BT_TUNNELS_MAX; i++)
        if (&T[i] != except && T[i].used && T[i].ts) bt_ts_net_changed(T[i].ts, now);
}

int bt_tunnel_up(const char* id, char* err, size_t errlen)
{
    bt_tunnel* t = bt_tunnel_find(id);
    char e[160];
    size_t cap_peers, cap_items, i;
    uint64_t now = bt_now_ns();
    int k, moved = 0;

    if (t && t->state != BT_TS_ERROR) return 1;         /* already up or on its way */
    if (!t) {
        for (k = 0; k < BT_TUNNELS_MAX && T[k].used; k++) {}
        if (k == BT_TUNNELS_MAX) {
            snprintf(err, errlen, "%d tunnels are up already", BT_TUNNELS_MAX);
            return 0;
        }
        t = &T[k];
        memset(t, 0, sizeof(*t));
        t->tun_fd = t->udp[0] = t->udp[1] = t->dnsfd[0] = t->dnsfd[1] = -1;
    } else {
        release(t);
    }
    if (!bt_store_load_meta(S, id, &t->meta)) {
        snprintf(err, errlen, "no such profile");
        return 0;
    }
    t->used = 1;
    snprintf(t->id, sizeof(t->id), "%s", id);
    t->state = BT_TS_DOWN;
    t->reason[0] = t->detail[0] = '\0';
    t->up_seq = ++up_counter;
    if (strcmp(t->meta.type, BT_TYPE_TAILSCALE) == 0) return ts_up(t, now);

    /* The configuration. */
    t->text = bt_store_load_conf(S, id, &t->text_len);
    if (!t->text) {
        fail(t, "conf", "the profile's .conf cannot be read");
        return 0;
    }
    count_caps(t->text, t->text_len, &cap_peers, &cap_items);
    t->cpeers = (wg_conf_peer*)calloc(cap_peers, sizeof(*t->cpeers));
    t->callowed = (wg_prefix*)calloc(cap_items, sizeof(*t->callowed));
    if (!t->cpeers || !t->callowed) {
        fail(t, "conf", "out of memory");
        return 0;
    }
    wg_conf_init(&t->conf, t->cpeers, cap_peers, t->callowed, cap_items);
    if (!wg_conf_parse(&t->conf, t->text, t->text_len)) {
        snprintf(e, sizeof(e), "line %d: %s", t->conf.error_line, t->conf.error);
        fail(t, "conf", e);
        return 0;
    }
    for (i = 0; i < t->conf.n_allowed; i++)
        if (t->callowed[i].cidr == 0) t->full[fam_index(t->callowed[i].family)] = 1;
    for (k = 0; k < BT_TUNNELS_MAX; k++) {
        bt_tunnel* o = &T[k];
        if (o == t || !o->used || o->state == BT_TS_ERROR) continue;
        if ((t->full[0] && o->full[0]) || (t->full[1] && o->full[1])) {
            snprintf(e, sizeof(e), "profile %s already holds the default route", o->id);
            t->full[0] = t->full[1] = 0;
            fail(t, "conflict", e);
            return 0;
        }
    }

    /* The engine. */
    t->n_peers = t->conf.n_peers;
    t->dev = (wg_device*)calloc(1, sizeof(*t->dev));
    t->awg = (wg_awg*)calloc(1, sizeof(*t->awg));
    t->peers = (wg_peer*)calloc(t->n_peers ? t->n_peers : 1, sizeof(*t->peers));
    t->stage = (uint8_t*)malloc((t->n_peers ? t->n_peers : 1) * STAGE_PER_PEER);
    t->nodes = (wg_allowedips_node*)calloc(2 * t->conf.n_allowed + 2, sizeof(*t->nodes));
    t->lookups = (bt_lookup*)calloc(t->n_peers ? t->n_peers : 1, sizeof(*t->lookups));
    if (!t->dev || !t->awg || !t->peers || !t->stage || !t->nodes || !t->lookups) {
        fail(t, "conf", "out of memory");
        return 0;
    }
    wg_device_init(t->dev);
    t->dev->ctx = t;
    t->dev->send = up_send;
    t->dev->deliver = up_deliver;
    t->dev->wall_clock = up_wall_clock;
    wg_device_set_allowedips_storage(t->dev, t->nodes, 2 * t->conf.n_allowed + 2);
    if (!wg_conf_apply(&t->conf, t->dev, t->awg, t->peers, t->stage, STAGE_PER_PEER, now, e, sizeof(e))) {
        fail(t, "conf", e);
        return 0;
    }
    t->engine = 1;
    t->mtu = t->conf.mtu ? t->conf.mtu : DEFAULT_MTU - (t->conf.awg ? t->conf.s[4] : 0);
    t->dev->mtu = (size_t)t->mtu;
    ceiling_start(t);

    /* The tun device. */
    t->tun_fd = bt_tun_open(t->ifname);
    if (t->tun_fd < 0) {
        snprintf(e, sizeof(e), "%s", strerror(errno));
        fail(t, "tun", e);
        return 0;
    }
    for (i = 0; i < t->conf.n_address; i++) {
        const wg_prefix* a = &t->conf.address[i];
        if (!bt_if_addr(t->ifname, a->family, a->addr, a->cidr)) {
            char at[BT_ADDR_TEXT_MAX];
            addr_text(a->family, a->addr, at, sizeof(at));
            snprintf(e, sizeof(e), "address %s/%d: %s", at, a->cidr, strerror(errno));
            fail(t, "tun", e);
            return 0;
        }
    }
    if (!bt_if_mtu(t->ifname, t->mtu) || !bt_if_up(t->ifname)) {
        snprintf(e, sizeof(e), "%s up: %s", t->ifname, strerror(errno));
        fail(t, "tun", e);
        return 0;
    }
    BT_I("tunnel %s: %s, mtu %d, %u peer(s), %u prefix(es)%s", t->id, t->ifname, t->mtu, (unsigned)t->n_peers,
         (unsigned)t->conf.n_allowed, t->conf.awg ? ", AmneziaWG" : "");

    /* Out of the tunnels, then the routes into it. */
    egress_ensure(t, 4, &moved);
    egress_ensure(t, 6, &moved);
    routes_apply(t, 1);
    if (t->full[0] || t->full[1]) ts_transport_moved(t, now);

    /* The peers' addresses: literal ones are set; names from the cache now, from DNS soon. */
    for (i = 0; i < t->n_peers; i++) {
        const wg_conf_peer* cp = &t->cpeers[i];
        wg_endpoint ce;
        memset(&ce, 0, sizeof(ce));
        if (cp->endpoint_host[0] && !cp->endpoint.family && cached_endpoint(t, cp->endpoint_host, &ce)) {
            ce.port = cp->endpoint_port;
            wg_peer_set_endpoint(&t->peers[i], &ce);
        }
    }
    lookups_start(t, now);
    bypass_sync(0);                     /* the cached addresses' host routes before the handshakes */

    wg_device_up(t->dev, now);
    for (i = 0; i < t->n_peers; i++)
        if (t->peers[i].endpoint.family) wg_peer_initiate(&t->peers[i], now);
    t->next_nudge_ns = now + NUDGE_NS;
    set_state(t, BT_TS_CONNECTING, (t->udp[0] < 0 && t->udp[1] < 0) ? "no_network" : "", NULL);
    dns_reconcile();
    return 1;
}

int bt_tunnel_down(const char* id)
{
    bt_tunnel* t = bt_tunnel_find(id);
    int full;

    if (!t) return 0;
    full = t->full[0] || t->full[1];
    if (t->dev) ceiling_check(t);
    release(t);
    set_state(t, BT_TS_DOWN, "", NULL);
    t->used = 0;
    dns_reconcile();
    if (full) ts_transport_moved(t, bt_now_ns());
    return 1;
}

void bt_tunnels_down_all(void)
{
    int i;
    for (i = 0; i < BT_TUNNELS_MAX; i++)
        if (T[i].used) bt_tunnel_down(T[i].id);
}

/* --------------------------------------------------------------------- for the clients */

void bt_tunnel_describe(const bt_tunnel* t, bt_writer* w)
{
    bt_put(w, "profile", t->id);
    bt_put(w, "state", bt_tstate_name(t->state));
    bt_put(w, "reason", t->reason);
    if (t->detail[0]) bt_put(w, "detail", t->detail);
    if (t->ifname[0]) bt_put(w, "ifname", t->ifname);
    if ((dns_owner >= 0 && &T[dns_owner] == t) || (dns_magic >= 0 && &T[dns_magic] == t)) bt_put(w, "dns", "1");
    if (t->ts) bt_ts_describe(t->ts, w);
}

void bt_tunnel_stats(const bt_tunnel* t, bt_writer* w)
{
    uint64_t rx = 0, tx = 0, last = 0, now = bt_now_ns(), sec;
    uint32_t nsec;
    const wg_peer* p;
    int has = 0;

    bt_put(w, "profile", t->id);
    for (p = first_peer(t); p; p = p->next) {
        rx += p->rx_bytes;
        tx += p->tx_bytes;
        if (p->has_handshake && (!has || p->last_handshake_ns > last)) {
            last = p->last_handshake_ns;
            has = 1;
        }
    }
    bt_put_u64(w, "rx_bytes", rx);
    bt_put_u64(w, "tx_bytes", tx);
    bt_wall(&sec, &nsec);
    bt_put_u64(w, "last_handshake_time_sec", has ? sec - (now - last) / BT_NSEC_PER_SEC : 0);
    /* An address, not a Tailscale peer's label: those go through relays, bt_ts_describe says which. */
    if (t->n_peers && (t->peers[0].endpoint.family == 4 || t->peers[0].endpoint.family == 6)) {
        char a[BT_ADDR_TEXT_MAX], ep[BT_ADDR_TEXT_MAX + 10];
        const wg_endpoint* e = &t->peers[0].endpoint;
        addr_text(e->family, e->addr, a, sizeof(a));
        snprintf(ep, sizeof(ep), e->family == 6 ? "[%s]:%u" : "%s:%u", a, e->port);
        bt_put(w, "endpoint", ep);
    }
}

/* --------------------------------------------------------------------- the loop */

int bt_tunnels_pollfds(struct pollfd* out, void** owner, int cap)
{
    int n = 0, i, k;

    for (i = 0; i < BT_TUNNELS_MAX; i++) {
        bt_tunnel* t = &T[i];
        int fds[5];
        if (!t->used || !t->dev) continue;
        fds[0] = t->tun_fd;
        fds[1] = t->udp[0];
        fds[2] = t->udp[1];
        fds[3] = t->dnsfd[0];
        fds[4] = t->dnsfd[1];
        for (k = 0; k < 5 && n < cap; k++) {
            if (fds[k] < 0) continue;
            out[n].fd = fds[k];
            out[n].events = POLLIN;
            out[n].revents = 0;
            owner[n++] = t;
        }
        if (t->ts && n < cap) {
            int m = bt_ts_pollfds(t->ts, out + n, cap - n);
            for (k = 0; k < m; k++) owner[n + k] = t;
            n += m;
        }
    }
    return n;
}

static void read_tun(bt_tunnel* t, uint64_t now)
{
    int burst;
    for (burst = 0; burst < TUN_BURST; burst++) {
        wg_drop_reason why = WG_DROP_NONE;
        ssize_t n = bt_tun_read(t->tun_fd, pkt, sizeof(pkt));
        if (n <= 0) break;
        /* Tailscale: a query to MagicDNS's resolver is answered here, it goes to no peer */
        if (t->ts && bt_ts_dns(t->ts, pkt, (size_t)n, now)) continue;
        /* Tailscale: no peer for it yet - the node that owns the destination becomes one. */
        if (!wg_device_send(t->dev, pkt, (size_t)n, now, &why) && why == WG_DROP_NO_ROUTE && t->ts &&
            bt_ts_no_route(t->ts, pkt, (size_t)n, now))
            wg_device_send(t->dev, pkt, (size_t)n, now, &why);
    }
}

static void read_udp(bt_tunnel* t, int fd, uint64_t now)
{
    int burst;
    for (burst = 0; burst < BURST; burst++) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        wg_endpoint src;
        ssize_t n = recvfrom(fd, pkt, sizeof(pkt), 0, (struct sockaddr*)&ss, &sl);
        if (n < 0) break;
        if (from_sockaddr(&ss, &src)) wg_device_receive(t->dev, pkt, (size_t)n, &src, now);
    }
}

static void read_dns(bt_tunnel* t, int fd, uint64_t now)
{
    int burst;
    for (burst = 0; burst < BURST; burst++) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        wg_endpoint src;
        bt_addr from;
        size_t i;
        ssize_t n = recvfrom(fd, pkt, BT_DNS_MSG_MAX, 0, (struct sockaddr*)&ss, &sl);
        if (n < 0) break;
        if (!from_sockaddr(&ss, &src)) continue;
        memset(&from, 0, sizeof(from));
        from.family = src.family;
        memcpy(from.addr, src.addr, 16);
        for (i = 0; i < t->n_peers; i++) {
            bt_lookup* l = &t->lookups[i];
            if (l->state != BT_LOOKUP_RUNNING) continue;
            if (bt_lookup_receive(l, &from, src.port, pkt, (size_t)n, now) &&
                (l->state == BT_LOOKUP_DONE || l->state == BT_LOOKUP_FAILED))
                lookup_done(t, i, now);
        }
    }
}

void bt_tunnels_io(struct pollfd* pfd, void* owner)
{
    bt_tunnel* t = (bt_tunnel*)owner;
    uint64_t now = bt_now_ns();

    if (!t->used || !t->dev) return;
    if (t->ts && bt_ts_owns(t->ts, pfd->fd)) {
        bt_ts_io(t->ts, pfd);           /* POLLOUT matters there: TCP connects and queued bytes */
        return;
    }
    if (!(pfd->revents & (POLLIN | POLLERR | POLLHUP))) return;
    if (pfd->fd == t->tun_fd) read_tun(t, now);
    else if (pfd->fd == t->udp[0] || pfd->fd == t->udp[1]) read_udp(t, pfd->fd, now);
    else if (pfd->fd == t->dnsfd[0] || pfd->fd == t->dnsfd[1]) read_dns(t, pfd->fd, now);
}

/*
 * A Tailscale tunnel is up while control's map stream and the home relay are both there - each
 * node is a peer of its own with its own handshakes, and a tailnet with nobody online is still
 * "connected". Stopped (the login refused or expired) is an error until the user logs in again.
 */
static void evaluate_ts(bt_tunnel* t)
{
    const char* reason = "";
    const char* detail = NULL;
    bt_ts_status s = bt_ts_state(t->ts, &reason, &detail);

    if (!reason) reason = "";
    switch (s) {
    case BT_TAIL_RUNNING:
        if (t->state != BT_TS_UP || t->reason[0]) set_state(t, BT_TS_UP, "", NULL);
        break;
    case BT_TAIL_STARTING:
        set_state(t, t->state == BT_TS_UP ? BT_TS_RECONNECTING : t->state, reason, detail);
        break;
    case BT_TAIL_LOST:
        set_state(t, t->state == BT_TS_CONNECTING ? BT_TS_CONNECTING : BT_TS_RECONNECTING, reason, detail);
        break;
    case BT_TAIL_STOPPED: {
        char r[16], d[160];
        snprintf(r, sizeof(r), "%s", reason[0] ? reason : "login");
        snprintf(d, sizeof(d), "%s", detail ? detail : "");
        fail(t, r, d[0] ? d : NULL);
        break;
    }
    }
}

static void evaluate(bt_tunnel* t, uint64_t now)
{
    size_t i;
    int fresh = 0, live = 0;

    if (t->ts) {
        evaluate_ts(t);
        return;
    }
    for (i = 0; i < t->n_peers; i++) {
        const wg_peer* p = &t->peers[i];
        if (!p->has_handshake || now - p->last_handshake_ns >= REJECT_NS) continue;
        /* Reconnecting, the path is new: the handshake from before the change says nothing of it -
         * taken as "fresh", it turned reconnecting back into up at once, and a server lost in the
         * move read as connected for up to REJECT_NS. A handshake since says it works, and so does
         * anything from the server since: the session goes on from the new address without one. */
        if (t->state != BT_TS_RECONNECTING || p->last_handshake_ns > t->since_ns) fresh = 1;
        else live = 1;
    }
    if (!fresh && live && rx_total(t) > t->rx_since) fresh = 1;
    if (fresh) {
        if (t->state != BT_TS_UP) set_state(t, BT_TS_UP, "", NULL);
        return;
    }
    if (t->state == BT_TS_UP) set_state(t, BT_TS_RECONNECTING, "", NULL);
    if (t->udp[0] < 0 && t->udp[1] < 0) {
        if (strcmp(t->reason, "no_network") != 0) set_state(t, t->state, "no_network", NULL);
        return;
    }
    if (strcmp(t->reason, "no_network") == 0) set_state(t, t->state, "", NULL);
    if (now - t->since_ns > STALL_NS && !t->reason[0]) {
        set_state(t, t->state, "handshake", "no answer from the server: its key, the protocol (AmneziaWG?) or a block");
    }
    if (now >= t->next_nudge_ns) {
        for (i = 0; i < t->n_peers; i++)
            if (t->peers[i].endpoint.family) wg_peer_initiate(&t->peers[i], now);
        t->next_nudge_ns = now + NUDGE_NS;
    }
}

uint64_t bt_tunnels_tick(uint64_t now)
{
    uint64_t next = BT_NEVER;
    int i;

    for (i = 0; i < BT_TUNNELS_MAX; i++) {
        bt_tunnel* t = &T[i];
        uint64_t d;
        size_t k;

        if (!t->used || !t->dev) continue;
        for (k = 0; k < t->n_peers; k++) {
            bt_lookup* l = &t->lookups[k];
            if (l->state != BT_LOOKUP_RUNNING) continue;
            d = bt_lookup_tick(l, now, lookup_send, t);
            if (l->state == BT_LOOKUP_DONE || l->state == BT_LOOKUP_FAILED) lookup_done(t, k, now);
            else if (d < next) next = d;
        }
        if (t->ts) {
            d = bt_ts_tick(t->ts, now);
            if (d < next) next = d;
            evaluate(t, now);
            if (!t->dev) continue;      /* stopped: the login is gone, the tunnel is in error */
            d = wg_device_tick(t->dev, now);
            if (d < next) next = d;
            ceiling_check(t);
            continue;
        }
        d = wg_device_tick(t->dev, now);
        if (d < next) next = d;
        evaluate(t, now);
        if (t->state != BT_TS_UP && t->next_nudge_ns < next) next = t->next_nudge_ns;
        if (t->state != BT_TS_UP && !t->reason[0] && t->since_ns + STALL_NS < next)
            next = t->since_ns + STALL_NS + 1;
        ceiling_check(t);
    }
    return next;
}

void bt_tunnels_net_changed(uint64_t now)
{
    int moved[BT_TUNNELS_MAX], i;

    for (i = 0; i < BT_TUNNELS_MAX; i++) {
        bt_tunnel* t = &T[i];

        moved[i] = 0;
        if (!t->used || !t->dev) continue;
        if (!t->ts) {
            egress_ensure(t, 4, &moved[i]);
            egress_ensure(t, 6, &moved[i]);
        } else {
            /* Tailscale's sockets follow the routes: they need new connections only when the way
             * out moved to another interface - not for every address the kernel settles. */
            char d[2][BT_IFNAME_MAX];
            int k;
            for (k = 0; k < 2; k++) {
                if (!bt_default_if(k ? 6 : 4, d[k])) d[k][0] = '\0';
                if (strcmp(d[k], t->egress[k]) != 0) moved[i] = 1;
                memcpy(t->egress[k], d[k], BT_IFNAME_MAX);
            }
        }
        routes_apply(t, 1);             /* the network manager may have wiped them */
    }
    /* The gateway may have moved: the host routes follow it before anything is sent. */
    bypass_sync(1);
    for (i = 0; i < BT_TUNNELS_MAX; i++) {
        bt_tunnel* t = &T[i];
        size_t k;

        if (!t->used || !t->dev) continue;
        if (t->ts) {
            /* The connections to control and the relays were on the old path: new ones now. Moved
             * or not, our own address may be another one (another Wi-Fi on the same interface). */
            if (moved[i]) bt_ts_net_changed(t->ts, now);
            else bt_ts_net_event(t->ts, now);
            evaluate(t, now);
            continue;
        }
        if (moved[i]) {
            /* Another network: its DNS for the names, and a handshake at once from the new
             * address instead of waiting for the timers. */
            if (t->state == BT_TS_UP) set_state(t, BT_TS_RECONNECTING, "", NULL);
            lookups_start(t, now);
            for (k = 0; k < t->n_peers; k++)
                if (t->peers[k].endpoint.family) wg_peer_initiate(&t->peers[k], now);
            t->next_nudge_ns = now + NUDGE_NS;
        }
        evaluate(t, now);
    }
    dns_reconcile();
}

void bt_tunnels_journal(bt_writer* w)
{
    char snap[BT_DNS_TEXT_MAX];
    int i;
    size_t k;

    for (i = 0; i < BT_TUNNELS_MAX; i++) {
        bt_tunnel* t = &T[i];
        if (t->used && t->routes_in && t->ifname[0]) bt_put(w, "tunnel", t->ifname);
    }
    if ((dns_owner >= 0 || dns_magic >= 0) && bt_dns_snapshot(snap, sizeof(snap))) bt_put(w, "dns", snap);
    for (k = 0; k < n_bypass_in; k++) {
        char a[BT_ADDR_TEXT_MAX];
        addr_text(bypass_in[k].family, bypass_in[k].addr, a, sizeof(a));
        bt_put(w, "bypass", a);
    }
}
