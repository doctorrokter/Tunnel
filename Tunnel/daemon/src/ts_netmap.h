/*
 * ts_netmap - the tailnet as Tailscale's control server describes it (docs/TAILSCALE.md, sections
 * 5-7), sans-IO: the answers to GET /key and to register, and the stream of map messages applied
 * to a model of the tailnet the way Tailscale's own client applies them.
 *
 * The reference is Tailscale v1.102.5: tailcfg (the types and their JSON), control/controlclient
 * map.go (mapSession: how a full netmap and its deltas combine), direct.go (the stream around it),
 * net/routemanager and ipn/ipnlocal/expiry.go (which node an address goes to), net/netcheck (the
 * home region). As there:
 *   - one map request is one session. Its first message that is not a KeepAlive must carry our
 *     Node (Go gives up on the session otherwise) and starts from nothing - peers, DERP map and
 *     domain of an earlier session do not carry over (ts_netmap_session_start). Until that first
 *     message is applied, the previous session's netmap stays readable;
 *   - KeepAlive: nothing else in the message counts but ControlTime;
 *   - Node replaces our node whole. Domain replaces the domain when not empty. DNSConfig, when not
 *     null, replaces the DNS config whole (lastDNSConfig; ts_dnsconf);
 *   - DERPMap replaces the map, except: no Regions keeps the previous regions (and
 *     omitDefaultRegions), no HomeParams keeps those, HomeParams without RegionScore keeps the
 *     scores. A region given as null is dropped;
 *   - Peers, when not empty, is the whole peer list, and every other peer field of the message is
 *     ignored. Otherwise, in this order: PeersRemoved; PeersChanged (the whole node, added or
 *     replaced); PeerSeenChange (LastSeen := now, or unset); OnlineChange; PeersChangedPatch (per
 *     field: DERPRegion when not 0, Key, DiscoKey, Online, LastSeen, KeyExpiry when present). A
 *     change for a node that is not there is ignored;
 *   - a PeersChanged node that differs from the copy we hold only in fields a patch can carry is
 *     made into a patch first (patchifyPeer, against the peers as they were before the message):
 *     then a field the new copy leaves out - HomeDERP 0, Online or LastSeen unknown on either
 *     side - keeps what we had, and the patch is applied after the explicit ones;
 *   - a patch carrying DiscoKey, Online=false and a LastSeen no later than the one we held is
 *     dropped whole, and a full Peers list cannot take a node that is not online back to another
 *     disco key with no newer LastSeen (removeUnwantedDiscoUpdates*): a stale disco key never wins;
 *   - every node goes through upgradeNode: the legacy DERP "127.3.3.40:N" gives HomeDERP N when
 *     HomeDERP is 0 (capver 111); AllowedIPs absent or null is its Addresses (capver 112 - an
 *     explicit [] stays empty); UnsignedPeerAPIOnly cuts AllowedIPs back to Addresses.
 * daemon/test/vectors/netmap/ replays message sequences through Tailscale's own mapSession and
 * checks this module against the result.
 *
 * Trouble comes in two kinds:
 *   - the message is refused - 0, the netmap exactly as before, the reason in the result. It is
 *     not JSON; a field we read has the wrong JSON type, or a malformed value (a key, a prefix, a
 *     time, an integer out of range) - where Go's json.Unmarshal fails the message and with it the
 *     session; null where a node or a patch must be (Go would crash); a field we read twice in one
 *     object (Go merges: a real server never sends that); PeersChanged or Peers naming a node we
 *     hold twice. The caller then starts the map stream again, as Go does;
 *   - an item is left out and the rest applies - what Go would hold but our memory does not: a
 *     peer when the table or its arena is full, its name over TS_NODE_NAME_MAX bytes or holding a
 *     NUL, more than TS_NODE_ADDRS_MAX addresses or TS_NODE_ALLOWED_MAX AllowedIPs; a DERP region,
 *     node, string or score beyond the map's arrays. Counted in the result; ts_netmap.incomplete
 *     stays set until a session's list fits whole.
 * Fields we do not read are skipped whatever their JSON type (Go would refuse a mistyped one).
 *
 * Memory is the caller's and fixed: the peer slots, two indexes and an arena for names and
 * prefixes (ts_netmap_init); the rest is inside ts_netmap (about 60 KB). The JSON is the caller's
 * too: parse a message with ts_json_parse - its tokens counted first with ts_json_count, bounded
 * by TS_NM_TOKENS_MAX - and hand the document over. Nothing here keeps pointers into it.
 */

#ifndef TS_NETMAP_H
#define TS_NETMAP_H

#include <stddef.h>
#include <stdint.h>

#include "bt_resolve.h"
#include "ts_json.h"
#include "wg_conf.h"
#include "wg_crypto.h"

/* --- limits ------------------------------------------------------------------------------- */

/*
 * The biggest map message to accept (each message on the stream is a little-endian 32-bit length,
 * then the JSON). A peer as Go writes it, Hostinfo and all, is about 0.8 KB: 1 MiB is a netmap of
 * some 1300 peers. Tokens come at about one per 13 bytes of such JSON (measured: 1000 peers are
 * 787 KB and 60017 tokens - 1.2 MB of tokens at 20 bytes each): count them (ts_json_count) and
 * allocate what the message needs, refusing more than TS_NM_TOKENS_MAX - a hostile [0,0,0,...]
 * needs one per 2 bytes. On a PC (-O2) those 1000 peers take 0.7 ms to count, 1.2 ms to parse,
 * 2 ms to apply.
 */
#define TS_NM_MSG_MAX           (1u << 20)
#define TS_NM_TOKENS_MAX        131072
#define TS_NM_KEY_MSG_MAX       (64u << 10)     /* /key: what Go reads of it */
#define TS_NM_REGISTER_MSG_MAX  (1u << 20)      /* register: likewise */

/*
 * The peer table the daemon should give (ts_netmap_init takes any capacity up to 65534). The
 * personal and free plans of Tailscale stop at 100 devices; 1024 leaves room for nodes shared in
 * from other tailnets and for a small company's tailnet. The slots are 172 KB (168 bytes each), the
 * indexes 4 KB; in the arena a peer with its two addresses and a 25-byte name takes 68 bytes, so
 * 128 KB hold some 1900 of them - fewer when they carry subnet routes.
 */
#define TS_NM_PEERS             1024
#define TS_NM_ARENA             (128u << 10)    /* names and prefixes of the peers */

#define TS_NODE_NAME_MAX        254             /* an FQDN with its trailing dot */
#define TS_NODE_ADDRS_MAX       8               /* Tailscale and Headscale give one IPv4 and one IPv6 */
#define TS_NODE_ALLOWED_MAX     1024            /* subnet routers and app connectors carry more */
#define TS_NM_DOMAIN_MAX        255

#define TS_DERPMAP_REGIONS_MAX  64              /* the official map has about thirty */
#define TS_DERPMAP_NODES_MAX    256             /* all regions together */
#define TS_DERPMAP_SCORES_MAX   64
#define TS_DERPMAP_STR_MAX      16384           /* all the map's names together */
#define TS_DERPMAP_NAME_MAX     253             /* HostName, CertName, RegionName... */

/* --- time ---------------------------------------------------------------------------------- */

/* A Go time.Time instant as Unix time. Go's zero time (year 1) means "not set" - a KeyExpiry that
 * never comes. */
typedef struct {
    int64_t sec;
    int32_t nsec;                       /* 0 .. 999999999 */
} ts_time;

#define TS_TIME_ZERO_SEC        (-62135596800LL)    /* 0001-01-01T00:00:00Z */

ts_time ts_time_zero(void);
int     ts_time_is_zero(ts_time t);
int     ts_time_cmp(ts_time a, ts_time b);          /* -1, 0, 1 */

/* RFC 3339 exactly as Go writes it ("2006-01-02T15:04:05.999999999Z07:00": a fraction of any
 * length, the first 9 digits counted; Z or +hh:mm). The odd forms only Go's lenient fallback
 * parser takes (one-digit hours, a comma before the fraction) are refused. 1 on success. */
int ts_time_parse(const char* s, size_t len, ts_time* t);

/* --- text forms of the wire, as Go's netip and key packages read them ------------------------ */

/* An IPv4 or IPv6 address (netip.ParseAddr): no leading zeros in IPv4 octets, at most 4 hex
 * digits a group, one "::", an IPv4 tail allowed. Zones ("%eth0") are refused. */
int ts_addr_parse(const char* s, size_t len, int* family, uint8_t addr[16]);

/* addr/bits (netip.ParsePrefix): bits without leading zeros, host bits kept as written. The empty
 * string is Go's zero prefix: 1 with family 0 - it matches and routes nothing. */
int ts_prefix_parse(const char* s, size_t len, wg_prefix* p);

/* A key as Tailscale writes it: `prefix` ("nodekey:", "discokey:", "mkey:") and 64 hex digits of
 * either case. */
int ts_key_parse(const char* s, size_t len, const char* prefix, uint8_t out[32]);

/* --- a node -------------------------------------------------------------------------------- */

#define TS_NODE_ONLINE_KNOWN    0x0001      /* Online was sent: control may know */
#define TS_NODE_ONLINE          0x0002      /* ... and it is connected to control */
#define TS_NODE_SEEN            0x0004      /* last_seen is set */
#define TS_NODE_EXPIRED         0x0008      /* Expired: control says its key expired */
#define TS_NODE_AUTHORIZED      0x0010      /* MachineAuthorized */
#define TS_NODE_UNSIGNED        0x0020      /* UnsignedPeerAPIOnly */
#define TS_NODE_WG_ONLY         0x0040      /* IsWireGuardOnly: no DERP, no disco */
#define TS_NODE_ALLOWED_ADDRS   0x0080      /* its AllowedIPs are its Addresses (kept once) */

typedef struct {
    int64_t   id;                       /* NodeID */
    int64_t   user;                     /* UserID */
    int64_t   home_derp;                /* the DERP region it is reached through; 0 = unknown */
    wg_key    key;                      /* node key = its WireGuard public key */
    wg_key    disco;                    /* all zero: none */
    ts_time   key_expiry;               /* zero time: never */
    ts_time   last_seen;                /* with TS_NODE_SEEN */
    uint16_t  flags;                    /* TS_NODE_* */
    uint16_t  n_addrs;                  /* Addresses: ts_node_addrs */
    uint16_t  n_allowed;                /* AllowedIPs after upgradeNode: ts_node_allowed */
    uint16_t  name_len;                 /* Name: ts_node_name */
    uint32_t  gen;                      /* ts_netmap.gen of the message that last touched it */

    /* The netmap's own bookkeeping below. */
    uint32_t  blob;                     /* name and prefixes in the arena */
    uint64_t  fp;                       /* the fields patchifyPeer compares that are not kept */
    uint8_t   state, plan, mask, snap;  /* one message's plan for the slot */
    ts_time   snap_seen;                /* LastSeen before the message (removeUnwantedDiscoUpdates) */
} ts_node;

/* A node as it is read from a message - one at a time, inside ts_netmap. */
typedef struct {
    ts_node   n;
    char      name[TS_NODE_NAME_MAX + 1];
    size_t    name_len;
    int       name_ok;                  /* fits and has no NUL */
    wg_prefix addrs[TS_NODE_ADDRS_MAX];
    size_t    n_addrs;                  /* as many as the message had - may exceed the array */
    wg_prefix allowed[TS_NODE_ALLOWED_MAX];
    size_t    n_allowed;
    int       allowed_nil;              /* AllowedIPs absent or null */
} ts_node_in;

/* --- the DERP map -------------------------------------------------------------------------- */

#define TS_DERPMAP_IP_DNS       0           /* IPv4/IPv6 "": look HostName up */
#define TS_DERPMAP_IP_ADDR      1           /* this address */
#define TS_DERPMAP_IP_OFF       2           /* anything else ("none"): not over this family */

typedef struct {
    int     mode;                       /* TS_DERPMAP_IP_* */
    bt_addr addr;                       /* with TS_DERPMAP_IP_ADDR */
} ts_derpmap_ip;

typedef struct {
    int64_t        region_id;           /* RegionID as the node gives it */
    uint16_t       name, host, cert;    /* Name, HostName, CertName ("sha256-raw:<hex>" = a pin):
                                         * ts_derpmap_str */
    ts_derpmap_ip  v4, v6;
    int64_t        stun_port;           /* 0: 3478; -1: no STUN */
    int64_t        derp_port;           /* 0: 443 (ts_derpmap_port) */
    uint8_t        stun_only;           /* a STUN server only: never dialed for DERP */
    uint8_t        insecure_for_tests;  /* no TLS verification (tests and stands only) */
    uint8_t        can_port80;
} ts_derpmap_node;

typedef struct {
    int64_t  id;                        /* its key in Regions - what HomeDERP and patches name */
    int64_t  region_id;                 /* its RegionID field (equal in any sane map) */
    uint16_t code, name;                /* RegionCode, RegionName */
    uint8_t  avoid;                     /* deprecated Avoid */
    uint8_t  no_measure_no_home;        /* never measured, never our home (capver 115) */
    uint16_t first, n_nodes;            /* its nodes, in the map's order: nodes[first ..] */
} ts_derpmap_region;

typedef struct {
    int64_t region;
    double  score;                      /* HomeParams.RegionScore: latency multiplier */
} ts_derpmap_score;

typedef struct {
    int               present;          /* a DERPMap came in this session */
    int               omit_default_regions;
    ts_derpmap_region regions[TS_DERPMAP_REGIONS_MAX];      /* ascending id */
    size_t            n_regions;
    ts_derpmap_node   nodes[TS_DERPMAP_NODES_MAX];
    size_t            n_nodes;
    int               home_params;      /* HomeParams present */
    int               scores_set;       /* RegionScore present (possibly empty) */
    ts_derpmap_score  scores[TS_DERPMAP_SCORES_MAX];        /* ascending region */
    size_t            n_scores;
    char              str[TS_DERPMAP_STR_MAX];              /* strings; offset 0 is "" */
    size_t            str_used;
} ts_derpmap;

/* --- DNS: what MagicDNS needs of MapResponse.DNSConfig (docs/TAILSCALE.md, section 8a) --------- */

#define TS_DNS_RESOLVERS_MAX    8
#define TS_DNS_DOMAINS_MAX      8
#define TS_DNS_EXTRA_MAX        64
#define TS_DNS_ROUTES_MAX       128         /* split-DNS routes kept: control sends 65 of its own (the
                                             * reverse zones of 100.64/10 and fd7a:115c:a1e0::/48) */
#define TS_DNS_ROUTE_SERVERS    4           /* ... servers kept per route */
#define TS_DNS_NAME_MAX         253         /* a name without its trailing dot */

/* An ExtraRecords entry we serve: an A or AAAA (Type "", "A" or "AAAA"; Value its address). */
typedef struct {
    char    name[TS_DNS_NAME_MAX + 1];  /* as control gave it, without a trailing dot */
    int     family;
    uint8_t addr[16];
} ts_dns_record;

/*
 * A split-DNS route (DNSConfig.Routes): names under `suffix` (lower case, no trailing dot) go to its
 * servers. None at all (null or []): MagicDNS's own, as Go's "handled by 100.100.100.100" - the
 * tailnet's names and ExtraRecords, NXDOMAIN for the rest under it. `unusable`: it named servers but
 * not one plain DNS server among them (DoH, DoT, another port) - its names get SERVFAIL rather than
 * go to servers they were not meant for.
 */
typedef struct {
    char    suffix[TS_DNS_NAME_MAX + 1];
    bt_addr servers[TS_DNS_ROUTE_SERVERS];
    size_t  n_servers;
    int     unusable;
} ts_dns_route;

/*
 * As mapSession keeps lastDNSConfig: a message that carries DNSConfig replaces it whole, null or
 * absent keeps it, a new session starts with none. Read: Proxied (MagicDNS on), Resolvers that are
 * plain DNS servers (an address, or address:53 - "Override local DNS"; DoH and the rest are left
 * out), Domains (search domains), ExtraRecords of A/AAAA and Routes (split DNS). The rest is not
 * read. What the arrays cannot hold, or we do not serve, is counted in left_out.
 */
typedef struct {
    int           present;
    int           proxied;
    bt_addr       resolvers[TS_DNS_RESOLVERS_MAX];
    size_t        n_resolvers;
    char          domains[TS_DNS_DOMAINS_MAX][TS_DNS_NAME_MAX + 1];
    size_t        n_domains;
    ts_dns_record extra[TS_DNS_EXTRA_MAX];
    size_t        n_extra;
    ts_dns_route  routes[TS_DNS_ROUTES_MAX];
    size_t        n_routes;
    unsigned      left_out;
} ts_dnsconf;

/* --- the netmap ---------------------------------------------------------------------------- */

typedef enum {
    TS_NM_OK = 0,
    TS_NM_ERR_NOT_OBJECT,               /* the message is not a JSON object */
    TS_NM_ERR_TYPE,                     /* a field we read has the wrong JSON type */
    TS_NM_ERR_VALUE,                    /* a malformed key, prefix, time or number */
    TS_NM_ERR_DUPLICATE,                /* a field we read appears twice in one object */
    TS_NM_ERR_NULL_ITEM,                /* null where a node, patch or DERP node must be */
    TS_NM_ERR_DUP_PEER,                 /* Peers or PeersChanged lists a node we hold twice */
    TS_NM_ERR_NO_SELF,                  /* a session's first message has no Node */
    TS_NM_ERR_SELF_LIMIT,               /* our own node is beyond the limits */
    TS_NM_ERR_NO_NOISE_KEY,             /* /key: no ts2021 key (a control server too old) */
    TS_NM_ERR_TOO_LONG                  /* register: an AuthURL longer than we keep */
} ts_netmap_err;

#define TS_NM_CHANGED_SELF      0x01
#define TS_NM_CHANGED_PEERS     0x02
#define TS_NM_CHANGED_DERP      0x04
#define TS_NM_CHANGED_DOMAIN    0x08
#define TS_NM_CHANGED_RESET     0x10        /* a session's first message replaced everything */
#define TS_NM_CHANGED_DNS       0x20        /* DNSConfig came (or a reset dropped it) */

typedef struct {
    int           keepalive;            /* a KeepAlive: nothing else applied */
    unsigned      changed;              /* TS_NM_CHANGED_* */
    int           full;                 /* Peers carried the whole list */
    unsigned      peers_dropped;        /* peers of this message left out (limits) */
    unsigned      derp_dropped;         /* DERP regions, nodes or scores left out */
    int           has_control_time;
    ts_time       control_time;         /* ControlTime: control's clock, for the expiry check */
    ts_netmap_err err;                  /* why the message was refused */
    size_t        err_at;               /* about where, as a byte offset into it */
} ts_netmap_result;

typedef struct {
    int         fresh;                  /* the next non-KeepAlive message starts a session */
    uint32_t    gen;                    /* +1 for every message applied, KeepAlives aside */
    int         incomplete;             /* a peer the server sent could not be kept */

    int         has_self;               /* our node: ts_netmap_self */
    ts_node     self;
    char        self_name[TS_NODE_NAME_MAX + 1];
    wg_prefix   self_addrs[TS_NODE_ADDRS_MAX];
    wg_prefix   self_allowed[TS_NODE_ADDRS_MAX];
    char        domain[TS_NM_DOMAIN_MAX + 1];
    ts_derpmap  derp;
    ts_dnsconf  dns;

    /* The peers, in the caller's memory: read them through the functions below. */
    ts_node*    nodes;                  /* slots */
    uint16_t*   by_id;                  /* slots by ascending id */
    uint16_t*   by_key;                 /* slots by key, then id */
    size_t      cap, n, n_keyed;
    size_t      free_hint;
    uint8_t*    arena;
    size_t      arena_size, arena_used, arena_garbage;
    ts_node_in  in;                     /* scratch */
} ts_netmap;

/*
 * An empty netmap over the caller's memory: `cap` peer slots (at most 65534), `index` of 2 * cap
 * entries, an arena of `arena_size` bytes (TS_NM_PEERS and TS_NM_ARENA are the daemon's sizes).
 * It waits for a session's first message.
 */
void ts_netmap_init(ts_netmap* nm, ts_node* nodes, uint16_t* index, size_t cap, uint8_t* arena,
                     size_t arena_size);

/* A new map stream begins: its first message (not a KeepAlive) will replace everything. */
void ts_netmap_session_start(ts_netmap* nm);

/*
 * Applies one map message, parsed (`d`). `now` is the wall clock (PeerSeenChange stamps it). 1
 * when applied - check res->keepalive, res->changed; 0 when refused (res->err), the netmap exactly
 * as it was: then start the map stream over.
 */
int ts_netmap_apply(ts_netmap* nm, const ts_json* d, ts_time now, ts_netmap_result* res);

const char* ts_netmap_err_text(ts_netmap_err e);

/* --- reading it ----------------------------------------------------------------------------- */

/* Our node; NULL until a session's first message. */
const ts_node* ts_netmap_self(const ts_netmap* nm);

/* The tailnet's name (MapResponse.Domain); "" until known. */
const char* ts_netmap_domain(const ts_netmap* nm);

/* The DNSConfig as it stands (present 0: none this session). */
const ts_dnsconf* ts_netmap_dns(const ts_netmap* nm);

/* netmap.MagicDNSSuffix: our node's Name after its first label, without dots at either end
 * ("tail1234.ts.net"); "" without our node. Written into `out` (cap > 0); returns the length. */
size_t ts_netmap_magic_suffix(const ts_netmap* nm, char* out, size_t cap);

/* The peers by ascending ID: i in [0, ts_netmap_count). Valid until the next apply. */
size_t         ts_netmap_count(const ts_netmap* nm);
const ts_node* ts_netmap_at(const ts_netmap* nm, size_t i);

const ts_node* ts_netmap_find_id(const ts_netmap* nm, int64_t id);

/* The peer with this node key - the one with the lowest ID if a broken map gives two. NULL: none.
 * What a packet from a relay is matched by. */
const ts_node* ts_netmap_find_key(const ts_netmap* nm, const uint8_t key[32]);

/* The peers that are online (Online known and true), ascending ID, at most `cap` of them; returns
 * how many there are. */
size_t ts_netmap_online(const ts_netmap* nm, const ts_node** out, size_t cap);

/* A node's Name ("host.tailnet.ts.net."), its Addresses, its AllowedIPs (n->n_addrs,
 * n->n_allowed of them). For ourselves too (ts_netmap_self). A prefix of family 0 is Go's zero
 * prefix: it routes nothing. Valid until the next apply. */
const char*      ts_node_name(const ts_netmap* nm, const ts_node* n);
const wg_prefix* ts_node_addrs(const ts_netmap* nm, const ts_node* n);
const wg_prefix* ts_node_allowed(const ts_netmap* nm, const ts_node* n);

/* 1 online, 0 offline, -1 unknown (control did not say). */
int ts_node_online(const ts_node* n);

/* Whether a node counts as expired at `now` (control's clock where known: see ControlTime), as
 * the expiry manager decides: control said so, or its KeyExpiry is not after `now`. A `now`
 * before 2023-01-10 is a clock not set yet - then only control's word counts. */
int ts_node_expired(const ts_node* n, ts_time now);

/* The name to show, as InitDisplayNames makes it: Name without the tailnet's MagicDNS suffix
 * (taken from our own Name) and without the trailing dot. Its length; "" when there is none. */
size_t ts_node_display_name(const ts_netmap* nm, const ts_node* n, char* out, size_t cap);

/* --- routing: which peer an address belongs to ------------------------------------------- */

#define TS_ROUTE_SUBNETS        0x01        /* take the peers' subnet routes (--accept-routes) */

/*
 * The peer a packet to `addr` (4 or 16 bytes) goes to, as Tailscale's route manager decides
 * (net/routemanager): a peer contributes nothing while it is expired (ts_node_expired at `now`)
 * or has neither a disco key nor a home DERP region (and is not WireGuard-only). Of its
 * AllowedIPs, its own addresses - single Tailscale IPs (100.64.0.0/10 but 100.115.92.0/23,
 * fd7a:115c:a1e0::/48) or any entry of its Addresses - always count; 0.0.0.0/0 and ::/0 only for
 * the exit node chosen (`exit_node`, 0 = none); other routes only with TS_ROUTE_SUBNETS. The
 * longest prefix wins; the same prefix from two peers goes to the lower ID. NULL: no peer - the
 * packet has nowhere to go. The lookup for a peer added on demand (WG_DROP_NO_ROUTE).
 */
const ts_node* ts_netmap_route(const ts_netmap* nm, int family, const uint8_t* addr, unsigned flags,
                               int64_t exit_node, ts_time now);

/* The prefixes of `n` that route to it by the same rules (its engine AllowedIPs), as written, each
 * network once, at most `cap`; returns how many there are. A network another peer wins (a lower ID
 * with it) is not among them. */
size_t ts_netmap_node_routes(const ts_netmap* nm, const ts_node* n, unsigned flags, int64_t exit_node,
                             ts_time now, wg_prefix* out, size_t cap);

/* The routes the tun needs beyond the tailnet's own ranges: every eligible prefix that is not a
 * peer's own address (subnet routes, the exit node's /0s), host bits cleared, each network once,
 * at most `cap`; returns how many there are. */
size_t ts_netmap_os_routes(const ts_netmap* nm, unsigned flags, int64_t exit_node, ts_time now,
                           wg_prefix* out, size_t cap);

/* --- the DERP map --------------------------------------------------------------------------- */

/* The region HomeDERP `id` names (its key in Regions); NULL: not in the map. The regions in
 * order are nm->derp.regions[0 .. n_regions). */
const ts_derpmap_region* ts_derpmap_find(const ts_netmap* nm, int64_t id);

/* A region's nodes (r->n_nodes of them), in the map's order - the order to try them in. */
const ts_derpmap_node*   ts_derpmap_nodes(const ts_netmap* nm, const ts_derpmap_region* r);

/* A string of the map by its offset ("" for 0). */
const char*              ts_derpmap_str(const ts_netmap* nm, uint16_t off);

/* The TCP port of a node's DERP server: DERPPort, 443 for 0; 0 when it is no port at all. */
uint16_t ts_derpmap_port(const ts_derpmap_node* n);

/*
 * The regions worth measuring for our home, as netcheck picks them: not NoMeasureNoHome; not
 * Avoid unless it is home now (`current`); with a node that is not STUN-only. Ascending id, at
 * most `cap`; returns how many there are.
 */
size_t ts_derpmap_home_candidates(const ts_netmap* nm, int64_t current, int64_t* out, size_t cap);

/*
 * Our home region from one round of measurements - latency_ns[i] for region[i], 0 = no answer -
 * as netcheck's addReportHistoryAndSetPreferredDERP decides with one report: each latency scaled
 * by its region's RegionScore (when > 0), the least wins (on a tie, the lower id); a region that
 * is NoMeasureNoHome or not in the map never does (capver 115). The current home stays while it
 * answered or was heard from in the last 8 s (`current_heard_ns` ago; ~0ULL = never) and the
 * winner is less than 10 ms or a third better; with no answer at all it stays when heard from in
 * the last 120 s. Unlike netcheck, a current home that is NoMeasureNoHome now, or gone from the
 * map, is given up whatever it answered. 0: no home.
 */
int64_t ts_derpmap_pick_home(const ts_netmap* nm, const int64_t* region, const uint64_t* latency_ns,
                             size_t n, int64_t current, uint64_t current_heard_ns);

/* --- the other answers from control -------------------------------------------------------- */

/* GET /key?v=<capver>: {"legacyPublicKey":"mkey:...","publicKey":"mkey:..."} */
typedef struct {
    wg_key public_key;                  /* the ts2021 (Noise) key */
    wg_key legacy_public_key;           /* all zero for any client this new */
} ts_server_keys;

/* 1 with the keys; 0 with *err - TS_NM_ERR_NO_NOISE_KEY when publicKey is missing or zero. */
int ts_server_keys_parse(const ts_json* d, ts_server_keys* out, ts_netmap_err* err);

#define TS_REG_URL_MAX          1024
#define TS_REG_TEXT_MAX         255
#define TS_REG_ERROR_MAX        511

/* POST /machine/register: RegisterResponse. */
typedef struct {
    char    error[TS_REG_ERROR_MAX + 1];    /* not "": refused; the rest means nothing (Go's order) */
    int     node_key_expired;               /* register a new node key (with OldNodeKey) */
    int     machine_authorized;             /* in the tailnet; 0 without auth_url: an admin must approve */
    char    auth_url[TS_REG_URL_MAX + 1];   /* not "": log in there (a login by a link, TAILSCALE.md 11b) */
    int     node_key_signature;             /* tailnet lock wants a signature: not supported */
    int64_t user_id;                        /* User.ID */
    char    login_name[TS_REG_TEXT_MAX + 1];    /* Login.LoginName, for the screens */
    char    display_name[TS_REG_TEXT_MAX + 1];  /* Login.DisplayName */
    int     truncated;                      /* error or a name was longer and is cut (UTF-8 whole) */
} ts_register;

int ts_register_parse(const ts_json* d, ts_register* out, ts_netmap_err* err);

#endif /* TS_NETMAP_H */
