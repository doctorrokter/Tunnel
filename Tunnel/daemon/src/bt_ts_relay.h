/*
 * bt_ts_relay - the DERP connections of one Tailscale tunnel (docs/TAILSCALE.md, section 6), and the
 * measurement that picks our home region.
 *
 * A connection per region, made when something is to be sent there (or it is home): TCP, TLS unless
 * the tailnet is the plain-HTTP stand, the HTTP upgrade to DERP (ts_http1), then ts_derp. Packets
 * sent while it connects wait in a small queue and go right after the login. Home is kept and
 * reconnected with a growing delay; another region's connection is closed after a minute without
 * traffic, as magicsock does. A connection the server says nothing on for two keepalive periods is
 * taken for dead.
 *
 * The home region: a TLS handshake with the first node of each region the caller names, all at once
 * (section 6), timed from the ClientHello to the handshake's end - about one round trip to the
 * server itself. The TCP connect before it is not counted: a proxy on the way (a VPN on a PC, a
 * carrier's) answers it for every region in the same few milliseconds, and a TCP-timed home was New
 * York for a phone next to Frankfurt. The certificate is checked as for a relay connection; one
 * that fails counts as no answer. The first answer is the nearest region: with no home yet it is
 * reported at once (io.measured with that one region), the whole round when every region has
 * answered or 3 s are over. The caller picks home from the times (ts_derpmap_pick_home: region
 * scores and the hysteresis of netcheck) and measures again after a network change.
 *
 * The nodes come with their addresses (a DERP map has them), so no name is looked up here: a node
 * with neither address is skipped.
 */

#ifndef BT_TS_RELAY_H
#define BT_TS_RELAY_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include "bt_resolve.h"
#include "wg_crypto.h"

#define BT_RELAY_NODES          4           /* per region: DERP regions have one to three */
#define BT_RELAY_REGIONS        48          /* the official map has about thirty */
#define BT_RELAY_CONNS          8           /* open at once: home and the regions in use */
#define BT_RELAY_HOST_MAX       253
#define BT_RELAY_IDLE_NS        (60ULL * 1000000000ULL)     /* a region not home: closed after this */

typedef struct {
    char     host[BT_RELAY_HOST_MAX + 1];   /* HostName: the TLS name and the Host header */
    char     name[64];                      /* Name, for Ideal-Node */
    bt_addr  v4;                            /* family 0 = none */
    bt_addr  v6;
    uint16_t port;                          /* DERPPort; 0 = 443 (80 on the plain stand) */
    char     pin[80];                       /* CertName when "sha256-raw:..."; else "" */
} bt_relay_node;

typedef struct {
    int           id;                       /* RegionID */
    char          code[16];
    int           no_home;                  /* NoMeasureNoHome or Avoid: never our home */
    bt_relay_node nodes[BT_RELAY_NODES];
    size_t        n_nodes;
} bt_relay_region;

typedef struct {
    void* ctx;
    /* A packet from node `src` arrived through `region`'s relay; `data` may be changed in place. */
    void (*packet)(void* ctx, int region, const uint8_t src[32], uint8_t* data, size_t len);
    /* Node `key` is not reachable through `region`'s relay any more. */
    void (*peer_gone)(void* ctx, int region, const uint8_t key[32]);
    /* The home relay logged in (1) or went away (0). */
    void (*home)(void* ctx, int up);
    /* The measurement is done: the time to each region measured, 0 where none answered. Also called
     * early with the first answer alone when there is no home yet (see above). */
    void (*measured)(void* ctx, const int64_t* region, const uint64_t* latency_ns, size_t n);
} bt_relay_io;

typedef struct bt_relays bt_relays;

/*
 * The relays of one tunnel, logging in with our node key. `plain`: the stand's DERP over plain HTTP
 * (a control URL of http:// says so). `tag` goes at the start of every log line. NULL when out of
 * memory.
 */
bt_relays* bt_relays_new(const wg_key* node_priv, const wg_key* node_pub, int plain, const char* tag,
                         const bt_relay_io* io);
void       bt_relays_free(bt_relays* rs);

/* The DERP map changed: connections to regions gone or changed are closed. */
void bt_relays_set_map(bt_relays* rs, const bt_relay_region* regions, size_t n, uint64_t now_ns);
const bt_relay_region* bt_relays_region(const bt_relays* rs, int id);

/* Our home region (0: none yet): connected and kept, told to its server with NotePreferred. */
void bt_relays_set_home(bt_relays* rs, int region, uint64_t now_ns);
int  bt_relays_home(const bt_relays* rs);
int  bt_relays_home_up(const bt_relays* rs);

/* 1 when a connection to `region` is logged in (a reply to a node heard there can go back). */
int  bt_relays_open(const bt_relays* rs, int region);

/*
 * A packet for node `dst` through `region`'s relay, connecting it when needed. 1 when sent or
 * queued; 0 when dropped: no such region, its queue or the TLS queue full.
 */
int  bt_relays_send(bt_relays* rs, int region, const uint8_t dst[32], const uint8_t* pkt, size_t len,
                    uint64_t now_ns);

/* Measures the regions named (see above); the answer comes through io.measured. */
void bt_relays_measure(bt_relays* rs, const int64_t* regions, size_t n, uint64_t now_ns);

/* The network changed: every connection is dropped and home made again at once. */
void bt_relays_reconnect(bt_relays* rs, uint64_t now_ns);

int      bt_relays_pollfds(bt_relays* rs, struct pollfd* out, int cap);
int      bt_relays_owns(const bt_relays* rs, int fd);
void     bt_relays_io(bt_relays* rs, const struct pollfd* pfd, uint64_t now_ns);
uint64_t bt_relays_tick(bt_relays* rs, uint64_t now_ns);

/* For the clients: packets both ways, and what home is. */
typedef struct {
    int      home;
    int      home_up;
    int      open;                          /* connections logged in */
    uint64_t packets_in, packets_out, dropped;
} bt_relay_stats;

void bt_relays_stats(const bt_relays* rs, bt_relay_stats* st);

#endif /* BT_TS_RELAY_H */
