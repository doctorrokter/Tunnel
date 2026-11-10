/*
 * bt_tailscale - the Tailscale side of a tunnel (docs/TAILSCALE.md, sections 4-9): the control
 * connection (the node's login and the netmap), the DERP relays, and the netmap's nodes turned into
 * the engine's peers as traffic needs them. bt_tunnel keeps what every tunnel has - the tun device,
 * its addresses and routes, the engine device, the state the clients see - and hands this module
 * the rest; both run in the daemon's one poll loop.
 *
 *   control   the server's Noise key (GET /key), then ts2021 (Noise IK over an HTTP upgrade),
 *             HTTP/2 inside it: register (only until the node is in the tailnet), a streaming map
 *             (the whole netmap, then changes), a short map now and then to tell our home relay
 *   relays    a DERP connection to our home region, kept; others while a node there is talked to
 *   peers     a node becomes an engine peer when a packet goes to one of its addresses or comes
 *             from its key, so a tailnet of hundreds costs what the few in use cost
 *
 * Its transport - TCP and TLS to control and the relays - is ordinary traffic of the phone: it
 * follows the routes (section 9), inside a full tunnel when one is up.
 */

#ifndef BT_TAILSCALE_H
#define BT_TAILSCALE_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include "bt_proto.h"
#include "bt_resolve.h"
#include "bt_store.h"
#include "wg_conf.h"
#include "wg_device.h"

#define BT_TS_CAPVER        130         /* the capability version we declare (section 2) */
#define BT_TS_MTU           1280        /* Tailscale's own */

typedef struct bt_ts bt_ts;

typedef struct {
    void* ctx;

    /* The node's own addresses from control, for the tun: with the first netmap, and again when
     * they change. */
    void (*addresses)(void* ctx, const wg_prefix* a, size_t n);

    /* The routes into the tun beyond the tailnet's own ranges (other nodes' subnet routes); the
     * whole set each time it changes. */
    void (*routes)(void* ctx, const wg_prefix* r, size_t n);

    /* The resolvers the phone uses now - the tunnel that owns DNS, else the network's - for the
     * names of control and the relays (their traffic follows the routes, so must their DNS). */
    size_t (*resolvers)(void* ctx, bt_addr* out, size_t cap);

    /* A node became a peer of the device: the tunnel sets where its handshake timestamps start
     * (the ceiling every tunnel keeps across restarts, DAEMON.md section 9). */
    void (*peer_added)(void* ctx, wg_peer* p);

    /* MagicDNS (TAILSCALE.md section 8a): an answer of the resolver, an IP packet for the tun; and
     * MagicDNS went on or off, or its search domains changed - the tunnel puts the system's DNS
     * right (bt_ts_magic_dns). */
    void (*to_tun)(void* ctx, const uint8_t* pkt, size_t len);
    void (*dns_changed)(void* ctx);

    /* The login by a link (TAILSCALE.md section 11b): control gave a new link, or the login went
     * through and there is none - the clients are to be told (bt_ts_describe's auth_url). */
    void (*login_link)(void* ctx);
} bt_ts_hooks;

typedef enum {
    BT_TAIL_STARTING = 0,   /* logging in, waiting for the netmap or the home relay */
    BT_TAIL_RUNNING,        /* control's map stream and the home relay are both there */
    BT_TAIL_LOST,           /* was running; one of them went away and is being reconnected */
    BT_TAIL_STOPPED         /* cannot go on without the user (reason: login, expired, removed) */
} bt_ts_status;

/*
 * Starts the Tailscale side of tunnel `id`: loads its profile from `store`, takes over `dev` (a
 * device that is initialized and up, with our node key set by this call, its ctx pointing at the
 * caller) and begins connecting. NULL with the reason in `err` when the profile cannot be used.
 */
bt_ts* bt_ts_start(const char* id, bt_store* store, wg_device* dev, const bt_ts_hooks* hooks,
                   uint64_t now_ns, char* err, size_t errlen);

/* Closes every connection, drops the peers from `dev`, wipes the keys and frees `ts`. */
void bt_ts_stop(bt_ts* ts);

/* The engine's upcall for everything that goes to a peer: through the relay the node is reached
 * by. `ts` is what the tunnel keeps; the tunnel's own upcall forwards here. */
void bt_ts_send_peer(bt_ts* ts, wg_peer* p, const uint8_t* msg, size_t len);

/*
 * A packet from the tun the engine had no peer for (WG_DROP_NO_ROUTE): the node that owns its
 * destination becomes a peer. 1 when it did - send the packet again; 0 when no node owns it.
 */
int bt_ts_no_route(bt_ts* ts, const uint8_t* pkt, size_t len, uint64_t now_ns);

/*
 * MagicDNS's resolver: a packet from the tun to 100.100.100.100 (or fd7a:115c:a1e0::53) port 53,
 * while MagicDNS is on - answered (hooks.to_tun) or forwarded upstream. 1 when it was one (not for
 * the engine); 0 for anything else, and for everything while MagicDNS is off.
 */
int bt_ts_dns(bt_ts* ts, const uint8_t* pkt, size_t len, uint64_t now_ns);

/* MagicDNS on: 1 and its search domains (space-separated, its own domain first) into `search`. */
int bt_ts_magic_dns(const bt_ts* ts, char* search, size_t cap);

/* The loop, as bt_tunnels_*: the fds with what they wait for, an fd's revents, the timers, and a
 * network change (reconnect now: the old paths are gone). bt_ts_net_event: any event of the network,
 * moved or not - our own addresses for direct paths (section 11a) may have changed with it. */
int      bt_ts_pollfds(bt_ts* ts, struct pollfd* out, int cap);
int      bt_ts_owns(const bt_ts* ts, int fd);
void     bt_ts_io(bt_ts* ts, const struct pollfd* pfd);
uint64_t bt_ts_tick(bt_ts* ts, uint64_t now_ns);
void     bt_ts_net_changed(bt_ts* ts, uint64_t now_ns);
void     bt_ts_net_event(bt_ts* ts, uint64_t now_ns);

/* Where it stands, for the tunnel's state: the status and, when there is one, a reason word
 * (control, relay, approval, login, expired, removed - the node is gone from the tailnet, browser - a
 * login link waits to be opened, bt_ts_describe's auth_url) and a line for the log and the screens. The tunnel
 * asks on every turn of its loop - never from inside this module: a stopped one it frees. */
bt_ts_status bt_ts_state(const bt_ts* ts, const char** reason, const char** detail);

/* For the clients: the tailnet, our name and addresses, the home relay (profile.get and status). */
void bt_ts_describe(const bt_ts* ts, bt_writer* w);

/* The netmap's nodes for the clients (tailscale.nodes): how many, and node i's fields into `w` -
 * its name, addresses, online, expired, whether it is a peer with a session, its traffic. */
size_t bt_ts_node_count(const bt_ts* ts);
void   bt_ts_node_put(const bt_ts* ts, size_t i, bt_writer* w);

#endif /* BT_TAILSCALE_H */
