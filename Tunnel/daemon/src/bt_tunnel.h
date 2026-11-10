/*
 * bt_tunnel - the tunnels the daemon holds up (docs/DAEMON.md, sections 4-7, 9, 10): for each, a
 * profile's .conf parsed into an engine device, a tun device with its addresses and MTU, the routes
 * of its AllowedIPs, sockets that bypass the tunnels (for the peers and for DNS lookups of their
 * names; where the backend does that by host routes, the addresses those sockets send to), the
 * DNS it may own, and what the UI sees - a state with a reason.
 *
 *   down          (not in the table)
 *   connecting    set up, no handshake yet
 *   up            a handshake younger than RejectAfterTime
 *   reconnecting  it was up; the network changed or the session aged - routes stay, nothing leaks
 *   error         could not be set up; `reason` says why, the entry stays until tunnel.down
 *
 * Reasons: conf, conflict (a second full tunnel), tun, route, no_network, resolve, handshake.
 *
 * Rules across tunnels: at most BT_TUNNELS_MAX (the phone has /dev/tun0-3); at most one holds the
 * default route per family; DNS belongs to the tunnel with the default route, else to the one
 * that came up last.
 *
 * Single-threaded; the daemon's loop drives it with pollfds, io, tick and net_changed.
 */

#ifndef BT_TUNNEL_H
#define BT_TUNNEL_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include "bt_plat.h"
#include "bt_proto.h"
#include "bt_store.h"

#define BT_TUNNELS_MAX      4
#define BT_TS_MARGIN_SEC    600         /* the handshake timestamp ceiling runs this far ahead */

typedef enum {
    BT_TS_DOWN = 0,
    BT_TS_CONNECTING,
    BT_TS_UP,
    BT_TS_RECONNECTING,
    BT_TS_ERROR
} bt_tstate;

const char* bt_tstate_name(bt_tstate s);

typedef struct bt_tunnel bt_tunnel;

typedef struct {
    void (*changed)(bt_tunnel* t);      /* state or reason changed: tell the clients */
    void (*applied)(void);              /* routes or DNS changed: rewrite the crash journal */
} bt_tunnel_hooks;

/* The monotonic clock and the wall clock (with the test offset) the whole daemon uses. */
uint64_t bt_now_ns(void);
void     bt_wall(uint64_t* sec, uint32_t* nsec);
extern int64_t bt_clock_offset_sec;     /* test hook: --clock-offset */

void bt_tunnels_init(bt_store* store, const bt_tunnel_hooks* hooks);

/* Brings a profile up (or reports what stops it). 1 when it is set up and connecting - or was
 * already up; 0 with a reason in the tunnel's state (error entry) or, when not even an entry could
 * be made, in `err`. */
int  bt_tunnel_up(const char* id, char* err, size_t errlen);

/* Takes it down and out of the table; 0 when it was not there. */
int  bt_tunnel_down(const char* id);
void bt_tunnels_down_all(void);

bt_tunnel* bt_tunnel_find(const char* id);
bt_tunnel* bt_tunnel_at(int i);                     /* NULL for a free slot */

/* A Tailscale tunnel's other half (bt_tailscale), NULL for any other or one not up. */
struct bt_ts* bt_tunnel_ts(const bt_tunnel* t);

/* What the clients see. */
void bt_tunnel_describe(const bt_tunnel* t, bt_writer* w);          /* state and reason */
void bt_tunnel_stats(const bt_tunnel* t, bt_writer* w);             /* counters, handshake, endpoint */
const char* bt_tunnel_id(const bt_tunnel* t);
bt_tstate   bt_tunnel_state(const bt_tunnel* t);

/* The loop. `owner[i]` of each pollfd returned is what io needs back. */
int      bt_tunnels_pollfds(struct pollfd* out, void** owner, int cap);
void     bt_tunnels_io(struct pollfd* pfd, void* owner);
uint64_t bt_tunnels_tick(uint64_t now_ns);          /* the next deadline */
void     bt_tunnels_net_changed(uint64_t now_ns);   /* after a (debounced) network change */

/* What is applied to the system, for the crash journal: tunnel=, dns= and bypass= (a host route
 * to a server, section 5) lines. */
void bt_tunnels_journal(bt_writer* w);

#endif /* BT_TUNNEL_H */
