/*
 * bt_plat - what the daemon needs from the system (docs/DAEMON.md, sections 4-7), one backend per
 * platform: bt_plat_linux.c (WSL: development and the netns tests) and bt_plat_qnx.c (the phone).
 * Everything above this line is the same code on both.
 *
 *   tun        a tun device: open, address, MTU, up; packets in and out WITHOUT framing - the
 *              backend adds and strips its own (Linux: none, IFF_NO_PI; QNX: the 4-byte address
 *              family header, AF_INET6 = 24)
 *   routes     a prefix to a tun device, in the table the phone's apps use (QNX: FIB 0)
 *   egress     a UDP socket that never goes into our tunnels, whatever routes they add
 *              (Linux: SO_BINDTODEVICE to the interface of the default route), or - the third way
 *              of section 5 - host routes through the physical gateway to every address such
 *              sockets send to
 *   DNS        the system resolver's servers: set ours, put the system's back, and know the
 *              physical network's servers even while ours are set
 *   network    fds to poll; after they fire, whether something that matters changed (default
 *              route, addresses, links, the system's DNS)
 *   status bar the system's VPN key
 *
 * Calls return 1 on success, 0 on failure with errno set, like the rest of the daemon. Non-blocking
 * fds throughout.
 */

#ifndef BT_PLAT_H
#define BT_PLAT_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "bt_resolve.h"

#define BT_IFNAME_MAX       16
#define BT_DNS_TEXT_MAX     4096        /* a saved system DNS setting, as the backend keeps it */

typedef struct {
    const char* dns_file;               /* Linux: the resolv.conf the daemon owns (required there) */
    const char* egress;                 /* "auto" (NULL), "fib", "bind" or "hostroute" - see the backends */
} bt_plat_opts;

int  bt_plat_init(const bt_plat_opts* o);
void bt_plat_fini(void);

/* --- tun --------------------------------------------------------------------------------- */

/* A free tun device; its name into `ifname`. Returns the fd, -1 on failure. */
int  bt_tun_open(char ifname[BT_IFNAME_MAX]);
void bt_tun_close(int fd, const char* ifname);

/* One packet, framing stripped: its length; 0 when there is nothing to read; -1 on error. */
ssize_t bt_tun_read(int fd, uint8_t* pkt, size_t cap);

/* One IP packet (version from its first byte): 1 when written. */
int bt_tun_write(int fd, const uint8_t* pkt, size_t len);

/* An address with its prefix length (family 4 or 6) - on the interface, or off it again. */
int bt_if_addr(const char* ifname, int family, const uint8_t* addr, int cidr);
int bt_if_addr_del(const char* ifname, int family, const uint8_t* addr, int cidr);
int bt_if_mtu(const char* ifname, int mtu);
int bt_if_up(const char* ifname);

/* --- routes ------------------------------------------------------------------------------ */

/* add: 1 also when it is there already; delete: 1 also when it is gone already. */
int bt_route(int add, const char* ifname, int family, const uint8_t* addr, int cidr);

/* Every route through `ifname` - after a crash, when the journal names a tun device that may
 * still have them. */
int bt_routes_flush(const char* ifname);

/* --- egress ------------------------------------------------------------------------------ */

/* A UDP socket of `family` bound to `port` (0: any) that bypasses every tunnel: its fd. -1 on
 * failure; errno ENETUNREACH when there is no physical network for that family now (no default
 * route) - try again after the next change. */
int bt_udp_open(int family, uint16_t port);

/* The interface the physical default route of `family` uses; 0 when there is none. */
int bt_default_if(int family, char ifname[BT_IFNAME_MAX]);

/*
 * Host routes (section 5, the third way): the remote addresses our sockets send to that a tunnel's
 * routes would catch - the peers' endpoints, and the resolvers while a name is being looked up.
 * Where the backend keeps its sockets out of the tunnels this way (Linux and QNX: --egress
 * hostroute; QNX auto: when FIB 15 is not there), each gets a host route through the physical
 * default gateway, marked as ours; an address inside an interface's own subnet needs none. The
 * ones not asked for any more go. Elsewhere this does nothing. Pass the whole set whenever it may
 * have changed - before anything is sent to a new one; `recheck` after a network change: the
 * gateway may have moved, the network manager may have wiped them.
 */
#define BT_BYPASS_MAX       64

int    bt_bypass_set(const bt_addr* addrs, size_t n, int recheck);

/* The host routes of ours in now, for the crash journal. */
size_t bt_bypass_list(bt_addr* out, size_t cap);

/* After a crash: the host route to `a` goes - if it is one of ours. */
int    bt_bypass_drop(const bt_addr* a);

/* --- DNS --------------------------------------------------------------------------------- */

/* The physical network's resolvers - never ours, even while ours are set. */
size_t bt_dns_system(bt_addr* out, size_t cap);

/* Ours: `servers` and the search domains (space-separated, may be ""). Remembers what the system
 * had, the first time. */
int bt_dns_apply(const bt_addr* servers, size_t n, const char* search);

/* The system's resolvers back, as the system has them NOW (the network may have changed since
 * ours went in). */
int bt_dns_restore(void);

/* The system's setting as text, for the crash journal, and back from it after a crash. */
size_t bt_dns_snapshot(char* out, size_t cap);
int    bt_dns_restore_text(const char* text);

/* --- network changes --------------------------------------------------------------------- */

/* The fds to poll for changes (into `out`, at most `cap`); returns how many. */
int bt_net_fds(struct pollfd* out, int cap);

/* After one of them fired: drains it; 1 when something that matters changed. */
int bt_net_event(const struct pollfd* pfd);

/* When the backend wants a look without an fd firing (QNX: _CS_RESOLVE has no notification, so
 * while ours are in it is read every few seconds); BT_NEVER for never. At or after it,
 * bt_net_check - 1 when something that matters changed, as bt_net_event. */
uint64_t bt_net_deadline(void);
int      bt_net_check(uint64_t now);

/* --- the status bar ---------------------------------------------------------------------- */

/* The system's VPN key: "off", "on" or "connected" (docs/DAEMON.md, section 10a). Elsewhere than
 * on the phone this does nothing and returns 1. */
int bt_status_icon(const char* state);

#endif /* BT_PLAT_H */
