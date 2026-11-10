/*
 * bt_plat for QNX: the phone (BB10 10.3, io-pkt - a NetBSD stack with QNX additions). See bt_plat.h.
 * Written from the SDK headers and what the probe already confirmed (docs/PLAN.md section 2);
 * what nobody has run on the phone yet is marked [phone] and has a fallback next to it.
 *
 *   tun       /dev/tun0-3, NetBSD tun(4): TUNSIFMODE point-to-point, TUNSIFHEAD - every packet
 *             carries a 4-byte address family in network order (AF_INET6 = 24 here). The
 *             interface is destroyed on close, which takes its addresses and routes with it
 *   routes    PF_ROUTE messages (rt_msghdr is 76 bytes here), gateway = the tun's link address
 *             (`route add -interface`), in FIB 0 - the personal perimeter. A delete removes only a
 *             route that leaves through our interface: a LAN route with the same prefix, which
 *             made our add answer EEXIST, stays
 *   egress    auto: SO_SETFIB 15 when FIB 15 has a default route of the family (the system keeps
 *             one there, dhclient runs in it) AND SO_BINDTODEVICE to that default's interface;
 *             either layer alone keeps the socket out of our /1 routes. Without FIB 15: host
 *             routes to the servers through the FIB 0 default gateway (RTF_PROTO2 marks them
 *             ours) AND SO_BINDTODEVICE, if it takes - with the host route in, the two agree.
 *             --egress fib|bind|hostroute: one of the three only  [phone]
 *   DNS       PPS status_public, its "nameservers" and "searchdomains": what BB10's resolver reads
 *             (libsocket, re-read on change; PLAN section 0, 2026-10-16). The network manager
 *             (net_pps) owns the object: we put the two attributes in, keep its values to give back,
 *             and put ours in again when it writes over them. Also confstr(_CS_SET | _CS_RESOLVE),
 *             "_" between words ("nameserver_192.168.1.1") - net_pps keeps that copy for old
 *             programs; the resolver does not read it. The physical network's servers come from
 *             status_public (never ours), else from the last _CS_RESOLVE the system wrote
 *   network   a PF_ROUTE socket (routes, addresses, links - not our own doings), PPS
 *             status_public?wait, and while our DNS is in, a look at _CS_RESOLVE every few
 *             seconds (bt_net_deadline): confstr has no notification, and the network manager
 *             may write it after its PPS event
 *   status bar the PPS object the navigator draws the VPN key from
 */

#include "bt_plat.h"
#include "bt_log.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_tun.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TUN_UNITS       4               /* /dev/tun0-3 */
#define TUN_MTU_MIN     576             /* SIOCSIFMTU range of NetBSD tun */
#define TUN_MTU_MAX     1500            /* ... and tunwrite refuses more than TUNMTU */
#define FIB_EGRESS      15              /* all_fib: its own default, kept by the system */
#define PPS_STATUS      "/pps/services/networking/status_public"
#define PPS_VPN_ICON    "/pps/system/navigator/status/vpn"
#define PPS_NS_MAX      8
#define PPS_SEARCH_MAX  256             /* the resolver's search list: 256 characters */
#define PPS_FIGHT_MAX   10              /* net_pps writing over ours this often in ... */
#define PPS_FIGHT_NS    (60 * 1000000000ULL)    /* ... a minute: we leave the object to it */
#define DNS_CHECK_NS    (5 * 1000000000ULL)
#define RT_REPLY_MS     1000

/* BSD sockaddrs in a routing message are padded to a long boundary. */
#define RT_ROUNDUP(a)   ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

enum { EG_AUTO, EG_FIB, EG_BIND, EG_HOSTROUTE };

/* What a routing reply says of a route. */
typedef struct {
    unsigned idx;                       /* its interface */
    int      flags;
    uint8_t  gw[64];                    /* RTA_GATEWAY as the kernel gave it: sockaddr_in, _in6, _dl */
    size_t   gw_len;
} rt_info;

/* A host route to a server. */
typedef struct {
    bt_addr  a;
    rt_info  via;                       /* the default route it went through */
    int      mine;                      /* we put it in; else one was there already - never ours to delete */
} pin;

#define PIN_MARK        (RTF_STATIC | RTF_PROTO2)

static struct {
    int      egress;                    /* EG_* */
    int      rt_req;                    /* requests in FIB 0 */
    int      rt_req15;                  /* RTM_GET in FIB 15: -1 not yet, -2 refused */
    int      rt_mon;                    /* change messages */
    int      pps;                       /* status_public?wait, -1 without it */
    int      seq;
    pid_t    pid;
    int      tun_used[TUN_UNITS];
    unsigned tun_idx[8];                /* the interface indexes our tun devices had, the latest ones */
    unsigned tun_idx_next;
    char     method[2][64];             /* the last egress method per family, for the log */
    bt_addr  pps_ns[PPS_NS_MAX];        /* the network manager's resolvers */
    size_t   pps_n;
    char     pps_search[PPS_SEARCH_MAX];/* ... its search domains, as it wrote them */
    char     pps_if[BT_IFNAME_MAX];     /* ... and its default interface */
    int      pps_ours_in;               /* ours are in status_public now */
    bt_addr  pps_ours[PPS_NS_MAX];      /* ... these */
    size_t   pps_ours_n;
    char     pps_ours_search[PPS_SEARCH_MAX];
    int      pps_given_up;              /* net_pps kept writing over ours: status_public is left to it */
    unsigned pps_fights;
    uint64_t pps_fight_since;
    char     sys_text[BT_DNS_TEXT_MAX]; /* _CS_RESOLVE as the system wrote it, the last we saw */
    char     our_text[BT_DNS_TEXT_MAX]; /* ours as it reads back; "" = ours are not in */
    uint64_t check_due;
    int      pin_fam[2];                /* host routes keep IPv4 [0] / IPv6 [1] sockets out */
    pin      pins[BT_BYPASS_MAX];
    size_t   n_pins;
} P;

/* --------------------------------------------------------------------- small helpers */

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int nonblock_cloexec(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);

    fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        int one = 1;
        return ioctl(fd, FIONBIO, &one) == 0;
    }
    return 1;
}

static void close_keep_errno(int fd)
{
    int e = errno;
    close(fd);
    errno = e;
}

static void set_ifname(char* dst, const char* name)
{
    size_t n = strlen(name);
    if (n >= IFNAMSIZ) n = IFNAMSIZ - 1;
    memset(dst, 0, IFNAMSIZ);
    memcpy(dst, name, n);
}

static int is_tun(const char* name)
{
    return strncmp(name, "tun", 3) == 0;
}

/* Whether an interface index is a tun device of ours: by its name while it lives; once it is gone
 * (the messages of its own removal), by the indexes our devices had. */
static int index_is_tun(unsigned idx)
{
    char name[IFNAMSIZ];
    size_t i;

    if (!idx) return 0;
    if (if_indextoname(idx, name)) return is_tun(name);
    for (i = 0; i < sizeof(P.tun_idx) / sizeof(P.tun_idx[0]); i++)
        if (P.tun_idx[i] == idx) return 1;
    return 0;
}

static int family_af(int family)
{
    return family == 4 ? AF_INET : AF_INET6;
}

/* --------------------------------------------------------------------- sockaddrs */

typedef union {
    struct sockaddr     sa;
    struct sockaddr_in  in;
    struct sockaddr_in6 in6;
    struct sockaddr_dl  dl;
} sa_any;

static void sa_ip(sa_any* s, int family, const uint8_t* addr)
{
    memset(s, 0, sizeof(*s));
    if (family == 4) {
        s->in.sin_len = sizeof(s->in);
        s->in.sin_family = AF_INET;
        if (addr) memcpy(&s->in.sin_addr, addr, 4);
    } else {
        s->in6.sin6_len = sizeof(s->in6);
        s->in6.sin6_family = AF_INET6;
        if (addr) memcpy(&s->in6.sin6_addr, addr, 16);
    }
}

static void mask_bytes(uint8_t m[16], int cidr)
{
    int b;
    memset(m, 0, 16);
    for (b = 0; b < cidr && b < 128; b++) m[b / 8] |= (uint8_t)(0x80 >> (b % 8));
}

static void sa_mask(sa_any* s, int family, int cidr)
{
    uint8_t m[16];
    mask_bytes(m, cidr);
    sa_ip(s, family, m);
}

static void sa_link(sa_any* s, unsigned idx, const char* ifname)
{
    size_t n = strlen(ifname);

    memset(s, 0, sizeof(*s));
    s->dl.sdl_len = sizeof(s->dl);
    s->dl.sdl_family = AF_LINK;
    s->dl.sdl_index = (uint16_t)idx;
    if (n > sizeof(s->dl.sdl_data)) n = sizeof(s->dl.sdl_data);
    s->dl.sdl_nlen = (u_char)n;
    memcpy(s->dl.sdl_data, ifname, n);
}

/* --------------------------------------------------------------------- routing socket */

typedef struct {
    struct rt_msghdr h;
    char             space[512];
} rt_msg;

static void rt_init(rt_msg* m, int type, int flags)
{
    memset(m, 0, sizeof(*m));
    m->h.rtm_version = RTM_VERSION;
    m->h.rtm_type = (u_char)type;
    m->h.rtm_flags = flags;
    m->h.rtm_pid = P.pid;
    m->h.rtm_seq = ++P.seq;
    m->h.rtm_msglen = sizeof(m->h);
}

/* Sockaddrs go in the order of their RTA_ bits; raw: one as a reply gave it (a gateway). */
static void rt_put_raw(rt_msg* m, int bit, const void* sa, size_t len)
{
    size_t room = RT_ROUNDUP(len);
    char* p = (char*)m + m->h.rtm_msglen;

    if (m->h.rtm_msglen + room > sizeof(*m)) return;
    memset(p, 0, room);
    memcpy(p, sa, len);
    m->h.rtm_msglen = (u_short)(m->h.rtm_msglen + room);
    m->h.rtm_addrs |= bit;
}

static void rt_put(rt_msg* m, int bit, const sa_any* s)
{
    rt_put_raw(m, bit, s, s->sa.sa_len);
}

/*
 * One message on a request socket: 0, or the negative errno. An RTM_GET waits for its reply (into
 * `m`). Every routing socket also hears what everybody else does, so what piled up is drained
 * first and foreign messages are skipped while waiting.
 */
static int rt_talk(int fd, rt_msg* m)
{
    char junk[2048];
    int seq = m->h.rtm_seq;
    uint64_t until;

    for (;;) {
        ssize_t n = read(fd, junk, sizeof(junk));
        if (n > 0 || (n < 0 && errno == EINTR)) continue;
        break;
    }
    if (write(fd, m, m->h.rtm_msglen) < 0) return -errno;
    if (m->h.rtm_type != RTM_GET) return 0;

    until = mono_ns() + RT_REPLY_MS * 1000000ULL;
    for (;;) {
        struct pollfd pfd;
        uint64_t now = mono_ns();
        ssize_t n;

        if (now >= until) return -ETIMEDOUT;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, (int)((until - now) / 1000000ULL) + 1) < 0 && errno != EINTR) return -errno;
        n = read(fd, m, sizeof(*m));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOBUFS) continue;
            return -errno;
        }
        if (n < (ssize_t)sizeof(m->h) || m->h.rtm_version != RTM_VERSION) continue;
        if (m->h.rtm_type == RTM_GET && m->h.rtm_pid == P.pid && m->h.rtm_seq == seq)
            return m->h.rtm_errno ? -m->h.rtm_errno : 0;
    }
}

/* The prefix length of a netmask sockaddr from a reply (possibly shortened, family 0). */
static int mask_len(const struct sockaddr* sa, int family)
{
    size_t off = family == 4 ? offsetof(struct sockaddr_in, sin_addr) : offsetof(struct sockaddr_in6, sin6_addr);
    size_t end = off + (family == 4 ? 4 : 16), i;
    const uint8_t* p = (const uint8_t*)sa;
    int bits = 0;

    if (sa->sa_len < end) end = sa->sa_len;
    for (i = off; i < end; i++) {
        uint8_t b = p[i];
        while (b & 0x80) {
            bits++;
            b = (uint8_t)(b << 1);
        }
        if (p[i] != 0xff) break;
    }
    return bits;
}

/* The sockaddrs after a routing message header, by RTAX_ index; NULL where absent. */
static void rt_addrs(const struct rt_msghdr* h, size_t len, const struct sockaddr* sa[RTAX_MAX])
{
    const char* p = (const char*)(h + 1);
    const char* end = (const char*)h + len;
    int i;

    for (i = 0; i < RTAX_MAX; i++) {
        sa[i] = NULL;
        if (!(h->rtm_addrs & (1 << i))) continue;
        if (p + 2 > end || p + ((const struct sockaddr*)p)->sa_len > end) break;
        sa[i] = (const struct sockaddr*)p;
        p += RT_ROUNDUP(sa[i]->sa_len);
    }
    for (; i < RTAX_MAX; i++) sa[i] = NULL;
}

static void rt_info_from(const struct rt_msghdr* h, size_t len, rt_info* out)
{
    const struct sockaddr* sa[RTAX_MAX];

    rt_addrs(h, len, sa);
    memset(out, 0, sizeof(*out));
    out->idx = h->rtm_index;
    out->flags = h->rtm_flags;
    if (sa[RTAX_GATEWAY] && sa[RTAX_GATEWAY]->sa_len) {
        out->gw_len = sa[RTAX_GATEWAY]->sa_len < sizeof(out->gw) ? sa[RTAX_GATEWAY]->sa_len : sizeof(out->gw);
        memcpy(out->gw, sa[RTAX_GATEWAY], out->gw_len);
    }
}

/*
 * The route the table has for exactly this prefix (a host route when cidr is the full length):
 * 0 with what it says of it (`out` may be NULL), or the negative errno (-ESRCH: none; -EDOM: the
 * answer was a covering route - should io-pkt answer RTM_GET by longest match [phone]).
 */
static int rt_get(int fd, int family, const uint8_t* addr, int cidr, rt_info* out)
{
    rt_msg m;
    sa_any s;
    const struct sockaddr* sa[RTAX_MAX];
    int full = cidr == (family == 4 ? 32 : 128), r;
    size_t len;

    rt_init(&m, RTM_GET, RTF_UP | (full ? RTF_HOST : 0));
    sa_ip(&s, family, addr);
    rt_put(&m, RTA_DST, &s);
    if (!full) {
        sa_mask(&s, family, cidr);
        rt_put(&m, RTA_NETMASK, &s);
    }
    r = rt_talk(fd, &m);
    if (r < 0) return r;

    /* A covering route is not the one asked about. */
    if (full != !!(m.h.rtm_flags & RTF_HOST)) return -EDOM;
    len = m.h.rtm_msglen < sizeof(m) ? m.h.rtm_msglen : sizeof(m);
    rt_addrs(&m.h, len, sa);
    if (!full && sa[RTAX_NETMASK] && mask_len(sa[RTAX_NETMASK], family) != cidr) return -EDOM;
    if (out) rt_info_from(&m.h, len, out);
    return 0;
}

/* RTM_ADD / RTM_DELETE of a prefix to an interface: 0 or the negative errno. `gw_addr` NULL: the
 * interface's link address (route add -interface); else that address of the interface. */
static int rt_change(int type, int family, const uint8_t* addr, int cidr, unsigned idx, const char* ifname,
                     const uint8_t* gw_addr)
{
    rt_msg m;
    sa_any s;
    int full = cidr == (family == 4 ? 32 : 128);

    rt_init(&m, type, RTF_UP | RTF_STATIC | (full ? RTF_HOST : 0));
    sa_ip(&s, family, addr);
    rt_put(&m, RTA_DST, &s);
    if (gw_addr) sa_ip(&s, family, gw_addr);
    else sa_link(&s, idx, ifname);
    rt_put(&m, RTA_GATEWAY, &s);
    if (!full) {
        sa_mask(&s, family, cidr);
        rt_put(&m, RTA_NETMASK, &s);
    }
    return rt_talk(P.rt_req, &m);
}

/* An address of `family` on the interface - the second way to name it as a gateway. */
static int if_own_addr(const char* ifname, int family, uint8_t out[16])
{
    struct ifaddrs *ifa, *p;
    int found = 0;

    if (getifaddrs(&ifa) != 0) return 0;
    for (p = ifa; p && !found; p = p->ifa_next) {
        if (!p->ifa_addr || strcmp(p->ifa_name, ifname) != 0) continue;
        if (family == 4 && p->ifa_addr->sa_family == AF_INET) {
            memcpy(out, &((struct sockaddr_in*)p->ifa_addr)->sin_addr, 4);
            found = 1;
        } else if (family == 6 && p->ifa_addr->sa_family == AF_INET6) {
            const uint8_t* a = (const uint8_t*)&((struct sockaddr_in6*)p->ifa_addr)->sin6_addr;
            if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) continue;        /* link-local: needs a scope */
            memcpy(out, a, 16);
            found = 1;
        }
    }
    freeifaddrs(ifa);
    return found;
}

int bt_route(int add, const char* ifname, int family, const uint8_t* addr, int cidr)
{
    unsigned idx = if_nametoindex(ifname);
    rt_info have;
    int r;

    if (!add) {
        if (!idx) return 1;                         /* the interface is gone, its routes with it */
        r = rt_get(P.rt_req, family, addr, cidr, &have);
        if (r == -ESRCH || r == -EDOM || (r == 0 && have.idx != idx)) return 1;     /* gone, or not ours */
        if (r == 0) r = rt_change(RTM_DELETE, family, addr, cidr, idx, ifname, NULL);
        if (r == 0 || r == -ESRCH) return 1;
        errno = -r;
        return 0;
    }
    if (!idx) {
        errno = ENXIO;
        return 0;
    }
    r = rt_change(RTM_ADD, family, addr, cidr, idx, ifname, NULL);
    if (r != 0 && r != -EEXIST) {
        /* [phone] if io-pkt will not take a link gateway: the tun's own address, as the probe did */
        uint8_t own[16];
        if (if_own_addr(ifname, family, own)) {
            int r2 = rt_change(RTM_ADD, family, addr, cidr, idx, ifname, own);
            BT_D("route via %s: link gateway %s, own address %s", ifname, strerror(-r), r2 ? strerror(-r2) : "ok");
            r = r2;
        }
    }
    if (r == 0 || r == -EEXIST) return 1;
    errno = -r;
    return 0;
}

/* The routing table of one family as rt_msghdr entries (malloc'ed; NULL on failure). */
static char* dump_fetch(int af, size_t* len)
{
    int mib[6] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0 };
    char* buf;

    mib[3] = af;
    *len = 0;
    if (sysctl(mib, 6, NULL, len, NULL, 0) < 0 || !*len) return NULL;
    *len += *len / 2 + 4096;                        /* the table may grow in between */
    buf = (char*)malloc(*len);
    if (!buf) return NULL;
    if (sysctl(mib, 6, buf, len, NULL, 0) < 0) {
        free(buf);
        return NULL;
    }
    return buf;
}

/* The default route of a family from a table dump: 1 and what it says of it, 0 when there is
 * none. For when RTM_GET answers with our /1 instead [phone]. */
static int default_from_dump(int family, rt_info* out)
{
    static const uint8_t zero[16] = { 0 };
    size_t len;
    char* buf = dump_fetch(family_af(family), &len);
    char* p;
    int found = 0;

    if (!buf) return 0;
    for (p = buf; !found && p + sizeof(struct rt_msghdr) <= buf + len;) {
        const struct rt_msghdr* h = (const struct rt_msghdr*)p;
        const struct sockaddr* sa[RTAX_MAX];
        const struct sockaddr* dst;
        int dst_zero = 0;

        if (h->rtm_msglen < sizeof(*h) || p + h->rtm_msglen > buf + len) break;
        p += h->rtm_msglen;
        if (h->rtm_version != RTM_VERSION || (h->rtm_flags & (RTF_HOST | RTF_REJECT | RTF_BLACKHOLE))) continue;
        rt_addrs(h, h->rtm_msglen, sa);
        dst = sa[RTAX_DST];
        if (dst && family == 4 && dst->sa_family == AF_INET)
            dst_zero = memcmp(&((const struct sockaddr_in*)dst)->sin_addr, zero, 4) == 0;
        else if (dst && family == 6 && dst->sa_family == AF_INET6)
            dst_zero = memcmp(&((const struct sockaddr_in6*)dst)->sin6_addr, zero, 16) == 0;
        if (!dst_zero || (sa[RTAX_NETMASK] && mask_len(sa[RTAX_NETMASK], family) != 0)) continue;
        if (!h->rtm_index || index_is_tun(h->rtm_index)) continue;
        rt_info_from(h, h->rtm_msglen, out);
        found = 1;
    }
    free(buf);
    return found;
}

/* Every route through interface `idx` of one family, from a table dump. */
static int routes_drop_dump(unsigned idx, int af)
{
    size_t len;
    char* buf = dump_fetch(af, &len);
    char* p;
    int dropped = 0;

    if (!buf) return 0;
    for (p = buf; p + sizeof(struct rt_msghdr) <= buf + len;) {
        const struct rt_msghdr* h = (const struct rt_msghdr*)p;
        rt_msg m;

        if (h->rtm_msglen < sizeof(*h) || p + h->rtm_msglen > buf + len) break;
        if (h->rtm_version == RTM_VERSION && h->rtm_index == idx && h->rtm_msglen <= sizeof(m)) {
            memcpy(&m, h, h->rtm_msglen);           /* what `route flush` does: the entry back as a delete */
            m.h.rtm_type = RTM_DELETE;
            m.h.rtm_pid = P.pid;
            m.h.rtm_seq = ++P.seq;
            if (rt_talk(P.rt_req, &m) == 0) dropped++;
        }
        p += h->rtm_msglen;
    }
    free(buf);
    return dropped;
}

/* --------------------------------------------------------------------- interfaces */

static int if_sock(int af)
{
    int s = socket(af, SOCK_DGRAM, 0);
    if (s >= 0) fcntl(s, F_SETFD, FD_CLOEXEC);
    return s;
}

static int if_flags_set(const char* ifname, int set, int clear)
{
    struct ifreq ifr;
    int s = if_sock(AF_INET), ok = 0;

    if (s < 0) return 0;
    memset(&ifr, 0, sizeof(ifr));
    set_ifname(ifr.ifr_name, ifname);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        /* QNX widened ifr_flags to int */
        ifr.ifr_flags = (ifr.ifr_flags | set) & ~clear;
        ok = ioctl(s, SIOCSIFFLAGS, &ifr) == 0;
    }
    close_keep_errno(s);
    return ok;
}

static int if_destroy(const char* ifname)
{
    struct ifreq ifr;
    int s = if_sock(AF_INET), ok;

    if (s < 0) return 0;
    memset(&ifr, 0, sizeof(ifr));
    set_ifname(ifr.ifr_name, ifname);
    ok = ioctl(s, SIOCIFDESTROY, &ifr) == 0;
    close_keep_errno(s);
    return ok;
}

/* Every address on the interface - a device left over by a crash still has the old ones. */
static void if_addrs_clear(const char* ifname)
{
    struct ifaddrs *ifa, *p;
    int s4 = -1, s6 = -1;

    if (getifaddrs(&ifa) != 0) return;
    for (p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || strcmp(p->ifa_name, ifname) != 0) continue;
        if (p->ifa_addr->sa_family == AF_INET) {
            struct ifreq ifr;
            if (s4 < 0) s4 = if_sock(AF_INET);
            if (s4 < 0) continue;
            memset(&ifr, 0, sizeof(ifr));
            set_ifname(ifr.ifr_name, ifname);
            memcpy(&ifr.ifr_addr, p->ifa_addr, sizeof(struct sockaddr_in));
            ioctl(s4, SIOCDIFADDR, &ifr);
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            struct in6_ifreq ifr6;
            if (s6 < 0) s6 = if_sock(AF_INET6);
            if (s6 < 0) continue;
            memset(&ifr6, 0, sizeof(ifr6));
            set_ifname(ifr6.ifr_name, ifname);
            memcpy(&ifr6.ifr_addr, p->ifa_addr, sizeof(struct sockaddr_in6));
            ioctl(s6, SIOCDIFADDR_IN6, &ifr6);
        }
    }
    freeifaddrs(ifa);
    if (s4 >= 0) close(s4);
    if (s6 >= 0) close(s6);
}

int bt_routes_flush(const char* ifname)
{
    unsigned idx = if_nametoindex(ifname);
    int n;

    if (!is_tun(ifname)) {                          /* only ever a tun device of ours */
        errno = EINVAL;
        return 0;
    }
    if (!idx) return 1;
    n = routes_drop_dump(idx, AF_INET) + routes_drop_dump(idx, AF_INET6);
    if (n) BT_D("%s: %d route(s) dropped", ifname, n);
    /* The device itself, and with it whatever the dump did not show (another FIB). */
    if (!if_destroy(ifname)) {
        BT_D("%s: SIOCIFDESTROY: %s; down and without addresses instead", ifname, strerror(errno));
        if_flags_set(ifname, 0, IFF_UP);
        if_addrs_clear(ifname);
    }
    return 1;
}

/* --------------------------------------------------------------------- tun */

int bt_tun_open(char ifname[BT_IFNAME_MAX])
{
    int unit, last = ENODEV;
    char refused[160] = "";                         /* units the system did not give, for the log */

    for (unit = 0; unit < TUN_UNITS; unit++) {
        char path[16], name[IFNAMSIZ];
        int fd, v;

        if (P.tun_used[unit]) continue;             /* a second open may succeed on io-pkt [phone] */
        snprintf(path, sizeof(path), "/dev/tun%d", unit);
        snprintf(name, sizeof(name), "tun%d", unit);
        fd = open(path, O_RDWR);
        if (fd < 0) {
            int e = errno;
            size_t n = strlen(refused);
            if (e != ENOENT) last = e;              /* EBUSY: someone else's */
            /* On the Passport tun0 is the system's TunnelManager's from boot: Resource busy, no
             * interface (2026-10-15) - ours start at tun1. */
            snprintf(refused + n, sizeof(refused) - n, "%s%s: %s, %s", n ? "; " : "", name, strerror(e),
                     if_nametoindex(name) ? "the interface exists" : "no interface");
            continue;
        }
        if (!nonblock_cloexec(fd)) {
            last = errno;
            close(fd);
            continue;
        }
        /* Left over by a crash without a journal: TUNSIFMODE is refused while up. */
        if_flags_set(name, 0, IFF_UP);
        if_addrs_clear(name);
        v = IFF_POINTOPOINT | IFF_MULTICAST;
        if (ioctl(fd, TUNSIFMODE, &v) < 0) BT_D("%s: TUNSIFMODE: %s (point-to-point is the default)", name, strerror(errno));
        v = 1;
        if (ioctl(fd, TUNSIFHEAD, &v) < 0) {        /* no family header: no IPv6, and our framing is wrong */
            last = errno;
            BT_W("%s: TUNSIFHEAD: %s", name, strerror(errno));
            close(fd);
            continue;
        }
        P.tun_used[unit] = 1;
        if (refused[0]) BT_D("%s taken, refused before it: %s", name, refused);
        snprintf(ifname, BT_IFNAME_MAX, "%s", name);
        /* the messages of its removal come when it has no name to look up any more */
        P.tun_idx[P.tun_idx_next++ % (sizeof(P.tun_idx) / sizeof(P.tun_idx[0]))] = if_nametoindex(name);
        return fd;
    }
    if (refused[0]) BT_W("tun: no unit free, refused: %s", refused);
    errno = last;
    return -1;
}

void bt_tun_close(int fd, const char* ifname)
{
    int unit;

    if (fd >= 0) close(fd);
    if (!ifname || !is_tun(ifname)) return;
    unit = atoi(ifname + 3);
    if (unit >= 0 && unit < TUN_UNITS) P.tun_used[unit] = 0;
    /* tunclose only downs it; the addresses would stay for the next owner of the unit. On the
     * Passport the destroy works and the unit comes back on the next open (2026-10-15). */
    if (!if_destroy(ifname)) {
        BT_D("%s: SIOCIFDESTROY: %s, the addresses cleared instead", ifname, strerror(errno));
        if_addrs_clear(ifname);
    }
}

ssize_t bt_tun_read(int fd, uint8_t* pkt, size_t cap)
{
    for (;;) {
        uint32_t af;
        struct iovec iov[2];
        ssize_t n;

        iov[0].iov_base = &af;
        iov[0].iov_len = 4;
        iov[1].iov_base = pkt;
        iov[1].iov_len = cap;
        n = readv(fd, iov, 2);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
        if (n < 0) return -1;
        if (n == 0) return 0;
        af = ntohl(af);
        if (n > 4 && (af == AF_INET || af == AF_INET6)) return n - 4;
        /* anything else: not ours to carry; the next one */
    }
}

int bt_tun_write(int fd, const uint8_t* pkt, size_t len)
{
    uint32_t af;
    struct iovec iov[2];

    if (!len) return 0;
    af = htonl((pkt[0] >> 4) == 6 ? AF_INET6 : AF_INET);
    iov[0].iov_base = &af;
    iov[0].iov_len = 4;
    iov[1].iov_base = (void*)pkt;
    iov[1].iov_len = len;
    return writev(fd, iov, 2) == (ssize_t)(len + 4);
}

int bt_if_addr(const char* ifname, int family, const uint8_t* addr, int cidr)
{
    int s, r;

    if (family == 4) {
        struct ifaliasreq ifra;
        sa_any a;

        s = if_sock(AF_INET);
        if (s < 0) return 0;
        memset(&ifra, 0, sizeof(ifra));
        set_ifname(ifra.ifra_name, ifname);
        sa_ip(&a, 4, addr);
        memcpy(&ifra.ifra_addr, &a.in, sizeof(a.in));
        /* point-to-point: the far end is ourselves, as wg-quick does it on the BSDs */
        memcpy(&ifra.ifra_dstaddr, &a.in, sizeof(a.in));
        sa_mask(&a, 4, cidr);
        memcpy(&ifra.ifra_mask, &a.in, sizeof(a.in));
        r = ioctl(s, SIOCAIFADDR, &ifra);
        if (r < 0) {                                /* [phone] then without a far end */
            BT_D("%s: SIOCAIFADDR with a far end: %s", ifname, strerror(errno));
            memset(&ifra.ifra_dstaddr, 0, sizeof(ifra.ifra_dstaddr));
            r = ioctl(s, SIOCAIFADDR, &ifra);
        }
    } else {
        struct in6_aliasreq ifra;
        sa_any a;

        s = if_sock(AF_INET6);
        if (s < 0) return 0;
        memset(&ifra, 0, sizeof(ifra));
        set_ifname(ifra.ifra_name, ifname);
        sa_ip(&a, 6, addr);
        memcpy(&ifra.ifra_addr, &a.in6, sizeof(a.in6));
        sa_mask(&a, 6, cidr);
        memcpy(&ifra.ifra_prefixmask, &a.in6, sizeof(a.in6));
        ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
        ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
        /* No IN6_IFF_NODAD: io-pkt (KAME as in NetBSD 5) takes it from userland for a read-only flag
         * and answers EINVAL (Passport, 2026-10-15). The address goes through DAD and is tentative
         * for about a second. */
        r = ioctl(s, SIOCAIFADDR_IN6, &ifra);
        if (r < 0 && errno == EINVAL && cidr != 128) {
            /* NetBSD wants /128 on some point-to-point setups [phone] */
            BT_D("%s: SIOCAIFADDR_IN6 /%d: EINVAL, /128 instead", ifname, cidr);
            sa_mask(&a, 6, 128);
            memcpy(&ifra.ifra_prefixmask, &a.in6, sizeof(a.in6));
            r = ioctl(s, SIOCAIFADDR_IN6, &ifra);
        }
    }
    close_keep_errno(s);
    return r == 0;
}

/* The address off the interface, as if_addrs_clear takes every one off: SIOCDIFADDR(_IN6) with the
 * address alone; the prefix length is not asked for. */
int bt_if_addr_del(const char* ifname, int family, const uint8_t* addr, int cidr)
{
    int s, r;
    sa_any a;

    (void)cidr;
    if (family == 4) {
        struct ifreq ifr;
        s = if_sock(AF_INET);
        if (s < 0) return 0;
        memset(&ifr, 0, sizeof(ifr));
        set_ifname(ifr.ifr_name, ifname);
        sa_ip(&a, 4, addr);
        memcpy(&ifr.ifr_addr, &a.in, sizeof(a.in));
        r = ioctl(s, SIOCDIFADDR, &ifr);
    } else {
        struct in6_ifreq ifr6;
        s = if_sock(AF_INET6);
        if (s < 0) return 0;
        memset(&ifr6, 0, sizeof(ifr6));
        set_ifname(ifr6.ifr_name, ifname);
        sa_ip(&a, 6, addr);
        memcpy(&ifr6.ifr_addr, &a.in6, sizeof(a.in6));
        r = ioctl(s, SIOCDIFADDR_IN6, &ifr6);
    }
    close_keep_errno(s);
    return r == 0;
}

int bt_if_mtu(const char* ifname, int mtu)
{
    struct ifreq ifr;
    int s = if_sock(AF_INET), ok;

    if (s < 0) return 0;
    if (mtu > TUN_MTU_MAX || mtu < TUN_MTU_MIN) {
        int m = mtu > TUN_MTU_MAX ? TUN_MTU_MAX : TUN_MTU_MIN;
        BT_W("%s: MTU %d is outside what tun takes, %d instead", ifname, mtu, m);
        mtu = m;
    }
    memset(&ifr, 0, sizeof(ifr));
    set_ifname(ifr.ifr_name, ifname);
    ifr.ifr_mtu = mtu;
    ok = ioctl(s, SIOCSIFMTU, &ifr) == 0;
    close_keep_errno(s);
    return ok;
}

int bt_if_up(const char* ifname)
{
    return if_flags_set(ifname, IFF_UP, 0);
}

/* --------------------------------------------------------------------- egress */

/* The default route of `fd`'s FIB: 1 with what it says of it; 0 none (or only ours); -1 no answer. */
static int default_route(int fd, int family, rt_info* out)
{
    static const uint8_t zero[16] = { 0 };
    char name[IFNAMSIZ];
    int r = rt_get(fd, family, zero, 0, out);

    if (r == -EDOM && fd == P.rt_req) {
        /* our /1 came back: the table itself (the dump is FIB 0; for FIB 15 this means "no") */
        r = default_from_dump(family, out) ? 0 : -ESRCH;
    }
    if (r == -ESRCH || r == -EDOM) return 0;
    if (r < 0) return -1;
    if (out->flags & (RTF_REJECT | RTF_BLACKHOLE)) return 0;
    if (!out->idx || !if_indextoname(out->idx, name)) return 0;
    if (is_tun(name) || strncmp(name, "lo", 2) == 0) return 0;
    return 1;
}

/* ... its interface's name. */
static int default_if_on(int fd, int family, char ifname[BT_IFNAME_MAX])
{
    rt_info d;
    char name[IFNAMSIZ];
    int r = default_route(fd, family, &d);

    if (r <= 0) return r;
    if (!if_indextoname(d.idx, name)) return 0;
    snprintf(ifname, BT_IFNAME_MAX, "%s", name);
    return 1;
}

int bt_default_if(int family, char ifname[BT_IFNAME_MAX])
{
    int r = default_if_on(P.rt_req, family, ifname);

    if (r < 0 && family == 4 && P.pps_if[0] && !is_tun(P.pps_if)) {
        /* the routing socket did not answer: the network manager's word for it */
        snprintf(ifname, BT_IFNAME_MAX, "%s", P.pps_if);
        return 1;
    }
    return r > 0;
}

/* FIB 15's default interface, when its routes can be asked about and it has one. */
static int fib15_default(int family, char ifname[BT_IFNAME_MAX])
{
    if (P.rt_req15 == -1) {
        int fd = socket(PF_ROUTE, SOCK_RAW, 0), fib = FIB_EGRESS;
        if (fd >= 0 && nonblock_cloexec(fd) && setsockopt(fd, SOL_SOCKET, SO_SETFIB, &fib, sizeof(fib)) == 0) {
            P.rt_req15 = fd;
        } else {
            BT_I("egress: FIB %d cannot be asked about (%s): SO_BINDTODEVICE only", FIB_EGRESS, strerror(errno));
            if (fd >= 0) close(fd);
            P.rt_req15 = -2;
        }
    }
    return P.rt_req15 >= 0 && default_if_on(P.rt_req15, family, ifname) > 0;
}

static void note_method(int family, const char* how)
{
    char* last = P.method[family == 4 ? 0 : 1];
    if (strcmp(last, how) == 0) return;
    BT_I("egress IPv%d: %s", family, how);
    snprintf(last, sizeof(P.method[0]), "%s", how);
}

int bt_udp_open(int family, uint16_t port)
{
    char dev[BT_IFNAME_MAX], dev15[BT_IFNAME_MAX], how[64];
    int fd, one = 1, fib = 0, bound = 0, pins;
    const char* bind_dev;

    if (!bt_default_if(family, dev)) {
        errno = ENETUNREACH;
        return -1;
    }
    if (P.egress == EG_AUTO || P.egress == EG_FIB) fib = fib15_default(family, dev15);
    if (P.egress == EG_FIB && !fib) {
        errno = ENETUNREACH;
        return -1;
    }
    bind_dev = fib ? dev15 : dev;

    fd = socket(family_af(family), SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    if (!nonblock_cloexec(fd)) goto fail;
    if (fib) {
        int n = FIB_EGRESS;
        if (setsockopt(fd, SOL_SOCKET, SO_SETFIB, &n, sizeof(n)) < 0) {
            if (P.egress == EG_FIB) goto fail;
            fib = 0;
            bind_dev = dev;
        }
    }
    /* Host routes: asked for - or auto without FIB 15, and then a binding, if it takes, is the
     * second layer (with the host route in, the two agree). */
    pins = P.egress == EG_HOSTROUTE || (P.egress == EG_AUTO && !fib);
    if (P.egress == EG_AUTO || P.egress == EG_BIND) {
        /* QNX takes a struct ifreq here, not a bare name as Linux does */
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        set_ifname(ifr.ifr_name, bind_dev);
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) == 0) bound = 1;
        else if (P.egress == EG_BIND) goto fail;    /* nothing else would keep it out of the tunnels */
    }
    if (family == 6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) < 0) goto fail;
    {
        sa_any a;
        sa_ip(&a, family, NULL);
        if (family == 4) a.in.sin_port = htons(port);
        else a.in6.sin6_port = htons(port);
        if (bind(fd, &a.sa, a.sa.sa_len) < 0) goto fail;
    }
    P.pin_fam[family == 6] = pins;
    if (fib) snprintf(how, sizeof(how), bound ? "FIB %d + bound to %s" : "FIB %d (via %s)", FIB_EGRESS, bind_dev);
    else if (pins && bound) snprintf(how, sizeof(how), "host routes + bound to %s", bind_dev);
    else if (pins) snprintf(how, sizeof(how), "host routes (via %s)", bind_dev);
    else snprintf(how, sizeof(how), "bound to %s", bind_dev);
    note_method(family, how);
    return fd;
fail:
    close_keep_errno(fd);
    return -1;
}

/* --------------------------------------------------------------------- host routes */

/* Byte i of a sockaddr's address part - 0 past its length, as the kernel cuts masks short. */
static uint8_t sa_byte(const struct sockaddr* s, int family, size_t i)
{
    size_t off = (family == 4 ? offsetof(struct sockaddr_in, sin_addr) : offsetof(struct sockaddr_in6, sin6_addr)) + i;
    return off < s->sa_len ? ((const uint8_t*)s)[off] : 0;
}

/* Whether `a` is in the subnet of an interface that is not a tunnel: its connected route, more
 * specific than our /1, takes it out already - and a host route through the gateway would only
 * bounce it off the router. */
static int on_link(const bt_addr* a)
{
    struct ifaddrs *ifa, *p;
    size_t len = a->family == 4 ? 4 : 16, i;
    int af = family_af(a->family), found = 0;

    if (getifaddrs(&ifa) != 0) return 0;
    for (p = ifa; p && !found; p = p->ifa_next) {
        int any = 0;

        if (!p->ifa_addr || p->ifa_addr->sa_family != af || !(p->ifa_flags & IFF_UP) ||
            (p->ifa_flags & IFF_LOOPBACK) || is_tun(p->ifa_name))
            continue;
        if (a->family == 6 && sa_byte(p->ifa_addr, 6, 0) == 0xfe && (sa_byte(p->ifa_addr, 6, 1) & 0xc0) == 0x80)
            continue;                                   /* link-local: every link has one */
        if ((p->ifa_flags & IFF_POINTOPOINT) && p->ifa_dstaddr && p->ifa_dstaddr->sa_family == af) {
            for (i = 0; i < len && sa_byte(p->ifa_dstaddr, a->family, i) == a->addr[i]; i++) {}
            if (i == len) {
                found = 1;
                break;
            }
        }
        if (!p->ifa_netmask) continue;
        for (i = 0; i < len; i++) any |= sa_byte(p->ifa_netmask, a->family, i);
        if (!any) continue;
        for (i = 0; i < len; i++) {
            uint8_t m = sa_byte(p->ifa_netmask, a->family, i);
            if ((sa_byte(p->ifa_addr, a->family, i) & m) != (a->addr[i] & m)) break;
        }
        if (i == len) found = 1;
    }
    freeifaddrs(ifa);
    return found;
}

static int same_via(const rt_info* x, const rt_info* y)
{
    return x->idx == y->idx && (x->flags & RTF_GATEWAY) == (y->flags & RTF_GATEWAY) && x->gw_len == y->gw_len &&
           memcmp(x->gw, y->gw, x->gw_len) == 0;
}

/* Adds the host route to `a` through the default route `via` (its gateway as the kernel gave
 * it), or deletes it (`via` NULL): 0 or the negative errno. Ours carry PIN_MARK. */
static int pin_route(int type, const bt_addr* a, const rt_info* via)
{
    rt_msg m;
    sa_any s;
    int flags = RTF_UP | RTF_HOST | PIN_MARK;

    if (via && (via->flags & RTF_GATEWAY)) flags |= RTF_GATEWAY;
    rt_init(&m, type, flags);
    sa_ip(&s, a->family, a->addr);
    rt_put(&m, RTA_DST, &s);
    if (via) {
        if (via->gw_len) {
            rt_put_raw(&m, RTA_GATEWAY, via->gw, via->gw_len);
        } else {
            char name[IFNAMSIZ] = "";
            if_indextoname(via->idx, name);
            sa_link(&s, via->idx, name);
            rt_put(&m, RTA_GATEWAY, &s);
        }
    }
    return rt_talk(P.rt_req, &m);
}

/* 1 when the host route to `a` is one of ours, 0 when there is none or it is someone else's,
 * the negative errno when the table did not answer. */
static int pin_ours(const bt_addr* a)
{
    rt_info i;
    int r = rt_get(P.rt_req, a->family, a->addr, a->family == 4 ? 32 : 128, &i);

    if (r == -ESRCH || r == -EDOM) return 0;
    if (r < 0) return r;
    return (i.flags & PIN_MARK) == PIN_MARK;
}

/* The host route to `a`, if it is ours: 0 (also when there is nothing to delete) or the negative errno. */
static int pin_delete(const bt_addr* a)
{
    int r = pin_ours(a);

    if (r <= 0) return r;
    r = pin_route(RTM_DELETE, a, NULL);
    return r == -ESRCH ? 0 : r;
}

static void pin_text(const bt_addr* a, const rt_info* via, char* out, size_t cap)
{
    char at[64], gt[64] = "", name[IFNAMSIZ] = "?";

    inet_ntop(family_af(a->family), a->addr, at, sizeof(at));
    if (!via) {
        snprintf(out, cap, "%s", at);
        return;
    }
    if_indextoname(via->idx, name);
    if ((via->flags & RTF_GATEWAY) && via->gw_len >= 2) {
        sa_any g;
        memset(&g, 0, sizeof(g));
        memcpy(&g, via->gw, via->gw_len < sizeof(g) ? via->gw_len : sizeof(g));
        if (g.sa.sa_family == AF_INET) inet_ntop(AF_INET, &g.in.sin_addr, gt, sizeof(gt));
        else if (g.sa.sa_family == AF_INET6) inet_ntop(AF_INET6, &g.in6.sin6_addr, gt, sizeof(gt));
    }
    if (gt[0]) snprintf(out, cap, "%s via %s (%s)", at, gt, name);
    else snprintf(out, cap, "%s (%s)", at, name);
}

int bt_bypass_set(const bt_addr* addrs, size_t n, int recheck)
{
    rt_info def[2];
    int have[2] = { -1, -1 }, ok = 1;
    size_t i, j;
    char text[160];

    /* What goes: not asked for any more, not the way out any more, or its way out moved. */
    for (i = P.n_pins; i-- > 0;) {
        pin* p = &P.pins[i];
        int k = p->a.family == 6, keep = 0;

        for (j = 0; j < n && !bt_addr_equal(&addrs[j], &p->a); j++) {}
        if (j < n && P.pin_fam[k]) {
            if (have[k] < 0) have[k] = default_route(P.rt_req, p->a.family, &def[k]) > 0;
            keep = have[k] && same_via(&p->via, &def[k]) && !(recheck && on_link(&p->a));
        }
        if (keep) {
            /* After a network change: the network manager may have wiped ours - or taken away the
             * one that was there before us. */
            if (recheck && pin_route(RTM_ADD, &p->a, &p->via) == 0) {
                pin_text(&p->a, &p->via, text, sizeof(text));
                BT_I("host route: %s %s", text, p->mine ? "back" : "ours now");
                p->mine = 1;
            }
            continue;
        }
        pin_text(&p->a, NULL, text, sizeof(text));
        if (p->mine) {
            int r = pin_delete(&p->a);
            if (r < 0) BT_W("host route to %s: %s", text, strerror(-r));
        }
        BT_I("host route: %s gone", text);
        P.pins[i] = P.pins[--P.n_pins];
    }

    /* What comes. */
    for (j = 0; j < n; j++) {
        const bt_addr* a = &addrs[j];
        int k = a->family == 6, r;
        pin* p;

        if (!P.pin_fam[k]) continue;
        for (i = 0; i < P.n_pins && !bt_addr_equal(&P.pins[i].a, a); i++) {}
        if (i < P.n_pins) continue;
        if (have[k] < 0) have[k] = default_route(P.rt_req, a->family, &def[k]) > 0;
        if (!have[k] || on_link(a)) continue;           /* no way out now - or no need of one */
        if (P.n_pins == BT_BYPASS_MAX) {
            errno = ENOSPC;
            ok = 0;
            break;
        }
        p = &P.pins[P.n_pins];
        p->a = *a;
        p->via = def[k];
        p->mine = 1;
        pin_text(a, &def[k], text, sizeof(text));
        r = pin_route(RTM_ADD, a, &def[k]);
        if (r == -EEXIST) {
            /* One of ours that a lost journal left - or someone else's, which stays as it is. */
            if (pin_ours(a) > 0 && pin_route(RTM_DELETE, a, NULL) == 0) {
                r = pin_route(RTM_ADD, a, &def[k]);
            } else {
                p->mine = 0;
                r = 0;
            }
        }
        if (r != 0) {
            BT_W("host route: %s: %s", text, strerror(-r));
            errno = -r;
            ok = 0;
            continue;
        }
        P.n_pins++;
        BT_I("host route: %s%s", text, p->mine ? "" : " - one was there already, left as it is");
    }
    return ok;
}

size_t bt_bypass_list(bt_addr* out, size_t cap)
{
    size_t i, n = 0;
    for (i = 0; i < P.n_pins && n < cap; i++)
        if (P.pins[i].mine) out[n++] = P.pins[i].a;
    return n;
}

int bt_bypass_drop(const bt_addr* a)
{
    int r = pin_delete(a);
    if (r == 0) return 1;
    errno = -r;
    return 0;
}

/* --------------------------------------------------------------------- DNS */

static void cs_get(char* out, size_t cap)
{
    size_t n = confstr(_CS_RESOLVE, out, cap);
    if (n == 0) out[0] = '\0';
    else out[cap - 1] = '\0';
}

/* Sets _CS_RESOLVE; what it reads back as goes into `stored`. */
static int cs_set(const char* text, char* stored, size_t cap)
{
    char before[BT_DNS_TEXT_MAX], after[BT_DNS_TEXT_MAX];

    cs_get(before, sizeof(before));
    errno = 0;
    confstr(_CS_SET | _CS_RESOLVE, (char*)text, 0);
    cs_get(after, sizeof(after));
    /* The same text back, or at least a change (it may be kept normalized). */
    if (strcmp(after, text) == 0 || strcmp(after, before) != 0) {
        snprintf(stored, cap, "%s", after);
        return 1;
    }
    if (!errno) errno = EPERM;
    return 0;
}

static int addr_add(bt_addr* out, size_t* n, size_t cap, const char* tok)
{
    bt_addr a;
    size_t i;

    memset(&a, 0, sizeof(a));
    if (inet_pton(AF_INET, tok, a.addr) == 1) a.family = 4;
    else if (inet_pton(AF_INET6, tok, a.addr) == 1) a.family = 6;
    else return 0;
    if (a.family == 6 && a.addr[0] == 0xfe && (a.addr[1] & 0xc0) == 0x80) return 0;    /* needs a scope */
    for (i = 0; i < *n; i++)
        if (bt_addr_equal(&out[i], &a)) return 0;
    if (*n < cap) out[(*n)++] = a;
    return 1;
}

/* Resolvers named in _CS_RESOLVE text: "nameserver" then an address, words split by _ or blanks. */
static size_t text_servers(const char* text, bt_addr* out, size_t cap)
{
    size_t n = 0;
    int after_kw = 0;
    const char* p = text;

    while (*p) {
        char word[64];
        size_t len = 0;
        while (*p && strchr("_ \t\r\n,", *p)) p++;
        while (*p && !strchr("_ \t\r\n,", *p)) {
            if (len + 1 < sizeof(word)) word[len++] = *p;
            p++;
        }
        word[len] = '\0';
        if (!len) break;
        if (after_kw) addr_add(out, &n, cap, word);
        after_kw = strcmp(word, "nameserver") == 0;
    }
    return n;
}

/* Every address anywhere in a PPS value, whatever its encoding (JSON list, commas, blanks). */
static size_t value_addrs(const char* v, bt_addr* out, size_t cap)
{
    size_t n = 0;

    while (*v) {
        char tok[64];
        size_t len = 0;
        while (*v && !strchr("0123456789abcdefABCDEF:.", *v)) v++;
        while (*v && strchr("0123456789abcdefABCDEF:.", *v)) {
            if (len + 1 < sizeof(tok)) tok[len++] = *v;
            v++;
        }
        tok[len] = '\0';
        if (len) addr_add(out, &n, cap, tok);
    }
    return n;
}

static int same_servers(const bt_addr* a, size_t na, const bt_addr* b, size_t nb)
{
    size_t i, j;
    if (na != nb) return 0;
    for (i = 0; i < na; i++) {
        for (j = 0; j < nb && !bt_addr_equal(&a[i], &b[j]); j++) {}
        if (j == nb) return 0;
    }
    return 1;
}

/* The same servers in the same order: the resolver asks them in it. */
static int same_order(const bt_addr* a, size_t na, const bt_addr* b, size_t nb)
{
    size_t i;
    if (na != nb) return 0;
    for (i = 0; i < na; i++)
        if (!bt_addr_equal(&a[i], &b[i])) return 0;
    return 1;
}

static size_t compose(char* out, size_t cap, const bt_addr* servers, size_t n, const char* search)
{
    size_t len = 0, i;

    out[0] = '\0';
    for (i = 0; i < n && len < cap; i++) {
        char a[64];
        inet_ntop(family_af(servers[i].family), servers[i].addr, a, sizeof(a));
        len += (size_t)snprintf(out + len, cap - len, "%snameserver_%s", i ? "_" : "", a);
    }
    /* No blank anywhere: _CS_RESOLVE refuses one (EINVAL - the phone, 2026-10-16; QNX's resolv.conf
     * page: "can't include spaces; separate the keywords by underscores"). The domains follow
     * "search" the same way, the first one - ours - right after it. */
    if (search && *search && len < cap) {
        len += (size_t)snprintf(out + len, cap - len, "_search_");
        for (i = 0; search[i] && len + 1 < cap; i++) out[len++] = search[i] == ' ' ? '_' : search[i];
        if (len < cap) out[len] = '\0';
        if (search[i]) len = cap;               /* did not fit: too long, as snprintf would say */
    }
    return len;
}

/* --- status_public: what the resolver reads ---------------------------------------------------- */

/*
 * The two attributes into status_public, in one write: "nameservers" as a JSON list of addresses,
 * "searchdomains" as the words of `search`. Appended - O_TRUNC would empty the whole object, and
 * the other attributes are the network manager's.
 */
static int pps_put(const bt_addr* servers, size_t n, const char* search)
{
    char buf[BT_DNS_TEXT_MAX];
    size_t len, i, kept = 0;
    int fd, e;
    ssize_t w;

    len = (size_t)snprintf(buf, sizeof(buf), "nameservers:json:[");
    for (i = 0; i < n && len < sizeof(buf); i++) {
        char a[64];
        inet_ntop(family_af(servers[i].family), servers[i].addr, a, sizeof(a));
        len += (size_t)snprintf(buf + len, sizeof(buf) - len, "%s\"%s\"", i ? "," : "", a);
    }
    if (len < sizeof(buf)) len += (size_t)snprintf(buf + len, sizeof(buf) - len, "]\nsearchdomains::");
    for (i = 0; search && search[i] && len + 2 < sizeof(buf) && kept + 1 < PPS_SEARCH_MAX; i++) {
        /* a line break would end the attribute: a blank in its place */
        buf[len++] = (unsigned char)search[i] < 0x20 ? ' ' : search[i];
        kept++;
    }
    if (len + 2 >= sizeof(buf)) {
        errno = E2BIG;
        return 0;
    }
    buf[len++] = '\n';
    buf[len] = '\0';
    fd = open(PPS_STATUS, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) return 0;
    w = write(fd, buf, len);
    e = errno;
    close(fd);
    if (w != (ssize_t)len) {
        errno = w < 0 ? e : EIO;
        return 0;
    }
    BT_D("DNS: into %s: %.*s", PPS_STATUS, (int)(len - 1), buf);
    return 1;
}

/* The network manager wrote over ours. Now and then it may (a network event); all the time, it
 * means it will not have ours - then it keeps the object, and we stop. */
static void pps_fight(void)
{
    uint64_t now = mono_ns();

    if (!P.pps_fights || now - P.pps_fight_since > PPS_FIGHT_NS) {
        P.pps_fights = 0;
        P.pps_fight_since = now;
    }
    P.pps_fights++;
    if (P.pps_fights > PPS_FIGHT_MAX) {
        if (!P.pps_given_up)
            BT_W("DNS: the network manager wrote over ours in %s %u times in a minute - left to it until the tunnels let go of DNS",
                 PPS_STATUS, P.pps_fights - 1);
        P.pps_given_up = 1;
    } else {
        BT_I("DNS: the network manager wrote over ours in %s - ours again", PPS_STATUS);
    }
}

/* The network manager's values back, when ours are in. */
static int pps_give_back(void)
{
    if (!P.pps_ours_in) return 1;
    P.pps_ours_in = 0;                          /* the write's echo then reads as the network's */
    return pps_put(P.pps_ns, P.pps_n, P.pps_search);
}

/* A part of a crash-journal snapshot: what follows "|<name>:" up to the next "|". */
static int snap_part(const char* text, const char* name, char* out, size_t cap)
{
    const char* p = text;
    size_t nl = strlen(name), len;

    out[0] = '\0';
    while ((p = strchr(p, '|')) != NULL) {
        p++;
        if (strncmp(p, name, nl) == 0 && p[nl] == ':') {
            p += nl + 1;
            for (len = 0; p[len] && p[len] != '|'; len++) {}
            if (len >= cap) len = cap - 1;
            memcpy(out, p, len);
            out[len] = '\0';
            return 1;
        }
    }
    return 0;
}

static void snap_addrs(char* out, size_t cap, size_t* len, const char* name, const bt_addr* a, size_t n)
{
    size_t i;

    if (*len < cap) *len += (size_t)snprintf(out + *len, cap - *len, "|%s:", name);
    for (i = 0; i < n && *len < cap; i++) {
        char t[64];
        inet_ntop(family_af(a[i].family), a[i].addr, t, sizeof(t));
        *len += (size_t)snprintf(out + *len, cap - *len, "%s%s", i ? "," : "", t);
    }
}

/* What the system has now: its last _CS_RESOLVE - or the network manager's resolvers, when they
 * say something else (the network changed while ours were in). */
static void system_now(char* out, size_t cap)
{
    bt_addr had[PPS_NS_MAX];
    size_t n = text_servers(P.sys_text, had, PPS_NS_MAX);

    if (P.pps_n && !same_servers(had, n, P.pps_ns, P.pps_n)) compose(out, cap, P.pps_ns, P.pps_n, NULL);
    else snprintf(out, cap, "%s", P.sys_text);
}

size_t bt_dns_system(bt_addr* out, size_t cap)
{
    size_t i, n;

    if (P.pps_n) {
        n = P.pps_n < cap ? P.pps_n : cap;
        for (i = 0; i < n; i++) out[i] = P.pps_ns[i];
        return n;
    }
    return text_servers(P.sys_text, out, cap);
}

int bt_dns_apply(const bt_addr* servers, size_t n, const char* search)
{
    char text[BT_DNS_TEXT_MAX];
    int cs_ok;

    if (compose(text, sizeof(text), servers, n, search) >= sizeof(text)) {
        errno = E2BIG;
        return 0;
    }
    if (!P.our_text[0]) {
        /* The first time in: what is there now is the system's. */
        char now[BT_DNS_TEXT_MAX];
        cs_get(now, sizeof(now));
        if (strcmp(now, text) != 0) snprintf(P.sys_text, sizeof(P.sys_text), "%s", now);
    }
    /* _CS_RESOLVE: the copy for old programs. Refused - still status_public, which is what counts. */
    cs_ok = cs_set(text, P.our_text, sizeof(P.our_text));
    if (cs_ok && P.check_due == BT_NEVER) P.check_due = mono_ns() + DNS_CHECK_NS;
    if (P.pps < 0 || P.pps_given_up) return cs_ok;      /* no PPS, or left to the network manager */
    /* The same as in already: no write - each one wakes every reader of the object. */
    if (P.pps_ours_in && same_order(servers, n, P.pps_ours, P.pps_ours_n) &&
        strcmp(search ? search : "", P.pps_ours_search) == 0)
        return 1;
    if (!pps_put(servers, n, search)) return 0;
    P.pps_ours_n = n < PPS_NS_MAX ? n : PPS_NS_MAX;
    memcpy(P.pps_ours, servers, P.pps_ours_n * sizeof(*servers));
    snprintf(P.pps_ours_search, sizeof(P.pps_ours_search), "%s", search ? search : "");
    P.pps_ours_in = 1;
    return 1;
}

int bt_dns_restore(void)
{
    char text[BT_DNS_TEXT_MAX];
    int cs_ok, pps_ok;

    system_now(text, sizeof(text));
    P.our_text[0] = '\0';
    P.check_due = BT_NEVER;
    cs_ok = cs_set(text, P.sys_text, sizeof(P.sys_text));
    pps_ok = pps_give_back();
    P.pps_given_up = 0;                                 /* the next tunnel may try again */
    P.pps_fights = 0;
    return cs_ok && pps_ok;
}

/* "<_CS_RESOLVE>" and, while ours are in status_public, "|net:<the network manager's servers>
 * |search:<its domains>|ours:<ours>" - so that after a crash its values go back only where ours are
 * still there. */
size_t bt_dns_snapshot(char* out, size_t cap)
{
    char text[BT_DNS_TEXT_MAX];
    size_t n;

    if (!cap) return 0;
    if (P.sys_text[0]) snprintf(text, sizeof(text), "%s", P.sys_text);
    else compose(text, sizeof(text), P.pps_ns, P.pps_n, NULL);     /* empty: nothing to give back */
    n = strlen(text);
    if (P.pps_ours_in) {
        snap_addrs(text, sizeof(text), &n, "net", P.pps_ns, P.pps_n);
        if (n < sizeof(text)) n += (size_t)snprintf(text + n, sizeof(text) - n, "|search:%s", P.pps_search);
        snap_addrs(text, sizeof(text), &n, "ours", P.pps_ours, P.pps_ours_n);
        if (n >= sizeof(text)) n = strlen(text);        /* cut: whatever fitted */
    }
    if (n >= cap) n = cap - 1;
    memcpy(out, text, n);
    out[n] = '\0';
    return n;
}

int bt_dns_restore_text(const char* snapshot)
{
    char now[BT_DNS_TEXT_MAX], text[BT_DNS_TEXT_MAX], part[BT_DNS_TEXT_MAX];
    size_t cut;

    /* status_public first: at the start it was read with the dead run's servers in it, if they are
     * still there - the network manager's go back, and they are the network's again for us */
    if (P.pps >= 0 && snap_part(snapshot, "ours", part, sizeof(part))) {
        bt_addr ours[PPS_NS_MAX], net[PPS_NS_MAX];
        char search[PPS_SEARCH_MAX];
        size_t no = value_addrs(part, ours, PPS_NS_MAX), nn = 0;
        if (snap_part(snapshot, "net", part, sizeof(part))) nn = value_addrs(part, net, PPS_NS_MAX);
        snap_part(snapshot, "search", search, sizeof(search));
        if (no && same_servers(P.pps_ns, P.pps_n, ours, no)) {
            memset(P.pps_ns, 0, sizeof(P.pps_ns));
            memcpy(P.pps_ns, net, nn * sizeof(*net));
            P.pps_n = nn;
            snprintf(P.pps_search, sizeof(P.pps_search), "%s", search);
            P.pps_ours_in = 0;
            if (!pps_put(P.pps_ns, P.pps_n, P.pps_search)) BT_W("journal: %s: %s", PPS_STATUS, strerror(errno));
            else BT_I("journal: the network's DNS back in %s", PPS_STATUS);
        }
    }
    /* then _CS_RESOLVE: the snapshot up to its first "|" */
    for (cut = 0; snapshot[cut] && snapshot[cut] != '|' && cut + 1 < sizeof(text); cut++) text[cut] = snapshot[cut];
    text[cut] = '\0';

    cs_get(now, sizeof(now));
    P.our_text[0] = '\0';
    P.check_due = BT_NEVER;
    if (P.pps_n) {
        /* The network manager knows what the system has: keep it if it is there already. */
        bt_addr have[PPS_NS_MAX];
        char sys[BT_DNS_TEXT_MAX];
        size_t n = text_servers(now, have, PPS_NS_MAX);
        if (same_servers(have, n, P.pps_ns, P.pps_n)) {
            snprintf(P.sys_text, sizeof(P.sys_text), "%s", now);
            return 1;
        }
        compose(sys, sizeof(sys), P.pps_ns, P.pps_n, NULL);
        return cs_set(sys, P.sys_text, sizeof(P.sys_text));
    }
    /* Without PPS there is no telling a newer system setting from ours: the journal's. */
    if (strcmp(now, text) == 0) {
        snprintf(P.sys_text, sizeof(P.sys_text), "%s", now);
        return 1;
    }
    return cs_set(text, P.sys_text, sizeof(P.sys_text));
}

/* _CS_RESOLVE now: 1 when the system wrote it (over ours, or anew). */
static int dns_recheck(void)
{
    char now[BT_DNS_TEXT_MAX];

    cs_get(now, sizeof(now));
    if (P.our_text[0]) {
        if (strcmp(now, P.our_text) == 0) return 0;
    } else if (strcmp(now, P.sys_text) == 0) {
        return 0;
    }
    snprintf(P.sys_text, sizeof(P.sys_text), "%s", now);
    return 1;
}

/* --------------------------------------------------------------------- changes */

/* status_public, whole (no ?delta): 1 when the resolvers or the default interface changed. */
static int pps_parse(char* text)
{
    bt_addr ns[PPS_NS_MAX];
    size_t n = 0;
    char dif[BT_IFNAME_MAX] = "", sd[PPS_SEARCH_MAX] = "";
    char* line = text;
    int changed;

    memset(ns, 0, sizeof(ns));
    while (line && *line) {
        char* eol = strchr(line, '\n');
        char *c1, *c2;
        if (eol) *eol = '\0';
        /* attr:encoding:value; "@object" heads it, "-attr" is a deletion */
        c1 = strchr(line, ':');
        c2 = c1 ? strchr(c1 + 1, ':') : NULL;
        if (line[0] != '@' && line[0] != '-' && c2) {
            *c1 = '\0';
            if (strcmp(line, "nameservers") == 0) {
                n = value_addrs(c2 + 1, ns, PPS_NS_MAX);
            } else if (strcmp(line, "default_interface") == 0) {
                const char* v = c2 + 1;
                size_t len = 0;
                while (*v == ' ' || *v == '"') v++;
                while (v[len] && ((v[len] >= 'a' && v[len] <= 'z') || (v[len] >= '0' && v[len] <= '9') ||
                                  (v[len] >= 'A' && v[len] <= 'Z')) && len + 1 < sizeof(dif)) len++;
                memcpy(dif, v, len);
                dif[len] = '\0';
            } else if (strcmp(line, "searchdomains") == 0) {
                snprintf(sd, sizeof(sd), "%s", c2 + 1);
            }
        }
        line = eol ? eol + 1 : NULL;
    }
    changed = strcmp(dif, P.pps_if) != 0;
    snprintf(P.pps_if, sizeof(P.pps_if), "%s", dif);
    /* Ours read back: the network manager's servers stay as they were. */
    if (P.pps_ours_in && same_servers(ns, n, P.pps_ours, P.pps_ours_n)) return changed;
    if (P.pps_ours_in) {
        /* It wrote over ours: the change puts them in again (bt_dns_apply), unless it keeps on. */
        P.pps_ours_in = 0;
        pps_fight();
        changed = 1;
    }
    changed |= !same_servers(ns, n, P.pps_ns, P.pps_n) || strcmp(sd, P.pps_search) != 0;
    memcpy(P.pps_ns, ns, sizeof(ns));
    P.pps_n = n;
    snprintf(P.pps_search, sizeof(P.pps_search), "%s", sd);
    return changed;
}

static void pps_close(const char* why)
{
    BT_W("PPS %s: %s; without it from now on", PPS_STATUS, why);
    close(P.pps);
    P.pps = -1;
}

static int pps_read(void)
{
    static char buf[16384];
    int changed = 0, rounds;

    for (rounds = 0; rounds < 16 && P.pps >= 0; rounds++) {
        ssize_t n = read(P.pps, buf, sizeof(buf) - 1);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (n <= 0) {                               /* gone: else poll would fire for ever */
            pps_close(n ? strerror(errno) : "end of file");
            break;
        }
        buf[n] = '\0';
        changed |= pps_parse(buf);
    }
    return changed;
}

/* Our own doings (routes by our pid, anything on a tun) are not a change of the network. */
static int rt_mon_read(void)
{
    union {
        struct rt_msghdr        rt;
        struct if_msghdr        ifm;
        struct ifa_msghdr       ifa;
        struct if_announcemsghdr ifan;
        char                    raw[2048];
    } u;
    int changed = 0, rounds;

    for (rounds = 0; rounds < 4096; rounds++) {
        ssize_t n = read(P.rt_mon, &u, sizeof(u));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == ENOBUFS) {            /* overrun: something happened, we lost what */
            changed = 1;
            continue;
        }
        if (n <= 0) break;
        if (n < 4 || u.rt.rtm_version != RTM_VERSION) continue;
        switch (u.rt.rtm_type) {
        case RTM_ADD: case RTM_DELETE: case RTM_CHANGE: case RTM_OLDADD: case RTM_OLDDEL:
            if (n < (ssize_t)sizeof(u.rt) || u.rt.rtm_pid == P.pid) break;
            if (u.rt.rtm_pid == 0 && index_is_tun(u.rt.rtm_index)) break;     /* the kernel, for our device */
            BT_D("network: message %u from pid %d, interface %u", u.rt.rtm_type, (int)u.rt.rtm_pid, u.rt.rtm_index);
            changed = 1;
            break;
        case RTM_NEWADDR: case RTM_DELADDR:
            if (n < (ssize_t)sizeof(u.ifa) || index_is_tun(u.ifa.ifam_index)) break;
            BT_D("network: message %u, interface %u", u.rt.rtm_type, u.ifa.ifam_index);
            changed = 1;
            break;
        case RTM_IFINFO:
            if (n < (ssize_t)sizeof(u.ifm) || index_is_tun(u.ifm.ifm_index)) break;
            BT_D("network: message %u, interface %u", u.rt.rtm_type, u.ifm.ifm_index);
            changed = 1;
            break;
        case RTM_IFANNOUNCE:
            if (n < (ssize_t)sizeof(u.ifan) || is_tun(u.ifan.ifan_name)) break;
            BT_D("network: interface %.*s %s", IFNAMSIZ, u.ifan.ifan_name, u.ifan.ifan_what == IFAN_ARRIVAL ? "came" : "went");
            changed = 1;
            break;
        default:                                    /* RTM_GET, RTM_MISS, RTM_RESOLVE...: lookups */
            break;
        }
    }
    return changed;
}

int bt_net_fds(struct pollfd* out, int cap)
{
    int n = 0;
    if (P.rt_mon >= 0 && n < cap) {
        out[n].fd = P.rt_mon;
        out[n].events = POLLIN;
        out[n++].revents = 0;
    }
    if (P.pps >= 0 && n < cap) {
        out[n].fd = P.pps;
        out[n].events = POLLIN;
        out[n++].revents = 0;
    }
    return n;
}

int bt_net_event(const struct pollfd* pfd)
{
    int changed = 0;

    if (pfd->fd == P.rt_mon && P.rt_mon >= 0) {
        changed = rt_mon_read();
    } else if (pfd->fd == P.pps && P.pps >= 0) {
        if (pfd->revents & POLLIN) changed = pps_read();
        if (P.pps >= 0 && (pfd->revents & (POLLERR | POLLHUP | POLLNVAL))) pps_close("hang-up");
    } else {
        return 0;
    }
    /* The network manager rewrites _CS_RESOLVE around the same time. */
    changed |= dns_recheck();
    return changed;
}

uint64_t bt_net_deadline(void)
{
    return P.check_due;
}

int bt_net_check(uint64_t now)
{
    (void)now;
    if (P.check_due == BT_NEVER || mono_ns() < P.check_due) return 0;
    P.check_due = P.our_text[0] ? mono_ns() + DNS_CHECK_NS : BT_NEVER;
    return dns_recheck();
}

/* --------------------------------------------------------------------- life */

int bt_plat_init(const bt_plat_opts* o)
{
    int fib = 0;

    memset(&P, 0, sizeof(P));
    P.rt_req = P.rt_req15 = P.rt_mon = P.pps = -1;
    P.check_due = BT_NEVER;
    P.pid = getpid();
    if (!o || !o->egress || strcmp(o->egress, "auto") == 0) P.egress = EG_AUTO;
    else if (strcmp(o->egress, "fib") == 0) P.egress = EG_FIB;
    else if (strcmp(o->egress, "bind") == 0) P.egress = EG_BIND;
    else if (strcmp(o->egress, "hostroute") == 0) P.egress = EG_HOSTROUTE;
    else {
        errno = EINVAL;
        return 0;
    }
    P.pin_fam[0] = P.pin_fam[1] = P.egress == EG_HOSTROUTE;    /* auto decides per socket */

    P.rt_req = socket(PF_ROUTE, SOCK_RAW, 0);
    if (P.rt_req < 0 || !nonblock_cloexec(P.rt_req)) return 0;
    /* Our routes belong in FIB 0 whatever group we were started with (mfib_gid_map). */
    if (setsockopt(P.rt_req, SOL_SOCKET, SO_SETFIB, &fib, sizeof(fib)) < 0)
        BT_D("routes: SO_SETFIB 0 on the routing socket: %s", strerror(errno));
    P.rt_mon = socket(PF_ROUTE, SOCK_RAW, 0);
    if (P.rt_mon < 0 || !nonblock_cloexec(P.rt_mon)) return 0;

    P.pps = open(PPS_STATUS "?wait", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (P.pps < 0) BT_W("PPS %s: %s; DNS from _CS_RESOLVE only", PPS_STATUS, strerror(errno));
    else pps_read();

    cs_get(P.sys_text, sizeof(P.sys_text));
    BT_I("platform: QNX, egress %s, PPS %s, default %s, DNS \"%s\"",
         P.egress == EG_AUTO ? "auto" : P.egress == EG_FIB ? "fib" : P.egress == EG_BIND ? "bind" : "hostroute",
         P.pps >= 0 ? "on" : "off", P.pps_if[0] ? P.pps_if : "-", P.sys_text);
    return 1;
}

void bt_plat_fini(void)
{
    if (P.rt_req >= 0) bt_bypass_set(NULL, 0, 0);     /* the tunnels took theirs; whatever is left */
    if (P.rt_req >= 0) close(P.rt_req);
    if (P.rt_req15 >= 0) close(P.rt_req15);
    if (P.rt_mon >= 0) close(P.rt_mon);
    if (P.pps >= 0) close(P.pps);
    P.rt_req = P.rt_req15 = P.rt_mon = P.pps = -1;
    P.check_due = BT_NEVER;
}

/* --------------------------------------------------------------------- the status bar */

/*
 * The navigator draws the VPN key from this object, and the system's VPN manager (vpn_pps) writes
 * its own connections into it in this very form. No O_CREAT: the object is the manager's, and one
 * made by us would be root's and closed to it.
 */
int bt_status_icon(const char* state)
{
    char text[64];
    int length;
    int fd;
    int write_errno;
    ssize_t written;

    length = snprintf(text, sizeof(text), "[n]dat:json:{\"vpn\":{\"state\":\"%s\"}}\n", state);
    fd = open(PPS_VPN_ICON, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    written = write(fd, text, (size_t)length);
    write_errno = errno;
    close(fd);
    if (written != length) {
        errno = written < 0 ? write_errno : EIO;
        return 0;
    }
    return 1;
}
