/*
 * bt_plat for Linux: the development and test backend (WSL, network namespaces). See bt_plat.h.
 *
 *   tun       /dev/net/tun with IFF_NO_PI: packets carry no framing at all
 *   routes    rtnetlink, the main table
 *   egress    SO_BINDTODEVICE to the default route's interface: a bound socket's route lookup only
 *             sees routes through that interface, so our /1 routes never catch it. With
 *             --egress hostroute instead: plain sockets, and a host route through the default
 *             gateway to each address they send to (proto 126 marks them ours) - the phone's
 *             third way, tested here end to end
 *   DNS       a resolv.conf the daemon is TOLD to own (--dns-file; in a netns, the file `ip netns
 *             exec` bind-mounts over /etc/resolv.conf). Written in place, never renamed over - a
 *             bind-mount target cannot be replaced. Whatever else writes it is "the system"
 *   network   an rtnetlink socket on the link, address and route groups, plus inotify on the
 *             resolv.conf. Our own doings are not a change of the network - what our requests did
 *             (the port id of the one request socket) and what the kernel says of our tun devices -
 *             as on QNX, where the phone never sees them either
 */

#include "bt_plat.h"
#include "bt_log.h"

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define BT_RTPROT   126                 /* our host routes: `ip route show proto 126` */

/* The physical default route of a family. */
typedef struct {
    char    dev[BT_IFNAME_MAX];
    int     has_gw;
    uint8_t gw[16];
} defroute;

/* A host route to a server. */
typedef struct {
    bt_addr  a;
    defroute via;                       /* the default route it went through */
    int      mine;                      /* we put it in; else one was there already - never ours to delete */
} pin;

static struct {
    char dns_file[256];
    int  nl_mon;                        /* rtnetlink, the change groups */
    int  ino;                           /* inotify on dns_file */
    int  ino_wd;
    char sys_text[BT_DNS_TEXT_MAX];     /* the system's resolv.conf, the last we saw of it */
    char our_text[BT_DNS_TEXT_MAX];     /* what we wrote; "" = ours are not in */
    uint32_t nl_seq;
    int  nl_req;                        /* rtnetlink, every request of ours */
    uint32_t nl_portid;                 /* ... its port id, on the change messages our requests cause */
    int  tun_idx[8];                    /* the interface indexes our tun devices had, the latest ones */
    unsigned tun_idx_next;
    int  hostroute;                     /* --egress hostroute */
    pin  pins[BT_BYPASS_MAX];
    size_t n_pins;
} P = { .nl_mon = -1, .ino = -1, .ino_wd = -1, .nl_seq = 1, .nl_req = -1 };

/* --------------------------------------------------------------------- small helpers */

static int read_text(const char* path, char* out, size_t cap)
{
    size_t got = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0) return 0;
    while (got + 1 < cap) {
        ssize_t r = read(fd, out + got, cap - 1 - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    out[got] = '\0';
    return 1;
}

/* In place: truncate and write. */
static int write_text(const char* path, const char* text)
{
    size_t len = strlen(text), put = 0;
    int fd = open(path, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0644);

    if (fd < 0) return 0;
    while (put < len) {
        ssize_t w = write(fd, text + put, len - put);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) {
            close(fd);
            return 0;
        }
        put += (size_t)w;
    }
    return close(fd) == 0;
}

static void watch_dns_file(void)
{
    if (P.ino < 0) return;
    if (P.ino_wd >= 0) inotify_rm_watch(P.ino, P.ino_wd);
    P.ino_wd = inotify_add_watch(P.ino, P.dns_file, IN_CLOSE_WRITE | IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF);
}

int bt_plat_init(const bt_plat_opts* o)
{
    struct sockaddr_nl sa;

    if (!o || !o->dns_file || strlen(o->dns_file) >= sizeof(P.dns_file)) {
        errno = EINVAL;
        return 0;
    }
    if (!o->egress || strcmp(o->egress, "auto") == 0 || strcmp(o->egress, "bind") == 0) P.hostroute = 0;
    else if (strcmp(o->egress, "hostroute") == 0) P.hostroute = 1;
    else {
        errno = EINVAL;                 /* fib: there is no FIB 15 here */
        return 0;
    }
    strcpy(P.dns_file, o->dns_file);
    if (!read_text(P.dns_file, P.sys_text, sizeof(P.sys_text))) P.sys_text[0] = '\0';

    P.nl_req = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (P.nl_req < 0) return 0;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(P.nl_req, (struct sockaddr*)&sa, sizeof(sa)) < 0) return 0;
    {
        socklen_t sl = sizeof(sa);
        struct timeval tv = { 2, 0 };   /* an ack that never comes must not stop the loop */
        if (getsockname(P.nl_req, (struct sockaddr*)&sa, &sl) < 0) return 0;
        P.nl_portid = sa.nl_pid;
        setsockopt(P.nl_req, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    P.nl_mon = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (P.nl_mon < 0) return 0;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
    if (bind(P.nl_mon, (struct sockaddr*)&sa, sizeof(sa)) < 0) return 0;

    P.ino = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    watch_dns_file();
    return 1;
}

void bt_plat_fini(void)
{
    bt_bypass_set(NULL, 0, 0);          /* the tunnels took theirs; whatever is left */
    if (P.nl_mon >= 0) close(P.nl_mon);
    if (P.ino >= 0) close(P.ino);
    if (P.nl_req >= 0) close(P.nl_req);
    P.nl_mon = P.ino = P.ino_wd = P.nl_req = -1;
}

/* --------------------------------------------------------------------- rtnetlink requests */

static void nl_attr(struct nlmsghdr* h, size_t cap, unsigned short type, const void* data, size_t len)
{
    struct rtattr* a = (struct rtattr*)((char*)h + NLMSG_ALIGN(h->nlmsg_len));
    size_t alen = RTA_LENGTH(len);

    if (NLMSG_ALIGN(h->nlmsg_len) + RTA_ALIGN(alen) > cap) return;
    a->rta_type = type;
    a->rta_len = (unsigned short)alen;
    memcpy(RTA_DATA(a), data, len);
    h->nlmsg_len = (uint32_t)(NLMSG_ALIGN(h->nlmsg_len) + RTA_ALIGN(alen));
}

/* Sends one request on the request socket and waits for its ack: 0 or the negative errno the
 * kernel gave. One socket for all of them: its port id marks the change messages that are ours. */
static int nl_talk(struct nlmsghdr* h)
{
    struct sockaddr_nl sa;
    char buf[4096];
    ssize_t n;

    if (P.nl_req < 0) return -EBADF;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    h->nlmsg_seq = ++P.nl_seq;
    h->nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK;
    if (sendto(P.nl_req, h, h->nlmsg_len, 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) return -errno;
    while ((n = recv(P.nl_req, buf, sizeof(buf), 0)) > 0) {
        struct nlmsghdr* r;
        int len = (int)n;
        for (r = (struct nlmsghdr*)buf; NLMSG_OK(r, (unsigned)len); r = NLMSG_NEXT(r, len)) {
            if (r->nlmsg_seq != h->nlmsg_seq) continue;         /* an earlier request's, late */
            if (r->nlmsg_type == NLMSG_ERROR) return ((struct nlmsgerr*)NLMSG_DATA(r))->error;
        }
    }
    return n < 0 ? -errno : -EIO;
}

int bt_if_addr(const char* ifname, int family, const uint8_t* addr, int cidr)
{
    struct {
        struct nlmsghdr  h;
        struct ifaddrmsg a;
        char             attrs[128];
    } req;
    size_t alen = family == 4 ? 4 : 16;
    int r;

    memset(&req, 0, sizeof(req));
    req.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.h.nlmsg_type = RTM_NEWADDR;
    req.h.nlmsg_flags = NLM_F_CREATE | NLM_F_REPLACE;
    req.a.ifa_family = family == 4 ? AF_INET : AF_INET6;
    req.a.ifa_prefixlen = (unsigned char)cidr;
    req.a.ifa_flags = family == 6 ? IFA_F_NODAD : 0;
    req.a.ifa_index = if_nametoindex(ifname);
    if (!req.a.ifa_index) return 0;
    nl_attr(&req.h, sizeof(req), IFA_LOCAL, addr, alen);
    nl_attr(&req.h, sizeof(req), IFA_ADDRESS, addr, alen);
    r = nl_talk(&req.h);
    if (r < 0) {
        errno = -r;
        return 0;
    }
    return 1;
}

int bt_if_addr_del(const char* ifname, int family, const uint8_t* addr, int cidr)
{
    struct {
        struct nlmsghdr  h;
        struct ifaddrmsg a;
        char             attrs[128];
    } req;
    size_t alen = family == 4 ? 4 : 16;
    int r;

    memset(&req, 0, sizeof(req));
    req.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.h.nlmsg_type = RTM_DELADDR;
    req.a.ifa_family = family == 4 ? AF_INET : AF_INET6;
    req.a.ifa_prefixlen = (unsigned char)cidr;
    req.a.ifa_index = if_nametoindex(ifname);
    if (!req.a.ifa_index) return 0;
    nl_attr(&req.h, sizeof(req), IFA_LOCAL, addr, alen);
    nl_attr(&req.h, sizeof(req), IFA_ADDRESS, addr, alen);
    r = nl_talk(&req.h);
    if (r < 0) {
        errno = -r;
        return 0;
    }
    return 1;
}

int bt_route(int add, const char* ifname, int family, const uint8_t* addr, int cidr)
{
    struct {
        struct nlmsghdr h;
        struct rtmsg    rt;
        char            attrs[128];
    } req;
    uint32_t oif = if_nametoindex(ifname);
    int r;

    if (!oif && add) return 0;
    memset(&req, 0, sizeof(req));
    req.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.h.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
    req.h.nlmsg_flags = add ? (NLM_F_CREATE | NLM_F_EXCL) : 0;
    req.rt.rtm_family = family == 4 ? AF_INET : AF_INET6;
    req.rt.rtm_dst_len = (unsigned char)cidr;
    req.rt.rtm_table = RT_TABLE_MAIN;
    req.rt.rtm_protocol = RTPROT_STATIC;
    req.rt.rtm_scope = RT_SCOPE_LINK;
    req.rt.rtm_type = RTN_UNICAST;
    if (cidr) nl_attr(&req.h, sizeof(req), RTA_DST, addr, family == 4 ? 4 : 16);
    if (oif) nl_attr(&req.h, sizeof(req), RTA_OIF, &oif, sizeof(oif));
    r = nl_talk(&req.h);
    if (r == 0 || (add && r == -EEXIST) || (!add && (r == -ESRCH || r == -ENOENT || r == -ENODEV))) return 1;
    errno = -r;
    return 0;
}

int bt_routes_flush(const char* ifname)
{
    (void)ifname;       /* a Linux tun device and its routes die with the fd that made it */
    return 1;
}

/* --------------------------------------------------------------------- tun */

int bt_tun_open(char ifname[BT_IFNAME_MAX])
{
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);

    if (fd < 0) return -1;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strcpy(ifr.ifr_name, "tun%d");
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return -1;
    }
    snprintf(ifname, BT_IFNAME_MAX, "%s", ifr.ifr_name);
    /* the messages of its removal come when it has no name to look up any more */
    P.tun_idx[P.tun_idx_next++ % (sizeof(P.tun_idx) / sizeof(P.tun_idx[0]))] = (int)if_nametoindex(ifname);
    return fd;
}

void bt_tun_close(int fd, const char* ifname)
{
    (void)ifname;                       /* a non-persistent device goes with its fd */
    if (fd >= 0) close(fd);
}

ssize_t bt_tun_read(int fd, uint8_t* pkt, size_t cap)
{
    ssize_t n = read(fd, pkt, cap);

    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    return n;
}

int bt_tun_write(int fd, const uint8_t* pkt, size_t len)
{
    return write(fd, pkt, len) == (ssize_t)len;
}

static int if_ioctl_sock(void)
{
    return socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
}

int bt_if_mtu(const char* ifname, int mtu)
{
    struct ifreq ifr;
    int s = if_ioctl_sock(), ok;

    if (s < 0) return 0;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    ifr.ifr_mtu = mtu;
    ok = ioctl(s, SIOCSIFMTU, &ifr) == 0;
    close(s);
    return ok;
}

int bt_if_up(const char* ifname)
{
    struct ifreq ifr;
    int s = if_ioctl_sock(), ok = 0;

    if (s < 0) return 0;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        ok = ioctl(s, SIOCSIFFLAGS, &ifr) == 0;
    }
    close(s);
    return ok;
}

/* --------------------------------------------------------------------- egress */

/* The physical default route of a family: its interface and gateway; 0 when there is none. */
static int default_route(int family, defroute* out)
{
    char line[512];
    unsigned long best_metric = ~0UL;
    FILE* f = fopen(family == 4 ? "/proc/net/route" : "/proc/net/ipv6_route", "r");

    memset(out, 0, sizeof(*out));
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        char dev[64];
        unsigned long metric, flags;
        uint8_t gw[16];
        int has_gw, i;

        memset(gw, 0, sizeof(gw));
        if (family == 4) {
            unsigned long dst, g, mask, refcnt, use, mtu, win, irtt;
            uint32_t g32;
            if (sscanf(line, "%63s %lx %lx %lx %lu %lu %lu %lx %lu %lu %lu", dev, &dst, &g, &flags, &refcnt,
                       &use, &metric, &mask, &mtu, &win, &irtt) != 11)
                continue;
            if (dst != 0 || mask != 0 || !(flags & 1)) continue;        /* default, RTF_UP */
            g32 = (uint32_t)g;                  /* the kernel printed the raw __be32 as a number */
            memcpy(gw, &g32, 4);
            has_gw = (flags & 2) && g32 != 0;   /* RTF_GATEWAY */
        } else {
            char d[40], s[40], nh[40];
            unsigned dlen, slen, refcnt, use;
            if (sscanf(line, "%39s %x %39s %x %39s %lx %x %x %lx %63s", d, &dlen, s, &slen, nh, &metric,
                       &refcnt, &use, &flags, dev) != 10)
                continue;
            if (dlen != 0 || strcmp(d, "00000000000000000000000000000000") != 0) continue;
            if (strcmp(dev, "lo") == 0 || (flags & 0x0200)) continue;  /* RTF_REJECT */
            for (i = 0; i < 16 && sscanf(nh + 2 * i, "%2hhx", &gw[i]) == 1; i++) {}
            has_gw = (flags & 2) && strcmp(nh, "00000000000000000000000000000000") != 0;
        }
        if (strncmp(dev, "tun", 3) == 0) continue;                      /* never our own */
        if (metric < best_metric) {
            best_metric = metric;
            snprintf(out->dev, sizeof(out->dev), "%.15s", dev);
            memcpy(out->gw, gw, sizeof(gw));
            out->has_gw = has_gw;
        }
    }
    fclose(f);
    return out->dev[0] != '\0';
}

int bt_default_if(int family, char ifname[BT_IFNAME_MAX])
{
    defroute d;
    if (!default_route(family, &d)) return 0;
    memcpy(ifname, d.dev, BT_IFNAME_MAX);
    return 1;
}

int bt_udp_open(int family, uint16_t port)
{
    char dev[BT_IFNAME_MAX];
    int fd, one = 1;

    if (!bt_default_if(family, dev)) {
        errno = ENETUNREACH;
        return -1;
    }
    fd = socket(family == 4 ? AF_INET : AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    /* hostroute: a plain socket - the host routes of bt_bypass_set keep it out of the tunnels */
    if (!P.hostroute && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, (socklen_t)strlen(dev) + 1) < 0) goto fail;
    if (family == 6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) < 0) goto fail;
    if (family == 4) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) goto fail;
    } else {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(port);
        if (bind(fd, (struct sockaddr*)&sin6, sizeof(sin6)) < 0) goto fail;
    }
    return fd;
fail:
    {
        int e = errno;
        close(fd);
        errno = e;
    }
    return -1;
}

/* --------------------------------------------------------------------- host routes */

/* Whether `a` is in the subnet of an interface that is not a tunnel: its connected route, more
 * specific than our /1, takes it out already - and a host route through the gateway would only
 * bounce it off the router. */
static int on_link(const bt_addr* a)
{
    struct ifaddrs *ifa, *p;
    size_t len = a->family == 4 ? 4 : 16, i;
    int found = 0;

    if (getifaddrs(&ifa) != 0) return 0;
    for (p = ifa; p && !found; p = p->ifa_next) {
        const uint8_t *ad, *mk, *peer = NULL;
        int any = 0;

        if (!p->ifa_addr || !p->ifa_netmask || !(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK) ||
            strncmp(p->ifa_name, "tun", 3) == 0)
            continue;
        if (a->family == 4 && p->ifa_addr->sa_family == AF_INET) {
            ad = (const uint8_t*)&((const struct sockaddr_in*)p->ifa_addr)->sin_addr;
            mk = (const uint8_t*)&((const struct sockaddr_in*)p->ifa_netmask)->sin_addr;
            if ((p->ifa_flags & IFF_POINTOPOINT) && p->ifa_dstaddr)
                peer = (const uint8_t*)&((const struct sockaddr_in*)p->ifa_dstaddr)->sin_addr;
        } else if (a->family == 6 && p->ifa_addr->sa_family == AF_INET6) {
            ad = (const uint8_t*)&((const struct sockaddr_in6*)p->ifa_addr)->sin6_addr;
            mk = (const uint8_t*)&((const struct sockaddr_in6*)p->ifa_netmask)->sin6_addr;
            if ((p->ifa_flags & IFF_POINTOPOINT) && p->ifa_dstaddr)
                peer = (const uint8_t*)&((const struct sockaddr_in6*)p->ifa_dstaddr)->sin6_addr;
            if (ad[0] == 0xfe && (ad[1] & 0xc0) == 0x80) continue;     /* link-local: every link has one */
        } else {
            continue;
        }
        if (peer && memcmp(peer, a->addr, len) == 0) {
            found = 1;
            break;
        }
        for (i = 0; i < len; i++) any |= mk[i];
        if (!any) continue;
        for (i = 0; i < len && (ad[i] & mk[i]) == (a->addr[i] & mk[i]); i++) {}
        if (i == len) found = 1;
    }
    freeifaddrs(ifa);
    return found;
}

static int same_via(const defroute* x, const defroute* y)
{
    return strcmp(x->dev, y->dev) == 0 && x->has_gw == y->has_gw && (!x->has_gw || memcmp(x->gw, y->gw, 16) == 0);
}

/* Adds (via the default route `via`) or deletes the host route to `a`: 0 or the negative errno.
 * A delete names our protocol, so the kernel only ever takes one of ours. */
static int pin_route(int add, const bt_addr* a, const defroute* via)
{
    struct {
        struct nlmsghdr h;
        struct rtmsg    rt;
        char            attrs[128];
    } req;
    size_t alen = a->family == 4 ? 4 : 16;

    memset(&req, 0, sizeof(req));
    req.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.h.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
    req.h.nlmsg_flags = add ? (NLM_F_CREATE | NLM_F_EXCL) : 0;
    req.rt.rtm_family = a->family == 4 ? AF_INET : AF_INET6;
    req.rt.rtm_dst_len = (unsigned char)(alen * 8);
    req.rt.rtm_table = RT_TABLE_MAIN;
    req.rt.rtm_protocol = BT_RTPROT;
    nl_attr(&req.h, sizeof(req), RTA_DST, a->addr, alen);
    if (add) {
        uint32_t oif = if_nametoindex(via->dev);
        if (!oif) return -ENODEV;
        req.rt.rtm_scope = via->has_gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
        req.rt.rtm_type = RTN_UNICAST;
        if (via->has_gw) nl_attr(&req.h, sizeof(req), RTA_GATEWAY, via->gw, alen);
        nl_attr(&req.h, sizeof(req), RTA_OIF, &oif, sizeof(oif));
    } else {
        req.rt.rtm_scope = RT_SCOPE_NOWHERE;            /* any scope */
    }
    return nl_talk(&req.h);
}

static void pin_text(const bt_addr* a, const defroute* via, char* out, size_t cap)
{
    char at[64], gt[64];

    inet_ntop(a->family == 4 ? AF_INET : AF_INET6, a->addr, at, sizeof(at));
    if (!via) snprintf(out, cap, "%s", at);
    else if (!via->has_gw) snprintf(out, cap, "%s (%s)", at, via->dev);
    else {
        inet_ntop(a->family == 4 ? AF_INET : AF_INET6, via->gw, gt, sizeof(gt));
        snprintf(out, cap, "%s via %s (%s)", at, gt, via->dev);
    }
}

int bt_bypass_set(const bt_addr* addrs, size_t n, int recheck)
{
    defroute def[2];
    int have[2] = { -1, -1 }, ok = 1;
    size_t i, j;
    char text[160];

    if (!P.hostroute) return 1;

    /* What goes: not asked for any more, or its way out moved. */
    for (i = P.n_pins; i-- > 0;) {
        pin* p = &P.pins[i];
        int k = p->a.family == 6, keep = 0;

        for (j = 0; j < n && !bt_addr_equal(&addrs[j], &p->a); j++) {}
        if (j < n) {
            if (have[k] < 0) have[k] = default_route(p->a.family, &def[k]);
            keep = have[k] && same_via(&p->via, &def[k]) && !(recheck && on_link(&p->a));
        }
        if (keep) {
            /* After a network change: the network manager may have wiped ours - or taken away the
             * one that was there before us. */
            if (recheck && pin_route(1, &p->a, &p->via) == 0) {
                pin_text(&p->a, &p->via, text, sizeof(text));
                BT_I("host route: %s %s", text, p->mine ? "back" : "ours now");
                p->mine = 1;
            }
            continue;
        }
        pin_text(&p->a, NULL, text, sizeof(text));
        if (p->mine) {
            int r = pin_route(0, &p->a, NULL);
            if (r != 0 && r != -ESRCH) BT_W("host route to %s: %s", text, strerror(-r));
        }
        BT_I("host route: %s gone", text);
        P.pins[i] = P.pins[--P.n_pins];
    }

    /* What comes. */
    for (j = 0; j < n; j++) {
        const bt_addr* a = &addrs[j];
        int k = a->family == 6, r;
        pin* p;

        for (i = 0; i < P.n_pins && !bt_addr_equal(&P.pins[i].a, a); i++) {}
        if (i < P.n_pins) continue;
        if (have[k] < 0) have[k] = default_route(a->family, &def[k]);
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
        r = pin_route(1, a, &def[k]);
        if (r == -EEXIST) {
            /* One of ours that a lost journal left - or someone else's, which stays as it is. */
            if (pin_route(0, a, NULL) == 0) r = pin_route(1, a, &def[k]);
            else {
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
    int r = pin_route(0, a, NULL);
    if (r == 0 || r == -ESRCH) return 1;
    errno = -r;
    return 0;
}

/* --------------------------------------------------------------------- DNS */

size_t bt_dns_system(bt_addr* out, size_t cap)
{
    const char* p = P.sys_text;
    size_t n = 0;

    while (*p && n < cap) {
        char word[16], addr[64];
        const char* eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[256];

        if (len < sizeof(line)) {
            memcpy(line, p, len);
            line[len] = '\0';
            if (sscanf(line, "%15s %63s", word, addr) == 2 && strcmp(word, "nameserver") == 0) {
                memset(&out[n], 0, sizeof(out[n]));
                if (inet_pton(AF_INET, addr, out[n].addr) == 1) out[n++].family = 4;
                else if (inet_pton(AF_INET6, addr, out[n].addr) == 1) out[n++].family = 6;
            }
        }
        p += len + (eol ? 1 : 0);
    }
    return n;
}

int bt_dns_apply(const bt_addr* servers, size_t n, const char* search)
{
    char text[BT_DNS_TEXT_MAX];
    size_t len, i;

    len = (size_t)snprintf(text, sizeof(text), "# written by bbtunneld: the tunnel's DNS\n");
    for (i = 0; i < n && len < sizeof(text); i++) {
        char a[64];
        inet_ntop(servers[i].family == 4 ? AF_INET : AF_INET6, servers[i].addr, a, sizeof(a));
        len += (size_t)snprintf(text + len, sizeof(text) - len, "nameserver %s\n", a);
    }
    if (search && *search && len < sizeof(text)) len += (size_t)snprintf(text + len, sizeof(text) - len, "search %s\n", search);
    if (len >= sizeof(text)) {
        errno = E2BIG;
        return 0;
    }
    if (!P.our_text[0]) {
        /* The first time in: what is there now is the system's. */
        char now[BT_DNS_TEXT_MAX];
        if (read_text(P.dns_file, now, sizeof(now)) && strcmp(now, text) != 0) strcpy(P.sys_text, now);
    }
    strcpy(P.our_text, text);
    return write_text(P.dns_file, text);
}

int bt_dns_restore(void)
{
    P.our_text[0] = '\0';
    return write_text(P.dns_file, P.sys_text);
}

size_t bt_dns_snapshot(char* out, size_t cap)
{
    size_t n = strlen(P.sys_text);
    if (!cap) return 0;
    if (n >= cap) n = cap - 1;
    memcpy(out, P.sys_text, n);
    out[n] = '\0';
    return n;
}

int bt_dns_restore_text(const char* text)
{
    char now[BT_DNS_TEXT_MAX];

    /* Only when what is there now is ours - the system may have moved on already. */
    if (read_text(P.dns_file, now, sizeof(now)) && strncmp(now, "# written by bbtunneld", 22) != 0) {
        strcpy(P.sys_text, now);
        return 1;
    }
    snprintf(P.sys_text, sizeof(P.sys_text), "%s", text);
    P.our_text[0] = '\0';
    return write_text(P.dns_file, P.sys_text);
}

/* --------------------------------------------------------------------- changes */

/* Whether an interface index is a tun device of ours: by its name while it lives; once it is gone
 * (the messages of its own removal), by the indexes our devices had. */
static int index_is_tun(int idx)
{
    char name[IF_NAMESIZE];
    size_t i;

    if (idx <= 0) return 0;
    if (if_indextoname((unsigned)idx, name)) return strncmp(name, "tun", 3) == 0;
    for (i = 0; i < sizeof(P.tun_idx) / sizeof(P.tun_idx[0]); i++)
        if (P.tun_idx[i] == idx) return 1;
    return 0;
}

/* A link message about a tun device - by the name it carries: a device being deleted has no
 * index to look up any more. */
static int link_is_tun(const struct nlmsghdr* h)
{
    const struct ifinfomsg* i = (const struct ifinfomsg*)NLMSG_DATA(h);
    const struct rtattr* a;
    int len = (int)h->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*i));

    if (len < 0) return 0;
    for (a = (const struct rtattr*)((const char*)i + NLMSG_ALIGN(sizeof(*i))); RTA_OK(a, len); a = RTA_NEXT(a, len))
        if (a->rta_type == IFLA_IFNAME) return strncmp((const char*)RTA_DATA(a), "tun", 3) == 0;
    return index_is_tun(i->ifi_index);
}

/* The interface a route message leaves by (RTA_OIF); 0 when it names none. */
static int route_oif(const struct nlmsghdr* h)
{
    const struct rtmsg* r = (const struct rtmsg*)NLMSG_DATA(h);
    const struct rtattr* a;
    int len = (int)h->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*r));

    if (len < 0) return 0;
    for (a = RTM_RTA(r); RTA_OK(a, len); a = RTA_NEXT(a, len)) {
        if (a->rta_type == RTA_OIF && RTA_PAYLOAD(a) >= sizeof(uint32_t)) {
            uint32_t oif;
            memcpy(&oif, RTA_DATA(a), sizeof(oif));
            return (int)oif;
        }
    }
    return 0;
}

/* For the debug log: what a route message is about (table, protocol, type, destination). */
static const char* route_text(const struct nlmsghdr* h)
{
    static char out[160];
    const struct rtmsg* r = (const struct rtmsg*)NLMSG_DATA(h);
    const struct rtattr* a;
    int len = (int)h->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*r));
    char dst[64] = "default";

    if ((h->nlmsg_type != RTM_NEWROUTE && h->nlmsg_type != RTM_DELROUTE) || len < 0) return "";
    for (a = RTM_RTA(r); RTA_OK(a, len); a = RTA_NEXT(a, len))
        if (a->rta_type == RTA_DST) inet_ntop(r->rtm_family, RTA_DATA(a), dst, sizeof(dst));
    snprintf(out, sizeof(out), " (%s/%u table %u proto %u type %u)", dst, r->rtm_dst_len, r->rtm_table,
             r->rtm_protocol, r->rtm_type);
    return out;
}

int bt_net_fds(struct pollfd* out, int cap)
{
    int n = 0;
    if (P.nl_mon >= 0 && n < cap) {
        out[n].fd = P.nl_mon;
        out[n].events = POLLIN;
        out[n++].revents = 0;
    }
    if (P.ino >= 0 && n < cap) {
        out[n].fd = P.ino;
        out[n].events = POLLIN;
        out[n++].revents = 0;
    }
    return n;
}

int bt_net_event(const struct pollfd* pfd)
{
    char buf[8192];
    int changed = 0;
    ssize_t n;

    if (pfd->fd == P.nl_mon) {
        while ((n = recv(P.nl_mon, buf, sizeof(buf), 0)) > 0 || (n < 0 && errno == ENOBUFS)) {
            struct nlmsghdr* h;
            int len = (int)n;
            if (n < 0) {                        /* overrun: something happened, we lost what */
                changed = 1;
                continue;
            }
            for (h = (struct nlmsghdr*)buf; NLMSG_OK(h, (unsigned)len); h = NLMSG_NEXT(h, len)) {
                int count = 0, idx = 0;
                if (P.nl_portid && h->nlmsg_pid == P.nl_portid) continue;      /* what we did */
                switch (h->nlmsg_type) {
                case RTM_NEWLINK: case RTM_DELLINK:
                    if (h->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifinfomsg)))
                        idx = ((struct ifinfomsg*)NLMSG_DATA(h))->ifi_index;
                    count = !link_is_tun(h);
                    break;
                case RTM_NEWADDR: case RTM_DELADDR:
                    if (h->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifaddrmsg)))
                        idx = (int)((struct ifaddrmsg*)NLMSG_DATA(h))->ifa_index;
                    count = !index_is_tun(idx);
                    break;
                case RTM_NEWROUTE: case RTM_DELROUTE:
                    /* the kernel's own, for our device (its local and link routes) */
                    idx = route_oif(h);
                    count = h->nlmsg_pid != 0 || !index_is_tun(idx);
                    break;
                default:
                    break;
                }
                if (count) {
                    BT_D("network: message %u from port %u, interface %d%s", h->nlmsg_type, h->nlmsg_pid, idx,
                         route_text(h));
                    changed = 1;
                }
            }
        }
        return changed;
    }
    if (pfd->fd == P.ino) {
        char now[BT_DNS_TEXT_MAX];
        int moved = 0;
        while ((n = read(P.ino, buf, sizeof(buf))) > 0) {
            char* p = buf;
            while (p < buf + n) {
                struct inotify_event* e = (struct inotify_event*)p;
                if (e->mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED)) moved = 1;
                p += sizeof(struct inotify_event) + e->len;
            }
        }
        if (moved) watch_dns_file();
        /* Someone else wrote it: that is the system's setting now - and if ours were in, they
         * are out, even when the system wrote back exactly what it had before. */
        if (read_text(P.dns_file, now, sizeof(now)) && strcmp(now, P.our_text) != 0 &&
            (P.our_text[0] || strcmp(now, P.sys_text) != 0)) {
            strcpy(P.sys_text, now);
            changed = 1;
        }
        return changed;
    }
    return 0;
}

/* inotify tells us about the resolv.conf: nothing to look at on a clock */
uint64_t bt_net_deadline(void)
{
    return BT_NEVER;
}

int bt_net_check(uint64_t now)
{
    (void)now;
    return 0;
}

/* No status bar here. bt_tunnel logs what it asks for, and the e2e test reads that. */
int bt_status_icon(const char* state)
{
    (void)state;
    return 1;
}
