/*
 * tunprobe - a read-mostly probe of the BB10 (QNX io-pkt) tun data path.
 *
 * Answers the open questions in docs/PLAN.md section 4 and the DEVICE TEST checklist in
 * research_notes/.../qnx_network_datapath.md before a line of the real daemon is written:
 * does /dev/tunN behave like NetBSD 4 tun(4), what framing does it use, do the size limits
 * hold, can we steer our own UDP socket off the tunnel, and does the full-tunnel route pair
 * survive.
 *
 * It is deliberately self-contained: both directions of the data path are proven without a
 * peer, without ping and without a second shell.
 *   - host -> tun: send a UDP datagram to the peer address, read it back off the tun fd.
 *   - tun -> host: write a forged IP+UDP packet into the tun fd, receive it on a local socket.
 *
 * Safety: everything it changes is temporary and undone on exit, including on SIGINT/SIGTERM.
 * The test addresses (10.99.99.0/30, fd00:99::/64) are chosen not to collide with a home LAN.
 * The default route is never touched; the full-tunnel route pair (0/1 + 128/1) is only added
 * with --routes, and a link route such as the USB 169.254.0.0/30 that carries our SSH session
 * is more specific than /1, so the session survives. Nothing here writes to disk.
 *
 * Build: daemon/probe/build.sh (gcc 9.3 cross toolchain, in WSL).
 * Run as root on the device: /tmp/tunprobe info | tun [--routes] [--serve N] | bind | dns
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/uio.h>
#include <sys/utsname.h>

#include <net/if.h>
#include <net/if_tun.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <unistd.h>            /* confstr */

/* ------------------------------------------------------------------ reporting */

static int g_pass, g_fail, g_note;

static void ok(const char* fmt, ...)
{
    va_list ap;
    printf("  [ OK ] ");
    va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n");
    g_pass++;
}

static void bad(const char* fmt, ...)
{
    va_list ap;
    printf("  [FAIL] ");
    va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n");
    g_fail++;
}

static void note(const char* fmt, ...)
{
    va_list ap;
    printf("  [note] ");
    va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n");
    g_note++;
}

static void section(const char* title)
{
    printf("\n== %s\n", title);
}

/* ------------------------------------------------------------------ test parameters */

#define TUN_LOCAL   "10.99.99.1"
#define TUN_PEER    "10.99.99.2"
#define TUN6_LOCAL  "fd00:99::1"
#define TUN6_PEER   "fd00:99::2"
#define TUN_MTU     1420
#define PORT_OUT    9999       /* we send here; the packet must surface on the tun fd */
#define PORT_IN     9998       /* we listen here; a forged packet from tun must arrive */

static char g_ifname[IFNAMSIZ] = "tun0";
static int  g_tunfd = -1;
static int  g_routes_added = 0;
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* ------------------------------------------------------------------ small helpers */

/* BSD sockaddrs in a routing message are padded to a long boundary. */
#define RT_ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

/* strncpy into a fixed ifr_name warns about truncation; copy the bounded length instead. */
static void set_ifname(char* dst, const char* name)
{
    size_t n = strlen(name);
    if (n >= IFNAMSIZ) n = IFNAMSIZ - 1;
    memset(dst, 0, IFNAMSIZ);
    memcpy(dst, name, n);
}

static void sin_set(struct sockaddr_in* sin, const char* addr)
{
    memset(sin, 0, sizeof(*sin));
    sin->sin_len = sizeof(*sin);
    sin->sin_family = AF_INET;
    if (addr) inet_pton(AF_INET, addr, &sin->sin_addr);
}

static void sin_set_raw(struct sockaddr_in* sin, uint32_t host_order)
{
    memset(sin, 0, sizeof(*sin));
    sin->sin_len = sizeof(*sin);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(host_order);
}

static uint16_t cksum16(const void* data, size_t len, uint32_t seed)
{
    const uint8_t* p = (const uint8_t*)data;
    uint32_t sum = seed;
    while (len > 1) { sum += (uint32_t)((p[0] << 8) | p[1]); p += 2; len -= 2; }
    if (len) sum += (uint32_t)(p[0] << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* ------------------------------------------------------------------ interface config */

static int if_set_addr4(const char* ifname, const char* local, const char* peer)
{
    struct ifaliasreq ifra;
    int s, r;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { bad("socket(AF_INET): %s", strerror(errno)); return -1; }

    memset(&ifra, 0, sizeof(ifra));
    set_ifname(ifra.ifra_name, ifname);
    sin_set((struct sockaddr_in*)&ifra.ifra_addr, local);
    sin_set((struct sockaddr_in*)&ifra.ifra_dstaddr, peer);
    sin_set((struct sockaddr_in*)&ifra.ifra_mask, "255.255.255.255");

    r = ioctl(s, SIOCAIFADDR, &ifra);
    close(s);
    return r;
}

static int if_set_addr6(const char* ifname, const char* local, const char* peer)
{
    struct in6_aliasreq ifra;
    struct sockaddr_in6* sa;
    int s, r, i;

    s = socket(AF_INET6, SOCK_DGRAM, 0);
    if (s < 0) { bad("socket(AF_INET6): %s", strerror(errno)); return -1; }

    memset(&ifra, 0, sizeof(ifra));
    set_ifname(ifra.ifra_name, ifname);

    sa = &ifra.ifra_addr;
    sa->sin6_len = sizeof(*sa);
    sa->sin6_family = AF_INET6;
    inet_pton(AF_INET6, local, &sa->sin6_addr);

    sa = &ifra.ifra_dstaddr;
    sa->sin6_len = sizeof(*sa);
    sa->sin6_family = AF_INET6;
    inet_pton(AF_INET6, peer, &sa->sin6_addr);

    sa = &ifra.ifra_prefixmask;
    sa->sin6_len = sizeof(*sa);
    sa->sin6_family = AF_INET6;
    for (i = 0; i < 16; i++) sa->sin6_addr.s6_addr[i] = 0xff;   /* /128 */

    ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
    ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

    r = ioctl(s, SIOCAIFADDR_IN6, &ifra);
    close(s);
    return r;
}

static int if_set_mtu(const char* ifname, int mtu)
{
    struct ifreq ifr;
    int s, r;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    memset(&ifr, 0, sizeof(ifr));
    set_ifname(ifr.ifr_name, ifname);
    ifr.ifr_mtu = mtu;
    r = ioctl(s, SIOCSIFMTU, &ifr);
    close(s);
    return r;
}

static int if_get_flags(const char* ifname, int* flags)
{
    struct ifreq ifr;
    int s, r;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    memset(&ifr, 0, sizeof(ifr));
    set_ifname(ifr.ifr_name, ifname);
    r = ioctl(s, SIOCGIFFLAGS, &ifr);
    /* QNX widened ifr_flags to int - NetBSD code that reads a short would truncate here. */
    if (r == 0) *flags = ifr.ifr_flags;
    close(s);
    return r;
}

static int if_up(const char* ifname)
{
    struct ifreq ifr;
    int s, r, flags = 0;

    if (if_get_flags(ifname, &flags) < 0) return -1;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    memset(&ifr, 0, sizeof(ifr));
    set_ifname(ifr.ifr_name, ifname);
    ifr.ifr_flags = flags | IFF_UP;
    r = ioctl(s, SIOCSIFFLAGS, &ifr);
    close(s);
    return r;
}

static int if_destroy(const char* ifname)
{
    struct ifreq ifr;
    int s, r;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    memset(&ifr, 0, sizeof(ifr));
    set_ifname(ifr.ifr_name, ifname);
    r = ioctl(s, SIOCIFDESTROY, &ifr);
    close(s);
    return r;
}

/* ------------------------------------------------------------------ routing socket */

/*
 * One RTM_ADD / RTM_DELETE with DST + GATEWAY + NETMASK. The gateway is an address on the
 * tunnel itself, which is how wg-quick installs the full-tunnel pair on BSD, so RTF_GATEWAY
 * is deliberately not set.
 */
static int route_change4(int rtm_type, const char* dst, uint32_t mask_host_order,
                         const char* gw, int host_route)
{
    struct {
        struct rt_msghdr hdr;
        char             space[512];
    } msg;
    struct sockaddr_in sa;
    char* p;
    int s, len, seq = (int)getpid();
    ssize_t n;

    s = socket(PF_ROUTE, SOCK_RAW, 0);
    if (s < 0) { bad("socket(PF_ROUTE): %s", strerror(errno)); return -1; }

    memset(&msg, 0, sizeof(msg));
    msg.hdr.rtm_version = RTM_VERSION;
    msg.hdr.rtm_type    = rtm_type;
    msg.hdr.rtm_flags   = RTF_UP | RTF_STATIC | (host_route ? RTF_HOST : 0);
    msg.hdr.rtm_addrs   = RTA_DST | RTA_GATEWAY | (host_route ? 0 : RTA_NETMASK);
    msg.hdr.rtm_pid     = getpid();
    msg.hdr.rtm_seq     = seq;

    p = msg.space;
    sin_set(&sa, dst);
    memcpy(p, &sa, sizeof(sa)); p += RT_ROUNDUP(sizeof(sa));
    sin_set(&sa, gw);
    memcpy(p, &sa, sizeof(sa)); p += RT_ROUNDUP(sizeof(sa));
    if (!host_route) {
        sin_set_raw(&sa, mask_host_order);
        memcpy(p, &sa, sizeof(sa)); p += RT_ROUNDUP(sizeof(sa));
    }

    len = (int)(p - (char*)&msg);
    msg.hdr.rtm_msglen = (u_short)len;

    n = write(s, &msg, (size_t)len);
    if (n < 0) {
        int e = errno;
        close(s);
        errno = e;
        return -1;
    }
    close(s);
    return 0;
}

/* RTM_GET for 0.0.0.0 - the current default gateway and the interface it leaves by. */
static int route_get_default(char* gw_out, size_t gw_len, unsigned* ifindex_out)
{
    struct {
        struct rt_msghdr hdr;
        char             space[512];
    } msg;
    struct sockaddr_in sa;
    char* p;
    int s, len, seq = (int)getpid() + 1;
    ssize_t n;

    s = socket(PF_ROUTE, SOCK_RAW, 0);
    if (s < 0) return -1;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.rtm_version = RTM_VERSION;
    msg.hdr.rtm_type    = RTM_GET;
    msg.hdr.rtm_flags   = RTF_UP | RTF_GATEWAY;
    msg.hdr.rtm_addrs   = RTA_DST | RTA_NETMASK;
    msg.hdr.rtm_pid     = getpid();
    msg.hdr.rtm_seq     = seq;

    p = msg.space;
    sin_set(&sa, "0.0.0.0");
    memcpy(p, &sa, sizeof(sa)); p += RT_ROUNDUP(sizeof(sa));
    sin_set_raw(&sa, 0);
    memcpy(p, &sa, sizeof(sa)); p += RT_ROUNDUP(sizeof(sa));

    len = (int)(p - (char*)&msg);
    msg.hdr.rtm_msglen = (u_short)len;

    if (write(s, &msg, (size_t)len) < 0) { close(s); return -1; }

    /* Read until our own reply comes back. */
    for (;;) {
        n = read(s, &msg, sizeof(msg));
        if (n <= 0) { close(s); return -1; }
        if (msg.hdr.rtm_seq == seq && msg.hdr.rtm_pid == getpid()) break;
    }
    close(s);

    *ifindex_out = msg.hdr.rtm_index;
    gw_out[0] = '\0';

    /* Walk the sockaddrs and pick RTA_GATEWAY. */
    p = msg.space;
    {
        int bit;
        for (bit = 1; bit; bit <<= 1) {
            struct sockaddr* s2;
            if (!(msg.hdr.rtm_addrs & bit)) continue;
            s2 = (struct sockaddr*)p;
            if (bit == RTA_GATEWAY && s2->sa_family == AF_INET) {
                inet_ntop(AF_INET, &((struct sockaddr_in*)s2)->sin_addr, gw_out, (socklen_t)gw_len);
            }
            p += RT_ROUNDUP(s2->sa_len ? s2->sa_len : sizeof(struct sockaddr));
            if (p >= (char*)&msg + msg.hdr.rtm_msglen) break;
        }
    }
    return gw_out[0] ? 0 : -1;
}

/* ------------------------------------------------------------------ cleanup */

static void cleanup(void)
{
    if (g_routes_added) {
        route_change4(RTM_DELETE, "0.0.0.0",   0x80000000u, TUN_LOCAL, 0);
        route_change4(RTM_DELETE, "128.0.0.0", 0x80000000u, TUN_LOCAL, 0);
        printf("  [cleanup] full-tunnel routes removed\n");
        g_routes_added = 0;
    }
    if (g_tunfd >= 0) {
        close(g_tunfd);
        g_tunfd = -1;
        printf("  [cleanup] tun fd closed (tunclose downs the interface)\n");
    }
    if (if_destroy(g_ifname) == 0)
        printf("  [cleanup] %s destroyed\n", g_ifname);
}

/* ------------------------------------------------------------------ info */

static int cmd_info(void)
{
    struct utsname un;
    struct ifaddrs *ifa, *p;
    char buf[512], gw[64];
    unsigned ifindex = 0;
    size_t n;

    section("system");
    if (uname(&un) == 0)
        printf("  %s %s %s %s\n", un.sysname, un.nodename, un.release, un.machine);
    printf("  uid=%d  AF_INET6=%d (Linux 10, FreeBSD 28, macOS 30 - tun framing depends on it)\n",
           (int)getuid(), AF_INET6);
    printf("  sizeof(rt_msghdr)=%u  sizeof(ifreq)=%u  sizeof(ifaliasreq)=%u\n",
           (unsigned)sizeof(struct rt_msghdr), (unsigned)sizeof(struct ifreq),
           (unsigned)sizeof(struct ifaliasreq));

    section("interfaces with addresses");
    if (getifaddrs(&ifa) == 0) {
        for (p = ifa; p; p = p->ifa_next) {
            char a[INET6_ADDRSTRLEN];
            if (!p->ifa_addr) continue;
            if (p->ifa_addr->sa_family == AF_INET) {
                inet_ntop(AF_INET, &((struct sockaddr_in*)p->ifa_addr)->sin_addr, a, sizeof(a));
                printf("  %-8s inet  %s\n", p->ifa_name, a);
            } else if (p->ifa_addr->sa_family == AF_INET6) {
                inet_ntop(AF_INET6, &((struct sockaddr_in6*)p->ifa_addr)->sin6_addr, a, sizeof(a));
                printf("  %-8s inet6 %s\n", p->ifa_name, a);
            }
        }
        freeifaddrs(ifa);
    } else {
        bad("getifaddrs: %s", strerror(errno));
    }

    section("default route (RTM_GET on the routing socket)");
    if (route_get_default(gw, sizeof(gw), &ifindex) == 0) {
        char ifn[IFNAMSIZ] = "?";
        if_indextoname(ifindex, ifn);
        ok("gateway %s via ifindex %u (%s)", gw, ifindex, ifn);
    } else {
        bad("RTM_GET for 0.0.0.0 failed: %s", strerror(errno));
    }

    section("resolver configuration strings");
    n = confstr(_CS_RESOLVE, buf, sizeof(buf));
    if (n > 0 && n <= sizeof(buf)) ok("_CS_RESOLVE = \"%s\"", buf);
    else                           note("_CS_RESOLVE empty or unreadable (n=%u)", (unsigned)n);
    n = confstr(_CS_DOMAIN, buf, sizeof(buf));
    if (n > 0 && n <= sizeof(buf)) ok("_CS_DOMAIN  = \"%s\"", buf);
    else                           note("_CS_DOMAIN empty or unreadable (n=%u)", (unsigned)n);

    return 0;
}

/* ------------------------------------------------------------------ tun tests */

static int open_tun(int unit)
{
    char path[32];
    int fd;

    snprintf(path, sizeof(path), "/dev/tun%d", unit);
    fd = open(path, O_RDWR);
    if (fd < 0) { bad("open(%s): %s", path, strerror(errno)); return -1; }
    ok("open(%s) -> fd %d", path, fd);
    snprintf(g_ifname, sizeof(g_ifname), "tun%d", unit);
    return fd;
}

/* host -> tun: a UDP datagram to the peer address must surface on the tun fd. */
static int test_outbound(void)
{
    struct sockaddr_in dst;
    uint8_t buf[4 + 2048];
    struct pollfd pfd;
    int s, r;
    const char payload[] = "tunprobe-out";
    ssize_t n;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { bad("socket: %s", strerror(errno)); return -1; }
    sin_set(&dst, TUN_PEER);
    dst.sin_port = htons(PORT_OUT);

    if (sendto(s, payload, sizeof(payload) - 1, 0, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
        bad("sendto %s:%d: %s - the kernel would not route into the tunnel",
            TUN_PEER, PORT_OUT, strerror(errno));
        close(s);
        return -1;
    }
    close(s);

    pfd.fd = g_tunfd;
    pfd.events = POLLIN;
    r = poll(&pfd, 1, 1000);
    if (r <= 0) {
        bad("poll on the tun fd reported no data within 1 s (r=%d) - host -> tun is broken", r);
        return -1;
    }
    ok("poll() reported POLLIN on the tun fd (revents=0x%x)", pfd.revents);

    n = read(g_tunfd, buf, sizeof(buf));
    if (n < 0) { bad("read(tun): %s", strerror(errno)); return -1; }
    if (n < 4 + 20) { bad("read(tun) returned only %d bytes", (int)n); return -1; }

    {
        uint32_t af;
        struct ip* iph;
        memcpy(&af, buf, 4);
        af = ntohl(af);
        if (af == (uint32_t)AF_INET)
            ok("read %d bytes, 4-byte AF header = %u (AF_INET) - TUNSIFHEAD framing confirmed",
               (int)n, af);
        else
            bad("AF header = %u, expected AF_INET (%d)", af, AF_INET);

        iph = (struct ip*)(buf + 4);
        {
            char sa[32], da[32];
            inet_ntop(AF_INET, &iph->ip_src, sa, sizeof(sa));
            inet_ntop(AF_INET, &iph->ip_dst, da, sizeof(da));
            if (strcmp(da, TUN_PEER) == 0 && strcmp(sa, TUN_LOCAL) == 0)
                ok("packet is %s -> %s proto %d - host -> tun works", sa, da, iph->ip_p);
            else
                note("packet is %s -> %s proto %d (unexpected addresses)", sa, da, iph->ip_p);
        }
    }
    return 0;
}

/* tun -> host: a forged IP+UDP packet written into the tun fd must reach a local socket. */
static int test_inbound(void)
{
    uint8_t pkt[64];
    uint32_t af = htonl(AF_INET);
    struct iovec iov[2];
    struct sockaddr_in me, from;
    socklen_t fromlen = sizeof(from);
    struct ip* iph;
    uint8_t* udp;
    const char payload[] = "tunprobe-in";
    size_t plen = sizeof(payload) - 1;
    size_t udplen = 8 + plen;
    size_t iplen = 20 + udplen;
    struct pollfd pfd;
    char rbuf[64];
    int s, r;
    ssize_t n;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { bad("socket: %s", strerror(errno)); return -1; }
    sin_set(&me, TUN_LOCAL);
    me.sin_port = htons(PORT_IN);
    if (bind(s, (struct sockaddr*)&me, sizeof(me)) < 0) {
        bad("bind %s:%d: %s", TUN_LOCAL, PORT_IN, strerror(errno));
        close(s);
        return -1;
    }

    memset(pkt, 0, sizeof(pkt));
    iph = (struct ip*)pkt;
    iph->ip_v   = 4;
    iph->ip_hl  = 5;
    iph->ip_len = htons((uint16_t)iplen);
    iph->ip_id  = htons(0x4242);
    iph->ip_ttl = 64;
    iph->ip_p   = IPPROTO_UDP;
    inet_pton(AF_INET, TUN_PEER,  &iph->ip_src);
    inet_pton(AF_INET, TUN_LOCAL, &iph->ip_dst);
    iph->ip_sum = htons(cksum16(pkt, 20, 0));

    udp = pkt + 20;
    udp[0] = 0x04; udp[1] = 0xd2;                       /* src port 1234 */
    udp[2] = (uint8_t)(PORT_IN >> 8); udp[3] = (uint8_t)(PORT_IN & 0xff);
    udp[4] = (uint8_t)(udplen >> 8);   udp[5] = (uint8_t)(udplen & 0xff);
    memcpy(udp + 8, payload, plen);
    /* A zero UDP checksum is legal on IPv4 and keeps the forging simple. */

    iov[0].iov_base = &af;  iov[0].iov_len = 4;
    iov[1].iov_base = pkt;  iov[1].iov_len = iplen;
    n = writev(g_tunfd, iov, 2);
    if (n < 0) {
        bad("writev(tun): %s - tun -> host is broken", strerror(errno));
        close(s);
        return -1;
    }
    ok("writev wrote %d bytes into the tun fd (4-byte AF header + %u byte packet)",
       (int)n, (unsigned)iplen);

    pfd.fd = s;
    pfd.events = POLLIN;
    r = poll(&pfd, 1, 1000);
    if (r <= 0) {
        bad("the forged packet never reached the local socket (poll r=%d) - tun -> host is broken", r);
        close(s);
        return -1;
    }
    n = recvfrom(s, rbuf, sizeof(rbuf) - 1, 0, (struct sockaddr*)&from, &fromlen);
    close(s);
    if (n < 0) { bad("recvfrom: %s", strerror(errno)); return -1; }
    rbuf[n] = '\0';
    {
        char fa[32];
        inet_ntop(AF_INET, &from.sin_addr, fa, sizeof(fa));
        ok("received \"%s\" from %s:%d - tun -> host works", rbuf, fa, ntohs(from.sin_port));
    }
    return 0;
}

static void test_limits(void)
{
    uint8_t big[4 + 1600];
    uint32_t af = htonl(AF_INET);
    ssize_t n;

    /* NetBSD's tunwrite rejects anything over TUNMTU (1500) with EIO, whatever the MTU is. */
    memset(big, 0, sizeof(big));
    memcpy(big, &af, 4);
    big[4] = 0x45;
    n = write(g_tunfd, big, 4 + 1501);
    if (n < 0 && errno == EIO)
        ok("write of 1501 payload bytes -> EIO (NetBSD TUNMTU limit is in place)");
    else if (n < 0)
        note("write of 1501 payload bytes -> %s (expected EIO)", strerror(errno));
    else
        note("write of 1501 payload bytes was accepted (%d bytes) - no TUNMTU limit here", (int)n);

    if (if_set_mtu(g_ifname, 1501) < 0 && errno == EINVAL)
        ok("SIOCSIFMTU 1501 -> EINVAL (MTU range 576..1500 enforced)");
    else
        note("SIOCSIFMTU 1501 did not fail with EINVAL (%s)", strerror(errno));
    if_set_mtu(g_ifname, TUN_MTU);
}

static void test_second_open(void)
{
    char path[32];
    int fd2;

    snprintf(path, sizeof(path), "/dev/%s", g_ifname);
    fd2 = open(path, O_RDWR);
    if (fd2 < 0)
        ok("second open(%s) refused with %s - one owner per tun, as expected", path, strerror(errno));
    else {
        note("second open(%s) SUCCEEDED (fd %d) - the daemon must guard against this itself",
             path, fd2);
        close(fd2);
    }
}

static void test_ipv6(void)
{
    struct sockaddr_in6 dst;
    uint8_t buf[4 + 2048];
    struct pollfd pfd;
    int s, r;
    ssize_t n;

    if (if_set_addr6(g_ifname, TUN6_LOCAL, TUN6_PEER) < 0) {
        bad("SIOCAIFADDR_IN6 %s: %s - no IPv6 on tun", TUN6_LOCAL, strerror(errno));
        return;
    }
    ok("SIOCAIFADDR_IN6 assigned %s/128 (peer %s)", TUN6_LOCAL, TUN6_PEER);

    s = socket(AF_INET6, SOCK_DGRAM, 0);
    if (s < 0) { bad("socket(AF_INET6): %s", strerror(errno)); return; }
    memset(&dst, 0, sizeof(dst));
    dst.sin6_len = sizeof(dst);
    dst.sin6_family = AF_INET6;
    dst.sin6_port = htons(PORT_OUT);
    inet_pton(AF_INET6, TUN6_PEER, &dst.sin6_addr);

    if (sendto(s, "v6", 2, 0, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
        bad("sendto %s: %s - IPv6 is not routed into the tunnel", TUN6_PEER, strerror(errno));
        close(s);
        return;
    }
    close(s);

    pfd.fd = g_tunfd;
    pfd.events = POLLIN;
    r = poll(&pfd, 1, 1000);
    if (r <= 0) { bad("no IPv6 packet surfaced on the tun fd within 1 s"); return; }

    n = read(g_tunfd, buf, sizeof(buf));
    if (n < 4) { bad("read(tun): %s", strerror(errno)); return; }
    {
        uint32_t af;
        memcpy(&af, buf, 4);
        af = ntohl(af);
        if (af == (uint32_t)AF_INET6)
            ok("IPv6 packet read, AF header = %u (AF_INET6 on QNX) - IPv6 over tun works", af);
        else
            bad("IPv6 packet read but AF header = %u, expected %d", af, AF_INET6);
    }
}

/* SO_BINDTODEVICE / SO_SETFIB, with and without the full-tunnel routes in place. */
static void test_socket_steering(const char* phys_if, int routes_present)
{
    struct sockaddr_in dst, local;
    socklen_t len;
    struct ifreq ifr;
    char a[32];
    int s;

    /* connect() on UDP sends nothing; it just runs the route lookup and picks a source. */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { bad("socket: %s", strerror(errno)); return; }
    sin_set(&dst, "8.8.8.8");
    dst.sin_port = htons(53);
    if (connect(s, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
        note("plain connect() to 8.8.8.8: %s", strerror(errno));
    } else {
        len = sizeof(local);
        if (getsockname(s, (struct sockaddr*)&local, &len) == 0) {
            inet_ntop(AF_INET, &local.sin_addr, a, sizeof(a));
            printf("  [info] plain socket would leave with source %s%s\n", a,
                   routes_present ? " (full-tunnel routes are active)" : "");
        }
    }
    close(s);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    memset(&ifr, 0, sizeof(ifr));
    set_ifname(ifr.ifr_name, phys_if);
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        bad("SO_BINDTODEVICE %s: %s", phys_if, strerror(errno));
        close(s);
        return;
    }
    ok("SO_BINDTODEVICE %s accepted", phys_if);

    if (connect(s, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
        bad("connect() after SO_BINDTODEVICE: %s%s", strerror(errno),
            routes_present ? " - it loses against the 0/1 routes" : "");
    } else {
        len = sizeof(local);
        if (getsockname(s, (struct sockaddr*)&local, &len) == 0) {
            inet_ntop(AF_INET, &local.sin_addr, a, sizeof(a));
            if (strcmp(a, TUN_LOCAL) == 0)
                bad("bound socket still picked the TUNNEL source %s%s", a,
                    routes_present ? " - SO_BINDTODEVICE does NOT override the routes" : "");
            else
                ok("bound socket picked source %s%s", a,
                   routes_present ? " - SO_BINDTODEVICE DOES override the 0/1 routes" : "");
        }
    }
    close(s);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        int fib = 15;
        if (setsockopt(s, SOL_SOCKET, SO_SETFIB, &fib, sizeof(fib)) < 0)
            note("SO_SETFIB 15: %s - multiple FIBs are not usable from a socket", strerror(errno));
        else
            ok("SO_SETFIB 15 accepted - the daemon could keep its own UDP in FIB 15");
        close(s);
    }
}

static void test_routes(const char* phys_if)
{
    section("full-tunnel routes 0.0.0.0/1 + 128.0.0.0/1 via the tunnel");
    note("the default route is left alone; a link route such as the USB 169.254.0.0/30 is");
    note("more specific than /1, so this SSH session keeps working");

    if (route_change4(RTM_ADD, "0.0.0.0", 0x80000000u, TUN_LOCAL, 0) < 0) {
        bad("RTM_ADD 0.0.0.0/1: %s", strerror(errno));
        return;
    }
    if (route_change4(RTM_ADD, "128.0.0.0", 0x80000000u, TUN_LOCAL, 0) < 0) {
        bad("RTM_ADD 128.0.0.0/1: %s", strerror(errno));
        route_change4(RTM_DELETE, "0.0.0.0", 0x80000000u, TUN_LOCAL, 0);
        return;
    }
    g_routes_added = 1;
    ok("both /1 routes installed via %s (%s)", g_ifname, TUN_LOCAL);

    section("socket steering WITH the full-tunnel routes active");
    test_socket_steering(phys_if, 1);

    route_change4(RTM_DELETE, "0.0.0.0",   0x80000000u, TUN_LOCAL, 0);
    route_change4(RTM_DELETE, "128.0.0.0", 0x80000000u, TUN_LOCAL, 0);
    g_routes_added = 0;
    ok("both /1 routes removed again");
}

/* Keep the tunnel up and answer ICMP echo, so a second shell can ping the peer address. */
static void serve(int seconds)
{
    time_t deadline = time(NULL) + seconds;

    section("serving: answering ICMP echo on the tunnel");
    printf("  ping %s from another shell for %d s\n", TUN_PEER, seconds);

    while (!g_stop && time(NULL) < deadline) {
        uint8_t buf[4 + 2048];
        struct pollfd pfd;
        struct ip* iph;
        uint8_t* icmp;
        size_t hl, iplen;
        ssize_t n;
        struct in_addr tmp;

        pfd.fd = g_tunfd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, 500) <= 0) continue;

        n = read(g_tunfd, buf, sizeof(buf));
        if (n < 4 + 20) continue;

        iph = (struct ip*)(buf + 4);
        if (iph->ip_p != IPPROTO_ICMP) continue;
        hl = (size_t)iph->ip_hl * 4;
        iplen = ntohs(iph->ip_len);
        if (iplen + 4 > (size_t)n || hl + 8 > iplen) continue;

        icmp = buf + 4 + hl;
        if (icmp[0] != 8) continue;                   /* echo request only */

        icmp[0] = 0;                                  /* echo reply */
        icmp[2] = icmp[3] = 0;
        {
            uint16_t c = cksum16(icmp, iplen - hl, 0);
            icmp[2] = (uint8_t)(c >> 8);
            icmp[3] = (uint8_t)(c & 0xff);
        }
        tmp = iph->ip_src;
        iph->ip_src = iph->ip_dst;
        iph->ip_dst = tmp;
        iph->ip_sum = 0;
        {
            uint16_t c = cksum16(iph, hl, 0);
            iph->ip_sum = htons(c);
        }
        if (write(g_tunfd, buf, 4 + iplen) < 0)
            note("write of the echo reply failed: %s", strerror(errno));
        else
            printf("  [echo] replied to an ICMP echo request\n");
    }
}

static int cmd_tun(int with_routes, int serve_secs)
{
    int v, flags = 0;
    char gw[64] = "?", phys[IFNAMSIZ] = "bcm0";
    unsigned ifindex = 0;

    if (route_get_default(gw, sizeof(gw), &ifindex) == 0)
        if_indextoname(ifindex, phys);
    printf("  physical path: gateway %s via %s\n", gw, phys);

    section("opening and configuring the tun device");
    g_tunfd = open_tun(0);
    if (g_tunfd < 0) return 1;

    v = 0;
    if (ioctl(g_tunfd, TUNGIFHEAD, &v) == 0) ok("TUNGIFHEAD before: %d", v);
    else                                     note("TUNGIFHEAD: %s", strerror(errno));

    /* TUNSIFMODE is refused with EBUSY once the interface is up, so it goes first. */
    v = IFF_POINTOPOINT | IFF_MULTICAST;
    if (ioctl(g_tunfd, TUNSIFMODE, &v) == 0) ok("TUNSIFMODE POINTOPOINT|MULTICAST");
    else                                     bad("TUNSIFMODE: %s", strerror(errno));

    v = 1;
    if (ioctl(g_tunfd, TUNSIFHEAD, &v) == 0) {
        int back = -1;
        ioctl(g_tunfd, TUNGIFHEAD, &back);
        if (back == 1) ok("TUNSIFHEAD 1 (4-byte AF header), read back as %d", back);
        else           note("TUNSIFHEAD 1 accepted but reads back as %d", back);
    } else {
        bad("TUNSIFHEAD: %s - no IPv6 over this tunnel", strerror(errno));
    }

    v = 1;
    if (ioctl(g_tunfd, FIONBIO, &v) == 0) ok("FIONBIO 1 (non-blocking)");
    else                                  bad("FIONBIO: %s", strerror(errno));
    {
        int fl = fcntl(g_tunfd, F_GETFL, 0);
        printf("  [info] fcntl F_GETFL = 0x%x, O_NONBLOCK %s\n",
               fl, (fl & O_NONBLOCK) ? "set" : "clear");
    }

    test_second_open();

    section("addressing");
    if (if_set_addr4(g_ifname, TUN_LOCAL, TUN_PEER) < 0) {
        bad("SIOCAIFADDR: %s", strerror(errno));
        cleanup();
        return 1;
    }
    ok("SIOCAIFADDR %s -> %s /32", TUN_LOCAL, TUN_PEER);

    if (if_set_mtu(g_ifname, TUN_MTU) == 0) ok("SIOCSIFMTU %d", TUN_MTU);
    else                                    bad("SIOCSIFMTU %d: %s", TUN_MTU, strerror(errno));

    if (if_up(g_ifname) == 0) ok("SIOCSIFFLAGS IFF_UP");
    else                      bad("SIOCSIFFLAGS: %s", strerror(errno));

    if (if_get_flags(g_ifname, &flags) == 0)
        printf("  [info] %s flags 0x%x%s%s%s\n", g_ifname, flags,
               (flags & IFF_UP) ? " UP" : "",
               (flags & IFF_RUNNING) ? " RUNNING" : "",
               (flags & IFF_POINTOPOINT) ? " POINTOPOINT" : "");

    section("data path host -> tun");
    test_outbound();

    section("data path tun -> host");
    test_inbound();

    section("driver limits");
    test_limits();

    section("IPv6 over tun");
    test_ipv6();

    section("socket steering WITHOUT the full-tunnel routes");
    test_socket_steering(phys, 0);

    if (with_routes) test_routes(phys);

    if (serve_secs > 0) serve(serve_secs);

    section("teardown");
    cleanup();
    return 0;
}

/* ------------------------------------------------------------------ dns */

static int cmd_dns(void)
{
    char saved[512], probe[512];
    size_t n;

    section("_CS_RESOLVE override and restore");
    n = confstr(_CS_RESOLVE, saved, sizeof(saved));
    if (n == 0 || n > sizeof(saved)) { bad("cannot read _CS_RESOLVE"); return 1; }
    ok("saved _CS_RESOLVE = \"%s\"", saved);

    if (confstr(_CS_SET | _CS_RESOLVE, "nameserver_10.99.99.53", 0) == 0)
        note("confstr(_CS_SET|_CS_RESOLVE) returned 0 (%s)", strerror(errno));

    n = confstr(_CS_RESOLVE, probe, sizeof(probe));
    if (n > 0 && strcmp(probe, "nameserver_10.99.99.53") == 0)
        ok("override took effect: \"%s\"", probe);
    else
        bad("override did not take effect, now \"%s\"", n ? probe : "");

    if (confstr(_CS_SET | _CS_RESOLVE, saved, 0) == 0 && errno)
        note("restore returned 0 (%s)", strerror(errno));
    n = confstr(_CS_RESOLVE, probe, sizeof(probe));
    if (n > 0 && strcmp(probe, saved) == 0) ok("restored to \"%s\"", probe);
    else                                    bad("RESTORE FAILED, now \"%s\" - set it back by hand with setconf", n ? probe : "");
    return 0;
}

/* ------------------------------------------------------------------ main */

static void usage(void)
{
    printf("usage: tunprobe info                      inventory, read-only\n"
           "       tunprobe tun [--routes] [--serve N] tun lifecycle and data path\n"
           "       tunprobe dns                       _CS_RESOLVE override and restore\n"
           "\n"
           "  --routes   also install 0/1 + 128/1 via the tunnel and test socket steering\n"
           "  --serve N  keep the tunnel up for N seconds answering ICMP echo on %s\n",
           TUN_PEER);
}

int main(int argc, char** argv)
{
    int rc, i, with_routes = 0, serve_secs = 0;
    const char* cmd;

    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (argc < 2) { usage(); return 2; }
    cmd = argv[1];

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--routes") == 0) with_routes = 1;
        else if (strcmp(argv[i], "--serve") == 0 && i + 1 < argc) serve_secs = atoi(argv[++i]);
        else { usage(); return 2; }
    }

    printf("tunprobe - BB10 tun data path probe (uid %d)\n", (int)getuid());
    if (getuid() != 0)
        note("not running as root: address, route and resolver changes will fail");

    if (strcmp(cmd, "info") == 0)      rc = cmd_info();
    else if (strcmp(cmd, "tun") == 0)  rc = cmd_tun(with_routes, serve_secs);
    else if (strcmp(cmd, "dns") == 0)  rc = cmd_dns();
    else { usage(); return 2; }

    printf("\n== summary: %d ok, %d failed, %d notes\n", g_pass, g_fail, g_note);
    return rc ? rc : (g_fail ? 1 : 0);
}
