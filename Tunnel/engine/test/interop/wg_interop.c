/*
 * wg_interop - the engine over a real UDP socket, against another WireGuard (the Linux kernel's, in
 * run.sh). The loop is the daemon's loop without tun: poll() on the socket with the device's next
 * deadline as the timeout; inside the tunnel the harness itself makes ICMP echoes and answers them.
 *
 *   wg_interop <conf> <port> ping <address> <count>   echo requests to <address> through the tunnel,
 *                                                     one every 200 ms; exit 0 when every reply came
 *   wg_interop <conf> <port> answer <seconds>         answer echo requests for that long - the other
 *                                                     side pings us and starts the handshake itself
 *   wg_interop <conf> <port> soak <address> <seconds> an echo a second for that long, through rekeys;
 *                                                     exit 0 when every reply came and the session
 *                                                     was renewed at least once
 *
 * <conf> is our side's .conf (PrivateKey, Address, [Peer] with the other side's key and Endpoint,
 * and AmneziaWG's keys when the other side is amneziawg-go); <port> is our UDP port on 127.0.0.1.
 * Messages are counted by the type the engine stamps, whatever the codec then puts on the wire.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "wg_conf.h"
#include "wg_device.h"

static wg_device dev;
static wg_awg awg;
static wg_codec real_codec;             /* the one the .conf chose; counting_ops wraps it */
static wg_codec_ops counting_ops;
static wg_conf conf;
static wg_conf_peer conf_peers[4];
static wg_prefix conf_allowed[16];
static wg_peer peers[4];
static uint8_t stage[4 * 16384];
static wg_allowedips_node nodes[64];
static int sock = -1;

static uint8_t our4[4], our6[16];
static int have4, have6;

/* what happened, for the report */
static int sent_by_type[5];
static int replies, requests_answered;
static uint8_t seen[4096];                  /* echo sequence numbers answered */

/* Echo replies built while the device is inside an upcall: sent once it has returned. */
static uint8_t pending[8][1500];
static size_t pending_len[8];
static int npending;

/* ------------------------------------------------------------------ time and the socket */

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * WG_NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

static void up_wall_clock(void* ctx, uint64_t* sec, uint32_t* nsec)
{
    struct timespec ts;
    (void)ctx;
    clock_gettime(CLOCK_REALTIME, &ts);
    *sec = (uint64_t)ts.tv_sec;
    *nsec = (uint32_t)ts.tv_nsec;
}

/* Every message the engine sends is stamped with its canonical type first: count it there. */
static void count_stamp(void* st, uint32_t type, uint8_t* msg, size_t len)
{
    if (type >= 1 && type <= 4) sent_by_type[type]++;
    if (real_codec.ops->stamp) real_codec.ops->stamp(st, type, msg, len);
}

static void up_send(void* ctx, const wg_endpoint* to, const uint8_t* msg, size_t len)
{
    struct sockaddr_in sa;

    (void)ctx;
    if (to->family != 4) return;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(to->port);
    memcpy(&sa.sin_addr, to->addr, 4);
    if (sendto(sock, msg, len, 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) perror("sendto");
}

/* ------------------------------------------------------------------ ICMP inside the tunnel */

static uint32_t sum16(const uint8_t* p, size_t n, uint32_t sum)
{
    size_t i;
    for (i = 0; i + 1 < n; i += 2) sum += (uint32_t)(p[i] << 8 | p[i + 1]);
    if (n & 1) sum += (uint32_t)(p[n - 1] << 8);
    return sum;
}

static uint16_t fold(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static void put16(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* An ICMP echo (type 8 request, 0 reply) from src to dst; returns the packet length. */
static size_t icmp4(uint8_t* pkt, const uint8_t* src, const uint8_t* dst, uint8_t type,
                    uint16_t id, uint16_t seq, const uint8_t* data, size_t dlen)
{
    size_t len = 20 + 8 + dlen;

    memset(pkt, 0, 28);
    pkt[0] = 0x45;
    put16(pkt + 2, (uint16_t)len);
    put16(pkt + 4, seq);
    pkt[8] = 64;
    pkt[9] = 1;
    memcpy(pkt + 12, src, 4);
    memcpy(pkt + 16, dst, 4);
    put16(pkt + 10, fold(sum16(pkt, 20, 0)));
    pkt[20] = type;
    put16(pkt + 24, id);
    put16(pkt + 26, seq);
    memcpy(pkt + 28, data, dlen);
    put16(pkt + 22, fold(sum16(pkt + 20, 8 + dlen, 0)));
    return len;
}

/* An ICMPv6 echo (128 request, 129 reply); the checksum covers the pseudo-header. */
static size_t icmp6(uint8_t* pkt, const uint8_t* src, const uint8_t* dst, uint8_t type,
                    uint16_t id, uint16_t seq, const uint8_t* data, size_t dlen)
{
    size_t plen = 8 + dlen;
    uint8_t pseudo[40];
    uint32_t sum;

    memset(pkt, 0, 48);
    pkt[0] = 0x60;
    put16(pkt + 4, (uint16_t)plen);
    pkt[6] = 58;
    pkt[7] = 64;
    memcpy(pkt + 8, src, 16);
    memcpy(pkt + 24, dst, 16);
    pkt[40] = type;
    put16(pkt + 44, id);
    put16(pkt + 46, seq);
    memcpy(pkt + 48, data, dlen);
    memcpy(pseudo, src, 16);
    memcpy(pseudo + 16, dst, 16);
    memset(pseudo + 32, 0, 8);
    pseudo[34] = (uint8_t)(plen >> 8);
    pseudo[35] = (uint8_t)plen;
    pseudo[39] = 58;
    sum = sum16(pseudo, 40, 0);
    put16(pkt + 42, fold(sum16(pkt + 40, plen, sum)));
    return 40 + plen;
}

static void up_deliver(void* ctx, wg_peer* from, uint8_t* pkt, size_t len)
{
    uint16_t id, seq;

    (void)ctx;
    (void)from;
    if (len >= 28 && (pkt[0] >> 4) == 4 && pkt[9] == 1) {
        id = (uint16_t)(pkt[24] << 8 | pkt[25]);
        seq = (uint16_t)(pkt[26] << 8 | pkt[27]);
        if (pkt[20] == 0 && id == 0x7a11) {
            if (!seen[seq % sizeof(seen)]++) replies++;
        } else if (pkt[20] == 8 && npending < 8 && have4 && memcmp(pkt + 16, our4, 4) == 0) {
            pending_len[npending] = icmp4(pending[npending], our4, pkt + 12, 0, id, seq, pkt + 28, len - 28);
            npending++;
        }
    } else if (len >= 48 && (pkt[0] >> 4) == 6 && pkt[6] == 58) {
        id = (uint16_t)(pkt[44] << 8 | pkt[45]);
        seq = (uint16_t)(pkt[46] << 8 | pkt[47]);
        if (pkt[40] == 129 && id == 0x7a11) {
            if (!seen[seq % sizeof(seen)]++) replies++;
        } else if (pkt[40] == 128 && npending < 8 && have6 && memcmp(pkt + 24, our6, 16) == 0) {
            pending_len[npending] = icmp6(pending[npending], our6, pkt + 8, 129, id, seq, pkt + 48, len - 48);
            npending++;
        }
    }
}

static void flush_pending(uint64_t now)
{
    int i;
    wg_drop_reason why;

    for (i = 0; i < npending; i++) {
        if (wg_device_send(&dev, pending[i], pending_len[i], now, &why)) requests_answered++;
        else fprintf(stderr, "reply not sent: reason %d\n", (int)why);
    }
    npending = 0;
}

/* ------------------------------------------------------------------ the loop */

static int ping_once(const uint8_t* target, int family, uint16_t seq, uint64_t now)
{
    uint8_t pkt[256], data[56];
    wg_drop_reason why;
    size_t len;
    int i;

    for (i = 0; i < (int)sizeof(data); i++) data[i] = (uint8_t)(seq + i);
    if (family == 4) len = icmp4(pkt, our4, target, 8, 0x7a11, seq, data, sizeof(data));
    else             len = icmp6(pkt, our6, target, 128, 0x7a11, seq, data, sizeof(data));
    if (!wg_device_send(&dev, pkt, len, now, &why)) {
        fprintf(stderr, "echo %u not sent: reason %d\n", seq, (int)why);
        return 0;
    }
    return 1;
}

/* Runs until `end`; with a target, sends an echo every `interval` (at most `count` of them). */
static void run(uint64_t end, const uint8_t* target, int family, int count, uint64_t interval)
{
    uint8_t buf[2048];
    struct sockaddr_in from;
    socklen_t fromlen;
    struct pollfd pfd;
    wg_endpoint ep;
    uint64_t now = mono_ns(), next_ping = now, wake;
    ssize_t n;
    int sent = 0, timeout;

    while ((now = mono_ns()) < end) {
        if (target && sent < count && now >= next_ping) {
            ping_once(target, family, (uint16_t)sent, now);
            sent++;
            next_ping += interval;
        }
        if (target && replies >= count) break;

        wake = wg_device_next_deadline(&dev);
        if (target && sent < count && next_ping < wake) wake = next_ping;
        if (end < wake) wake = end;
        timeout = wake <= now ? 0 : (int)((wake - now) / 1000000 + 1);
        if (timeout > 100) timeout = 100;

        pfd.fd = sock;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, timeout) > 0 && (pfd.revents & POLLIN)) {
            for (;;) {
                fromlen = sizeof(from);
                n = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&from, &fromlen);
                if (n <= 0) break;
                ep.family = 4;
                memset(ep.addr, 0, sizeof(ep.addr));
                memcpy(ep.addr, &from.sin_addr, 4);
                ep.port = ntohs(from.sin_port);
                wg_device_receive(&dev, buf, (size_t)n, &ep, mono_ns());
                flush_pending(mono_ns());
            }
        }
        wg_device_tick(&dev, mono_ns());
    }
}

/* ------------------------------------------------------------------ setup */

static int load_conf(const char* path)
{
    static char text[8192];
    char err[128];
    FILE* f = fopen(path, "rb");
    size_t n, i;

    if (!f) {
        perror(path);
        return 0;
    }
    n = fread(text, 1, sizeof(text) - 1, f);
    fclose(f);
    text[n] = 0;

    wg_conf_init(&conf, conf_peers, 4, conf_allowed, 16);
    if (!wg_conf_parse(&conf, text, n)) {
        fprintf(stderr, "%s:%d: %s\n", path, conf.error_line, conf.error);
        return 0;
    }
    if (!wg_conf_apply(&conf, &dev, &awg, peers, stage, 16384, mono_ns(), err, sizeof(err))) {
        fprintf(stderr, "%s: %s\n", path, err);
        return 0;
    }
    real_codec = dev.codec;
    counting_ops = *dev.codec.ops;
    counting_ops.stamp = count_stamp;
    dev.codec.ops = &counting_ops;
    printf("codec: %s\n", real_codec.ops->name);
    for (i = 0; i < conf.n_address; i++) {
        if (conf.address[i].family == 4 && !have4) {
            memcpy(our4, conf.address[i].addr, 4);
            have4 = 1;
        }
        if (conf.address[i].family == 6 && !have6) {
            memcpy(our6, conf.address[i].addr, 16);
            have6 = 1;
        }
    }
    return 1;
}

int main(int argc, char** argv)
{
    struct sockaddr_in sa;
    uint8_t target[16];
    int family = 0, count = 0, ok;
    uint64_t start;
    unsigned seconds;
    int initiations;

    if (argc < 4) {
        fprintf(stderr, "usage: %s <conf> <port> ping <addr> <count> | answer <seconds> | soak <addr> <seconds>\n", argv[0]);
        return 2;
    }
    if (!wg_crypto_init()) return 2;

    wg_device_init(&dev);
    dev.send = up_send;
    dev.deliver = up_deliver;
    dev.wall_clock = up_wall_clock;
    if (!wg_device_set_allowedips_storage(&dev, nodes, 64) || !load_conf(argv[1])) return 2;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)atoi(argv[2]));
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (sock < 0 || bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("bind");
        return 2;
    }
    start = mono_ns();
    wg_device_up(&dev, start);

    if (!strcmp(argv[3], "ping") && argc == 6) {
        if (!wg_addr_parse(argv[4], strlen(argv[4]), &family, target)) return 2;
        count = atoi(argv[5]);
        run(start + (uint64_t)(count + 10) * WG_NSEC_PER_SEC, target, family, count, 200 * 1000000ULL);
        ok = replies == count;
        printf("ping %s: %d/%d replies, %d initiation(s), %d response(s)\n", argv[4], replies, count,
               sent_by_type[WG_MSG_INITIATION], sent_by_type[WG_MSG_RESPONSE]);
    } else if (!strcmp(argv[3], "answer") && argc == 5) {
        seconds = (unsigned)atoi(argv[4]);
        run(start + (uint64_t)seconds * WG_NSEC_PER_SEC, NULL, 0, 0, 0);
        ok = requests_answered > 0 && sent_by_type[WG_MSG_RESPONSE] > 0;
        printf("answer: %d echo request(s) answered, %d response(s), %d initiation(s)\n",
               requests_answered, sent_by_type[WG_MSG_RESPONSE], sent_by_type[WG_MSG_INITIATION]);
    } else if (!strcmp(argv[3], "soak") && argc == 6) {
        if (!wg_addr_parse(argv[4], strlen(argv[4]), &family, target)) return 2;
        seconds = (unsigned)atoi(argv[5]);
        count = (int)seconds;
        run(start + (uint64_t)(seconds + 10) * WG_NSEC_PER_SEC, target, family, count, WG_NSEC_PER_SEC);
        initiations = sent_by_type[WG_MSG_INITIATION];
        ok = replies == count && initiations >= 2;
        printf("soak %s: %d/%d replies over %u s, %d initiation(s)\n", argv[4], replies, count, seconds,
               initiations);
    } else {
        fprintf(stderr, "bad arguments\n");
        return 2;
    }

    printf("peer: handshake %s, tx %llu B, rx %llu B\n", peers[0].has_handshake ? "yes" : "no",
           (unsigned long long)peers[0].tx_bytes, (unsigned long long)peers[0].rx_bytes);
    wg_device_down(&dev);
    wg_crypto_cleanup();
    close(sock);
    return ok ? 0 : 1;
}
