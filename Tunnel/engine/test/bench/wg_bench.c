/*
 * wg_bench - what the engine costs, on one core: a full handshake, sealing and opening data - plain
 * and through AmneziaWG 3.x - and an AllowedIPs lookup in a split-tunnel-sized table. Built for the
 * workstation and (build.sh cross) for the phone, to answer "how fast can a Passport tunnel be"
 * before tun is in the picture.
 *
 *   wg_bench [seconds per measurement, default 2]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wg_allowedips.h"
#include "wg_awg.h"
#include "wg_device.h"
#include "wg_noise.h"
#include "wg_session.h"

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * WG_NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

/* ---- a minimal owner for two noise identities ---- */

typedef struct {
    wg_noise_local  local;
    wg_noise_remote peer;
    uint32_t        next;
} side;

static wg_noise_remote* get_peer(void* ctx, const wg_key* pub)
{
    side* s = (side*)ctx;
    return memcmp(s->peer.public_key.b, pub->b, WG_KEY_LEN) == 0 ? &s->peer : NULL;
}

static int set_index(void* ctx, wg_noise_remote* r, uint32_t* index)
{
    (void)r;
    *index = ++((side*)ctx)->next;
    return 1;
}

static void side_init(side* s, const wg_key* sk)
{
    memset(s, 0, sizeof(*s));
    wg_noise_local_init(&s->local);
    s->local.ctx = s;
    s->local.remote_get = get_peer;
    s->local.index_set = set_index;
    wg_noise_local_set_private_key(&s->local, sk);
}

static int handshake(side* a, side* b, uint64_t wall, wg_noise_keys* ka, wg_noise_keys* kb)
{
    uint8_t init[WG_INIT_LEN], resp[WG_RESP_LEN], ts[WG_TIMESTAMP_LEN];
    wg_noise_remote* r;

    wg_tai64n(ts, wall, 0);
    return wg_noise_create_initiation(&a->peer, ts, init)
        && wg_noise_consume_initiation(&b->local, init, wall * WG_NSEC_PER_SEC, &r)
        && wg_noise_create_response(r, resp)
        && wg_noise_consume_response(&a->peer, resp)
        && wg_noise_begin_session(&a->peer, ka)
        && wg_noise_begin_session(r, kb);
}

static side A, B;
static wg_session SA, SB;
static uint8_t msg[2048], out[2048], pkt[1500], wire[4096];
static wg_allowedips_node nodes[8192];
static wg_allowedips table;
static wg_device dev;                   /* only the rng the codec draws from */
static wg_awg awg;
static wg_awg_params params;

int main(int argc, char** argv)
{
    double secs = argc > 1 ? atof(argv[1]) : 2.0;
    uint64_t budget = (uint64_t)(secs * 1e9), t0, t, count, bytes;
    wg_key ska, pka, skb, pkb;
    wg_noise_keys ka, kb;
    wg_recv rv;
    size_t n, i;
    uint32_t x = 0x12345678;
    uint8_t addr[4];
    volatile uintptr_t sink = 0;

    if (!wg_crypto_init()) return 2;
    wg_key_generate(&ska, &pka);
    wg_key_generate(&skb, &pkb);
    side_init(&A, &ska);
    side_init(&B, &skb);
    wg_noise_remote_init(&A.peer, &A.local, &pkb);
    wg_noise_remote_init(&B.peer, &B.local, &pka);

    /* handshakes: both sides' work, one core */
    t0 = now_ns();
    for (count = 0; (t = now_ns()) - t0 < budget; count++)
        if (!handshake(&A, &B, 1759140000ULL + count, &ka, &kb)) return 1;
    printf("handshake (both sides)   %8.2f ms each\n", (double)(t - t0) / 1e6 / (double)count);

    wg_session_init(&SA, &A.local);
    wg_session_init(&SB, &B.local);
    wg_session_add(&SA, &ka, 0);
    wg_session_add(&SB, &kb, 0);
    memset(pkt, 0x45, sizeof(pkt));

    /* seal: 1400-byte packets, as the phone would send them */
    t0 = now_ns();
    for (count = 0, bytes = 0; (t = now_ns()) - t0 < budget; count++) {
        if (!wg_session_encrypt(&SA, msg, &n, pkt, 1400, wg_data_padding(1400, 1420), 0)) return 1;
        bytes += 1400;
    }
    printf("seal 1400 B              %8.1f Mbit/s   %8.0f packets/s\n",
           (double)bytes * 8 / ((double)(t - t0) / 1e9) / 1e6, (double)count / ((double)(t - t0) / 1e9));

    /* open: every message fresh (counter moves on), so the replay window is in the measurement */
    t0 = now_ns();
    for (count = 0, bytes = 0; (t = now_ns()) - t0 < budget; count++) {
        if (!wg_session_encrypt(&SA, msg, &n, pkt, 1400, wg_data_padding(1400, 1420), 0)) return 1;
        if (!wg_session_decrypt(&SB, out, msg, n, 0, &rv)) return 1;
        bytes += 1400;
    }
    printf("seal + open 1400 B       %8.1f Mbit/s   %8.0f packets/s\n",
           (double)bytes * 8 / ((double)(t - t0) / 1e9) / 1e6, (double)count / ((double)(t - t0) / 1e9));

    /* the same through AmneziaWG 3.x: a random 20-byte prefix, a type from a range, header
     * protection, padding drawn from 0-64 - what every packet pays on top */
    wg_awg_params_default(&params);
    for (i = 1; i <= 4; i++) params.s[i] = 20;
    for (i = 0; i < WG_KEY_LEN; i++) params.hp_key[i] = (uint8_t)(i + 1);
    params.h[4].lo = 400000;
    params.h[4].hi = 499999;
    params.content_padding.hi = 64;
    wg_device_init(&dev);
    wg_awg_attach(&awg, &params, &dev);
    t0 = now_ns();
    for (count = 0, bytes = 0; (t = now_ns()) - t0 < budget; count++) {
        uint32_t type;
        size_t off, mlen, m;

        if (!wg_session_encrypt(&SA, msg, &n, pkt, 1400, wg_codec_awg.padding(&awg, 1400, 1420), 0)) return 1;
        wg_codec_awg.stamp(&awg, WG_MSG_DATA, msg, n);
        m = wg_codec_awg.wrap(&awg, WG_MSG_DATA, msg, n, wire, sizeof(wire));
        if (!m || !wg_codec_awg.classify(&awg, wire, m, &type, &off, &mlen)) return 1;
        if (!wg_session_decrypt(&SB, out, wire + off, mlen, 0, &rv)) return 1;
        bytes += 1400;
    }
    printf("AmneziaWG seal + open    %8.1f Mbit/s   %8.0f packets/s\n",
           (double)bytes * 8 / ((double)(t - t0) / 1e9) / 1e6, (double)count / ((double)(t - t0) / 1e9));

    /* AllowedIPs: 3000 prefixes, the size of a "everything but these networks" profile */
    wg_allowedips_init(&table, nodes, sizeof(nodes) / sizeof(nodes[0]));
    for (i = 0; i < 3000; i++) {
        x = x * 1664525u + 1013904223u;
        addr[0] = (uint8_t)(x >> 24); addr[1] = (uint8_t)(x >> 16); addr[2] = (uint8_t)(x >> 8); addr[3] = 0;
        wg_allowedips_insert(&table, 4, addr, (uint8_t)(12 + x % 13), (struct wg_peer*)&table);
    }
    t0 = now_ns();
    for (count = 0; (t = now_ns()) - t0 < budget; count++) {
        x = x * 1664525u + 1013904223u;
        addr[0] = (uint8_t)(x >> 24); addr[1] = (uint8_t)(x >> 16); addr[2] = (uint8_t)(x >> 8); addr[3] = (uint8_t)x;
        sink ^= (uintptr_t)wg_allowedips_lookup(&table, 4, addr);
    }
    printf("AllowedIPs lookup (3000) %8.0f ns each   (%d nodes)\n",
           (double)(t - t0) / (double)count, (int)table.used);

    wg_crypto_cleanup();
    return 0;
}
