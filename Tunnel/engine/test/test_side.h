/*
 * A stand-in for the engine, shared by the tests that need one: a peer table, an index table, and
 * randomness that is either real or scripted. Each test sets up its own sides, so a failure never
 * leaks state into the next test. Include after test_util.h.
 */

#ifndef TEST_SIDE_H
#define TEST_SIDE_H

#include "../src/wg_noise.h"

#define MS        1000000ULL
#define SEC       WG_NSEC_PER_SEC
#define T0        (1000 * SEC)          /* an arbitrary monotonic start */
#define WALL      1759140000ULL         /* an arbitrary wall-clock start, unix seconds */

#define MAX_PEERS   4
#define MAX_INDICES 16

typedef struct {
    wg_noise_local  local;
    wg_noise_remote peers[MAX_PEERS];
    int             npeers;
    struct { uint32_t index; wg_noise_remote* r; } live[MAX_INDICES];
    int             nlive;
    int             drops;              /* index_drop calls */
    int             bad_drops;          /* index_drop of an index that was not live: a bug */
    uint32_t        next_index;         /* nonzero: hand out indices in sequence, for transcripts */
    uint8_t         script[128];        /* scripted randomness, served in order */
    size_t          script_len, script_pos;
} side;

static wg_noise_remote* side_lookup(side* s, uint32_t index)
{
    int i;
    for (i = 0; i < s->nlive; i++)
        if (s->live[i].index == index) return s->live[i].r;
    return NULL;
}

static int side_is_live(side* s, uint32_t index)
{
    return side_lookup(s, index) != NULL;
}

static wg_noise_remote* up_remote_get(void* ctx, const wg_key* pub)
{
    side* s = (side*)ctx;
    int i;
    for (i = 0; i < s->npeers; i++)
        if (memcmp(s->peers[i].public_key.b, pub->b, WG_KEY_LEN) == 0) return &s->peers[i];
    return NULL;
}

static int up_index_set(void* ctx, wg_noise_remote* r, uint32_t* index)
{
    side* s = (side*)ctx;
    uint32_t v;

    if (s->nlive == MAX_INDICES) return 0;
    do {
        if (s->next_index) v = s->next_index++;
        else if (!wg_random(&v, sizeof(v))) return 0;
    } while (side_lookup(s, v));
    s->live[s->nlive].index = v;
    s->live[s->nlive].r = r;
    s->nlive++;
    *index = v;
    return 1;
}

static void up_index_drop(void* ctx, uint32_t index)
{
    side* s = (side*)ctx;
    int i;

    s->drops++;
    for (i = 0; i < s->nlive; i++) {
        if (s->live[i].index == index) {
            s->live[i] = s->live[--s->nlive];
            return;
        }
    }
    s->bad_drops++;
}

static int rng_script(void* ctx, void* buf, size_t len)
{
    side* s = (side*)ctx;
    /* Asking for more randomness than the reference used is a bug in itself. */
    if (s->script_pos + len > s->script_len) return 0;
    memcpy(buf, s->script + s->script_pos, len);
    s->script_pos += len;
    return 1;
}

static void side_script(side* s, const char* hex)
{
    s->script_len += t_hex(s->script + s->script_len, sizeof(s->script) - s->script_len, hex);
    s->local.rng.fn = rng_script;
    s->local.rng.ctx = s;
}

/* A side with the given static private key, or a fresh one. */
static void side_init(side* s, const wg_key* sk)
{
    wg_key gen, unused;

    memset(s, 0, sizeof(*s));
    wg_noise_local_init(&s->local);
    s->local.ctx = s;
    s->local.remote_get = up_remote_get;
    s->local.index_set = up_index_set;
    s->local.index_drop = up_index_drop;
    if (!sk) {
        CHECK(wg_key_generate(&gen, &unused));
        sk = &gen;
    }
    CHECK(wg_noise_local_set_private_key(&s->local, sk));
}

static wg_noise_remote* side_add_peer(side* s, const wg_key* pub, const uint8_t* psk)
{
    wg_noise_remote* r = &s->peers[s->npeers++];
    wg_noise_remote_init(r, &s->local, pub);
    wg_noise_remote_set_psk(r, psk);
    return r;
}

/* Two sides that know each other; returns a's view of b through *ab, b's view of a through *ba. */
static void pair(side* a, side* b, const uint8_t* psk_a, const uint8_t* psk_b,
                 wg_noise_remote** ab, wg_noise_remote** ba)
{
    side_init(a, NULL);
    side_init(b, NULL);
    *ab = side_add_peer(a, &b->local.public_key, psk_a);
    *ba = side_add_peer(b, &a->local.public_key, psk_b);
}

static void initiation_at(wg_noise_remote* r, uint64_t wall_sec, uint8_t msg[WG_INIT_LEN], int* ok)
{
    uint8_t ts[WG_TIMESTAMP_LEN];
    wg_tai64n(ts, wall_sec, 0);
    *ok = wg_noise_create_initiation(r, ts, msg);
}

/* The whole exchange, the way the engine will drive it; 1 when both sides hold session keys. */
static int handshake(side* a, wg_noise_remote* ab, side* b, uint64_t now, uint64_t wall,
                     wg_noise_keys* ka, wg_noise_keys* kb)
{
    uint8_t init[WG_INIT_LEN], resp[WG_RESP_LEN];
    wg_noise_remote* ba;
    wg_noise_remote* found;
    int ok;

    initiation_at(ab, wall, init, &ok);
    if (!ok) return 0;
    if (!wg_noise_consume_initiation(&b->local, init, now, &ba)) return 0;
    if (!wg_noise_create_response(ba, resp)) return 0;
    found = side_lookup(a, wg_load32(resp + WG_RESP_OFF_RECEIVER));
    if (found != ab) return 0;
    if (!wg_noise_consume_response(found, resp)) return 0;
    return wg_noise_begin_session(ab, ka) && wg_noise_begin_session(ba, kb);
}

#endif /* TEST_SIDE_H */
