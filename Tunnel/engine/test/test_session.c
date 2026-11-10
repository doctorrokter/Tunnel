/*
 * wg_session: the replay window (directed cases and a randomized run against a naive model), the
 * keypair rotation as Linux does it, data messages both ways over real handshakes, the refusals,
 * and byte-exact data messages from test/vectors/gen_noise_vectors.py.
 */

#include "test_util.h"
#include "test_side.h"
#include "../src/wg_session.h"
#include "vectors/kat_noise.h"

static side A, B;
static wg_noise_remote *AB, *BA;
static wg_session SA, SB;

/* ------------------------------------------------------------------------------ replay window */

TEST(replay_basics)
{
    wg_replay w;
    uint64_t i;
    int bad = 0;

    wg_replay_init(&w);
    CHECK(wg_replay_check(&w, 0));
    CHECK(wg_replay_accept(&w, 0));
    CHECK(!wg_replay_check(&w, 0));
    CHECK(!wg_replay_accept(&w, 0));

    /* In order, each once; check() always agrees with what accept() then does. */
    for (i = 1; i < 1000; i++) {
        if (!wg_replay_check(&w, i) || !wg_replay_accept(&w, i)) bad++;
        if (wg_replay_check(&w, i) || wg_replay_accept(&w, i)) bad++;
    }
    CHECK(bad == 0);
    CHECK(w.last == 999);
}

TEST(replay_window_edge)
{
    wg_replay w;

    /* The first counter may be anything; everything up to WG_REPLAY_WINDOW behind it is open. */
    wg_replay_init(&w);
    CHECK(wg_replay_accept(&w, 10000));
    CHECK(wg_replay_accept(&w, 10000 - WG_REPLAY_WINDOW));
    CHECK(!wg_replay_accept(&w, 10000 - WG_REPLAY_WINDOW));
    CHECK(!wg_replay_check(&w, 10000 - WG_REPLAY_WINDOW - 1));
    CHECK(!wg_replay_accept(&w, 10000 - WG_REPLAY_WINDOW - 1));
    CHECK(wg_replay_accept(&w, 0 + 9999));
    CHECK(wg_replay_accept(&w, 5000));
    CHECK(w.last == 10000);
}

TEST(replay_ring_reuse)
{
    wg_replay w;

    /* 5 and 5 + 8192 share a ring slot; moving a whole lap forward must clear the old bits. */
    wg_replay_init(&w);
    CHECK(wg_replay_accept(&w, 5));
    CHECK(wg_replay_accept(&w, 5 + 128 * 64));
    CHECK(!wg_replay_accept(&w, 5 + 128 * 64));
    CHECK(!wg_replay_accept(&w, 5));                 /* now too old */

    /* A jump of many laps clears everything, and the space behind it is open again. */
    CHECK(wg_replay_accept(&w, 1000000));
    CHECK(wg_replay_accept(&w, 1000000 - 1));
    CHECK(wg_replay_accept(&w, 1000000 - WG_REPLAY_WINDOW));
    CHECK(!wg_replay_accept(&w, 1000000 - 1));
}

TEST(replay_limit)
{
    wg_replay w;
    const uint64_t top = WG_REJECT_AFTER_MESSAGES - 1;

    wg_replay_init(&w);
    CHECK(!wg_replay_check(&w, WG_REJECT_AFTER_MESSAGES));
    CHECK(!wg_replay_accept(&w, WG_REJECT_AFTER_MESSAGES));
    CHECK(!wg_replay_accept(&w, ~0ULL));
    CHECK(wg_replay_accept(&w, top));
    CHECK(wg_replay_accept(&w, top - WG_REPLAY_WINDOW));
    CHECK(!wg_replay_accept(&w, top - WG_REPLAY_WINDOW - 1));
    CHECK(!wg_replay_accept(&w, top));
    CHECK(w.last == top);
}

/* The naive model: a set of every counter ever accepted, and the rule stated plainly. */
#define MODEL_BITS (1u << 23)
static uint8_t model_seen[MODEL_BITS / 8];

static uint64_t xs_state = 0x9e3779b97f4a7c15ULL;
static uint64_t xs_next(void)
{
    xs_state ^= xs_state >> 12;
    xs_state ^= xs_state << 25;
    xs_state ^= xs_state >> 27;
    return xs_state * 0x2545f4914f6cdd1dULL;
}

TEST(replay_against_model)
{
    wg_replay w;
    uint64_t last = 0, c, r;
    long ops = 0, accepted = 0, mismatches = 0;
    int want;

    wg_replay_init(&w);
    memset(model_seen, 0, sizeof(model_seen));

    while (last + 3 * WG_REPLAY_WINDOW + 1000 < MODEL_BITS) {
        r = xs_next();
        switch (r % 1000) {
        default:                                                    /* mostly in order */
            c = last + 1 + (r >> 10) % 4;
            break;
        case 550: case 551: case 552: case 553: case 554:           /* a big jump */
            c = last + WG_REPLAY_WINDOW + (r >> 10) % (2 * WG_REPLAY_WINDOW);
            break;
        }
        if (r % 1000 >= 600 && r % 1000 < 800) {                    /* reordered, or too old */
            uint64_t back = (r >> 10) % (WG_REPLAY_WINDOW + 200);
            c = back <= last ? last - back : 0;
        } else if (r % 1000 >= 800 && r % 1000 < 950) {             /* a recent duplicate */
            uint64_t back = (r >> 10) % 64;
            c = back <= last ? last - back : 0;
        }

        want = !(model_seen[c >> 3] & (1u << (c & 7)))
            && (c > last || last - c <= WG_REPLAY_WINDOW);
        if (wg_replay_check(&w, c) != want) mismatches++;
        if (wg_replay_accept(&w, c) != want) mismatches++;
        if (want) {
            model_seen[c >> 3] |= (uint8_t)(1u << (c & 7));
            if (c > last) last = c;
            accepted++;
        }
        ops++;
    }
    CHECK(mismatches == 0);
    CHECK(ops > 50000);
    CHECK(accepted > ops / 3 && accepted < ops);     /* both outcomes were exercised */
}

/* ------------------------------------------------------------------------------ sessions */

static void sessions_init(void)
{
    pair(&A, &B, NULL, NULL, &AB, &BA);
    wg_session_init(&SA, &A.local);
    wg_session_init(&SB, &B.local);
}

/* A handshake, A or B initiating, and both sides install the keys. */
static int rekey(int a_initiates, uint64_t now, uint64_t wall)
{
    wg_noise_keys ka, kb;

    if (a_initiates) {
        if (!handshake(&A, AB, &B, now, wall, &ka, &kb)) return 0;
    } else {
        if (!handshake(&B, BA, &A, now, wall, &kb, &ka)) return 0;
    }
    wg_session_add(&SA, &ka, now);
    wg_session_add(&SB, &kb, now);
    return 1;
}

static uint8_t pkt[2048], msg[2048], out[2048];

/* The local index of a keypair slot, 0 for an empty one: comparable without a NULL check. */
static uint32_t idx(const wg_keypair* kp)
{
    return kp ? kp->local_index : 0;
}

static void fill(uint8_t* p, size_t len, uint8_t seed)
{
    size_t i;
    for (i = 0; i < len; i++) p[i] = (uint8_t)(seed + i * 7);
}

/* Seals `len` bytes from `from` (padded for an MTU of 1420) into msg; returns the message length or 0. */
static size_t seal(wg_session* from, size_t len, uint8_t seed, uint64_t now)
{
    size_t n = 0;
    fill(pkt, len, seed);
    if (!wg_session_encrypt(from, msg, &n, pkt, len, wg_data_padding(len, 1420), now)) return 0;
    return n;
}

/* Opens msg at `to` and checks the packet came through intact, padding zeroed. */
static int open_ok(wg_session* to, size_t n, size_t len, uint8_t seed, uint64_t now, wg_recv* rv)
{
    size_t i;
    if (!wg_session_decrypt(to, out, msg, n, now, rv)) return 0;
    fill(pkt, len, seed);
    if (rv->len != len + wg_data_padding(len, 1420) || memcmp(out, pkt, len) != 0) return 0;
    for (i = len; i < rv->len; i++)
        if (out[i]) return 0;
    return 1;
}

TEST(data_both_ways)
{
    wg_recv rv;
    size_t n;

    sessions_init();
    CHECK(rekey(1, T0, WALL));
    CHECK(SA.current && !SA.next && !SA.previous);
    CHECK(SB.next && !SB.current && !SB.previous);

    /* The responder has nothing to send with until the initiator has used the new keys. */
    CHECK(seal(&SB, 60, 1, T0) == 0);

    CHECK((n = seal(&SA, 100, 2, T0)) == WG_DATA_MSG_LEN(112));
    CHECK(open_ok(&SB, n, 100, 2, T0, &rv));
    CHECK(rv.confirmed);
    CHECK(SB.current && !SB.next);

    CHECK((n = seal(&SB, 60, 3, T0)) == WG_DATA_MSG_LEN(64));
    CHECK(open_ok(&SA, n, 60, 3, T0, &rv));
    CHECK(!rv.confirmed);

    /* A keepalive: no payload, 32 bytes on the wire. */
    CHECK((n = seal(&SA, 0, 0, T0)) == 32);
    CHECK(wg_session_decrypt(&SB, out, msg, n, T0, &rv) && rv.len == 0 && !rv.confirmed);

    REQUIRE(SA.current && SB.current);
    CHECK(SA.current->send_counter == 2 && SB.current->send_counter == 1);
    CHECK(A.bad_drops == 0 && B.bad_drops == 0);
}

TEST(sealed_in_place)
{
    wg_recv rv;
    uint8_t copy[300];
    size_t n = 0;

    sessions_init();
    CHECK(rekey(1, T0, WALL));

    /* The engine reads a packet from tun straight into msg + 16, seals it there, and opens a
     * datagram where it landed. */
    fill(msg + WG_DATA_HEADER_LEN, 300, 9);
    memcpy(copy, msg + WG_DATA_HEADER_LEN, sizeof(copy));
    CHECK(wg_session_encrypt(&SA, msg, &n, msg + WG_DATA_HEADER_LEN, 300, wg_data_padding(300, 1420), T0));
    CHECK(n == WG_DATA_MSG_LEN(304));
    CHECK(memcmp(msg + WG_DATA_HEADER_LEN, copy, sizeof(copy)) != 0);
    CHECK(wg_session_decrypt(&SB, msg + WG_DATA_HEADER_LEN, msg, n, T0, &rv));
    CHECK(rv.len == 304);
    CHECK_MEM(msg + WG_DATA_HEADER_LEN, copy, sizeof(copy));
}

TEST(padding_rules)
{
    CHECK(wg_data_padding(0, 1420) == 0);
    CHECK(wg_data_padding(1, 1420) == 15);
    CHECK(wg_data_padding(16, 1420) == 0);
    CHECK(wg_data_padding(17, 1420) == 15);
    CHECK(wg_data_padding(100, 0) == 12);           /* no MTU: plain multiple of 16 */
    CHECK(wg_data_padding(1415, 1420) == 5);        /* 1424 would pass the MTU: stop at 1420 */
    CHECK(wg_data_padding(1420, 1420) == 0);
    CHECK(wg_data_padding(1425, 1420) == 11);       /* oversized: the remainder 5 is padded to 16 */
}

TEST(replays_and_reordering)
{
    uint8_t saved[5][WG_DATA_MSG_LEN(16)], early[WG_DATA_MSG_LEN(16)];
    size_t n = 0;
    wg_recv rv;
    int i, ok = 1;
    static const int order[5] = { 3, 1, 4, 0, 2 };

    sessions_init();
    CHECK(rekey(1, T0, WALL));
    CHECK((n = seal(&SA, 16, 0, T0)) == sizeof(early));
    memcpy(early, msg, n);
    CHECK(wg_session_decrypt(&SB, out, early, n, T0, &rv));

    for (i = 0; i < 5; i++) {
        if (seal(&SA, 16, (uint8_t)i, T0) != sizeof(saved[i])) ok = 0;
        memcpy(saved[i], msg, sizeof(saved[i]));
    }
    CHECK(ok);

    /* Out of order: all arrive, each once. */
    for (i = 0; i < 5; i++) {
        memcpy(msg, saved[order[i]], sizeof(saved[0]));
        if (!open_ok(&SB, sizeof(saved[0]), 16, (uint8_t)order[i], T0, &rv)) ok = 0;
    }
    CHECK(ok);
    CHECK(!wg_session_decrypt(&SB, out, saved[2], sizeof(saved[2]), T0, &rv));
    CHECK(rv.drop == WG_DROP_REPLAY);

    /* Far ahead: the early message falls out of the window. */
    REQUIRE(SA.current);
    SA.current->send_counter = 20000;
    CHECK((n = seal(&SA, 16, 7, T0)) != 0);
    CHECK(open_ok(&SB, n, 16, 7, T0, &rv));
    CHECK(!wg_session_decrypt(&SB, out, early, sizeof(early), T0, &rv));
    CHECK(rv.drop == WG_DROP_REPLAY);
}

TEST(forgeries_do_not_move_the_window)
{
    uint8_t good[WG_DATA_MSG_LEN(16)], bad[WG_DATA_MSG_LEN(16)];
    uint64_t counter;
    size_t n;
    wg_recv rv;

    sessions_init();
    CHECK(rekey(1, T0, WALL));
    CHECK((n = seal(&SA, 16, 1, T0)) == sizeof(good));
    memcpy(good, msg, n);
    counter = wg_load64(good + WG_DATA_OFF_COUNTER);

    /* A counter pushed far ahead: the tag was made for the old nonce and fails - and the window
     * must not have moved, or the genuine message would now be "too old". */
    memcpy(bad, good, n);
    wg_store64(bad + WG_DATA_OFF_COUNTER, counter + 50000);
    CHECK(!wg_session_decrypt(&SB, out, bad, n, T0, &rv));
    CHECK(rv.drop == WG_DROP_FORGED);
    CHECK(SB.next && SB.next->replay.last == 0);

    /* One flipped bit of ciphertext or tag */
    memcpy(bad, good, n);
    bad[WG_DATA_HEADER_LEN + 3] ^= 0x01;
    CHECK(!wg_session_decrypt(&SB, out, bad, n, T0, &rv) && rv.drop == WG_DROP_FORGED);
    memcpy(bad, good, n);
    bad[n - 1] ^= 0x80;
    CHECK(!wg_session_decrypt(&SB, out, bad, n, T0, &rv) && rv.drop == WG_DROP_FORGED);

    /* None of it confirmed the session either. */
    CHECK(SB.next && !SB.current);

    /* The type field is not this layer's business (the codec classifies; AmneziaWG rewrites it). */
    memcpy(bad, good, n);
    bad[WG_DATA_OFF_TYPE] = 0x77;
    memcpy(msg, bad, n);
    CHECK(open_ok(&SB, n, 16, 1, T0, &rv));
    CHECK(rv.confirmed);
}

TEST(unknown_index_and_runts)
{
    size_t n;
    wg_recv rv;

    sessions_init();
    CHECK(rekey(1, T0, WALL));
    CHECK((n = seal(&SA, 16, 1, T0)) != 0);

    msg[WG_DATA_OFF_RECEIVER] ^= 0x01;
    CHECK(!wg_session_decrypt(&SB, out, msg, n, T0, &rv) && rv.drop == WG_DROP_UNKNOWN_INDEX);
    msg[WG_DATA_OFF_RECEIVER] ^= 0x01;
    CHECK(!wg_session_decrypt(&SB, out, msg, WG_DATA_MSG_LEN(0) - 1, T0, &rv) && rv.drop == WG_DROP_MALFORMED);
    CHECK(wg_session_decrypt(&SB, out, msg, n, T0, &rv) && rv.drop == WG_DROP_NONE);
}

TEST(rotation_like_linux)
{
    uint32_t k1a, k1b;
    size_t n;
    wg_recv rv;
    uint8_t k1_msg[WG_DATA_MSG_LEN(16)];

    /* K1: A initiates, B confirms on A's first packet. */
    sessions_init();
    CHECK(rekey(1, T0, WALL));
    CHECK((n = seal(&SA, 16, 1, T0)) != 0);
    CHECK(open_ok(&SB, n, 16, 1, T0, &rv) && rv.confirmed);
    REQUIRE(SA.current && SB.current);
    k1a = SA.current->local_index;
    k1b = SB.current->local_index;

    /* K2 two minutes later, A initiating again. A sends with it at once; B holds it as `next` and
     * keeps sending with K1, which A still opens as `previous`. */
    CHECK(rekey(1, T0 + 120 * SEC, WALL + 120));
    CHECK(SA.current && idx(SA.current) != k1a && idx(SA.previous) == k1a);
    CHECK(SB.next && idx(SB.current) == k1b && !SB.previous);
    CHECK((n = seal(&SB, 16, 2, T0 + 120 * SEC)) != 0);
    memcpy(k1_msg, msg, n);
    CHECK(open_ok(&SA, n, 16, 2, T0 + 120 * SEC, &rv));

    /* A's first packet on K2 confirms it at B: K2 current, K1 previous. */
    CHECK((n = seal(&SA, 16, 3, T0 + 121 * SEC)) != 0);
    CHECK(open_ok(&SB, n, 16, 3, T0 + 121 * SEC, &rv) && rv.confirmed);
    CHECK(idx(SB.previous) == k1b && !SB.next);
    CHECK(A.drops == 0 && B.drops == 0);

    /* K3: now K1 is pushed out on both sides, and its indices go back to the owners. */
    CHECK(rekey(1, T0 + 240 * SEC, WALL + 240));
    CHECK(!side_is_live(&A, k1a) && !side_is_live(&B, k1b));
    CHECK(A.drops == 1 && B.drops == 1);
    CHECK(!wg_session_decrypt(&SA, out, k1_msg, sizeof(k1_msg), T0 + 240 * SEC, &rv));
    CHECK(rv.drop == WG_DROP_UNKNOWN_INDEX);
    CHECK(A.bad_drops == 0 && B.bad_drops == 0);
}

TEST(responder_next_superseded)
{
    uint32_t first_next;
    size_t n;
    wg_recv rv;

    /* A initiates twice before sending anything: B's first `next` is replaced and released. */
    sessions_init();
    CHECK(rekey(1, T0, WALL));
    REQUIRE(SB.next);
    first_next = SB.next->local_index;
    CHECK(rekey(1, T0 + 5 * SEC, WALL + 5));
    CHECK(SB.next && idx(SB.next) != first_next && !side_is_live(&B, first_next));
    CHECK(!SB.current && !SB.previous);

    CHECK((n = seal(&SA, 16, 1, T0 + 6 * SEC)) != 0);
    CHECK(open_ok(&SB, n, 16, 1, T0 + 6 * SEC, &rv) && rv.confirmed);
    CHECK(B.bad_drops == 0);
}

TEST(initiator_with_pending_next)
{
    uint32_t k1a, k2a;
    size_t n;
    wg_recv rv;

    /* K1 as usual, then B initiates K2 - A holds it as `next`, unconfirmed... */
    sessions_init();
    CHECK(rekey(1, T0, WALL));
    CHECK((n = seal(&SA, 16, 1, T0)) != 0);
    CHECK(open_ok(&SB, n, 16, 1, T0, &rv));
    REQUIRE(SA.current);
    k1a = SA.current->local_index;
    CHECK(rekey(0, T0 + 10 * SEC, WALL + 10));
    REQUIRE(SA.next);
    CHECK(idx(SA.current) == k1a);
    k2a = SA.next->local_index;

    /* B sends with K2 right away (it initiated), but the packet is still in flight... */
    CHECK((n = seal(&SB, 16, 2, T0 + 10 * SEC)) != 0);

    /* ...when A completes an initiation of its own (K3). Linux keeps the unconfirmed K2 as
     * `previous` and drops K1; the in-flight packet on K2 still opens. */
    CHECK(rekey(1, T0 + 11 * SEC, WALL + 11));
    CHECK(idx(SA.previous) == k2a && !SA.next);
    CHECK(!side_is_live(&A, k1a));
    CHECK(open_ok(&SA, n, 16, 2, T0 + 11 * SEC, &rv) && !rv.confirmed);
    CHECK(A.bad_drops == 0 && B.bad_drops == 0);
}

TEST(expiry)
{
    size_t n;
    wg_recv rv;

    sessions_init();
    CHECK(rekey(1, T0, WALL));
    CHECK((n = seal(&SA, 16, 1, T0 + WG_REJECT_AFTER_TIME_NS - 1)) != 0);
    CHECK(open_ok(&SB, n, 16, 1, T0 + WG_REJECT_AFTER_TIME_NS - 1, &rv));

    /* At 180 s nobody uses the keys any more, and they stay dead. */
    CHECK(seal(&SA, 16, 2, T0 + WG_REJECT_AFTER_TIME_NS) == 0);
    REQUIRE(SA.current);
    CHECK(!SA.current->send_valid);
    CHECK(seal(&SB, 16, 3, T0 + WG_REJECT_AFTER_TIME_NS - 1) != 0);
    CHECK(!wg_session_decrypt(&SA, out, msg, WG_DATA_MSG_LEN(16), T0 + WG_REJECT_AFTER_TIME_NS, &rv));
    CHECK(rv.drop == WG_DROP_EXPIRED && !SA.current->recv_valid);

    /* The limit is the session's own field. */
    sessions_init();
    SA.reject_after_ns = 10 * SEC;
    CHECK(rekey(1, T0, WALL));
    CHECK(seal(&SA, 16, 1, T0 + 10 * SEC - 1) != 0);
    CHECK(seal(&SA, 16, 1, T0 + 10 * SEC) == 0);
}

TEST(counter_exhaustion)
{
    wg_recv rv;
    size_t n;

    sessions_init();
    CHECK(rekey(1, T0, WALL));
    REQUIRE(SA.current);
    SA.current->send_counter = WG_REJECT_AFTER_MESSAGES - 1;
    CHECK((n = seal(&SA, 16, 1, T0)) != 0);
    CHECK(open_ok(&SB, n, 16, 1, T0, &rv));
    CHECK(seal(&SA, 16, 2, T0) == 0);
    CHECK(!SA.current->send_valid);

    /* A validly sealed message AT the limit is refused by the receiver too. */
    wg_store32(msg + WG_DATA_OFF_TYPE, WG_MSG_DATA);
    wg_store32(msg + WG_DATA_OFF_RECEIVER, SA.current->remote_index);
    wg_store64(msg + WG_DATA_OFF_COUNTER, WG_REJECT_AFTER_MESSAGES);
    CHECK(wg_aead_encrypt(msg + WG_DATA_HEADER_LEN, SA.current->send_key, WG_REJECT_AFTER_MESSAGES,
                          NULL, 0, NULL, 0));
    CHECK(!wg_session_decrypt(&SB, out, msg, WG_DATA_MSG_LEN(0), T0, &rv));
    CHECK(rv.drop == WG_DROP_EXPIRED);
}

TEST(expire_and_clear)
{
    wg_recv rv;
    size_t n;

    sessions_init();
    CHECK(rekey(1, T0, WALL));
    CHECK((n = seal(&SA, 16, 1, T0)) != 0);
    CHECK(open_ok(&SB, n, 16, 1, T0, &rv));

    /* Expired on purpose: A stops sending (the next packet will start a handshake) but still
     * receives. */
    wg_session_expire(&SA);
    CHECK(seal(&SA, 16, 2, T0) == 0);
    CHECK((n = seal(&SB, 16, 3, T0)) != 0);
    CHECK(open_ok(&SA, n, 16, 3, T0, &rv));

    /* Cleared: nothing left, every index returned. */
    CHECK(A.nlive == 1);
    wg_session_clear(&SA);
    CHECK(A.nlive == 0 && A.bad_drops == 0);
    CHECK(!SA.current && !SA.next && !SA.previous);
    CHECK((n = seal(&SB, 16, 4, T0)) != 0);
    CHECK(!wg_session_decrypt(&SA, out, msg, n, T0, &rv) && rv.drop == WG_DROP_UNKNOWN_INDEX);
}

/* ------------------------------------------------------------------------------ transcripts */

static void run_transcript(const char* i_eph, const char* r_eph, const char* psk_hex,
                           const char* i_send_hex, const char* keepalive_hex,
                           const char* data_i_hex, const char* data_r_hex)
{
    wg_key isk, rsk, ipub, rpub;
    uint8_t psk[WG_KEY_LEN], want_send[WG_KEY_LEN], packet_i[37], packet_r[20], want[128];
    wg_noise_keys ka, kb;
    wg_recv rv;
    size_t n = 0;

    CHECK(t_hex(isk.b, WG_KEY_LEN, KAT_I_STATIC) == WG_KEY_LEN);
    CHECK(t_hex(rsk.b, WG_KEY_LEN, KAT_R_STATIC) == WG_KEY_LEN);
    CHECK(t_hex(ipub.b, WG_KEY_LEN, KAT_I_STATIC_PUB) == WG_KEY_LEN);
    CHECK(t_hex(rpub.b, WG_KEY_LEN, KAT_R_STATIC_PUB) == WG_KEY_LEN);
    CHECK(t_hex(psk, sizeof(psk), psk_hex) == WG_KEY_LEN);
    CHECK(t_hex(want_send, sizeof(want_send), i_send_hex) == WG_KEY_LEN);
    CHECK(t_hex(packet_i, sizeof(packet_i), KAT_PACKET_I) == sizeof(packet_i));
    CHECK(t_hex(packet_r, sizeof(packet_r), KAT_PACKET_R) == sizeof(packet_r));

    /* The reference's handshake: same keys, ephemerals and indices. (The timestamp is not the
     * reference's, which changes the handshake's hash but not the chaining key: same keys.) */
    side_init(&A, &isk);
    side_init(&B, &rsk);
    A.next_index = KAT_I_INDEX;
    B.next_index = KAT_R_INDEX;
    side_script(&A, i_eph);
    side_script(&B, r_eph);
    AB = side_add_peer(&A, &rpub, psk);
    BA = side_add_peer(&B, &ipub, psk);
    CHECK(handshake(&A, AB, &B, T0, WALL, &ka, &kb));
    CHECK_MEM(ka.send_key, want_send, WG_KEY_LEN);
    wg_session_init(&SA, &A.local);
    wg_session_init(&SB, &B.local);
    wg_session_add(&SA, &ka, T0);
    wg_session_add(&SB, &kb, T0);

    /* The initiator's keepalive (counter 0) confirms the session at the responder. */
    CHECK(wg_session_encrypt(&SA, msg, &n, NULL, 0, 0, T0));
    CHECK(n == t_hex(want, sizeof(want), keepalive_hex));
    CHECK_MEM(msg, want, n);
    CHECK(wg_session_decrypt(&SB, out, msg, n, T0, &rv) && rv.confirmed && rv.len == 0);

    /* A 37-byte packet at counter 1, padded to 48 */
    CHECK(wg_session_encrypt(&SA, msg, &n, packet_i, sizeof(packet_i),
                             wg_data_padding(sizeof(packet_i), KAT_MTU), T0));
    CHECK(n == t_hex(want, sizeof(want), data_i_hex));
    CHECK_MEM(msg, want, n);
    CHECK(wg_session_decrypt(&SB, out, msg, n, T0, &rv) && rv.len == 48);
    CHECK_MEM(out, packet_i, sizeof(packet_i));

    /* The responder's 20-byte packet at its counter 0, padded to 32 */
    CHECK(wg_session_encrypt(&SB, msg, &n, packet_r, sizeof(packet_r),
                             wg_data_padding(sizeof(packet_r), KAT_MTU), T0));
    CHECK(n == t_hex(want, sizeof(want), data_r_hex));
    CHECK_MEM(msg, want, n);
    CHECK(wg_session_decrypt(&SA, out, msg, n, T0, &rv) && rv.len == 32);
    CHECK_MEM(out, packet_r, sizeof(packet_r));
}

TEST(transcript_no_psk)
{
    run_transcript(KAT_NOPSK_I_EPH_SEED, KAT_NOPSK_R_EPH_SEED, KAT_NOPSK_PSK, KAT_NOPSK_I_SEND,
                   KAT_NOPSK_KEEPALIVE, KAT_NOPSK_DATA_I, KAT_NOPSK_DATA_R);
}

TEST(transcript_psk)
{
    run_transcript(KAT_PSK_I_EPH_SEED, KAT_PSK_R_EPH_SEED, KAT_PSK_PSK, KAT_PSK_I_SEND,
                   KAT_PSK_KEEPALIVE, KAT_PSK_DATA_I, KAT_PSK_DATA_R);
}

int main(void)
{
    if (!wg_crypto_init()) {
        fprintf(stderr, "wg_crypto_init failed\n");
        return 2;
    }
    RUN(replay_basics);
    RUN(replay_window_edge);
    RUN(replay_ring_reuse);
    RUN(replay_limit);
    RUN(replay_against_model);
    RUN(data_both_ways);
    RUN(sealed_in_place);
    RUN(padding_rules);
    RUN(replays_and_reordering);
    RUN(forgeries_do_not_move_the_window);
    RUN(unknown_index_and_runts);
    RUN(rotation_like_linux);
    RUN(responder_next_superseded);
    RUN(initiator_with_pending_next);
    RUN(expiry);
    RUN(counter_exhaustion);
    RUN(expire_and_clear);
    RUN(transcript_no_psk);
    RUN(transcript_psk);
    wg_crypto_cleanup();
    return t_summary("test_session");
}
