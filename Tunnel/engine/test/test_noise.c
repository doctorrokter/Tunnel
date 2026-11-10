/*
 * wg_noise: the handshake between two sides in memory, the ways it must refuse, and byte-exact
 * transcripts from the independent Python implementation (test/vectors/gen_noise_vectors.py).
 */

#include "test_util.h"
#include "test_side.h"
#include "../src/wg_noise.h"
#include "../src/wg_cookie.h"
#include "vectors/kat_noise.h"

static side A, B, C;

static void check_session_pair(const wg_noise_keys* ka, const wg_noise_keys* kb)
{
    CHECK_MEM(ka->send_key, kb->recv_key, WG_KEY_LEN);
    CHECK_MEM(ka->recv_key, kb->send_key, WG_KEY_LEN);
    CHECK(memcmp(ka->send_key, ka->recv_key, WG_KEY_LEN) != 0);
    CHECK(ka->local_index == kb->remote_index);
    CHECK(ka->remote_index == kb->local_index);
    CHECK(ka->initiator && !kb->initiator);
}

/* ------------------------------------------------------------------------------ tests */

TEST(tai64n_layout)
{
    uint8_t out[WG_TIMESTAMP_LEN], want[WG_TIMESTAMP_LEN];

    wg_tai64n(out, 0, 0);
    t_hex(want, sizeof(want), "400000000000000a00000000");
    CHECK_MEM(out, want, sizeof(want));

    /* nanoseconds are rounded down to 2^24 */
    wg_tai64n(out, 0, (1u << 24) - 1);
    CHECK_MEM(out, want, sizeof(want));
    wg_tai64n(out, 0, 1u << 24);
    t_hex(want, sizeof(want), "400000000000000a01000000");
    CHECK_MEM(out, want, sizeof(want));

    wg_tai64n(out, KAT_SEC, KAT_NSEC);
    t_hex(want, sizeof(want), KAT_TIMESTAMP);
    CHECK_MEM(out, want, sizeof(want));
}

TEST(handshake_no_psk)
{
    wg_noise_remote *ab, *ba;
    wg_noise_keys ka, kb;

    pair(&A, &B, NULL, NULL, &ab, &ba);
    CHECK(handshake(&A, ab, &B, T0, WALL, &ka, &kb));
    check_session_pair(&ka, &kb);

    /* Both handshakes are spent; each index lives on in its session, none was dropped. */
    CHECK(ab->hs.state == WG_HS_ZEROED && ba->hs.state == WG_HS_ZEROED);
    CHECK(A.nlive == 1 && B.nlive == 1);
    CHECK(A.drops == 0 && B.drops == 0);
}

TEST(handshake_with_psk)
{
    uint8_t psk[WG_KEY_LEN];
    wg_noise_remote *ab, *ba;
    wg_noise_keys ka, kb, ka2, kb2;

    memset(psk, 0x5a, sizeof(psk));
    pair(&A, &B, psk, psk, &ab, &ba);
    CHECK(handshake(&A, ab, &B, T0, WALL, &ka, &kb));
    check_session_pair(&ka, &kb);

    /* A second handshake gives new keys: the ephemerals are fresh. */
    CHECK(handshake(&A, ab, &B, T0 + 5 * SEC, WALL + 5, &ka2, &kb2));
    check_session_pair(&ka2, &kb2);
    CHECK(memcmp(ka.send_key, ka2.send_key, WG_KEY_LEN) != 0);
    CHECK(ka.local_index != ka2.local_index);
}

TEST(psk_mismatch_fails_at_the_response)
{
    uint8_t psk_a[WG_KEY_LEN], psk_b[WG_KEY_LEN], init[WG_INIT_LEN], resp[WG_RESP_LEN];
    wg_noise_remote *ab, *ba, *got;
    int ok;

    memset(psk_a, 0x11, sizeof(psk_a));
    memset(psk_b, 0x22, sizeof(psk_b));
    pair(&A, &B, psk_a, psk_b, &ab, &ba);

    /* The PSK enters only at the end of the second message: the initiation still goes through... */
    initiation_at(ab, WALL, init, &ok);
    CHECK(ok);
    CHECK(wg_noise_consume_initiation(&B.local, init, T0, &got));
    CHECK(wg_noise_create_response(got, resp));

    /* ...and the initiator refuses the response, keeping its initiation. */
    CHECK(!wg_noise_consume_response(ab, resp));
    CHECK(ab->hs.state == WG_HS_CREATED_INITIATION);

    /* No PSK on one side is a mismatch too. */
    pair(&A, &B, psk_a, NULL, &ab, &ba);
    initiation_at(ab, WALL, init, &ok);
    CHECK(wg_noise_consume_initiation(&B.local, init, T0, &got));
    CHECK(wg_noise_create_response(got, resp));
    CHECK(!wg_noise_consume_response(ab, resp));
}

TEST(wrong_responder_key)
{
    uint8_t init[WG_INIT_LEN];
    wg_noise_remote *ab, *ba, *got;
    int ok;

    /* A believes B's key is C's: the initiation is sealed to C, and B cannot open it. */
    pair(&A, &B, NULL, NULL, &ab, &ba);
    side_init(&C, NULL);
    ab = side_add_peer(&A, &C.local.public_key, NULL);
    initiation_at(ab, WALL, init, &ok);
    CHECK(ok);
    CHECK(!wg_noise_consume_initiation(&B.local, init, T0, &got));
    CHECK(got == NULL);
    CHECK(ba->hs.state == WG_HS_ZEROED);
}

TEST(unknown_initiator)
{
    uint8_t init[WG_INIT_LEN];
    wg_noise_remote *ab, *got;
    int ok;

    /* B has no peer entry for A: the static key decrypts, the lookup fails. */
    side_init(&A, NULL);
    side_init(&B, NULL);
    ab = side_add_peer(&A, &B.local.public_key, NULL);
    initiation_at(ab, WALL, init, &ok);
    CHECK(ok);
    CHECK(!wg_noise_consume_initiation(&B.local, init, T0, &got));
    CHECK(got == NULL);
}

TEST(tampered_initiation)
{
    uint8_t init[WG_INIT_LEN], bad[WG_INIT_LEN];
    wg_noise_remote *ab, *ba, *got;
    int ok, i, refused = 0;

    pair(&A, &B, NULL, NULL, &ab, &ba);
    initiation_at(ab, WALL, init, &ok);
    CHECK(ok);

    /* Every byte of the ephemeral, the sealed static and the sealed timestamp is covered. */
    for (i = WG_INIT_OFF_EPHEMERAL; i < WG_INIT_OFF_MAC1; i++) {
        memcpy(bad, init, sizeof(bad));
        bad[i] ^= 0x01;
        if (!wg_noise_consume_initiation(&B.local, bad, T0, &got)) refused++;
    }
    CHECK(refused == WG_INIT_OFF_MAC1 - WG_INIT_OFF_EPHEMERAL);
    CHECK(ba->hs.state == WG_HS_ZEROED);

    /* The sender index is NOT in the Noise transcript - only mac1 covers it (wg_cookie). */
    memcpy(bad, init, sizeof(bad));
    bad[WG_INIT_OFF_SENDER] ^= 0x01;
    CHECK(wg_noise_consume_initiation(&B.local, bad, T0, &got));
    CHECK(got == ba);
    CHECK(ba->hs.remote_index == (wg_load32(init + WG_INIT_OFF_SENDER) ^ 0x01));
}

TEST(replay_and_flood)
{
    uint8_t init1[WG_INIT_LEN], init2[WG_INIT_LEN];
    wg_noise_remote *ab, *ba, *got;
    int ok;

    pair(&A, &B, NULL, NULL, &ab, &ba);
    initiation_at(ab, WALL, init1, &ok);
    CHECK(ok);
    CHECK(wg_noise_consume_initiation(&B.local, init1, T0, &got));

    /* A newer initiation 10 ms later is a flood; 25 ms later it is fine. */
    initiation_at(ab, WALL + 1, init2, &ok);
    CHECK(ok);
    CHECK(!wg_noise_consume_initiation(&B.local, init2, T0 + 10 * MS, &got));
    CHECK(wg_noise_consume_initiation(&B.local, init2, T0 + 25 * MS, &got));

    /* Replays fail however late they come: older timestamp, then an equal one. */
    CHECK(!wg_noise_consume_initiation(&B.local, init1, T0 + 1 * SEC, &got));
    CHECK(!wg_noise_consume_initiation(&B.local, init2, T0 + 2 * SEC, &got));
    CHECK(ba->hs.state == WG_HS_CONSUMED_INITIATION);
}

TEST(clock_stepping_back)
{
    uint8_t init[WG_INIT_LEN], want[WG_TIMESTAMP_LEN];
    wg_noise_remote *ab, *ba, *got;
    int ok;

    pair(&A, &B, NULL, NULL, &ab, &ba);
    initiation_at(ab, WALL, init, &ok);
    CHECK(wg_noise_consume_initiation(&B.local, init, T0, &got));

    /* The phone's clock is stepped back an hour. Sent as is, the timestamp would be refused as a
     * replay until the clock caught up; one quantum past the last one goes through at once. */
    initiation_at(ab, WALL - 3600, init, &ok);
    CHECK(ok);
    CHECK(wg_noise_consume_initiation(&B.local, init, T0 + 1 * SEC, &got));
    t_hex(want, sizeof(want), "4000000068da58aa01000000");     /* TAI64N(WALL) + 2^24 ns */
    CHECK_MEM(ab->sent_timestamp, want, sizeof(want));
    CHECK_MEM(ba->last_timestamp, want, sizeof(want));

    /* The same wall second twice: still strictly increasing. */
    initiation_at(ab, WALL - 3600, init, &ok);
    CHECK(wg_noise_consume_initiation(&B.local, init, T0 + 2 * SEC, &got));

    /* The quantum carries into the seconds at the top of the range. */
    t_hex(ab->sent_timestamp, WG_TIMESTAMP_LEN, "4000000068da58aa3b000000");   /* nsec 989855744 */
    initiation_at(ab, WALL - 3600, init, &ok);
    CHECK(ok);
    t_hex(want, sizeof(want), "4000000068da58ab00653600");                     /* +1 s, nsec 6632960 */
    CHECK_MEM(ab->sent_timestamp, want, sizeof(want));
}

TEST(response_checks)
{
    uint8_t init[WG_INIT_LEN], resp[WG_RESP_LEN], bad[WG_RESP_LEN];
    wg_noise_remote *ab, *ba, *got;
    wg_noise_keys ka, kb;
    int ok;

    pair(&A, &B, NULL, NULL, &ab, &ba);

    /* No initiation outstanding: nothing to consume, nothing to respond to, no session. */
    memset(resp, 0, sizeof(resp));
    CHECK(!wg_noise_consume_response(ab, resp));
    CHECK(!wg_noise_create_response(ba, resp));
    CHECK(!wg_noise_begin_session(ab, &ka));

    initiation_at(ab, WALL, init, &ok);
    CHECK(wg_noise_consume_initiation(&B.local, init, T0, &got));
    CHECK(!wg_noise_begin_session(got, &kb));      /* no response made yet */
    CHECK(wg_noise_create_response(got, resp));

    /* A response to some other initiation of ours (wrong receiver index) */
    memcpy(bad, resp, sizeof(bad));
    bad[WG_RESP_OFF_RECEIVER] ^= 0x01;
    CHECK(!wg_noise_consume_response(ab, bad));

    /* A forged ephemeral, a forged tag */
    memcpy(bad, resp, sizeof(bad));
    bad[WG_RESP_OFF_EPHEMERAL + 7] ^= 0x01;
    CHECK(!wg_noise_consume_response(ab, bad));
    memcpy(bad, resp, sizeof(bad));
    bad[WG_RESP_OFF_EMPTY + 15] ^= 0x80;
    CHECK(!wg_noise_consume_response(ab, bad));

    /* None of that disturbed the initiation: the real response still completes it, once. */
    CHECK(ab->hs.state == WG_HS_CREATED_INITIATION);
    CHECK(wg_noise_consume_response(ab, resp));
    CHECK(!wg_noise_consume_response(ab, resp));
    CHECK(wg_noise_begin_session(ab, &ka));
    CHECK(wg_noise_begin_session(ba, &kb));
    check_session_pair(&ka, &kb);
}

TEST(simultaneous_initiation)
{
    uint8_t init_a[WG_INIT_LEN], init_b[WG_INIT_LEN], resp_a[WG_RESP_LEN], resp_b[WG_RESP_LEN];
    wg_noise_remote *ab, *ba, *got;
    wg_noise_keys ka, kb;
    int ok;

    pair(&A, &B, NULL, NULL, &ab, &ba);
    initiation_at(ab, WALL, init_a, &ok);
    CHECK(ok);
    initiation_at(ba, WALL, init_b, &ok);
    CHECK(ok);

    /* Each side takes the other's initiation over its own, releasing its own index... */
    CHECK(wg_noise_consume_initiation(&A.local, init_b, T0, &got) && got == ab);
    CHECK(wg_noise_consume_initiation(&B.local, init_a, T0, &got) && got == ba);
    CHECK(A.drops == 1 && B.drops == 1 && A.nlive == 0 && B.nlive == 0);

    /* ...so both responses find no initiation to answer. */
    CHECK(wg_noise_create_response(ab, resp_a));
    CHECK(wg_noise_create_response(ba, resp_b));
    CHECK(!wg_noise_consume_response(ab, resp_b));
    CHECK(!wg_noise_consume_response(ba, resp_a));

    /* The retransmit timer settles it: one side initiates again, alone this time. */
    CHECK(handshake(&A, ab, &B, T0 + 5 * SEC, WALL + 5, &ka, &kb));
    check_session_pair(&ka, &kb);
    CHECK(A.bad_drops == 0 && B.bad_drops == 0);
}

TEST(index_accounting)
{
    uint8_t init[WG_INIT_LEN];
    wg_noise_remote *ab, *ba;
    wg_noise_keys ka, kb;
    int ok;

    pair(&A, &B, NULL, NULL, &ab, &ba);

    /* A new initiation replaces the old one and releases its index. */
    initiation_at(ab, WALL, init, &ok);
    CHECK(A.nlive == 1);
    initiation_at(ab, WALL + 1, init, &ok);
    CHECK(A.nlive == 1 && A.drops == 1);

    /* A finished handshake hands its index to the session: clearing afterwards releases nothing. */
    CHECK(handshake(&A, ab, &B, T0, WALL + 2, &ka, &kb));
    CHECK(A.nlive == 1 && A.drops == 2);
    wg_noise_remote_clear(ab);
    CHECK(A.nlive == 1 && A.drops == 2);

    /* Clearing or wiping a peer mid-handshake releases the handshake's index. */
    initiation_at(ab, WALL + 3, init, &ok);
    CHECK(A.nlive == 2);
    wg_noise_remote_wipe(ab);
    CHECK(A.nlive == 1 && A.drops == 3);
    CHECK(A.bad_drops == 0 && B.bad_drops == 0);
}

TEST(no_index_no_initiation)
{
    uint8_t init[WG_INIT_LEN];
    wg_noise_remote *ab, *ba;
    int ok;

    /* The owner's index table is full: the initiation is not made and the handshake is untouched. */
    pair(&A, &B, NULL, NULL, &ab, &ba);
    A.nlive = MAX_INDICES;
    initiation_at(ab, WALL, init, &ok);
    CHECK(!ok);
    CHECK(ab->hs.state == WG_HS_ZEROED);
    CHECK(A.drops == 0);
}

TEST(low_order_peer_key)
{
    wg_key zero;
    uint8_t init[WG_INIT_LEN];
    wg_noise_remote* r;
    int ok;

    /* The all-zero point: DH with it is zero, so the peer is kept but can never handshake. */
    side_init(&A, NULL);
    memset(&zero, 0, sizeof(zero));
    r = side_add_peer(&A, &zero, NULL);
    CHECK(!r->ss_valid);
    initiation_at(r, WALL, init, &ok);
    CHECK(!ok);
    CHECK(A.nlive == 0);
}

TEST(identity_change)
{
    uint8_t init[WG_INIT_LEN];
    wg_noise_remote *ab, *ba, *got;
    wg_key sk, pk;
    int ok;

    /* B changes its key while A's initiation is in flight, and precomputes its peers. */
    pair(&A, &B, NULL, NULL, &ab, &ba);
    initiation_at(ab, WALL, init, &ok);
    CHECK(wg_key_generate(&sk, &pk));
    CHECK(wg_noise_local_set_private_key(&B.local, &sk));
    wg_noise_remote_precompute(ba);
    CHECK(ba->ss_valid);
    CHECK_MEM(B.local.public_key.b, pk.b, WG_KEY_LEN);

    /* The old initiation was sealed to the old key. */
    CHECK(!wg_noise_consume_initiation(&B.local, init, T0, &got));

    /* A learns the new key and it works again. */
    wg_noise_remote_wipe(ab);
    ab = side_add_peer(&A, &pk, NULL);
    initiation_at(ab, WALL + 1, init, &ok);
    CHECK(wg_noise_consume_initiation(&B.local, init, T0, &got) && got == ba);
}

/* ------------------------------------------------------------------------------ transcripts */

typedef struct {
    const char* i_eph_seed;
    const char* r_eph_seed;
    const char* psk;
    const char* init;
    const char* resp;
    const char* i_send;
    const char* i_recv;
    const char* keepalive;
} transcript;

static void run_transcript(const transcript* t)
{
    wg_key isk, rsk, ipub, rpub;
    uint8_t psk[WG_KEY_LEN], ts[WG_TIMESTAMP_LEN];
    uint8_t init[WG_INIT_LEN], want_init[WG_INIT_LEN], resp[WG_RESP_LEN], want_resp[WG_RESP_LEN];
    uint8_t want_send[WG_KEY_LEN], want_recv[WG_KEY_LEN], data[32], want_data[32];
    wg_noise_remote *ab, *ba, *got;
    wg_cookie_maker ma, mb;
    wg_cookie_checker ca, cb;
    wg_noise_keys ka, kb;

    CHECK(t_hex(isk.b, WG_KEY_LEN, KAT_I_STATIC) == WG_KEY_LEN);
    CHECK(t_hex(rsk.b, WG_KEY_LEN, KAT_R_STATIC) == WG_KEY_LEN);
    CHECK(t_hex(ipub.b, WG_KEY_LEN, KAT_I_STATIC_PUB) == WG_KEY_LEN);
    CHECK(t_hex(rpub.b, WG_KEY_LEN, KAT_R_STATIC_PUB) == WG_KEY_LEN);
    CHECK(t_hex(psk, sizeof(psk), t->psk) == WG_KEY_LEN);
    CHECK(t_hex(want_init, sizeof(want_init), t->init) == WG_INIT_LEN);
    CHECK(t_hex(want_resp, sizeof(want_resp), t->resp) == WG_RESP_LEN);
    CHECK(t_hex(want_send, sizeof(want_send), t->i_send) == WG_KEY_LEN);
    CHECK(t_hex(want_recv, sizeof(want_recv), t->i_recv) == WG_KEY_LEN);
    CHECK(t_hex(want_data, sizeof(want_data), t->keepalive) == sizeof(want_data));

    side_init(&A, &isk);
    side_init(&B, &rsk);
    CHECK_MEM(A.local.public_key.b, ipub.b, WG_KEY_LEN);
    CHECK_MEM(B.local.public_key.b, rpub.b, WG_KEY_LEN);
    A.next_index = KAT_I_INDEX;
    B.next_index = KAT_R_INDEX;
    side_script(&A, t->i_eph_seed);
    side_script(&B, t->r_eph_seed);
    ab = side_add_peer(&A, &rpub, psk);
    ba = side_add_peer(&B, &ipub, psk);
    CHECK(wg_cookie_maker_init(&ma, &rpub));
    CHECK(wg_cookie_maker_init(&mb, &ipub));
    wg_cookie_checker_init(&ca);
    wg_cookie_checker_init(&cb);
    CHECK(wg_cookie_checker_set_key(&ca, &ipub));
    CHECK(wg_cookie_checker_set_key(&cb, &rpub));

    /* initiation, with mac1 */
    wg_tai64n(ts, KAT_SEC, KAT_NSEC);
    CHECK(wg_noise_create_initiation(ab, ts, init));
    CHECK(wg_cookie_add_macs(&ma, init, sizeof(init), T0));
    CHECK_MEM(init, want_init, WG_INIT_LEN);

    /* response, with mac1 */
    CHECK(wg_cookie_validate(&cb, init, sizeof(init), NULL, 0, 0, T0) == WG_MAC_VALID_NO_COOKIE);
    CHECK(wg_noise_consume_initiation(&B.local, init, T0, &got));
    CHECK(got == ba);
    CHECK(wg_noise_create_response(ba, resp));
    CHECK(wg_cookie_add_macs(&mb, resp, sizeof(resp), T0));
    CHECK_MEM(resp, want_resp, WG_RESP_LEN);

    /* transport keys, seen from both ends */
    CHECK(wg_cookie_validate(&ca, resp, sizeof(resp), NULL, 0, 0, T0) == WG_MAC_VALID_NO_COOKIE);
    CHECK(side_lookup(&A, wg_load32(resp + WG_RESP_OFF_RECEIVER)) == ab);
    CHECK(wg_noise_consume_response(ab, resp));
    CHECK(wg_noise_begin_session(ab, &ka));
    CHECK(wg_noise_begin_session(ba, &kb));
    CHECK_MEM(ka.send_key, want_send, WG_KEY_LEN);
    CHECK_MEM(ka.recv_key, want_recv, WG_KEY_LEN);
    CHECK_MEM(kb.send_key, want_recv, WG_KEY_LEN);
    CHECK_MEM(kb.recv_key, want_send, WG_KEY_LEN);
    CHECK(ka.local_index == KAT_I_INDEX && ka.remote_index == KAT_R_INDEX && ka.initiator);
    CHECK(kb.local_index == KAT_R_INDEX && kb.remote_index == KAT_I_INDEX && !kb.initiator);

    /* The initiator's first data message: a keepalive, empty payload, counter 0. */
    wg_store32(data + WG_DATA_OFF_TYPE, WG_MSG_DATA);
    wg_store32(data + WG_DATA_OFF_RECEIVER, ka.remote_index);
    wg_store64(data + WG_DATA_OFF_COUNTER, 0);
    CHECK(wg_aead_encrypt(data + WG_DATA_OFF_PAYLOAD, ka.send_key, 0, NULL, 0, NULL, 0));
    CHECK_MEM(data, want_data, sizeof(data));

    /* Each side drew exactly the randomness the reference did: one ephemeral each. */
    CHECK(A.script_pos == A.script_len && B.script_pos == B.script_len);
}

TEST(transcript_no_psk)
{
    static const transcript t = {
        KAT_NOPSK_I_EPH_SEED, KAT_NOPSK_R_EPH_SEED, KAT_NOPSK_PSK, KAT_NOPSK_INIT, KAT_NOPSK_RESP,
        KAT_NOPSK_I_SEND, KAT_NOPSK_I_RECV, KAT_NOPSK_KEEPALIVE
    };
    run_transcript(&t);
}

TEST(transcript_psk)
{
    static const transcript t = {
        KAT_PSK_I_EPH_SEED, KAT_PSK_R_EPH_SEED, KAT_PSK_PSK, KAT_PSK_INIT, KAT_PSK_RESP,
        KAT_PSK_I_SEND, KAT_PSK_I_RECV, KAT_PSK_KEEPALIVE
    };
    run_transcript(&t);
}

int main(void)
{
    if (!wg_crypto_init()) {
        fprintf(stderr, "wg_crypto_init failed\n");
        return 2;
    }
    RUN(tai64n_layout);
    RUN(handshake_no_psk);
    RUN(handshake_with_psk);
    RUN(psk_mismatch_fails_at_the_response);
    RUN(wrong_responder_key);
    RUN(unknown_initiator);
    RUN(tampered_initiation);
    RUN(replay_and_flood);
    RUN(clock_stepping_back);
    RUN(response_checks);
    RUN(simultaneous_initiation);
    RUN(index_accounting);
    RUN(no_index_no_initiation);
    RUN(low_order_peer_key);
    RUN(identity_change);
    RUN(transcript_no_psk);
    RUN(transcript_psk);
    wg_crypto_cleanup();
    return t_summary("test_noise");
}
