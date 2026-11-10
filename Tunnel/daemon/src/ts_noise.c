/*
 * ts_noise - see ts_noise.h.
 *
 * The handshake follows controlbase's handshake.go step for step (ClientDeferred, then
 * continueClientHandshake); the record layer follows conn.go (encryptLocked, decryptLocked,
 * readNLocked, Write). In Noise terms: Noise_IK_25519_ChaChaPoly_BLAKE2s, no PSK, empty payloads
 * both ways. Every AEAD of the handshake runs under a key fresh from MixKey, so its nonce is
 * always zero; the counter's byte order matters only from the first record on.
 *
 * The handshake computes on local copies of h and ck and stores them only once a message has
 * checked out. A failure wipes the object anyway; the copies keep a half-mixed state from ever
 * being visible in it.
 */

#include "ts_noise.h"

#include <string.h>

/* 33 bytes - longer than HASHLEN, so Noise hashes it rather than padding it (spec section 5.2). */
static const char PROTOCOL_NAME[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/* controlbase protocolVersionPrefix; the version follows in decimal ASCII (strconv.AppendUint). */
static const char PROLOGUE_PREFIX[] = "Tailscale Control Protocol v";

/* ts2021 EarlyPayloadMagic: 5 bytes that cannot start an HTTP/2 frame (no frame type 'T'). */
static const uint8_t EARLY_MAGIC[5] = { 0xff, 0xff, 0xff, 'T', 'S' };

/* The handshake's AEADs: a fresh key each, so the nonce is always zero. */
static const uint8_t ZERO_NONCE[12];

/* --------------------------------------------------------------------- byte order */

static void store_be16(uint8_t* p, unsigned v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static unsigned load_be16(const uint8_t* p)
{
    return ((unsigned)p[0] << 8) | p[1];
}

static uint32_t load_be32(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/*
 * ts2021's record nonce: four zero bytes, then the counter BIG-endian - controlbase's `nonce`
 * type, binary.BigEndian.PutUint64(n[4:], counter). wg_aead_encrypt writes WireGuard's (and
 * Noise's) little-endian counter; the two agree on record 0 alone, so records get this encoder.
 */
static void record_nonce(uint8_t nonce[12], uint64_t counter)
{
    int i;

    memset(nonce, 0, 4);
    for (i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(counter >> (56 - 8 * i));
}

/* --------------------------------------------------------------------- state */

/* Everything secret, and the receive buffer (it holds plaintext). The rest stays for the log. */
static void wipe_secrets(ts_noise* n)
{
    wg_wipe(&n->machine_private, sizeof(n->machine_private));
    wg_wipe(&n->ephemeral_private, sizeof(n->ephemeral_private));
    wg_wipe(n->chaining_key, sizeof(n->chaining_key));
    wg_wipe(n->tx_key, sizeof(n->tx_key));
    wg_wipe(n->rx_key, sizeof(n->rx_key));
    wg_wipe(n->rx, sizeof(n->rx));
    n->rx_len = 0;
    n->rx_need = 0;
}

/* A failure of the protocol is final: the stream is out of step with the server for good. */
static int fail(ts_noise* n, ts_noise_error e)
{
    wipe_secrets(n);
    n->state = TS_NOISE_DEAD;
    n->err = e;
    return 0;
}

/* A call in the wrong state: refused, nothing changes - a dead object keeps the reason it died. */
static int refuse(ts_noise* n)
{
    if (n->state != TS_NOISE_DEAD) n->err = TS_NOISE_ERR_STATE;
    return 0;
}

/* --------------------------------------------------------------------- symmetric state */

/* h = HASH(h || in) */
static int mix_hash(uint8_t h[WG_HASH_LEN], const void* in, size_t len)
{
    return wg_hash2(h, h, WG_HASH_LEN, in, len);
}

/*
 * MixKey(dh): (ck, key) = HKDF(ck, dh), two outputs; `key` NULL keeps the first alone (the ee
 * token, whose key nothing uses). controlbase's MixDH is hkdf.New(BLAKE2s, dh, ck, nil) read for
 * 32 + 32 bytes - which is wg_kdf's HMAC chain exactly.
 */
static int mix_key(uint8_t ck[WG_HASH_LEN], uint8_t* key, const uint8_t dh[WG_KEY_LEN])
{
    return wg_kdf(ck, key, NULL, ck, dh, WG_KEY_LEN);
}

/* out = AEAD(key, 0, pt, ad = h); h = HASH(h || out). `out` takes len + WG_TAG_LEN bytes. */
static int encrypt_and_hash(uint8_t* out, const uint8_t key[WG_KEY_LEN], uint8_t h[WG_HASH_LEN],
                            const void* pt, size_t len)
{
    return wg_aead_encrypt_n(out, key, ZERO_NONCE, pt, len, h, WG_HASH_LEN)
        && mix_hash(h, out, len + WG_TAG_LEN);
}

/* "Tailscale Control Protocol v" + the version in decimal; returns the length. */
static size_t prologue(char out[sizeof(PROLOGUE_PREFIX) + 5], uint16_t version)
{
    char digits[5];
    size_t len = sizeof(PROLOGUE_PREFIX) - 1, k = 0;
    unsigned v = version;

    memcpy(out, PROLOGUE_PREFIX, len);
    do {
        digits[k++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (k) out[len++] = digits[--k];
    return len;
}

/* --------------------------------------------------------------------- handshake */

int ts_noise_init(ts_noise* n, const wg_key* machine_private, const wg_key* control_public,
                  uint16_t version, const wg_rng* rng)
{
    char pro[sizeof(PROLOGUE_PREFIX) + 5];
    size_t plen;

    wg_wipe(n, sizeof(*n));
    n->state = TS_NOISE_IDLE;
    n->err = TS_NOISE_OK;
    n->version = version;
    n->machine_private = *machine_private;
    n->control_public = *control_public;
    if (rng) n->rng = *rng;

    /* Initialize: h = HASH(name), ck = h; then the prologue and IK's pre-message "<- s". */
    plen = prologue(pro, version);
    if (!wg_hash(n->hash, PROTOCOL_NAME, sizeof(PROTOCOL_NAME) - 1)) return fail(n, TS_NOISE_ERR_CRYPTO);
    memcpy(n->chaining_key, n->hash, WG_HASH_LEN);
    if (!mix_hash(n->hash, pro, plen)) return fail(n, TS_NOISE_ERR_CRYPTO);
    if (!mix_hash(n->hash, control_public->b, WG_KEY_LEN)) return fail(n, TS_NOISE_ERR_CRYPTO);

    if (!wg_key_public(&n->machine_private, &n->machine_public)) return fail(n, TS_NOISE_ERR_CRYPTO);
    n->state = TS_NOISE_READY;
    return 1;
}

/* -> e, es, s, ss */
int ts_noise_initiation(ts_noise* n, uint8_t msg[TS_NOISE_INIT_LEN])
{
    uint8_t h[WG_HASH_LEN], ck[WG_HASH_LEN], key[WG_KEY_LEN], dh[WG_KEY_LEN];
    wg_key e_priv, e_pub;
    ts_noise_error err = TS_NOISE_ERR_CRYPTO;

    if (n->state != TS_NOISE_READY) return refuse(n);
    memcpy(h, n->hash, WG_HASH_LEN);
    memcpy(ck, n->chaining_key, WG_HASH_LEN);

    /* e: in the clear and hashed. Not mixed into ck - only psk mode does that (WireGuard). */
    if (!wg_key_generate_rng(&n->rng, &e_priv, &e_pub)) {
        err = TS_NOISE_ERR_RNG;
        goto out;
    }
    memcpy(msg + TS_NOISE_INIT_OFF_EPHEMERAL, e_pub.b, WG_KEY_LEN);
    if (!mix_hash(h, e_pub.b, WG_KEY_LEN)) goto out;

    /* es */
    if (!wg_dh(&e_priv, &n->control_public, dh)) {
        err = TS_NOISE_ERR_KEY;
        goto out;
    }
    if (!mix_key(ck, key, dh)) goto out;

    /* s: our machine key, sealed - the server learns who we are only after its es */
    if (!encrypt_and_hash(msg + TS_NOISE_INIT_OFF_MACHINE, key, h, n->machine_public.b, WG_KEY_LEN)) goto out;

    /* ss */
    if (!wg_dh(&n->machine_private, &n->control_public, dh)) {
        err = TS_NOISE_ERR_KEY;
        goto out;
    }
    if (!mix_key(ck, key, dh)) goto out;

    /* payload: empty, so the tag alone; it binds the whole message */
    if (!encrypt_and_hash(msg + TS_NOISE_INIT_OFF_TAG, key, h, NULL, 0)) goto out;

    store_be16(msg + TS_NOISE_INIT_OFF_VERSION, n->version);
    msg[TS_NOISE_INIT_OFF_TYPE] = TS_NOISE_MSG_INITIATION;
    store_be16(msg + TS_NOISE_INIT_OFF_LENGTH, TS_NOISE_INIT_PAYLOAD_LEN);

    n->ephemeral_private = e_priv;
    memcpy(n->hash, h, WG_HASH_LEN);
    memcpy(n->chaining_key, ck, WG_HASH_LEN);
    n->state = TS_NOISE_SENT;
    err = TS_NOISE_OK;
out:
    wg_wipe(&e_priv, sizeof(e_priv));
    wg_wipe(key, sizeof(key));
    wg_wipe(dh, sizeof(dh));
    wg_wipe(ck, sizeof(ck));
    wg_wipe(h, sizeof(h));
    if (err != TS_NOISE_OK) {
        memset(msg, 0, TS_NOISE_INIT_LEN);
        return fail(n, err);
    }
    return 1;
}

/* <- e, ee, se; then Split. The response is whole in n->rx. */
static int take_response(ts_noise* n)
{
    uint8_t h[WG_HASH_LEN], ck[WG_HASH_LEN], key[WG_KEY_LEN], dh[WG_KEY_LEN], empty[1];
    const uint8_t* tag = n->rx + TS_NOISE_RESP_OFF_TAG;
    wg_key re;
    ts_noise_error err = TS_NOISE_ERR_CRYPTO;

    n->rx_len = 0;
    n->rx_need = 0;
    memcpy(h, n->hash, WG_HASH_LEN);
    memcpy(ck, n->chaining_key, WG_HASH_LEN);
    memcpy(re.b, n->rx + TS_NOISE_RESP_OFF_EPHEMERAL, WG_KEY_LEN);

    /* e */
    if (!mix_hash(h, re.b, WG_KEY_LEN)) goto out;

    /* ee: moves ck only */
    if (!wg_dh(&n->ephemeral_private, &re, dh)) {
        err = TS_NOISE_ERR_KEY;
        goto out;
    }
    if (!mix_key(ck, NULL, dh)) goto out;

    /* se, from our side: our static with their ephemeral */
    if (!wg_dh(&n->machine_private, &re, dh)) {
        err = TS_NOISE_ERR_KEY;
        goto out;
    }
    if (!mix_key(ck, key, dh)) goto out;

    /* payload: empty. The tag's key descends from es and ss, so it verifies only if the server
     * holds the control key's private half; a stale key from /key fails exactly here. */
    if (!wg_aead_decrypt_n(empty, key, ZERO_NONCE, tag, WG_TAG_LEN, h, WG_HASH_LEN)) {
        err = TS_NOISE_ERR_AUTH;
        goto out;
    }
    if (!mix_hash(h, tag, WG_TAG_LEN)) goto out;

    /* Split: HKDF(ck, empty); the first key carries client -> server (controlbase: tx = c1). */
    if (!wg_kdf(n->tx_key, n->rx_key, NULL, ck, NULL, 0)) goto out;

    memcpy(n->hash, h, WG_HASH_LEN);
    n->tx_counter = 0;
    n->rx_counter = 0;
    wg_wipe(&n->machine_private, sizeof(n->machine_private));
    wg_wipe(&n->ephemeral_private, sizeof(n->ephemeral_private));
    wg_wipe(n->chaining_key, sizeof(n->chaining_key));
    n->state = TS_NOISE_OPEN;
    err = TS_NOISE_OK;
out:
    wg_wipe(key, sizeof(key));
    wg_wipe(dh, sizeof(dh));
    wg_wipe(ck, sizeof(ck));
    wg_wipe(h, sizeof(h));
    if (err != TS_NOISE_OK) return fail(n, err);
    return 1;
}

/* The server refused the handshake. Its text is unauthenticated: kept printable, for the log. */
static int take_error(ts_noise* n)
{
    size_t len = n->rx_need - TS_NOISE_HEADER_LEN, i;

    for (i = 0; i < len; i++) {
        uint8_t c = n->rx[TS_NOISE_HEADER_LEN + i];
        n->err_text[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
    }
    n->err_text[len] = '\0';
    return fail(n, TS_NOISE_ERR_SERVER);
}

/* --------------------------------------------------------------------- records */

/* A whole record in n->rx: decrypted in place, the plaintext right after the header. */
static int take_record(ts_noise* n, const uint8_t** pt, size_t* pt_len)
{
    size_t ctlen = n->rx_need - TS_NOISE_HEADER_LEN;
    uint8_t* ct = n->rx + TS_NOISE_HEADER_LEN;
    uint8_t nonce[12];

    n->rx_len = 0;
    n->rx_need = 0;
    if (n->rx_counter == TS_NOISE_COUNTER_LIMIT) return fail(n, TS_NOISE_ERR_EXHAUSTED);
    record_nonce(nonce, n->rx_counter);
    if (!wg_aead_decrypt_n(ct, n->rx_key, nonce, ct, ctlen, NULL, 0)) return fail(n, TS_NOISE_ERR_AUTH);
    n->rx_counter++;
    *pt_len = ctlen - WG_TAG_LEN;
    *pt = *pt_len ? ct : NULL;
    return 1;
}

/*
 * The header of the next message is in: how long is the message, and may it come now? Before
 * the handshake is done only the response or the server's error may; after it, only records.
 */
static int take_header(ts_noise* n)
{
    unsigned type = n->rx[0];
    size_t length = load_be16(n->rx + 1);

    if (n->state == TS_NOISE_SENT) {
        if (type == TS_NOISE_MSG_RESPONSE) {
            if (length != TS_NOISE_RESP_PAYLOAD_LEN) return fail(n, TS_NOISE_ERR_LENGTH);
            n->rx_need = TS_NOISE_RESP_LEN;
            return 1;
        }
        if (type == TS_NOISE_MSG_ERROR) {
            /* Only what the log keeps is read; the connection ends with this message anyway. */
            n->rx_need = TS_NOISE_HEADER_LEN + (length < TS_NOISE_ERR_TEXT_MAX ? length : TS_NOISE_ERR_TEXT_MAX);
            return 1;
        }
        return fail(n, TS_NOISE_ERR_TYPE);
    }

    if (type != TS_NOISE_MSG_RECORD) return fail(n, TS_NOISE_ERR_TYPE);
    /* controlbase refuses a frame over 4096 bytes before reading it (errReadTooBig); one with no
     * room for a tag would fail its Open after arriving - refused at once here, same outcome. */
    if (length > TS_NOISE_MAX_CIPHERTEXT || length < WG_TAG_LEN) return fail(n, TS_NOISE_ERR_LENGTH);
    n->rx_need = TS_NOISE_HEADER_LEN + length;
    return 1;
}

int ts_noise_receive(ts_noise* n, const uint8_t* in, size_t len, size_t* used,
                     const uint8_t** pt, size_t* pt_len)
{
    size_t off = 0;

    *used = 0;
    *pt = NULL;
    *pt_len = 0;
    if (n->state != TS_NOISE_SENT && n->state != TS_NOISE_OPEN) return refuse(n);

    while (off < len) {
        size_t want = n->rx_need ? n->rx_need : TS_NOISE_HEADER_LEN;
        size_t take = want - n->rx_len;

        if (take > len - off) take = len - off;
        memcpy(n->rx + n->rx_len, in + off, take);
        n->rx_len += take;
        off += take;
        *used = off;
        if (n->rx_len < want) break;                    /* the input ran out mid-message */

        if (!n->rx_need && !take_header(n)) return 0;
        if (n->rx_len < n->rx_need) continue;           /* the header alone so far */

        if (n->state == TS_NOISE_OPEN) return take_record(n, pt, pt_len);
        if (n->rx[0] == TS_NOISE_MSG_ERROR) return take_error(n);
        return take_response(n);
    }
    return 1;
}

int ts_noise_seal(ts_noise* n, const uint8_t* in, size_t len, size_t* used,
                  uint8_t* out, size_t cap, size_t* out_len)
{
    size_t take = 0, room = cap, records = 0, taken = 0, made = 0;

    *used = 0;
    *out_len = 0;
    if (n->state != TS_NOISE_OPEN) return refuse(n);

    /* Count first: a call that would run the counter out must not write anything. */
    while (take < len && room > TS_NOISE_RECORD_OVERHEAD) {
        size_t chunk = len - take;
        if (chunk > TS_NOISE_MAX_PLAINTEXT) chunk = TS_NOISE_MAX_PLAINTEXT;
        if (chunk > room - TS_NOISE_RECORD_OVERHEAD) chunk = room - TS_NOISE_RECORD_OVERHEAD;
        take += chunk;
        room -= chunk + TS_NOISE_RECORD_OVERHEAD;
        records++;
    }
    if (records > TS_NOISE_COUNTER_LIMIT - n->tx_counter) return fail(n, TS_NOISE_ERR_EXHAUSTED);

    while (taken < take) {
        size_t chunk = take - taken;
        uint8_t nonce[12];

        if (chunk > TS_NOISE_MAX_PLAINTEXT) chunk = TS_NOISE_MAX_PLAINTEXT;
        if (chunk > cap - made - TS_NOISE_RECORD_OVERHEAD) chunk = cap - made - TS_NOISE_RECORD_OVERHEAD;

        out[made] = TS_NOISE_MSG_RECORD;
        store_be16(out + made + 1, (unsigned)(chunk + WG_TAG_LEN));
        record_nonce(nonce, n->tx_counter);
        if (!wg_aead_encrypt_n(out + made + TS_NOISE_HEADER_LEN, n->tx_key, nonce, in + taken, chunk, NULL, 0))
            return fail(n, TS_NOISE_ERR_CRYPTO);
        n->tx_counter++;
        taken += chunk;
        made += chunk + TS_NOISE_RECORD_OVERHEAD;
    }
    *used = taken;
    *out_len = made;
    return 1;
}

size_t ts_noise_sealed_len(size_t len)
{
    size_t records = len / TS_NOISE_MAX_PLAINTEXT + (len % TS_NOISE_MAX_PLAINTEXT != 0);
    return len + records * TS_NOISE_RECORD_OVERHEAD;
}

void ts_noise_wipe(ts_noise* n)
{
    wg_wipe(n, sizeof(*n));
    n->state = TS_NOISE_IDLE;
    n->err = TS_NOISE_OK;
}

const char* ts_noise_error_text(ts_noise_error e)
{
    switch (e) {
    case TS_NOISE_OK:               return "ok";
    case TS_NOISE_ERR_STATE:        return "called in the wrong state";
    case TS_NOISE_ERR_CRYPTO:       return "crypto primitive failed";
    case TS_NOISE_ERR_RNG:          return "no randomness for the ephemeral key";
    case TS_NOISE_ERR_KEY:          return "low-order key";
    case TS_NOISE_ERR_SERVER:       return "server refused the handshake";
    case TS_NOISE_ERR_TYPE:         return "unexpected message type";
    case TS_NOISE_ERR_LENGTH:       return "message length out of range";
    case TS_NOISE_ERR_AUTH:         return "authentication failed";
    case TS_NOISE_ERR_EXHAUSTED:    return "record counter exhausted";
    }
    return "?";
}

/* --------------------------------------------------------------------- EarlyNoise */

ts_early_result ts_noise_early(const uint8_t* p, size_t len, uint32_t* json_len)
{
    uint32_t l;

    *json_len = 0;
    /* ts2021 reads all 9 bytes before it decides, and so do we. */
    if (len < TS_EARLY_HEADER_LEN) return TS_EARLY_MORE;
    if (memcmp(p, EARLY_MAGIC, sizeof(EARLY_MAGIC)) != 0) return TS_EARLY_NONE;
    l = load_be32(p + sizeof(EARLY_MAGIC));
    if (l > TS_EARLY_MAX_JSON) return TS_EARLY_BAD;
    *json_len = l;
    return TS_EARLY_FOUND;
}
