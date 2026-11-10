/*
 * ts_noise - the base transport of Tailscale's control protocol, "ts2021" (docs/TAILSCALE.md,
 * section 5): a Noise IK handshake between our machine key and the control server's key, then a
 * stream of encrypted records both ways that carries HTTP/2.
 *
 * Sans-IO like the engine: bytes in, bytes out, the ephemeral key through wg_rng, no clock (the
 * caller times the connection out). Written against controlbase of Tailscale v1.102.5
 * (control/controlbase: handshake.go, conn.go, messages.go) and control/ts2021/conn.go for
 * EarlyNoise, with microlink's ml_noise.c as a map. test/vectors/noise checks it byte for byte
 * against controlbase itself.
 *
 *   us (client)                                              control server
 *   ts_noise_initiation   --- initiation, 101 bytes --->     base64 in the HTTP upgrade request
 *   ts_noise_receive      <-- response, 51 bytes ------      (or an error message)
 *   ts_noise_seal         --- records --------------->
 *   ts_noise_receive      <-- records ----------------
 *
 * The cryptography is the engine's (wg_crypto), WireGuard's handshake minus the PSK:
 * Noise_IK_25519_ChaChaPoly_BLAKE2s with the prologue "Tailscale Control Protocol v<version>".
 * Where it differs from WireGuard, on purpose:
 *   - the record nonce is four zero bytes and the counter BIG-endian (controlbase; Noise's
 *     ChaChaPoly and WireGuard put it little-endian) - only record 0 looks the same either way;
 *   - the "e" token is only hashed into h, never mixed into the chaining key (that is psk mode);
 *   - records travel on a TCP stream: type 4, a 2-byte big-endian length, then the ciphertext
 *     with its tag, at most 4096 bytes in all.
 *
 * A stream cannot be resynchronized, so every failure of the protocol is final, as in controlbase,
 * which drops its cipher: the object goes to TS_NOISE_DEAD, wipes its keys and refuses every later
 * call, and the caller closes the connection. Nothing unauthenticated reaches the caller except
 * the reason (`err`) and a server's error text (`err_text`, printable ASCII) - both for the log
 * only. A call in the wrong state is a bug of the caller, not of the stream: it is refused with
 * TS_NOISE_ERR_STATE and changes nothing.
 *
 * The control connection in the poll loop drives it like this:
 *
 *   ts_noise_init(&n, &machine_private, &control_public, capver, NULL);
 *   ts_noise_initiation(&n, init);     -> base64 into X-Tailscale-Handshake of POST /ts2021
 *   every byte after the HTTP 101 headers (the response and the first records often come in one
 *   read - the server corks them together):
 *       while (off < got) {
 *           if (!ts_noise_receive(&n, buf + off, got - off, &used, &pt, &pt_len)) -> close, log n.err
 *           off += used;
 *           if (pt_len) -> the plaintext stream: ts_noise_early on its first 9 bytes, then HTTP/2
 *       }
 *       n.state turns TS_NOISE_OPEN with the response: send the HTTP/2 preface at once
 *   outgoing plaintext:
 *       ts_noise_seal(&n, data, len, &used, out, room, &out_len) -> send out[0..out_len)
 *
 * All functions return 1 on success and 0 on failure (the wg_crypto convention).
 */

#ifndef TS_NOISE_H
#define TS_NOISE_H

#include <stddef.h>
#include <stdint.h>

#include "wg_crypto.h"

/* --- wire layout (controlbase messages.go, conn.go) ------------------------------------ */

#define TS_NOISE_MSG_INITIATION     1
#define TS_NOISE_MSG_RESPONSE       2
#define TS_NOISE_MSG_ERROR          3       /* unauthenticated text: a hint for the log, no more */
#define TS_NOISE_MSG_RECORD         4

#define TS_NOISE_HEADER_LEN         3       /* type, length (big-endian): every message but the initiation */

/* initiation: version (2, big-endian), type, length (2) = 96, then the Noise message */
#define TS_NOISE_INIT_LEN           101
#define TS_NOISE_INIT_PAYLOAD_LEN   96
#define TS_NOISE_INIT_OFF_VERSION   0
#define TS_NOISE_INIT_OFF_TYPE      2
#define TS_NOISE_INIT_OFF_LENGTH    3
#define TS_NOISE_INIT_OFF_EPHEMERAL 5       /* our ephemeral public key, in the clear */
#define TS_NOISE_INIT_OFF_MACHINE   37      /* our machine public key, sealed: 32 + tag */
#define TS_NOISE_INIT_OFF_TAG       85      /* the empty payload's tag */

/* response: type, length (2) = 48, then the Noise message */
#define TS_NOISE_RESP_LEN           51
#define TS_NOISE_RESP_PAYLOAD_LEN   48
#define TS_NOISE_RESP_OFF_EPHEMERAL 3       /* the server's ephemeral public key */
#define TS_NOISE_RESP_OFF_TAG       35

/* A record on the wire is at most 4096 bytes, header included (controlbase maxMessageSize). */
#define TS_NOISE_MAX_RECORD         4096
#define TS_NOISE_MAX_CIPHERTEXT     (TS_NOISE_MAX_RECORD - TS_NOISE_HEADER_LEN)     /* 4093 */
#define TS_NOISE_MAX_PLAINTEXT      (TS_NOISE_MAX_CIPHERTEXT - WG_TAG_LEN)          /* 4077 */
#define TS_NOISE_RECORD_OVERHEAD    (TS_NOISE_HEADER_LEN + WG_TAG_LEN)              /* 19 */

/*
 * Record counters run from 0 up to, not including, this value: controlbase's invalidNonce. A
 * connection that reaches it in either direction is spent (errCipherExhausted).
 */
#define TS_NOISE_COUNTER_LIMIT      (~0ULL)

/* How much of a server's error message is kept for the log; the rest is never read. */
#define TS_NOISE_ERR_TEXT_MAX       128

/* --- state ----------------------------------------------------------------------------- */

typedef enum {
    TS_NOISE_IDLE = 0,              /* zeroed, or wiped */
    TS_NOISE_READY,                 /* keys set, no initiation made yet */
    TS_NOISE_SENT,                  /* initiation made: waiting for the response */
    TS_NOISE_OPEN,                  /* handshake done: records both ways */
    TS_NOISE_DEAD                   /* failed: see err; close the connection */
} ts_noise_state;

typedef enum {
    TS_NOISE_OK = 0,
    TS_NOISE_ERR_STATE,             /* called in the wrong state (a bug of the caller) */
    TS_NOISE_ERR_CRYPTO,            /* a primitive failed: is wg_crypto_init done? */
    TS_NOISE_ERR_RNG,               /* no randomness for the ephemeral key */
    TS_NOISE_ERR_KEY,               /* a DH came out all zeroes: a low-order key, ours or theirs */
    TS_NOISE_ERR_SERVER,            /* the server refused the handshake; its text is in err_text */
    TS_NOISE_ERR_TYPE,              /* a message of a type not allowed at this point */
    TS_NOISE_ERR_LENGTH,            /* a length field out of range */
    TS_NOISE_ERR_AUTH,              /* a tag did not verify: a wrong server key, or bytes altered */
    TS_NOISE_ERR_EXHAUSTED          /* a record counter reached TS_NOISE_COUNTER_LIMIT */
} ts_noise_error;

typedef struct {
    ts_noise_state state;
    ts_noise_error err;             /* why it is DEAD, or why the last call was refused */
    uint16_t version;               /* in the initiation header and the prologue */

    wg_key   machine_private;       /* ours; wiped once the handshake is done */
    wg_key   machine_public;
    wg_key   control_public;        /* the server's, from /key */
    wg_key   ephemeral_private;     /* this handshake's; wiped once it is done */
    uint8_t  hash[WG_HASH_LEN];     /* Noise h; once OPEN, the handshake hash (not secret) */
    uint8_t  chaining_key[WG_HASH_LEN];     /* Noise ck; wiped once the handshake is done */

    uint8_t  tx_key[WG_KEY_LEN];    /* us -> server: the first key of Split */
    uint8_t  rx_key[WG_KEY_LEN];    /* server -> us: the second */
    uint64_t tx_counter;            /* the next record's nonce, each way */
    uint64_t rx_counter;

    uint8_t  rx[TS_NOISE_MAX_RECORD];       /* the message being put together; then its plaintext */
    size_t   rx_len;                /* bytes of it in so far */
    size_t   rx_need;               /* its whole length once the header is in; 0 before */

    char     err_text[TS_NOISE_ERR_TEXT_MAX + 1];   /* the server's error message, NUL-terminated */
    wg_rng   rng;
} ts_noise;

/* --- handshake ------------------------------------------------------------------------- */

/*
 * Sets `n` up for one connection: our machine key (its public half is derived), the server's key
 * (the "publicKey" of GET /key, mkey: hex decoded by the caller) and the protocol version.
 * Tailscale v1.102.5 sends its capability version as the protocol version
 * (uint16(tailcfg.CurrentCapabilityVersion)), so do we: the capver we declare. `rng` NULL: the
 * ephemeral key comes from OpenSSL. One object per connection - a new connection, a new init.
 */
int ts_noise_init(ts_noise* n, const wg_key* machine_private, const wg_key* control_public,
                  uint16_t version, const wg_rng* rng);

/*
 * The initiation, 101 bytes, for the X-Tailscale-Handshake header of the upgrade request (base64,
 * standard alphabet with padding). Once per object: READY -> SENT.
 */
int ts_noise_initiation(ts_noise* n, uint8_t msg[TS_NOISE_INIT_LEN]);

/* --- the stream ------------------------------------------------------------------------ */

/*
 * Bytes from the server, fed in as they arrive, in pieces of any size: first the handshake
 * response, then records. Takes bytes until one message is whole or the input runs out;
 * `*used` says how many - call again with the rest. When the message is the response, `n` turns
 * OPEN; when it is a record, `*pt` / `*pt_len` are its plaintext, valid until the next call on
 * `n` (a record may be empty). `*pt` is NULL whenever `*pt_len` is 0. When the input runs out
 * first, the partial message waits in `n` for more.
 *
 * Refused, and final: a message type out of place, a length out of range, a failed tag, an
 * exhausted counter, and the server's error message instead of the response (ERR_SERVER, text in
 * err_text). Nothing is handed out then.
 */
int ts_noise_receive(ts_noise* n, const uint8_t* in, size_t len, size_t* used,
                     const uint8_t** pt, size_t* pt_len);

/*
 * Seals plaintext into records: as many whole records as fit in `cap` bytes of `out`, each
 * carrying up to TS_NOISE_MAX_PLAINTEXT bytes, the way controlbase cuts a Write. `*used` is the
 * plaintext taken (less than `len` when `out` fills up; 0 when not even a one-byte record fits),
 * `*out_len` the bytes to send. Every sealed byte must go out, in order - a connection that
 * cannot send them is dead. `in` and `out` must not overlap.
 *
 * Final: the counter would run out within this call - then nothing at all is written.
 */
int ts_noise_seal(ts_noise* n, const uint8_t* in, size_t len, size_t* used,
                  uint8_t* out, size_t cap, size_t* out_len);

/* The bytes `len` of plaintext take on the wire in full records. */
size_t ts_noise_sealed_len(size_t len);

/* Wipes every key and buffer; the object is IDLE again. */
void ts_noise_wipe(ts_noise* n);

const char* ts_noise_error_text(ts_noise_error e);

/* --- EarlyNoise (control/ts2021/conn.go) ----------------------------------------------- */

/*
 * The first 9 bytes the server sends through the records are either an HTTP/2 frame header (its
 * SETTINGS) or EarlyNoise: the magic "\xff\xff\xffTS" and a big-endian uint32 length, followed by
 * that many bytes of JSON (tailcfg.EarlyNoise: {"nodeKeyChallenge":"chalpub:..."}). The server may
 * send either; v1.102.5 reads the JSON and nothing uses it, so the caller may just skip it.
 */
#define TS_EARLY_HEADER_LEN         9
#define TS_EARLY_MAX_JSON           (10u << 20)     /* ts2021: longer is "invalid early payload length" */

typedef enum {
    TS_EARLY_MORE = 0,              /* fewer than 9 bytes yet: call again with more */
    TS_EARLY_NONE,                  /* no EarlyNoise: HTTP/2 starts at the first byte */
    TS_EARLY_FOUND,                 /* EarlyNoise: *json_len bytes of JSON follow the 9; HTTP/2 after them */
    TS_EARLY_BAD                    /* EarlyNoise longer than TS_EARLY_MAX_JSON: close the connection */
} ts_early_result;

/* Looks at the start of the decrypted stream from the server, `len` bytes of it so far. */
ts_early_result ts_noise_early(const uint8_t* p, size_t len, uint32_t* json_len);

#endif /* TS_NOISE_H */
