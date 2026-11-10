/*
 * wg_msg - the WireGuard message layouts, as byte offsets.
 *
 * Offsets instead of packed structs: the phone is 32-bit ARM, where a packed struct turns into
 * byte-by-byte access anyway and an unpacked one would be one misplaced pragma away from a
 * misaligned load. Every multi-byte integer on the wire is little-endian.
 *
 * These are the CANONICAL layouts. A wire codec (plain WireGuard, AmneziaWG) may reshape a
 * datagram around them - another value in the 4-byte type field, junk before the message - but
 * the handshake and cookie code only ever see a message in this form. The type field is not
 * interpreted here: classifying a datagram is the codec's job, which is also why the handshake
 * code never looks at it on input.
 *
 * Portability trap, for every file of the engine: the BB10 cross headers (QNX 8.0 <stdint.h>)
 * define NONE of the limit and constant macros - UINT64_MAX, SIZE_MAX, INT64_C... - below C11,
 * and the engine builds as gnu99. The workstation's glibc does define them, so only
 * `build.sh cross` catches a use. Spell such values out instead (~0ULL, (size_t)-1).
 */

#ifndef WG_MSG_H
#define WG_MSG_H

#include <stdint.h>

/* Message types in the canonical 4-byte type field (1 byte type + 3 reserved zero bytes). */
#define WG_MSG_INITIATION   1
#define WG_MSG_RESPONSE     2
#define WG_MSG_COOKIE       3
#define WG_MSG_DATA         4

#define WG_TIMESTAMP_LEN    12      /* TAI64N */
#define WG_COOKIE_LEN       16
#define WG_COOKIE_NONCE_LEN 24
#define WG_MACS_LEN         32      /* mac1 + mac2: the tail of every handshake message */

/* Engine time is nanoseconds of a monotonic clock, always passed in by the caller. */
#define WG_NSEC_PER_SEC     1000000000ULL

/* An inclusive range of 32-bit values - AmneziaWG's H1-H4, timings, padding: lo..hi, a single
 * value when lo == hi. 0..0 means "not set" wherever a setting may be absent. */
typedef struct {
    uint32_t lo, hi;
} wg_range;

/* Why a packet was dropped, wherever on its way (for stats, logs and tests). */
typedef enum {
    WG_DROP_NONE = 0,
    /* a data message, before decryption or at it (wg_session) */
    WG_DROP_MALFORMED,                  /* too short to be a data message */
    WG_DROP_UNKNOWN_INDEX,              /* no keypair of this peer has that receiver index */
    WG_DROP_EXPIRED,                    /* the keypair is too old, or the counter reached the limit */
    WG_DROP_REPLAY,                     /* counter seen before, or behind the window */
    WG_DROP_FORGED,                     /* authentication failed */
    /* the packet inside, after decryption (wg_peer) */
    WG_DROP_NOT_IP,                     /* neither IPv4 nor IPv6, or shorter than its header */
    WG_DROP_BAD_LENGTH,                 /* the IP header claims more than there is */
    WG_DROP_WRONG_SOURCE,               /* its source address does not route to the peer it came from */
    /* a packet to send (wg_device) */
    WG_DROP_DOWN,                       /* the device is down */
    WG_DROP_NO_ROUTE,                   /* no peer's AllowedIPs cover the destination */
    WG_DROP_NO_ENDPOINT,                /* the peer has no known address yet */
    WG_DROP_NO_ROOM                     /* no key yet, and the packet does not fit the waiting queue */
} wg_drop_reason;

/* Handshake initiation, 148 bytes. */
#define WG_INIT_OFF_TYPE        0
#define WG_INIT_OFF_SENDER      4
#define WG_INIT_OFF_EPHEMERAL   8
#define WG_INIT_OFF_STATIC      40      /* 32-byte key + 16-byte tag */
#define WG_INIT_OFF_TIMESTAMP   88      /* 12-byte TAI64N + 16-byte tag */
#define WG_INIT_OFF_MAC1        116
#define WG_INIT_OFF_MAC2        132
#define WG_INIT_LEN             148

/* Handshake response, 92 bytes. */
#define WG_RESP_OFF_TYPE        0
#define WG_RESP_OFF_SENDER      4
#define WG_RESP_OFF_RECEIVER    8
#define WG_RESP_OFF_EPHEMERAL   12
#define WG_RESP_OFF_EMPTY       44      /* an empty payload: the 16-byte tag alone */
#define WG_RESP_OFF_MAC1        60
#define WG_RESP_OFF_MAC2        76
#define WG_RESP_LEN             92

/* Cookie reply, 64 bytes. */
#define WG_COOKIE_OFF_TYPE      0
#define WG_COOKIE_OFF_RECEIVER  4
#define WG_COOKIE_OFF_NONCE     8
#define WG_COOKIE_OFF_COOKIE    32      /* 16-byte cookie + 16-byte tag */
#define WG_COOKIE_MSG_LEN       64

/* Transport data: a 16-byte header, then the encrypted packet and its tag. */
#define WG_DATA_OFF_TYPE        0
#define WG_DATA_OFF_RECEIVER    4
#define WG_DATA_OFF_COUNTER     8
#define WG_DATA_OFF_PAYLOAD     16
#define WG_DATA_HEADER_LEN      16

static inline uint32_t wg_load32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void wg_store32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline uint64_t wg_load64(const uint8_t* p)
{
    return (uint64_t)wg_load32(p) | ((uint64_t)wg_load32(p + 4) << 32);
}

static inline void wg_store64(uint8_t* p, uint64_t v)
{
    wg_store32(p, (uint32_t)v);
    wg_store32(p + 4, (uint32_t)(v >> 32));
}

#endif /* WG_MSG_H */
