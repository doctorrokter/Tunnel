/*
 * wg_awg - AmneziaWG: WireGuard's protocol in a disguise, byte for byte as amneziawg-go puts it on
 * the wire (v3.1.20260828, commit b5928ef, the reference in ../../refs/amneziawg-go). The crypto is
 * WireGuard's; everything that differs is what the wire sees, and all of it lives here, in the
 * wg_codec hooks:
 *
 *   handshake / cookie   [S1..S3 random][message, type = random from H1..H3][random trailer*]
 *   transport            [S4 random][header, type = random from H4][sealed packet + padding]
 *   header protection    with a key: ChaCha20 (nonce = the datagram's first 12 bytes, counter 0)
 *                        over the whole message, or a transport message's 16-byte header - which
 *                        is why every S must then be at least 12
 *   before an initiation I1..I5 (built from a small tag language), then Jc junk datagrams of
 *                        Jmin..Jmax-1 random bytes - before every initiation, retries included
 *   padding              zeroes inside the sealed packet: ContentPaddingAddition, or random ones
 *                        with RandomTrailers, else WireGuard's multiple of 16
 *   (*) trailers only with RandomTrailers, which the RECEIVER must allow too
 *
 * The macs cover the message with its H value in the type field, before header protection, and
 * are checked over the same bytes on arrival. Nothing is negotiated: both ends need the same
 * S1-S4, H1-H4 and header protection key. Jc/Jmin/Jmax, I1-I5, padding and timings are each side's
 * own. The reference has no protocol versions - one algorithm, every feature switched on by its own
 * parameter; with all of them at their defaults the wire is plain WireGuard.
 *
 * Trailers and random padding are bounded by a UDP window: 500 bytes, grown to the largest datagram
 * known to pass (each data packet we send, each authentic one we receive), back to 500 when the
 * peer moves (see awg_authentic for where this reads the reference's intent over its letter).
 *
 * Timings (ranges) and DisableCookies are the device's, not the codec's: wg_timing
 * (wg_device_set_timing) and disable_cookies. So is the keepalive rule: a decrypted packet that is
 * empty or starts with a zero byte (padding) is a keepalive.
 */

#ifndef WG_AWG_H
#define WG_AWG_H

#include <stddef.h>
#include <stdint.h>

#include "wg_codec.h"
#include "wg_crypto.h"
#include "wg_msg.h"

#define WG_AWG_CHAIN_OPS    32          /* tags in one I-packet */
#define WG_AWG_CHAIN_BYTES  1536        /* <b> bytes in one I-packet */
#define WG_AWG_MAX_PREFIX   1024        /* S1-S4: far above any real profile, within the wire buffer */
#define WG_AWG_UDP_WINDOW   500         /* the reference's DefaultUdpWindow */
#define WG_AWG_REKEY_BLOCKS 16384       /* wire randomness: a new ChaCha20 key every 1 MiB */

/* One I-packet: what its tags produce, in order. */
typedef struct {
    struct {
        uint8_t  kind;                  /* see wg_awg.c */
        uint16_t len;                   /* bytes it produces */
        uint16_t off;                   /* <b>: where its bytes are in data[] */
    } ops[WG_AWG_CHAIN_OPS];
    int      nops;                      /* 0: this I-packet is not sent */
    uint8_t  data[WG_AWG_CHAIN_BYTES];
    size_t   ndata;
    size_t   len;                       /* the packet's length */
} wg_awg_chain;

typedef struct {
    uint32_t     jc, jmin, jmax;
    uint32_t     s[5];                  /* S1..S4 in s[1..4] */
    wg_range     h[5];                  /* H1..H4 in h[1..4]; 1..4 by default */
    wg_awg_chain i[6];                  /* I1..I5 in i[1..5] */
    uint8_t      hp_key[WG_KEY_LEN];    /* zeroes: no header protection */
    wg_range     content_padding;       /* 0..0: off */
    int          random_trailers;
} wg_awg_params;

struct wg_device;

typedef struct {
    wg_awg_params     p;
    int               hp;               /* header protection on */
    uint32_t          udp_window;       /* bounds trailers and random padding (see above) */
    struct wg_device* dev;              /* its rng and wall clock (for <t>) */

    /* Wire randomness (prefixes, trailers, junk, I-packet bytes, picks): public once sent, it only
     * has to look random. OpenSSL's generator costs a DRBG step per call - three calls a packet,
     * most of the codec's time - so it only draws keys, and a ChaCha20 keystream under them serves
     * the bytes (arc4random's construction). A source plugged into the device's rng (tests) is used
     * as it is instead. */
    uint8_t           rkey[WG_KEY_LEN];
    uint8_t           rbuf[64];
    uint32_t          rleft;            /* unserved bytes at the end of rbuf */
    uint32_t          rblocks;          /* blocks under rkey; 0: draw a key first */
} wg_awg;

extern const wg_codec_ops wg_codec_awg;

/* Everything off: plain WireGuard (H1..H4 = 1..4). */
void wg_awg_params_default(wg_awg_params* p);

/*
 * Parses an I-packet spec: <b 0xHEX> bytes, <t> the time (4 bytes big-endian), <r N> random bytes,
 * <rc N> random letters, <rd N> random digits, <dz N> N zero bytes, <d> and <ds> nothing; text
 * outside tags is ignored. A spec without tags leaves the packet off. 0 with `*why` on an error -
 * including a negative N, which the reference accepts and then crashes on.
 */
int wg_awg_parse_chain(wg_awg_chain* c, const char* spec, size_t len, const char** why);

/* The reference's rules for a parameter set: H1-H4 must not overlap (their defaults included),
 * every S must be at least 12 with a header protection key; plus Jmin <= Jmax, which the
 * reference forgets (and overflows on). */
int wg_awg_check(const wg_awg_params* p, const char** why);

/* 1 when every parameter is at the value plain WireGuard has anyway. */
int wg_awg_is_plain(const wg_awg_params* p);

/* Makes `a` the device's codec with parameters `p` (copied). The device's rng and wall clock are
 * used from then on. */
void wg_awg_attach(wg_awg* a, const wg_awg_params* p, struct wg_device* d);

/* Builds one I-packet into `out` (c->len bytes); for the codec and the tests. */
size_t wg_awg_chain_build(wg_awg* a, const wg_awg_chain* c, uint8_t* out);

#endif /* WG_AWG_H */
