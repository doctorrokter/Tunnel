/*
 * wg_codec - how WireGuard messages look on the wire.
 *
 * The rest of the engine speaks canonical WireGuard: a 4-byte type field (1..4) at the start of
 * every message, fixed lengths, nothing around it. A codec is the one place allowed to change that
 * - AmneziaWG puts other values in the type field, random bytes in front of messages, extra
 * datagrams ahead of a handshake, and its later versions more. The device calls it at fixed points:
 *
 *   outgoing   stamp              the type field, BEFORE the macs, so mac1 covers what goes out
 *              wrap               around the finished message: bytes in front, bytes behind
 *              before_initiation  datagrams to send ahead of every initiation (junk, signatures)
 *              padding            the zero padding inside a data message (AmneziaWG 3.x adds some)
 *   incoming   classify           which message a datagram carries and where it starts; the bytes
 *                                 stay as they came, because the macs were computed over them
 *              authentic          a message classify found proved genuine (a codec that sizes its
 *                                 output by what the path carries learns from it, never from
 *                                 datagrams anyone could forge)
 *
 * Classification never goes by the first byte alone: a codec may check lengths, offsets and any
 * header value it likes. A datagram it does not recognise (junk, probes) is dropped in silence.
 *
 * wg_codec_wireguard is plain WireGuard, wg_codec_awg (wg_awg.h) AmneziaWG. Every op except
 * classify may be NULL.
 */

#ifndef WG_CODEC_H
#define WG_CODEC_H

#include <stddef.h>
#include <stdint.h>

typedef void (*wg_emit_fn)(void* ctx, const uint8_t* dgram, size_t len);

typedef struct {
    const char* name;

    /* Writes the type field of an outgoing canonical message of `type` (1..4). NULL: canonical. */
    void (*stamp)(void* st, uint32_t type, uint8_t* msg, size_t len);

    /* Builds the datagram around a finished message into `out` (`cap` bytes); returns its length,
     * 0 to drop it. NULL: the message goes out as it is. */
    size_t (*wrap)(void* st, uint32_t type, const uint8_t* msg, size_t len, uint8_t* out, size_t cap);

    /* Emits the datagrams that go ahead of each initiation, built in `buf` (`cap` bytes). */
    void (*before_initiation)(void* st, uint8_t* buf, size_t cap, wg_emit_fn emit, void* ctx);

    /* Finds the canonical message in a datagram: its type (1..4), its offset and length. 0: not a
     * message of this codec. May rewrite the datagram in place (a codec that encrypted a header
     * restores it), but must leave the message exactly as its sender's macs saw it. */
    int (*classify)(void* st, uint8_t* dgram, size_t len, uint32_t* type, size_t* offset,
                    size_t* msg_len);

    /* Zero bytes to pad a data packet of `len` with. NULL: WireGuard's (wg_data_padding). The
     * device caps the answer at what its buffers hold. */
    size_t (*padding)(void* st, size_t len, size_t mtu);

    /* A message of `type` (`len` bytes, as classify delimited it) came from a peer and was
     * authentic; `moved`: from another address than the peer's last. */
    void (*authentic)(void* st, uint32_t type, size_t len, int moved);
} wg_codec_ops;

typedef struct {
    const wg_codec_ops* ops;
    void*               st;             /* the codec's own state */
} wg_codec;

/* Plain WireGuard. */
extern const wg_codec_ops wg_codec_wireguard;

/* 1 when `len` is right for a canonical message of `type`: 148, 92, 64 bytes for the handshake
 * messages, at least 32 for data. For codecs that keep WireGuard's messages inside. */
int wg_codec_length_ok(uint32_t type, size_t len);

/* The most any codec may add around one message (wrap) - the device's wire buffer has this room. */
#define WG_CODEC_MAX_OVERHEAD 2048

#endif /* WG_CODEC_H */
