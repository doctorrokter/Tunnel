/*
 * ts_derp - a client of Tailscale's DERP relay (docs/TAILSCALE.md, section 6), sans-IO: the byte
 * stream that follows the HTTP upgrade goes in, the frames for the server come out through an
 * upcall. The connection, TLS and the upgrade itself are the caller's.
 *
 * Every frame is a type byte and a big-endian 32-bit length, then the payload:
 *
 *   server  ServerKey     "DERP🔑" (8 bytes) + the server's key; the first frame, always
 *   client  ClientInfo    our node key + a NaCl box to the server's key: nonce 24, tag 16, JSON
 *   server  ServerInfo    a NaCl box of its own JSON back - the login is done
 *   both    SendPacket (destination key + packet) / RecvPacket (source key + packet), KeepAlive,
 *           Ping/Pong, PeerGone, Health, Restarting; the rest is for meshed servers and skipped
 *
 * Packets are addressed by node key (the WireGuard public key of a node). The reference is
 * derp/derp.go and derp/derp_client.go of Tailscale v1.102.5; where this client differs, it says
 * so next to the code.
 */

#ifndef TS_DERP_H
#define TS_DERP_H

#include <stddef.h>
#include <stdint.h>

#include "wg_crypto.h"

#define TS_DERP_KEY_LEN         32
#define TS_DERP_HDR_LEN         5
#define TS_DERP_MAX_PACKET      (64 * 1024)         /* MaxPacketSize: the most one packet may be */
#define TS_DERP_FRAME_MAX       (1u << 20)          /* larger breaks the connection, as in Recv */
#define TS_DERP_PROTOCOL        2                   /* ProtocolVersion: RecvPacket carries its source */

/* Frame types (derp.go). */
#define TS_DERP_SERVER_KEY      0x01
#define TS_DERP_CLIENT_INFO     0x02
#define TS_DERP_SERVER_INFO     0x03
#define TS_DERP_SEND_PACKET     0x04
#define TS_DERP_RECV_PACKET     0x05
#define TS_DERP_KEEP_ALIVE      0x06
#define TS_DERP_NOTE_PREFERRED  0x07
#define TS_DERP_PEER_GONE       0x08
#define TS_DERP_PEER_PRESENT    0x09
#define TS_DERP_PING            0x12
#define TS_DERP_PONG            0x13
#define TS_DERP_HEALTH          0x14
#define TS_DERP_RESTARTING      0x15

/* PeerGone reasons. */
#define TS_DERP_GONE_DISCONNECTED   0x00        /* it left this server */
#define TS_DERP_GONE_NOT_HERE       0x01        /* the server never had it */

typedef enum {
    TS_DERP_WAIT_KEY = 0,       /* connected, the server's key has not come yet */
    TS_DERP_WAIT_INFO,          /* ClientInfo sent; packets may be sent already, as Go's client does */
    TS_DERP_READY,              /* ServerInfo opened */
    TS_DERP_BROKEN              /* not DERP, tampered with, or a write failed: close the connection */
} ts_derp_state;

typedef struct {
    void* ctx;

    /*
     * Bytes for the server: `a` then `b` (b may be NULL), queued whole or not at all - 1 when
     * queued. A frame is never split between two calls, so a refusal cannot leave half of one on
     * the wire; it breaks the client all the same (the caller closes and reconnects).
     */
    int  (*write)(void* ctx, const uint8_t* a, size_t alen, const uint8_t* b, size_t blen);

    /* A packet from the node with key `src`. `data` is valid until the upcall returns and may be
     * changed in place (the engine decrypts there); the upcall may send (ts_derp_send), on this
     * client or another. */
    void (*packet)(void* ctx, const uint8_t src[TS_DERP_KEY_LEN], uint8_t* data, size_t len);

    /* ServerInfo opened, its JSON as the server sent it (for the log and the rate limit): the
     * login is done. The server may send it again later; every time comes here. */
    void (*ready)(void* ctx, const char* json, size_t len);

    /* Optional, as the rest below: the node `key` is not reachable through this server. */
    void (*peer_gone)(void* ctx, const uint8_t key[TS_DERP_KEY_LEN], int reason);

    /* The server's word on this connection's health; empty text = healthy again. */
    void (*health)(void* ctx, const char* text, size_t len);

    /* The server is restarting: reconnect in about `reconnect_ms`, keep trying for `try_ms`. */
    void (*restarting)(void* ctx, uint32_t reconnect_ms, uint32_t try_ms);
} ts_derp_io;

typedef struct {
    ts_derp_state state;
    ts_derp_io    io;
    const char*   error;                        /* why BROKEN, a constant string for the log */

    wg_key        priv;                         /* our node key */
    wg_key        pub;
    uint8_t       server[TS_DERP_KEY_LEN];      /* its key, from ServerKey */
    uint8_t       shared[32];                   /* the box key for the two: kept for ServerInfo */
    const wg_rng* rng;                          /* the ClientInfo nonce; NULL = the CSPRNG */
    int           preferred;                    /* our home region: NotePreferred(true) at login */

    /* the frame coming in */
    uint8_t       hdr[TS_DERP_HDR_LEN];
    size_t        hdr_have;
    uint8_t       type;
    uint32_t      len;                          /* its payload length */
    uint32_t      have;                         /* of the payload, read so far */
    uint32_t      keep;                         /* how much of it goes into buf: the rest is skipped */

    uint64_t      frames_in;
    uint64_t      packets_in;
    uint64_t      packets_out;
    uint64_t      dropped_in;                   /* short or oversized frames skipped */

    uint8_t       buf[TS_DERP_KEY_LEN + TS_DERP_MAX_PACKET];
} ts_derp;

/*
 * A client for one connection, logging in with the node key pair `priv`/`pub`. `preferred` marks
 * the connection to our home region (the server counts it; nothing else changes). `rng` may be
 * NULL. The struct is large (the frame buffer): allocate it, do not put it on the stack.
 */
void ts_derp_init(ts_derp* c, const wg_key* priv, const wg_key* pub, int preferred,
                  const wg_rng* rng, const ts_derp_io* io);

/* Wipes the keys. */
void ts_derp_clear(ts_derp* c);

/*
 * Bytes from the server, in whatever pieces they arrived. Frames are handled as they complete,
 * the upcalls called from here. 0 when the client is (or just became) BROKEN - `error` says why;
 * everything after that is ignored.
 */
int ts_derp_input(ts_derp* c, const uint8_t* data, size_t len);

/*
 * A packet for the node `dst`. 1 when queued; 0 before the login is sent, for a packet over
 * TS_DERP_MAX_PACKET, or when the write fails (the client is BROKEN then).
 */
int ts_derp_send(ts_derp* c, const uint8_t dst[TS_DERP_KEY_LEN], const uint8_t* pkt, size_t len);

/* Tells the server whether this is our home region now; 1 when queued. */
int ts_derp_note_preferred(ts_derp* c, int preferred);

/* The ClientInfo JSON this client sends, for the tests and the log. */
extern const char ts_derp_client_info[];

#endif /* TS_DERP_H */
