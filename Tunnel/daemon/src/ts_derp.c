/*
 * ts_derp - see ts_derp.h.
 */

#include "ts_derp.h"
#include "wg_salsa.h"

#include <string.h>

/* "DERP" and the key emoji, U+1F511 in UTF-8. */
static const uint8_t magic[8] = { 0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91 };

/*
 * What Go's client sends (ClientInfo in derp_client.go): the version, and that we answer pings -
 * magicsock does, and so do we. meshKey, IsProber and AppName are omitted when empty there, so
 * they are simply absent here.
 */
const char ts_derp_client_info[] = "{\"version\":2,\"CanAckPings\":true}";

#define NONCE_LEN       24
#define BOX_TAG_LEN     16
#define KEY_FRAME_MIN   (sizeof(magic) + TS_DERP_KEY_LEN)
#define KEY_FRAME_MAX   1024                /* the reference reads the greeting with this limit */
#define INFO_TEXT_MAX   4096                /* ServerInfo JSON: tens of bytes in practice */

static uint32_t get_be32(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void put_header(uint8_t* h, uint8_t type, uint32_t len)
{
    h[0] = type;
    h[1] = (uint8_t)(len >> 24);
    h[2] = (uint8_t)(len >> 16);
    h[3] = (uint8_t)(len >> 8);
    h[4] = (uint8_t)len;
}

static int broken(ts_derp* c, const char* why)
{
    if (c->state != TS_DERP_BROKEN) c->error = why;
    c->state = TS_DERP_BROKEN;
    return 0;
}

static int emit(ts_derp* c, const uint8_t* a, size_t alen, const uint8_t* b, size_t blen)
{
    if (c->state == TS_DERP_BROKEN) return 0;
    if (!c->io.write || !c->io.write(c->io.ctx, a, alen, b, blen)) return broken(c, "cannot queue a frame");
    return 1;
}

void ts_derp_init(ts_derp* c, const wg_key* priv, const wg_key* pub, int preferred,
                  const wg_rng* rng, const ts_derp_io* io)
{
    memset(c, 0, offsetof(ts_derp, buf));
    c->state = TS_DERP_WAIT_KEY;
    c->priv = *priv;
    c->pub = *pub;
    c->preferred = preferred ? 1 : 0;
    c->rng = rng;
    if (io) c->io = *io;
}

void ts_derp_clear(ts_derp* c)
{
    wg_wipe(&c->priv, sizeof(c->priv));
    wg_wipe(c->shared, sizeof(c->shared));
    wg_wipe(c->buf, sizeof(c->buf));
}

/* --------------------------------------------------------------------- the login */

static int send_preferred(ts_derp* c)
{
    uint8_t f[TS_DERP_HDR_LEN + 1];
    put_header(f, TS_DERP_NOTE_PREFERRED, 1);
    f[TS_DERP_HDR_LEN] = (uint8_t)c->preferred;
    return emit(c, f, sizeof(f), NULL, 0);
}

/* ServerKey came: our ClientInfo, sealed to the key it carries. */
static int login(ts_derp* c)
{
    size_t jlen = sizeof(ts_derp_client_info) - 1;
    uint8_t f[TS_DERP_HDR_LEN + TS_DERP_KEY_LEN + NONCE_LEN + BOX_TAG_LEN + sizeof(ts_derp_client_info)];
    uint8_t* nonce = f + TS_DERP_HDR_LEN + TS_DERP_KEY_LEN;
    wg_key server;
    int ok;

    if (memcmp(c->buf, magic, sizeof(magic)) != 0) return broken(c, "not a DERP server: no magic in its greeting");
    memcpy(c->server, c->buf + sizeof(magic), TS_DERP_KEY_LEN);
    memcpy(server.b, c->server, TS_DERP_KEY_LEN);
    /* A key whose shared secret is zero (a low-order point) is no server's: Go's client would go
     * on regardless, but nothing it says could be trusted. */
    if (!wg_box_beforenm(c->shared, &server, &c->priv)) return broken(c, "the server's key is unusable");

    put_header(f, TS_DERP_CLIENT_INFO, (uint32_t)(TS_DERP_KEY_LEN + NONCE_LEN + BOX_TAG_LEN + jlen));
    memcpy(f + TS_DERP_HDR_LEN, c->pub.b, TS_DERP_KEY_LEN);
    if (!wg_rng_bytes(c->rng, nonce, NONCE_LEN)) return broken(c, "no random bytes for the login");
    ok = wg_secretbox_seal(nonce + NONCE_LEN, (const uint8_t*)ts_derp_client_info, jlen, nonce, c->shared);
    if (!ok) return broken(c, "cannot seal the login");
    c->state = TS_DERP_WAIT_INFO;
    if (!emit(c, f, TS_DERP_HDR_LEN + TS_DERP_KEY_LEN + NONCE_LEN + BOX_TAG_LEN + jlen, NULL, 0)) return 0;
    /* derphttp sends it right after the login, and only when true. */
    if (c->preferred && !send_preferred(c)) return 0;
    return 1;
}

/* ServerInfo: a box from the server's key. One that does not open means someone else speaks for
 * the server - the reference drops the connection, and so do we. */
static int server_info(ts_derp* c)
{
    uint8_t text[INFO_TEXT_MAX];
    size_t n;

    if (c->len < NONCE_LEN + BOX_TAG_LEN) return broken(c, "a short ServerInfo");
    n = c->len - NONCE_LEN - BOX_TAG_LEN;
    if (n > sizeof(text)) return broken(c, "a ServerInfo too large");
    if (!wg_secretbox_open(text, c->buf + NONCE_LEN, c->len - NONCE_LEN, c->buf, c->shared))
        return broken(c, "a ServerInfo not from the server's key");
    if (c->state == TS_DERP_WAIT_INFO) c->state = TS_DERP_READY;
    if (c->io.ready) c->io.ready(c->io.ctx, (const char*)text, n);
    wg_wipe(text, n);
    return c->state != TS_DERP_BROKEN;
}

/* --------------------------------------------------------------------- frames in */

/* The header is in: checks it and decides how much of the payload to keep. */
static int frame_start(ts_derp* c)
{
    c->type = c->hdr[0];
    c->len = get_be32(c->hdr + 1);
    c->have = 0;
    if (c->len > TS_DERP_FRAME_MAX) return broken(c, "a frame over 1 MiB");
    if (c->state == TS_DERP_WAIT_KEY) {
        if (c->type != TS_DERP_SERVER_KEY) return broken(c, "not a DERP server: the first frame is not its key");
        if (c->len < KEY_FRAME_MIN || c->len > KEY_FRAME_MAX) return broken(c, "not a DERP server: a bad greeting");
        c->keep = KEY_FRAME_MIN;            /* anything after the key is for future use */
        return 1;
    }
    if (c->type == TS_DERP_SERVER_INFO && c->len > sizeof(c->buf)) return broken(c, "a ServerInfo too large");
    c->keep = c->len <= sizeof(c->buf) ? c->len : 0;
    return 1;
}

/* A whole frame is in (what fits of it in buf). */
static int frame_done(ts_derp* c)
{
    int whole = c->keep == c->len;

    c->frames_in++;
    if (c->state == TS_DERP_WAIT_KEY) return login(c);

    switch (c->type) {
    case TS_DERP_SERVER_INFO:
        return server_info(c);

    case TS_DERP_RECV_PACKET:
        /* Protocol 2: the source key first. Short ones the reference drops and goes on; ones too
         * large to be a packet we drop the same way - no WireGuard message is near 64 KiB. */
        if (c->len < TS_DERP_KEY_LEN || !whole) {
            c->dropped_in++;
            return 1;
        }
        c->packets_in++;
        if (c->io.packet) c->io.packet(c->io.ctx, c->buf, c->buf + TS_DERP_KEY_LEN, c->len - TS_DERP_KEY_LEN);
        return c->state != TS_DERP_BROKEN;

    case TS_DERP_PING:
        /* The first 8 bytes back, as magicsock does; a short ping is dropped. */
        if (c->len < 8 || !whole) {
            c->dropped_in++;
            return 1;
        }
        {
            uint8_t f[TS_DERP_HDR_LEN + 8];
            put_header(f, TS_DERP_PONG, 8);
            memcpy(f + TS_DERP_HDR_LEN, c->buf, 8);
            return emit(c, f, sizeof(f), NULL, 0);
        }

    case TS_DERP_PEER_GONE:
        if (c->len < TS_DERP_KEY_LEN || !whole) {
            c->dropped_in++;
            return 1;
        }
        /* Old servers send no reason byte: that meant "disconnected". */
        if (c->io.peer_gone)
            c->io.peer_gone(c->io.ctx, c->buf, c->len > TS_DERP_KEY_LEN ? c->buf[TS_DERP_KEY_LEN] : TS_DERP_GONE_DISCONNECTED);
        return c->state != TS_DERP_BROKEN;

    case TS_DERP_HEALTH:
        if (!whole) {
            c->dropped_in++;
            return 1;
        }
        if (c->io.health) c->io.health(c->io.ctx, (const char*)c->buf, c->len);
        return c->state != TS_DERP_BROKEN;

    case TS_DERP_RESTARTING:
        if (c->len < 8 || !whole) {
            c->dropped_in++;
            return 1;
        }
        if (c->io.restarting) c->io.restarting(c->io.ctx, get_be32(c->buf), get_be32(c->buf + 4));
        return c->state != TS_DERP_BROKEN;

    default:
        /* KeepAlive, Pong (we send no pings), PeerPresent (mesh watchers only), a second
         * ServerKey and types yet to come: skipped, as the reference skips them. */
        return 1;
    }
}

int ts_derp_input(ts_derp* c, const uint8_t* data, size_t len)
{
    size_t off = 0;

    if (c->state == TS_DERP_BROKEN) return 0;
    while (off < len) {
        if (c->hdr_have < TS_DERP_HDR_LEN) {
            size_t n = TS_DERP_HDR_LEN - c->hdr_have;
            if (n > len - off) n = len - off;
            memcpy(c->hdr + c->hdr_have, data + off, n);
            c->hdr_have += n;
            off += n;
            if (c->hdr_have < TS_DERP_HDR_LEN) break;
            if (!frame_start(c)) return 0;
        } else {
            size_t n = c->len - c->have;
            if (n > len - off) n = len - off;
            if (c->have < c->keep) {
                size_t k = c->keep - c->have;
                if (k > n) k = n;
                memcpy(c->buf + c->have, data + off, k);
            }
            c->have += (uint32_t)n;
            off += n;
        }
        if (c->hdr_have == TS_DERP_HDR_LEN && c->have == c->len) {
            c->hdr_have = 0;
            if (!frame_done(c)) return 0;
        }
    }
    return c->state != TS_DERP_BROKEN;
}

/* --------------------------------------------------------------------- frames out */

int ts_derp_send(ts_derp* c, const uint8_t dst[TS_DERP_KEY_LEN], const uint8_t* pkt, size_t len)
{
    uint8_t h[TS_DERP_HDR_LEN + TS_DERP_KEY_LEN];

    if (c->state != TS_DERP_WAIT_INFO && c->state != TS_DERP_READY) return 0;
    if (len > TS_DERP_MAX_PACKET) return 0;
    put_header(h, TS_DERP_SEND_PACKET, (uint32_t)(TS_DERP_KEY_LEN + len));
    memcpy(h + TS_DERP_HDR_LEN, dst, TS_DERP_KEY_LEN);
    if (!emit(c, h, sizeof(h), pkt, len)) return 0;
    c->packets_out++;
    return 1;
}

int ts_derp_note_preferred(ts_derp* c, int preferred)
{
    c->preferred = preferred ? 1 : 0;
    if (c->state == TS_DERP_WAIT_KEY) return 1;         /* goes with the login */
    if (c->state == TS_DERP_BROKEN) return 0;
    return send_preferred(c);
}
