/*
 * bt_ts_control - the connection to Tailscale's control server (docs/TAILSCALE.md, section 5): the
 * transport and HTTP/2 under the node's requests; what they say is bt_tailscale's.
 *
 *   resolve      the server's name, through the resolvers the phone uses now (an address: none)
 *   /key         GET /key over HTTPS (HTTP on the stand), once - then the key is known
 *   ts2021       POST /ts2021 with the Noise initiation, 101, the handshake (ts_noise)
 *   HTTP/2       inside the Noise records (ts_h2), after EarlyNoise if the server sends it
 *   requests     POST /machine/register and /machine/map, as many at once as HTTP/2 allows: a
 *                whole body back, a stream of map messages (a little-endian 32-bit length, then
 *                the JSON), or nothing kept
 *
 * Lost - any failure, the server closing, two minutes with nothing on a map stream (Go's watchdog)
 * - it reconnects by itself after a delay that grows to a minute, sooner when asked
 * (bt_tsc_connect). A handshake refused with a key from the cache throws the key away: /key again.
 */

#ifndef BT_TS_CONTROL_H
#define BT_TS_CONTROL_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include "bt_resolve.h"
#include "ts_profile.h"
#include "wg_crypto.h"

typedef struct bt_tsc bt_tsc;

typedef enum {
    BT_TSC_BODY = 0,                    /* the response's body, whole, up to a limit */
    BT_TSC_STREAM,                      /* map messages one by one, as they complete */
    BT_TSC_DISCARD                      /* the status only */
} bt_tsc_mode;

typedef struct {
    void* ctx;

    /* The HTTP/2 session is there: requests may go. */
    void (*open)(void* ctx);

    /* The connection went (`why` for the log and the screens); it comes back by itself. Requests
     * in flight are gone with it. */
    void (*lost)(void* ctx, const char* why);

    /* The answer to request `req`: the HTTP status, the body (BODY: whole; STREAM: what came
     * before an error status; DISCARD: nothing), and Retry-After in seconds when the server gave
     * one (0 = none). For a STREAM request this comes only when it ends - with an error status or
     * when the server closes the stream. */
    void (*response)(void* ctx, int req, int status, const uint8_t* body, size_t len,
                     uint64_t retry_after);

    /* One message of map stream `req`, whole. `json` may be changed in place (it is the caller's
     * to parse) and lives until the upcall returns. */
    void (*message)(void* ctx, int req, char* json, size_t len);

    /* The server's Noise key, fetched from /key: for the profile's cache. */
    void (*server_key)(void* ctx, const wg_key* key);

    /* Where the server's name led: for the profile's cache. */
    void (*address)(void* ctx, const bt_addr* a);

    /* The resolvers to ask for the server's name. */
    size_t (*resolvers)(void* ctx, bt_addr* out, size_t cap);
} bt_tsc_calls;

/*
 * A control connection to `url` with our machine key, not started yet. `server_key` and `addr`
 * come from the profile's cache (NULL: none). NULL when out of memory.
 */
bt_tsc* bt_tsc_new(const ts_url* url, const wg_key* machine_priv, const wg_key* server_key,
                   const bt_addr* addr, uint16_t capver, const char* tag, const bt_tsc_calls* io);
void    bt_tsc_free(bt_tsc* c);

/* Connect now, without waiting out a delay (the start, a network change). */
void bt_tsc_connect(bt_tsc* c, uint64_t now_ns);

/* Drop the connection; again after `delay_ns` (0: the growing delay). */
void bt_tsc_drop(bt_tsc* c, const char* why, uint64_t delay_ns, uint64_t now_ns);

/* 1 while the HTTP/2 session is up. */
int bt_tsc_is_open(const bt_tsc* c);

/* The last reason it was lost, "" when there is none; for the screens. */
const char* bt_tsc_error(const bt_tsc* c);

/*
 * POST `path` with a JSON body; `lb_key` (NULL: none) goes in the Ts-Lb header that routes a node's
 * requests to its server, as tailscaled sends it. The request's number (> 0), or 0 when it cannot
 * go now (not open, too many in flight).
 */
int bt_tsc_post(bt_tsc* c, const char* path, const char* json, size_t len, const char* lb_key,
                bt_tsc_mode mode, uint64_t now_ns);

int      bt_tsc_pollfds(bt_tsc* c, struct pollfd* out, int cap);
int      bt_tsc_owns(const bt_tsc* c, int fd);
void     bt_tsc_io(bt_tsc* c, const struct pollfd* pfd, uint64_t now_ns);
uint64_t bt_tsc_tick(bt_tsc* c, uint64_t now_ns);

#endif /* BT_TS_CONTROL_H */
