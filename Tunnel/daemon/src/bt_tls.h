/*
 * bt_tls - a TLS client over TCP for the daemon's poll loop: the connections to Tailscale's control
 * server and to the DERP relays (docs/TAILSCALE.md, sections 4 and 6).
 *
 * Nothing blocks. A connection is a state machine the loop moves along:
 *
 *   bt_tls_connect   a TCP connect to the caller's address (IPv4 or IPv6), then the handshake
 *   bt_tls_fd        the socket to poll (-1: none) ...
 *   bt_tls_events    ... for what OpenSSL waits for now: POLLIN and/or POLLOUT
 *   bt_tls_step      the fd's revents: moves the connect, the handshake, the queue of bytes not yet
 *                    sent and the close along
 *   bt_tls_read      after every step, until it returns 0: what arrived
 *   bt_tls_write     any amount up to the queue's limit, at any time from bt_tls_connect on; what the
 *                    socket does not take at once goes out on POLLOUT
 *   bt_tls_tick      the deadline of the connect + handshake, or of a close
 *   bt_tls_close     graceful: the queue, then close_notify; bt_tls_free: at once
 *
 *   idle -> connecting -> handshake -> open -> closing -> closed
 *                  \____________\__________\________\___> failed         (`error` says why)
 *
 * The server's certificate is always verified (microlink's DERP client does not - we must):
 *   - Without a pin: the chain up to a trusted root - the built-in Let's Encrypt roots (bt_roots.h,
 *     the ones tailscaled bakes in) and those of a CA file the daemon adds (bt_tls_add_ca_file) - and
 *     the name: `host` against the certificate's DNS names (no fallback to the CN, a wildcard only as
 *     a whole left-most label: as Go), an IP literal against its IP addresses. BB10's own store is
 *     never used: it is years out of date.
 *   - With a pin - a DERP map's CertName "sha256-raw:<hex>", for a DERP server of the test stand with a
 *     self-signed certificate - exactly as Tailscale's tlsdial.SetConfigExpectedCertHash
 *     (net/tlsdial/tlsdial.go, v1.102.5): no chain and no roots at all. Of the certificates the server
 *     sends, those whose CN starts with "derpkey" (derper's meta certificate) are skipped; the rest
 *     must be exactly ONE, whose SHA-256 over its whole DER encoding is the pin (lowercase hex), which
 *     is within its validity dates, and which matches `host` - unless `host` is an IP literal: Go
 *     checks the name it sent as SNI, and it sends none for an IP.
 *
 * TLS 1.3 with TLS_CHACHA20_POLY1305_SHA256 first (Krait has no AES instructions; a Go server takes
 * ChaCha20 when the client lists it first), TLS 1.2 at the least and only forward-secret AEAD suites
 * there. SNI is `host` unless it is an IP literal (RFC 6066). No ALPN: control and DERP are HTTP/1.1
 * Upgrade over TLS. No renegotiation, no session resumption, no TCP keepalives (the protocols have
 * their own, and the radio should sleep).
 *
 * Plain TCP (`plain`): the same connection without TLS - open as soon as the TCP connect is, no
 * certificate, host and pin ignored, a close is the queue and then close(). For the test stand's
 * stage A only (TAILSCALE.md, section 13: Headscale and its DERP over http://), so that control and
 * DERP have one kind of connection either way. Never for a real server.
 *
 * Who opens the socket: the module, by default - it knows the family from the address and sets what
 * it needs (non-blocking, close-on-exec, TCP_NODELAY as Go does: DERP frames are small and late ones
 * hurt). A caller that has to place the socket first - bound to an interface, in another FIB, from a
 * source address, as bt_udp_open does for WireGuard's UDP - makes it itself and hands it over
 * unconnected; the module connects it and owns it from then on. (A "socket created" hook would do the
 * same with one more indirection; handing over the fd keeps such code in bt_plat, next to
 * bt_udp_open.) Tailscale's own transport follows the routes (TAILSCALE.md, section 9), so the daemon
 * passes -1 for now.
 *
 * `error` is text for the daemon's journal: what failed, the address or the certificate's name,
 * OpenSSL's reason. Nothing secret goes there - no key material ever passes through this module's
 * messages.
 *
 * Single-threaded. The process must ignore SIGPIPE (the daemon does): OpenSSL writes to the socket
 * with write(). A bt_tls must not move in memory while it holds a connection (OpenSSL points back at
 * it). A zeroed bt_tls is idle.
 */

#ifndef BT_TLS_H
#define BT_TLS_H

#include <stddef.h>
#include <stdint.h>

#include "bt_resolve.h"                 /* bt_addr, BT_NEVER */

#define BT_TLS_HOST_MAX         253
#define BT_TLS_ERROR_MAX        256
#define BT_TLS_TIMEOUT_MS       15000           /* connect + handshake, and a close, by default */
#define BT_TLS_OUT_MAX          (256 * 1024)    /* the queue of bytes not yet sent, by default */
#define BT_TLS_PIN_PREFIX       "sha256-raw:"

/* The module: one client context all connections share. */

/* The built-in roots (bt_roots.h). 1 on success; 0 with the reason in `err` - they did not parse (a
 * build that broke them) or OpenSSL is out of memory. Again after bt_tls_init: nothing happens. */
int  bt_tls_init(char* err, size_t errlen);

/* Also trust the certificates in the PEM file `path` (the daemon's cacert.pem): 1, with how many it
 * added in `added` (may be NULL; one trusted already does not count again); 0 with the reason - the
 * built-in roots stay either way. Connections made from now on see them. */
int  bt_tls_add_ca_file(const char* path, size_t* added, char* err, size_t errlen);

/* Forgets the roots; the connections still open keep what they have until freed. */
void bt_tls_fini(void);

/* A connection. */

typedef enum {
    BT_TLS_IDLE = 0,                    /* never connected, or freed */
    BT_TLS_CONNECTING,                  /* the TCP connect is on its way */
    BT_TLS_HANDSHAKE,
    BT_TLS_OPEN,                        /* read and write */
    BT_TLS_CLOSING,                     /* bt_tls_close: the queue goes out, then close_notify */
    BT_TLS_CLOSED,                      /* cleanly: by us, or by the server's close_notify */
    BT_TLS_FAILED                       /* see error */
} bt_tls_state;

typedef struct {
    bt_addr     addr;                   /* where: family 4 or 6 */
    uint16_t    port;
    const char* host;                   /* the server's name: SNI and what its certificate must match;
                                           an IP literal ("192.0.2.1", "2001:db8::1", "[2001:db8::1]")
                                           sends no SNI; trailing dots are dropped, as Go does */
    const char* pin;                    /* NULL, or "sha256-raw:<64 lowercase hex>" (see above); a
                                           CertName in any other form is refused, not guessed at */
    int         plain;                  /* 1: plain TCP, no TLS - the test stand only (see above) */
    uint32_t    timeout_ms;             /* connect + handshake, and a close; 0: BT_TLS_TIMEOUT_MS */
    size_t      out_max;                /* the most bytes queued at once; 0: BT_TLS_OUT_MAX */
} bt_tls_params;

typedef struct {
    bt_tls_state   state;
    char           error[BT_TLS_ERROR_MAX];     /* why it is closed or failed; "" before that */
    char           peer[64];                    /* "192.0.2.1:443", "[2001:db8::1]:443" */
    char           host[BT_TLS_HOST_MAX + 1];   /* as used: no brackets, no trailing dot */

    /* The module's. */
    int            fd;                          /* valid from connecting to closing only */
    struct ssl_st* ssl;                         /* NULL when plain */
    int            plain;
    int            host_ip;                     /* host is an IP literal */
    int            pinned;
    char           pin[65];                     /* the pin's hex */
    char           verify_error[160];           /* the certificate check's own words */
    uint8_t*       out;                         /* the queue: out[out_off .. out_off + out_len) */
    size_t         out_off, out_len, out_cap, out_max;
    uint64_t       timeout_ns;
    uint64_t       deadline;
    short          hs_wait;                     /* what the handshake or close_notify waits for */
    short          flush_wait;                  /* what the queue waits for (an SSL_write's WANT_*) */
    short          read_wait;                   /* POLLOUT when SSL_read had to write first */
    int            said_bye;                    /* closing: close_notify and our FIN are out */
} bt_tls;

/*
 * Starts connecting `c` (a zeroed or used bt_tls: what it held is released first). `fd` -1: the module
 * opens the socket; else the caller's unconnected TCP socket of the address's family, which the
 * module owns from here on - also when this call fails. Returns 1 when on its way (or already open);
 * 0 when it failed at once - bad parameters, no socket, a connect refused on the spot - with state
 * FAILED and the reason in `error`. `now_ns` starts the timeout.
 */
int bt_tls_connect(bt_tls* c, const bt_tls_params* p, int fd, uint64_t now_ns);

int      bt_tls_fd(const bt_tls* c);                    /* -1 when it holds no socket */
short    bt_tls_events(const bt_tls* c);                /* for poll; 0 with no socket */
void     bt_tls_step(bt_tls* c, short revents);
uint64_t bt_tls_tick(bt_tls* c, uint64_t now_ns);      /* fails a late connect/handshake/close; the
                                                           next deadline, BT_NEVER for none */

/*
 * Up to `cap` bytes that arrived: how many; 0 when nothing is there now, or the connection is not
 * open (see state: the server's close_notify makes it CLOSED, a reset or a close without
 * close_notify FAILED; plain: the server's close is CLOSED, a reset FAILED). Read until 0 after every
 * bt_tls_step: OpenSSL keeps what it decrypted, and poll cannot see that. A caller that stops early
 * (its own buffer is full) comes back without waiting for poll while bt_tls_pending says so.
 */
size_t bt_tls_read(bt_tls* c, uint8_t* out, size_t cap);
int    bt_tls_pending(const bt_tls* c);

/*
 * Queues `len` bytes, all or nothing - a frame never goes half: 1 when queued (connecting, handshake
 * or open; they go out once open); 0 when not - the queue would pass out_max (wait for bt_tls_queued
 * to fall), or the connection cannot send (see state). What the socket takes goes out at once, the
 * rest on POLLOUT.
 */
int    bt_tls_write(bt_tls* c, const uint8_t* data, size_t len);
size_t bt_tls_queued(const bt_tls* c);                  /* bytes not yet taken by TLS */

/*
 * Graceful: the queue goes out, then close_notify and our FIN, and the socket closes once the server
 * has closed its side too (or the timeout says enough): CLOSED. FAILED when the queue cannot go out
 * (the timeout, a reset, the server gone first). What arrives meanwhile is read and thrown away - left
 * unread, it would make the kernel answer the close with a reset, and a reset can destroy what the
 * server has not read of ours yet. Before the handshake finished: CLOSED at once, the queue dropped.
 */
void bt_tls_close(bt_tls* c, uint64_t now_ns);

/* At once, without close_notify; the struct is idle again. */
void bt_tls_free(bt_tls* c);

const char* bt_tls_state_name(bt_tls_state s);
/* While open or closing: "TLSv1.3", "TLS_CHACHA20_POLY1305_SHA256"; "" otherwise, and when plain. */
const char* bt_tls_version(const bt_tls* c);
const char* bt_tls_cipher(const bt_tls* c);

#endif /* BT_TLS_H */
