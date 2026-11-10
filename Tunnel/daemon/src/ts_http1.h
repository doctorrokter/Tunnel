/*
 * ts_http1 - the HTTP/1.1 client side of Tailscale's transport (docs/TAILSCALE.md, sections 5 and
 * 6), sans-IO: requests are built into the caller's buffer, a response is parsed from bytes as they
 * arrive. The connection, TLS and the clock are the caller's.
 *
 * Three requests, byte for byte as tailscaled's Go writes them (net/http: the Host, Go's default
 * User-Agent, the fields sorted by name; test_ts_http1.c holds them against Go's own output):
 *
 *   GET /key?v=130     the control server's Noise key (control/controlclient/direct.go)
 *   POST /ts2021       Upgrade: tailscale-control-protocol with the Noise initiation in base64 in
 *                      X-Tailscale-Handshake (control/controlhttp/client.go)
 *   GET /derp          Upgrade: DERP (derp/derphttp/derphttp_client.go)
 *
 * The response parser takes the bytes in any pieces and stops exactly where the response ends:
 * after a 101 the rest belongs to the protocol switched to, and the caller learns where it starts.
 * Everything from the wire is hostile: the head is at most TS_HTTP1_HEAD_MAX bytes and
 * TS_HTTP1_MAX_FIELDS fields, the body goes into the caller's buffer and no further, nothing is
 * allocated. Where the parser is stricter than Go's client, it says so next to the code.
 */

#ifndef TS_HTTP1_H
#define TS_HTTP1_H

#include <stddef.h>
#include <stdint.h>

#define TS_HTTP1_USER_AGENT     "Go-http-client/1.1"    /* net/http's default: what tailscaled sends */
#define TS_HTTP1_HANDSHAKE_MAX  1024        /* the most initiation bytes put into a header (Noise: 101) */
#define TS_HTTP1_HEAD_MAX       8192        /* status line and fields, line ends included */
#define TS_HTTP1_MAX_FIELDS     64
#define TS_HTTP1_MAX_INTERIM    5           /* 1xx responses skipped before the real one, as Go's transport */
#define TS_HTTP1_CHUNK_LINE_MAX 4096        /* a chunk-size line with its extensions, as Go's maxLineLength */

/* --- requests ------------------------------------------------------------------------------- */

/*
 * Each builder writes the request head into `out` (a NUL after it, not counted) and returns its
 * length; 0 when `cap` is short or an argument is bad - a host must be a DNS name or an IPv4 / IPv6
 * literal (without brackets), so nothing from a DERP map can smuggle a line into the request.
 *
 * `tls` picks the default port the Host leaves out, as a URL without a port does: 443 with TLS, 80
 * without. Port 0 means that default (DERPPort 0 is 443).
 */

/* GET /key?v=<capver>: the control server's keys. Its Host is the server URL's. */
size_t ts_http1_key_request(char* out, size_t cap, const char* host, uint16_t port, int tls, unsigned capver);

/* POST /ts2021 with the Noise initiation `init` (1-TS_HTTP1_HANDSHAKE_MAX bytes). The Host always
 * carries the port, as tailscaled's dial URL is net.JoinHostPort(host, port); port 0 is refused. */
size_t ts_http1_ts2021_request(char* out, size_t cap, const char* host, uint16_t port,
                               const uint8_t* init, size_t init_len);

/* GET /derp. `ideal_node` - the region's first node's name when connected to another one, sent
 * as Ideal-Node like derphttp does (only for the server's statistics); NULL for none. */
size_t ts_http1_derp_request(char* out, size_t cap, const char* host, uint16_t port, int tls,
                             const char* ideal_node);

/* --- the response --------------------------------------------------------------------------- */

typedef enum {
    TS_HTTP1_MORE = 0,          /* feed more bytes */
    TS_HTTP1_DONE,              /* a whole response: status, fields, body */
    TS_HTTP1_UPGRADED,          /* a 101: the bytes after its head belong to the new protocol */
    TS_HTTP1_FAILED             /* see error; the connection is beyond repair */
} ts_http1_state;

typedef enum {
    TS_HTTP1_OK = 0,
    TS_HTTP1_ERR_SYNTAX,        /* not an HTTP/1.x response, or a malformed line */
    TS_HTTP1_ERR_TOO_BIG,       /* the head over TS_HTTP1_HEAD_MAX / TS_HTTP1_MAX_FIELDS, too many 1xx */
    TS_HTTP1_ERR_BODY_TOO_BIG,  /* the body over the caller's buffer */
    TS_HTTP1_ERR_FRAMING,       /* a bad or conflicting Content-Length / Transfer-Encoding, a bad chunk */
    TS_HTTP1_ERR_TRUNCATED      /* the connection closed before the response was whole */
} ts_http1_error;

/* A field as received: both strings point into the parser and are NUL-terminated; the value is
 * without the whitespace around it (an obsolete line folding becomes spaces, RFC 9112 5.2). */
typedef struct {
    const char* name;
    const char* value;
    size_t      value_len;
} ts_http1_field;

typedef struct {
    /* the result, valid from DONE / UPGRADED on */
    ts_http1_state state;
    ts_http1_error error;
    int            status;
    int            minor;           /* HTTP/1.0 or 1.1 (a later 1.x is taken as 1.1) */
    const char*    reason;
    ts_http1_field fields[TS_HTTP1_MAX_FIELDS];
    size_t         n_fields;
    uint8_t*       body;            /* the caller's buffer */
    size_t         body_cap;
    size_t         body_len;

    /* the parser's own */
    char           head[TS_HTTP1_HEAD_MAX + 1];
    size_t         head_len;
    size_t         line_start;      /* where the head's current line began */
    int            phase;
    uint64_t       left;            /* body bytes still to come: Content-Length, or of this chunk */
    unsigned       digits;          /* of the chunk size */
    size_t         line_len;        /* of the chunk-size or trailer line so far */
    int            saw_cr;          /* the trailer line's CR came: its LF must follow */
    size_t         trailer_bytes;
    unsigned       trailers;
    unsigned       interim;
} ts_http1_resp;

/* Starts a response. The body lands in body[0, body_cap), and one that does not fit fails it.
 * With body NULL the body is read and dropped (body_len stays 0): for an upgrade, where only the
 * status of a refusal matters - a 426 with a page still comes out DONE with its status. */
void ts_http1_resp_init(ts_http1_resp* r, uint8_t* body, size_t body_cap);

/*
 * Feeds `len` bytes; *used is how many were taken (all of them unless the response ended inside:
 * after DONE or UPGRADED, in[*used..len) is whatever came behind it - for a 101 the first bytes of
 * the new protocol). Returns the state; once it is not MORE, further bytes are not taken.
 */
ts_http1_state ts_http1_resp_feed(ts_http1_resp* r, const uint8_t* in, size_t len, size_t* used);

/* The connection closed: ends a body that runs to the close, and fails anything unfinished. */
ts_http1_state ts_http1_resp_eof(ts_http1_resp* r);

/* The value of the first field named `name` (any case), NULL when absent. */
const char* ts_http1_resp_field(const ts_http1_resp* r, const char* name, size_t* len);

/* 1 when the response is a 101 to `protocol`: Upgrade names exactly it (any case) and Connection
 * holds the token "upgrade" - what Go's transport needs to hand the connection over. */
int ts_http1_resp_upgraded(const ts_http1_resp* r, const char* protocol);

const char* ts_http1_error_text(ts_http1_error e);

/* --- HTTP semantics shared with HTTP/2 ------------------------------------------------------- */

/*
 * Retry-After (RFC 9110 10.2.3) as seconds from now: delta-seconds (anything above 2^31 counts as
 * 2^31, as the RFC says), or an IMF-fixdate against `now_unix`, a past date giving 0. 1 on success,
 * 0 for anything else - the obsolete date formats included; the caller then picks its own delay,
 * as tailscaled does (5-10 s, also when the value is 0 or over an hour).
 */
int ts_http_retry_after(const char* v, size_t len, uint64_t now_unix, uint64_t* seconds);

#endif /* TS_HTTP1_H */
