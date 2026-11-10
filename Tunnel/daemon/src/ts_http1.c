/*
 * ts_http1 - see ts_http1.h. The grammar is RFC 9112 (messages) and RFC 9110 (fields, Retry-After).
 * The reference for what goes out is Go's net/http as tailscaled uses it (Request.write: request
 * line, Host, User-Agent, Content-Length, then the header map sorted by name); for what comes in,
 * where Go's reader is laxer or stricter, the choice is noted next to the code.
 */

#include "ts_http1.h"

#include <string.h>

/* --------------------------------------------------------------------- building requests */

typedef struct {
    char*  p;
    size_t cap;
    size_t len;
    int    failed;
} wbuf;

static void w_mem(wbuf* w, const void* s, size_t n)
{
    if (w->failed) return;
    if (n > w->cap - w->len) {
        w->failed = 1;
        return;
    }
    memcpy(w->p + w->len, s, n);
    w->len += n;
}

static void w_str(wbuf* w, const char* s)
{
    w_mem(w, s, strlen(s));
}

static void w_uint(wbuf* w, uint64_t v)
{
    char s[24];
    size_t i = sizeof(s);

    do {
        s[--i] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    w_mem(w, s + i, sizeof(s) - i);
}

/* The request's length with a NUL after it (not counted); 0 when anything failed or did not fit. */
static size_t w_end(wbuf* w)
{
    if (w->failed || w->len >= w->cap) return 0;
    w->p[w->len] = '\0';
    return w->len;
}

static int is_alnum(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

static int is_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

enum { HOST_BAD = 0, HOST_NAME, HOST_V6 };

/*
 * What a host may be: a DNS name or an IPv4 literal ([A-Za-z0-9._-]), or an IPv6 literal (hex
 * digits, colons, dots for a mapped IPv4 tail). Not full DNS rules - bt_resolve has those - only
 * what keeps the Host line one well-formed line whatever a DERP map says.
 */
static int host_kind(const char* h)
{
    size_t n = strlen(h), i, colons = 0;
    int name = 1, v6 = 1;

    if (!n || n > 253) return HOST_BAD;
    for (i = 0; i < n; i++) {
        char c = h[i];
        if (!(is_alnum(c) || c == '-' || c == '.' || c == '_')) name = 0;
        if (!(is_hex(c) || c == ':' || c == '.')) v6 = 0;
        if (c == ':') colons++;
    }
    if (name) return HOST_NAME;
    if (v6 && colons >= 2 && n <= 45) return HOST_V6;
    return HOST_BAD;
}

/* The URL's host[:port] as Go puts it into Host: brackets around IPv6, the port unless it is the
 * scheme's default (0: always written - net.JoinHostPort). */
static void w_authority(wbuf* w, const char* host, uint16_t port, uint16_t default_port)
{
    int kind = host ? host_kind(host) : HOST_BAD;

    if (kind == HOST_BAD) {
        w->failed = 1;
        return;
    }
    if (kind == HOST_V6) w_str(w, "[");
    w_str(w, host);
    if (kind == HOST_V6) w_str(w, "]");
    if (port != default_port) {
        w_str(w, ":");
        w_uint(w, port);
    }
}

/* Standard base64 with padding - Go's base64.StdEncoding, what the server decodes. */
static void w_base64(wbuf* w, const uint8_t* in, size_t n)
{
    static const char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char q[4];
    size_t i;
    uint32_t v;

    for (i = 0; i + 3 <= n; i += 3) {
        v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        q[0] = tab[v >> 18];
        q[1] = tab[(v >> 12) & 63];
        q[2] = tab[(v >> 6) & 63];
        q[3] = tab[v & 63];
        w_mem(w, q, 4);
    }
    if (n - i == 1) {
        v = (uint32_t)in[i] << 16;
        q[0] = tab[v >> 18];
        q[1] = tab[(v >> 12) & 63];
        q[2] = '=';
        q[3] = '=';
        w_mem(w, q, 4);
    } else if (n - i == 2) {
        v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        q[0] = tab[v >> 18];
        q[1] = tab[(v >> 12) & 63];
        q[2] = tab[(v >> 6) & 63];
        q[3] = '=';
        w_mem(w, q, 4);
    }
}

size_t ts_http1_key_request(char* out, size_t cap, const char* host, uint16_t port, int tls, unsigned capver)
{
    uint16_t def = tls ? 443 : 80;
    wbuf w = { out, cap, 0, 0 };

    if (!port) port = def;
    w_str(&w, "GET /key?v=");
    w_uint(&w, capver);
    w_str(&w, " HTTP/1.1\r\nHost: ");
    w_authority(&w, host, port, def);
    /* No Accept-Encoding: tailscaled's transport has DisableCompression. */
    w_str(&w, "\r\nUser-Agent: " TS_HTTP1_USER_AGENT "\r\n\r\n");
    return w_end(&w);
}

size_t ts_http1_ts2021_request(char* out, size_t cap, const char* host, uint16_t port,
                               const uint8_t* init, size_t init_len)
{
    wbuf w = { out, cap, 0, 0 };

    if (!port || !init || !init_len || init_len > TS_HTTP1_HANDSHAKE_MAX) return 0;
    w_str(&w, "POST /ts2021 HTTP/1.1\r\nHost: ");
    w_authority(&w, host, port, 0);
    /* A POST without a body still says Content-Length: 0 in Go (shouldSendContentLength); the
     * fields after it come out of Go's header map in sorted order. */
    w_str(&w, "\r\nUser-Agent: " TS_HTTP1_USER_AGENT "\r\n"
              "Content-Length: 0\r\n"
              "Connection: upgrade\r\n"
              "Upgrade: tailscale-control-protocol\r\n"
              "X-Tailscale-Handshake: ");
    w_base64(&w, init, init_len);
    w_str(&w, "\r\n\r\n");
    return w_end(&w);
}

/* A DERP node's name as a field value: 1-64 of [A-Za-z0-9._-]. */
static int node_name_valid(const char* s)
{
    size_t n = strlen(s), i;

    if (!n || n > 64) return 0;
    for (i = 0; i < n; i++)
        if (!(is_alnum(s[i]) || s[i] == '-' || s[i] == '.' || s[i] == '_')) return 0;
    return 1;
}

size_t ts_http1_derp_request(char* out, size_t cap, const char* host, uint16_t port, int tls,
                             const char* ideal_node)
{
    uint16_t def = tls ? 443 : 80;
    wbuf w = { out, cap, 0, 0 };

    if (!port) port = def;
    if (ideal_node && !node_name_valid(ideal_node)) return 0;
    w_str(&w, "GET /derp HTTP/1.1\r\nHost: ");
    w_authority(&w, host, port, def);
    /* Sorted as Go writes the map: Connection, Ideal-Node, Upgrade. No Derp-Fast-Start: that needs
     * the server's key from its TLS certificate, and the upgrade answer is cheap. */
    w_str(&w, "\r\nUser-Agent: " TS_HTTP1_USER_AGENT "\r\nConnection: Upgrade\r\n");
    if (ideal_node) {
        w_str(&w, "Ideal-Node: ");
        w_str(&w, ideal_node);
        w_str(&w, "\r\n");
    }
    w_str(&w, "Upgrade: DERP\r\n\r\n");
    return w_end(&w);
}

/* --------------------------------------------------------------------- the response */

enum {
    P_HEAD = 0,         /* the status line and the fields, up to the empty line */
    P_BODY_LENGTH,      /* `left` more bytes (Content-Length) */
    P_BODY_EOF,         /* everything until the connection closes */
    P_CHUNK_SIZE,       /* hex digits */
    P_CHUNK_WS,         /* whitespace after them */
    P_CHUNK_EXT,        /* ";ext..." - skipped */
    P_CHUNK_LF,         /* the size line's LF after its CR */
    P_CHUNK_DATA,
    P_CHUNK_CR,         /* the CRLF after a chunk's data */
    P_CHUNK_DATA_LF,
    P_TRAILER,          /* trailer fields up to the empty line - skipped */
    P_END
};

static void fail(ts_http1_resp* r, ts_http1_error e)
{
    r->state = TS_HTTP1_FAILED;
    r->error = e;
    r->phase = P_END;
}

static void done(ts_http1_resp* r)
{
    r->state = TS_HTTP1_DONE;
    r->phase = P_END;
}

void ts_http1_resp_init(ts_http1_resp* r, uint8_t* body, size_t body_cap)
{
    memset(r, 0, sizeof(*r));
    r->body = body;
    r->body_cap = body ? body_cap : 0;
    r->reason = "";
}

static char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

static int ci_equal_n(const char* a, const char* b, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        if (lower(a[i]) != lower(b[i])) return 0;
    return 1;
}

static int ci_equal(const char* a, const char* b)
{
    size_t n = strlen(a);

    return n == strlen(b) && ci_equal_n(a, b, n);
}

/* tchar (RFC 9110 5.6.2): what a field name is made of. */
static int tchar(char c)
{
    return is_alnum(c) || (c && strchr("!#$%&'*+-.^_`|~", c) != NULL);
}

/* A byte of a field value or reason phrase: HTAB, SP, VCHAR, obs-text - no other control. */
static int vchar(char c)
{
    unsigned char u = (unsigned char)c;

    return u == '\t' || (u >= 0x20 && u != 0x7f);
}

static int digit(char c)
{
    return c >= '0' && c <= '9';
}

/* "HTTP/1.x SP 3DIGIT [SP reason]", NUL-terminated in place at s[n]. */
static int status_line(ts_http1_resp* r, char* s, size_t n)
{
    size_t i;

    if (n < 12 || memcmp(s, "HTTP/1.", 7) != 0 || !digit(s[7]) || s[8] != ' ') return 0;
    if (!digit(s[9]) || !digit(s[10]) || !digit(s[11])) return 0;
    r->minor = s[7] == '0' ? 0 : 1;
    r->status = (s[9] - '0') * 100 + (s[10] - '0') * 10 + (s[11] - '0');
    if (r->status < 100 || r->status > 599) return 0;
    /* Go takes a status line without a reason, even without the space before it: so do we. */
    if (n == 12) {
        r->reason = s + 12;
        return 1;
    }
    if (s[12] != ' ') return 0;
    for (i = 13; i < n; i++)
        if (!vchar(s[i])) return 0;
    r->reason = s + 13;
    return 1;
}

/* "name: value" of n bytes at s; the name and the trimmed value are NUL-terminated in place. */
static int field_line(ts_http1_resp* r, char* s, size_t n)
{
    char* colon = (char*)memchr(s, ':', n);
    char *v, *ve, *p;

    if (!colon || colon == s) return 0;
    /* No whitespace before the colon (RFC 9112 5.1): tchar only. */
    for (p = s; p < colon; p++)
        if (!tchar(*p)) return 0;
    v = colon + 1;
    ve = s + n;
    while (v < ve && (*v == ' ' || *v == '\t')) v++;
    while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
    for (p = v; p < ve; p++)
        if (!vchar(*p)) return 0;
    if (r->n_fields == TS_HTTP1_MAX_FIELDS) {
        fail(r, TS_HTTP1_ERR_TOO_BIG);
        return 1;
    }
    *colon = '\0';
    *ve = '\0';
    r->fields[r->n_fields].name = s;
    r->fields[r->n_fields].value = v;
    r->fields[r->n_fields].value_len = (size_t)(ve - v);
    r->n_fields++;
    return 1;
}

/* A decimal Content-Length, at most 18 digits (well inside uint64). */
static int parse_length(const char* s, size_t n, uint64_t* out)
{
    uint64_t v = 0;
    size_t i;

    if (!n || n > 18) return 0;
    for (i = 0; i < n; i++) {
        if (!digit(s[i])) return 0;
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    *out = v;
    return 1;
}

static void restart_head(ts_http1_resp* r)
{
    r->head_len = 0;
    r->line_start = 0;
    r->n_fields = 0;
    r->status = 0;
    r->reason = "";
}

/* The head is complete in head[0, head_len), ending with its empty line: parse it and decide how
 * the body is framed (RFC 9112 6.3). */
static void head_done(ts_http1_resp* r)
{
    char* s = r->head;
    char* e = r->head + r->head_len;
    char* nl;
    size_t i, len, n_cl = 0, n_te = 0;
    uint64_t cl = 0;
    int chunked = 0, first = 1;

    for (i = 0; i < r->head_len; i++) {
        if (r->head[i] == '\0') {
            fail(r, TS_HTTP1_ERR_SYNTAX);
            return;
        }
    }
    /* Obsolete line folding: a line break followed by whitespace continues the field before it; a
     * user agent replaces it with spaces (RFC 9112 5.2). Right after the status line it is refused
     * (2.2) - that line is no field to continue. */
    for (i = 0; i + 1 < r->head_len; i++) {
        if (r->head[i] != '\n' || (r->head[i + 1] != ' ' && r->head[i + 1] != '\t')) continue;
        if (memchr(r->head, '\n', i) == NULL) {
            fail(r, TS_HTTP1_ERR_SYNTAX);
            return;
        }
        r->head[i] = ' ';
        if (r->head[i - 1] == '\r') r->head[i - 1] = ' ';
    }

    /* Lines; every one ends with LF, a CR before it is dropped, a CR anywhere else is refused. */
    while (s < e) {
        nl = (char*)memchr(s, '\n', (size_t)(e - s));
        len = (size_t)(nl - s);
        if (len && s[len - 1] == '\r') len--;
        if (memchr(s, '\r', len)) {
            fail(r, TS_HTTP1_ERR_SYNTAX);
            return;
        }
        s[len] = '\0';
        if (first) {
            if (!status_line(r, s, len)) {
                fail(r, TS_HTTP1_ERR_SYNTAX);
                return;
            }
            first = 0;
        } else if (len) {
            if (!field_line(r, s, len)) {
                fail(r, TS_HTTP1_ERR_SYNTAX);
                return;
            }
            if (r->state == TS_HTTP1_FAILED) return;
        }
        s = nl + 1;
    }

    if (r->status < 200) {
        if (r->status == 101) {
            r->state = TS_HTTP1_UPGRADED;
            r->phase = P_END;
            return;
        }
        /* 100 Continue, 103 Early Hints...: the real response follows. */
        if (++r->interim > TS_HTTP1_MAX_INTERIM) {
            fail(r, TS_HTTP1_ERR_TOO_BIG);
            return;
        }
        restart_head(r);
        return;
    }
    if (r->status == 204 || r->status == 304) {
        done(r);
        return;
    }

    for (i = 0; i < r->n_fields; i++) {
        const ts_http1_field* f = &r->fields[i];
        uint64_t v;

        if (ci_equal(f->name, "Content-Length")) {
            /* Repeats must agree, as in Go; unlike Go, a list in one field is refused too. */
            if (!parse_length(f->value, f->value_len, &v) || (n_cl && v != cl)) {
                fail(r, TS_HTTP1_ERR_FRAMING);
                return;
            }
            cl = v;
            n_cl++;
        } else if (ci_equal(f->name, "Transfer-Encoding")) {
            /* Like Go: one field, exactly "chunked"; no other coding can be undone here. */
            if (++n_te > 1 || f->value_len != 7 || !ci_equal_n(f->value, "chunked", 7)) {
                fail(r, TS_HTTP1_ERR_FRAMING);
                return;
            }
            chunked = 1;
        }
    }
    if (chunked) {
        /* With a Content-Length too it smells of smuggling (RFC 9112 6.3): Go drops the length,
         * we refuse. An HTTP/1.0 response cannot be chunked (6.1). */
        if (n_cl || r->minor == 0) {
            fail(r, TS_HTTP1_ERR_FRAMING);
            return;
        }
        r->phase = P_CHUNK_SIZE;
        r->left = 0;
        r->digits = 0;
        r->line_len = 0;
        return;
    }
    if (n_cl) {
        if (r->body && cl > r->body_cap) {
            fail(r, TS_HTTP1_ERR_BODY_TOO_BIG);
            return;
        }
        r->left = cl;
        if (!cl) done(r);
        else r->phase = P_BODY_LENGTH;
        return;
    }
    r->phase = P_BODY_EOF;
}

/* Head bytes up to and including the empty line that ends the head; returns how many were taken. */
static size_t head_bytes(ts_http1_resp* r, const uint8_t* in, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        size_t line;

        if (r->head_len == TS_HTTP1_HEAD_MAX) {
            fail(r, TS_HTTP1_ERR_TOO_BIG);
            return i;
        }
        r->head[r->head_len++] = (char)in[i];
        if (in[i] != '\n') continue;
        line = r->head_len - r->line_start;             /* with its LF */
        if (line == 1 || (line == 2 && r->head[r->line_start] == '\r')) {
            if (r->line_start == 0) {
                /* An empty line where the status line belongs: Go's client refuses it too. */
                fail(r, TS_HTTP1_ERR_SYNTAX);
                return i + 1;
            }
            r->head[r->head_len] = '\0';
            head_done(r);
            return i + 1;
        }
        r->line_start = r->head_len;
    }
    return len;
}

static int hexval(uint8_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void chunk_size_done(ts_http1_resp* r)
{
    r->line_len = 0;
    if (!r->left) {
        r->phase = P_TRAILER;
        r->saw_cr = 0;
        return;
    }
    if (r->body && r->left > r->body_cap - r->body_len) {
        fail(r, TS_HTTP1_ERR_BODY_TOO_BIG);
        return;
    }
    r->phase = P_CHUNK_DATA;
}

/* The end of the size's digits: what may follow them. */
static void after_size(ts_http1_resp* r, uint8_t c)
{
    if (c == ' ' || c == '\t') r->phase = P_CHUNK_WS;
    else if (c == ';') r->phase = P_CHUNK_EXT;
    else if (c == '\r') r->phase = P_CHUNK_LF;
    else if (c == '\n') chunk_size_done(r);     /* a bare LF, as Go's chunked reader takes */
    else fail(r, TS_HTTP1_ERR_FRAMING);
}

static void trailer_byte(ts_http1_resp* r, uint8_t c)
{
    if (++r->trailer_bytes > TS_HTTP1_HEAD_MAX) {
        fail(r, TS_HTTP1_ERR_TOO_BIG);
        return;
    }
    if (r->saw_cr && c != '\n') {
        fail(r, TS_HTTP1_ERR_FRAMING);
        return;
    }
    if (c == '\r') {
        r->saw_cr = 1;
        return;
    }
    if (c == '\n') {
        if (!r->line_len) {
            done(r);                    /* the empty line */
            return;
        }
        if (++r->trailers > TS_HTTP1_MAX_FIELDS) {
            fail(r, TS_HTTP1_ERR_TOO_BIG);
            return;
        }
        r->line_len = 0;
        r->saw_cr = 0;
        return;
    }
    if (!vchar((char)c)) {
        fail(r, TS_HTTP1_ERR_FRAMING);
        return;
    }
    r->line_len++;                      /* trailers are skipped, not parsed */
}

/* One byte of the chunk framing (everything but the data itself). */
static void chunk_byte(ts_http1_resp* r, uint8_t c)
{
    int h;

    if (r->phase <= P_CHUNK_LF && ++r->line_len > TS_HTTP1_CHUNK_LINE_MAX) {
        fail(r, TS_HTTP1_ERR_FRAMING);
        return;
    }
    switch (r->phase) {
    case P_CHUNK_SIZE:
        h = hexval(c);
        if (h >= 0) {
            /* 15 hex digits is 2^60: far over any buffer, and no overflow on the way. */
            if (++r->digits > 15) {
                fail(r, TS_HTTP1_ERR_FRAMING);
                return;
            }
            r->left = r->left * 16 + (uint64_t)h;
            return;
        }
        if (!r->digits) {
            fail(r, TS_HTTP1_ERR_FRAMING);
            return;
        }
        after_size(r, c);
        return;
    case P_CHUNK_WS:
        if (c == ' ' || c == '\t') return;
        if (c == ';') r->phase = P_CHUNK_EXT;
        else if (c == '\r') r->phase = P_CHUNK_LF;
        else if (c == '\n') chunk_size_done(r);
        else fail(r, TS_HTTP1_ERR_FRAMING);
        return;
    case P_CHUNK_EXT:
        if (c == '\r') r->phase = P_CHUNK_LF;
        else if (c == '\n') chunk_size_done(r);
        else if (!vchar((char)c)) fail(r, TS_HTTP1_ERR_FRAMING);
        return;
    case P_CHUNK_LF:
        if (c == '\n') chunk_size_done(r);
        else fail(r, TS_HTTP1_ERR_FRAMING);
        return;
    case P_CHUNK_CR:
        /* Strictly CRLF after the data, as Go's chunked reader. */
        if (c == '\r') r->phase = P_CHUNK_DATA_LF;
        else fail(r, TS_HTTP1_ERR_FRAMING);
        return;
    case P_CHUNK_DATA_LF:
        if (c != '\n') {
            fail(r, TS_HTTP1_ERR_FRAMING);
            return;
        }
        r->phase = P_CHUNK_SIZE;
        r->left = 0;
        r->digits = 0;
        r->line_len = 0;
        return;
    case P_TRAILER:
        trailer_byte(r, c);
        return;
    default:
        fail(r, TS_HTTP1_ERR_FRAMING);
        return;
    }
}

ts_http1_state ts_http1_resp_feed(ts_http1_resp* r, const uint8_t* in, size_t len, size_t* used)
{
    size_t pos = 0;

    while (pos < len && r->state == TS_HTTP1_MORE) {
        size_t n = len - pos;

        switch (r->phase) {
        case P_HEAD:
            pos += head_bytes(r, in + pos, n);
            break;
        case P_BODY_LENGTH:
        case P_CHUNK_DATA:
            /* The room was checked when the length became known. */
            if (n > r->left) n = (size_t)r->left;
            if (r->body) {
                memcpy(r->body + r->body_len, in + pos, n);
                r->body_len += n;
            }
            r->left -= n;
            pos += n;
            if (!r->left) {
                if (r->phase == P_BODY_LENGTH) done(r);
                else r->phase = P_CHUNK_CR;
            }
            break;
        case P_BODY_EOF:
            if (r->body) {
                /* Full up to the last byte, then refused: the same however the bytes came. */
                size_t room = r->body_cap - r->body_len;
                if (n > room) {
                    memcpy(r->body + r->body_len, in + pos, room);
                    r->body_len += room;
                    pos += room;
                    fail(r, TS_HTTP1_ERR_BODY_TOO_BIG);
                    break;
                }
                memcpy(r->body + r->body_len, in + pos, n);
                r->body_len += n;
            }
            pos += n;
            break;
        default:
            chunk_byte(r, in[pos++]);
            break;
        }
    }
    if (used) *used = pos;
    return r->state;
}

ts_http1_state ts_http1_resp_eof(ts_http1_resp* r)
{
    if (r->state == TS_HTTP1_MORE) {
        if (r->phase == P_BODY_EOF) done(r);
        else fail(r, TS_HTTP1_ERR_TRUNCATED);
    }
    return r->state;
}

const char* ts_http1_resp_field(const ts_http1_resp* r, const char* name, size_t* len)
{
    size_t i;

    for (i = 0; i < r->n_fields; i++) {
        if (ci_equal(r->fields[i].name, name)) {
            if (len) *len = r->fields[i].value_len;
            return r->fields[i].value;
        }
    }
    return NULL;
}

/* Does the comma-separated list `v` hold `token` (any case, whitespace around the elements)? */
static int list_has(const char* v, size_t n, const char* token)
{
    size_t tlen = strlen(token), i = 0;

    while (i < n) {
        size_t start, end;

        while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) i++;
        start = i;
        while (i < n && v[i] != ',') i++;
        end = i;
        while (end > start && (v[end - 1] == ' ' || v[end - 1] == '\t')) end--;
        if (end - start == tlen && ci_equal_n(v + start, token, tlen)) return 1;
    }
    return 0;
}

int ts_http1_resp_upgraded(const ts_http1_resp* r, const char* protocol)
{
    const char* up;
    size_t n, i;

    if (r->state != TS_HTTP1_UPGRADED || r->status != 101) return 0;
    up = ts_http1_resp_field(r, "Upgrade", &n);
    if (!up || n != strlen(protocol) || !ci_equal_n(up, protocol, n)) return 0;
    for (i = 0; i < r->n_fields; i++)
        if (ci_equal(r->fields[i].name, "Connection") &&
            list_has(r->fields[i].value, r->fields[i].value_len, "upgrade"))
            return 1;
    return 0;
}

const char* ts_http1_error_text(ts_http1_error e)
{
    switch (e) {
    case TS_HTTP1_OK:               return "ok";
    case TS_HTTP1_ERR_SYNTAX:       return "not an HTTP/1.x response";
    case TS_HTTP1_ERR_TOO_BIG:      return "response head too large";
    case TS_HTTP1_ERR_BODY_TOO_BIG: return "response body too large";
    case TS_HTTP1_ERR_FRAMING:      return "bad body framing";
    case TS_HTTP1_ERR_TRUNCATED:    return "connection closed mid-response";
    }
    return "?";
}

/* --------------------------------------------------------------------- Retry-After */

/* Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's days_from_civil). */
static int64_t days_from_civil(int64_t y, int m, int d)
{
    int64_t era, yoe, doy, doe;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static int two_digits(const char* s, int* v)
{
    if (!digit(s[0]) || !digit(s[1])) return 0;
    *v = (s[0] - '0') * 10 + (s[1] - '0');
    return 1;
}

/* "Sun, 06 Nov 1994 08:49:37 GMT" (RFC 9110 5.6.7), exactly 29 bytes, as Unix seconds. The day
 * name must be one, but is not checked against the date - Go's parser does not either. */
static int imf_fixdate(const char* s, int64_t* t)
{
    static const char days[] = "MonTueWedThuFriSatSun";
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    static const unsigned char mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    int d, mo = -1, y, hh, mm, ss, i, leap;

    for (i = 0; i < 7; i++)
        if (memcmp(s, days + 3 * i, 3) == 0) break;
    if (i == 7 || memcmp(s + 3, ", ", 2) != 0 || s[7] != ' ' || s[11] != ' ' || s[16] != ' ') return 0;
    if (s[19] != ':' || s[22] != ':' || memcmp(s + 25, " GMT", 4) != 0) return 0;
    for (i = 0; i < 12; i++)
        if (memcmp(s + 8, months + 3 * i, 3) == 0) mo = i + 1;
    if (mo < 0 || !two_digits(s + 5, &d) || !two_digits(s + 17, &hh) || !two_digits(s + 20, &mm) ||
        !two_digits(s + 23, &ss))
        return 0;
    if (!two_digits(s + 12, &y) || !two_digits(s + 14, &i)) return 0;
    y = y * 100 + i;
    leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    if (d < 1 || d > mdays[mo - 1] + (mo == 2 && leap) || hh > 23 || mm > 59 || ss > 60) return 0;
    *t = days_from_civil(y, mo, d) * 86400 + hh * 3600 + mm * 60 + ss;
    return 1;
}

int ts_http_retry_after(const char* v, size_t len, uint64_t now_unix, uint64_t* seconds)
{
    size_t i;
    int64_t t;

    while (len && (*v == ' ' || *v == '\t')) {
        v++;
        len--;
    }
    while (len && (v[len - 1] == ' ' || v[len - 1] == '\t')) len--;
    if (!len) return 0;
    if (digit(v[0])) {
        uint64_t s = 0;
        for (i = 0; i < len; i++) {
            if (!digit(v[i])) return 0;
            if (s <= (1ULL << 31)) s = s * 10 + (uint64_t)(v[i] - '0');
        }
        *seconds = s > (1ULL << 31) ? (1ULL << 31) : s;
        return 1;
    }
    if (len != 29 || !imf_fixdate(v, &t)) return 0;
    *seconds = t > 0 && (uint64_t)t > now_unix ? (uint64_t)t - now_unix : 0;
    return 1;
}
