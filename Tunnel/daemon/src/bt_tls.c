/*
 * bt_tls - see bt_tls.h.
 */

#include "bt_tls.h"
#include "bt_roots.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL    0               /* SIGPIPE is ignored by the process anyway (bt_tls.h) */
#endif

/* TLS 1.3: ChaCha20 first - Krait has no AES instructions, and a Go server picks ChaCha20 when the
 * client lists it first. */
#define SUITES_TLS13    "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
/* TLS 1.2: forward-secret AEAD only, ChaCha20 first again. */
#define CIPHERS_TLS12   "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:" \
                        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" \
                        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"

/* Names as Go's x509 matches them: the DNS names only - never the CN - and a wildcard only as a
 * whole left-most label. */
#define HOST_FLAGS      (X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT)

/* derper's meta certificate: derpconst.MetaCertCommonNamePrefix. */
#define META_CN         "derpkey"

#define OUT_KEEP        (16 * 1024)     /* a queue buffer larger than this is given back once empty */

static SSL_CTX* g_ctx;

static void flush(bt_tls* c);
static void handshake(bt_tls* c);

/* --------------------------------------------------------------------- small helpers */

/* The states that hold a socket. */
static int active(const bt_tls* c)
{
    return c->state == BT_TLS_CONNECTING || c->state == BT_TLS_HANDSHAKE || c->state == BT_TLS_OPEN ||
           c->state == BT_TLS_CLOSING;
}

static void wipe_free(uint8_t* p, size_t n)
{
    if (!p) return;
    OPENSSL_cleanse(p, n);
    free(p);
}

/* Lets go of OpenSSL, the socket and the queue; the state and the text stay. */
static void release(bt_tls* c)
{
    if (c->ssl) SSL_free(c->ssl);       /* the socket is ours to close: SSL_set_fd's BIO does not */
    c->ssl = NULL;
    if (active(c) && c->fd >= 0) close(c->fd);
    c->fd = -1;
    wipe_free(c->out, c->out_cap);
    c->out = NULL;
    c->out_off = c->out_len = c->out_cap = 0;
    c->hs_wait = c->flush_wait = c->read_wait = 0;
    c->said_bye = 0;
    c->deadline = BT_NEVER;
}

/* The end: CLOSED or FAILED, and why. */
static void finish(bt_tls* c, bt_tls_state s, const char* fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 3, 4)))
#endif
    ;

static void finish(bt_tls* c, bt_tls_state s, const char* fmt, ...)
{
    va_list ap;

    release(c);
    c->state = s;
    va_start(ap, fmt);
    vsnprintf(c->error, sizeof(c->error), fmt, ap);
    va_end(ap);
}

/* OpenSSL's reason for what just failed; its error queue is empty afterwards. */
static void ssl_reason(char* out, size_t cap)
{
    unsigned long e = ERR_get_error();
    const char* r = e ? ERR_reason_error_string(e) : NULL;

    if (r) snprintf(out, cap, "%s", r);
    else if (e) snprintf(out, cap, "OpenSSL error %lx", e);
    else snprintf(out, cap, "no reason given");
    ERR_clear_error();
}

/*
 * An SSL call ended without success and without waiting: CLOSED or FAILED, with words for the
 * journal. `saved_errno` is errno right after the call - OpenSSL reads and writes the socket with
 * read() and write(), and SSL_ERROR_SYSCALL means one of them failed.
 */
static void ssl_failed(bt_tls* c, const char* what, int e, int saved_errno)
{
    unsigned long code = ERR_peek_error();
    char reason[128];

    if (c->verify_error[0]) {
        ERR_clear_error();
        finish(c, BT_TLS_FAILED, "certificate of %s (%s): %s", c->host, c->peer, c->verify_error);
        return;
    }
    if (e == SSL_ERROR_ZERO_RETURN) {
        snprintf(reason, sizeof(reason), "the server closed the connection");
    } else if (e == SSL_ERROR_SYSCALL && !code) {
        /* OpenSSL 1.1 reported a close without close_notify this way: EOF, errno 0 */
        snprintf(reason, sizeof(reason), "%s",
                 saved_errno ? strerror(saved_errno) : "the server closed the connection without close_notify");
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
    } else if (ERR_GET_LIB(code) == ERR_LIB_SSL && ERR_GET_REASON(code) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
        snprintf(reason, sizeof(reason), "the server closed the connection without close_notify");
#endif
    } else {
        ssl_reason(reason, sizeof(reason));
    }
    ERR_clear_error();
    finish(c, BT_TLS_FAILED, "%s %s: %s", what, c->peer, reason);
}

static void peer_text(bt_tls* c, const bt_addr* a, uint16_t port)
{
    char ip[INET6_ADDRSTRLEN];

    if (!inet_ntop(a->family == 6 ? AF_INET6 : AF_INET, a->addr, ip, sizeof(ip))) snprintf(ip, sizeof(ip), "?");
    snprintf(c->peer, sizeof(c->peer), a->family == 6 ? "[%s]:%u" : "%s:%u", ip, (unsigned)port);
}

static socklen_t to_sockaddr(const bt_addr* a, uint16_t port, struct sockaddr_storage* ss)
{
    memset(ss, 0, sizeof(*ss));
    if (a->family == 4) {
        struct sockaddr_in* s = (struct sockaddr_in*)ss;
        s->sin_family = AF_INET;
        s->sin_port = htons(port);
        memcpy(&s->sin_addr, a->addr, 4);
        return (socklen_t)sizeof(*s);
    }
    {
        struct sockaddr_in6* s = (struct sockaddr_in6*)ss;
        s->sin6_family = AF_INET6;
        s->sin6_port = htons(port);
        memcpy(&s->sin6_addr, a->addr, 16);
        return (socklen_t)sizeof(*s);
    }
}

/*
 * The host as Go's hostnameInSNI takes it: brackets and trailing dots dropped. 1 for an IP literal or a
 * name of [A-Za-z0-9._-] - what a DERP map or a control URL can hold; anything else is refused rather
 * than passed on to SNI and the name check.
 */
static int host_take(bt_tls* c, const char* host)
{
    uint8_t ip[16];
    size_t n, i;
    int bracketed = 0;

    if (!host) return 0;
    n = strlen(host);
    if (n >= 2 && host[0] == '[' && host[n - 1] == ']') {
        host++;
        n -= 2;
        bracketed = 1;
    }
    while (n > 0 && host[n - 1] == '.') n--;
    if (n == 0 || n > BT_TLS_HOST_MAX) return 0;
    memcpy(c->host, host, n);
    c->host[n] = '\0';
    if (inet_pton(AF_INET, c->host, ip) == 1 || inet_pton(AF_INET6, c->host, ip) == 1) {
        c->host_ip = 1;
        return 1;
    }
    if (bracketed) return 0;
    for (i = 0; i < n; i++) {
        char ch = c->host[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' ||
              ch == '-' || ch == '_'))
            return 0;
    }
    return 1;
}

/* "sha256-raw:" and 64 lowercase hex digits - the only form Go's check can ever match (it compares
 * with fmt's %02x text), so any other is refused here instead of failing every handshake. */
static int pin_take(bt_tls* c, const char* pin)
{
    size_t plen = strlen(BT_TLS_PIN_PREFIX), i;

    if (strncmp(pin, BT_TLS_PIN_PREFIX, plen) != 0) return 0;
    pin += plen;
    for (i = 0; i < 64; i++)
        if (!((pin[i] >= '0' && pin[i] <= '9') || (pin[i] >= 'a' && pin[i] <= 'f'))) return 0;
    if (pin[64] != '\0') return 0;
    memcpy(c->pin, pin, 65);
    c->pinned = 1;
    return 1;
}

/* The subject's CN as printable ASCII, for messages and the meta certificate's prefix. The LAST CN,
 * as Go's pkix.Name.CommonName holds it. */
static void subject_cn(X509* x, char* out, size_t cap)
{
    X509_NAME* name = x ? X509_get_subject_name(x) : NULL;
    unsigned char* utf8 = NULL;
    int i = -1, last = -1, n;
    size_t k = 0;

    out[0] = '\0';
    if (!name) return;
    while ((i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0) last = i;
    if (last < 0) return;
    n = ASN1_STRING_to_UTF8(&utf8, X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, last)));
    if (n < 0) return;
    for (i = 0; i < n && k + 1 < cap; i++) out[k++] = utf8[i] >= 0x20 && utf8[i] < 0x7f ? (char)utf8[i] : '?';
    out[k] = '\0';
    OPENSSL_free(utf8);
}

/* --------------------------------------------------------------------- the certificate */

static int pin_refuse(bt_tls* c, X509_STORE_CTX* x, const char* what, const char* cn)
{
    snprintf(c->verify_error, sizeof(c->verify_error), "sha256-raw pin: %s%s%s%s", what, cn ? " (CN=" : "",
             cn ? cn : "", cn ? ")" : "");
    X509_STORE_CTX_set_error(x, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;
}

/*
 * Tailscale's tlsdial.SetConfigExpectedCertHash step for step (net/tlsdial/tlsdial.go:326-358,
 * v1.102.5), over the certificates as the server sent them (leaf first). There is no chain to build
 * and no root: the pin is the trust.
 */
static int verify_pin(bt_tls* c, X509_STORE_CTX* x)
{
    STACK_OF(X509)* sent = X509_STORE_CTX_get0_untrusted(x);
    time_t now = time(NULL);
    int i, n = sent ? sk_X509_num(sent) : 0, good = 0;

    for (i = 0; i < n; i++) {
        X509* cert = sk_X509_value(sent, i);
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int mdlen = 0, k;
        char cn[80], hex[65];
        int t;

        subject_cn(cert, cn, sizeof(cn));
        if (strncmp(cn, META_CN, strlen(META_CN)) == 0) continue;       /* derper's meta certificate */
        if (good) return pin_refuse(c, x, "the server sent more than one certificate", cn);
        /* SHA-256 over the whole certificate as DER - Go's sha256.Sum256(cert.Raw) */
        if (!X509_digest(cert, EVP_sha256(), md, &mdlen) || mdlen != 32)
            return pin_refuse(c, x, "the certificate cannot be hashed", cn);
        for (k = 0; k < 32; k++) snprintf(hex + 2 * k, 3, "%02x", md[k]);
        if (strcmp(hex, c->pin) != 0) return pin_refuse(c, x, "the certificate is not the pinned one", cn);
        /* the name Go sent as SNI - none for an IP literal, and then no check */
        if (!c->host_ip && X509_check_host(cert, c->host, strlen(c->host), HOST_FLAGS, NULL) != 1)
            return pin_refuse(c, x, "the pinned certificate is not for this name", cn);
        t = ASN1_TIME_cmp_time_t(X509_get0_notAfter(cert), now);
        if (t < 0) return pin_refuse(c, x, "the pinned certificate has expired", cn);           /* -2: unreadable */
        t = ASN1_TIME_cmp_time_t(X509_get0_notBefore(cert), now);
        if (t > 0 || t == -2) return pin_refuse(c, x, "the pinned certificate is not valid yet (the clock?)", cn);
        good = 1;
    }
    if (!good) return pin_refuse(c, x, "the server sent no certificate but meta ones", NULL);
    X509_STORE_CTX_set_error(x, X509_V_OK);
    return 1;
}

/* OpenSSL's whole chain check, replaced: the pin when there is one, else OpenSSL's own - the roots and
 * the name set on the connection - with its failure put into words. */
static int verify_chain(X509_STORE_CTX* x, void* arg)
{
    SSL* ssl = (SSL*)X509_STORE_CTX_get_ex_data(x, SSL_get_ex_data_X509_STORE_CTX_idx());
    bt_tls* c = ssl ? (bt_tls*)SSL_get_app_data(ssl) : NULL;
    char cn[80];
    int err;

    (void)arg;
    if (!c) return 0;
    if (c->pinned) return verify_pin(c, x);
    if (X509_verify_cert(x) > 0) return 1;
    err = X509_STORE_CTX_get_error(x);
    subject_cn(X509_STORE_CTX_get_current_cert(x), cn, sizeof(cn));
    snprintf(c->verify_error, sizeof(c->verify_error), "%s (depth %d%s%s)", X509_verify_cert_error_string(err),
             X509_STORE_CTX_get_error_depth(x), cn[0] ? ", CN=" : "", cn);
    return 0;
}

/* --------------------------------------------------------------------- the module */

int bt_tls_init(char* err, size_t errlen)
{
    SSL_CTX* ctx;
    X509_STORE* store;
    char reason[128];
    size_t i;

    if (g_ctx) return 1;
    ERR_clear_error();
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ssl_reason(reason, sizeof(reason));
        snprintf(err, errlen, "TLS: no client context: %s", reason);
        return 0;
    }
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) || !SSL_CTX_set_ciphersuites(ctx, SUITES_TLS13) ||
        !SSL_CTX_set_cipher_list(ctx, CIPHERS_TLS12)) {
        ssl_reason(reason, sizeof(reason));
        snprintf(err, errlen, "TLS: the protocol and cipher settings: %s", reason);
        SSL_CTX_free(ctx);
        return 0;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
    /* Partial writes: SSL_write returns after each record, the queue keeps the rest. Moving buffer: the
     * queue may slide or grow between a WANT_WRITE and the retry (same bytes, never fewer). */
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                              SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_cert_verify_callback(ctx, verify_chain, NULL);

    store = SSL_CTX_get_cert_store(ctx);
    for (i = 0; i < BT_ROOTS_N; i++) {
        BIO* b = BIO_new_mem_buf(bt_roots[i].pem, -1);
        X509* x = b ? PEM_read_bio_X509(b, NULL, NULL, NULL) : NULL;
        int ok = x && X509_STORE_add_cert(store, x);
        X509_free(x);
        BIO_free(b);
        if (!ok) {
            ssl_reason(reason, sizeof(reason));
            snprintf(err, errlen, "TLS: the built-in root %s does not load: %s", bt_roots[i].name, reason);
            SSL_CTX_free(ctx);
            return 0;
        }
    }
    g_ctx = ctx;
    return 1;
}

int bt_tls_add_ca_file(const char* path, size_t* added, char* err, size_t errlen)
{
    X509_STORE* store;
    char reason[128];
    int before;

    if (added) *added = 0;
    if (!g_ctx) {
        snprintf(err, errlen, "TLS: bt_tls_init has not run");
        return 0;
    }
    store = SSL_CTX_get_cert_store(g_ctx);
    before = sk_X509_OBJECT_num(X509_STORE_get0_objects(store));
    ERR_clear_error();
    if (!SSL_CTX_load_verify_locations(g_ctx, path, NULL)) {
        ssl_reason(reason, sizeof(reason));
        snprintf(err, errlen, "TLS: CA file %s: %s", path, reason);
        return 0;
    }
    if (added) {
        int after = sk_X509_OBJECT_num(X509_STORE_get0_objects(store));
        *added = after > before ? (size_t)(after - before) : 0;
    }
    return 1;
}

void bt_tls_fini(void)
{
    SSL_CTX_free(g_ctx);                /* refcounted: open connections keep theirs */
    g_ctx = NULL;
}

/* --------------------------------------------------------------------- the queue */

static void consumed(bt_tls* c, size_t n)
{
    c->out_off += n;
    c->out_len -= n;
    c->flush_wait = 0;
}

/* Room for `len` more bytes after the queue, in one piece. */
static int queue_room(bt_tls* c, size_t len)
{
    size_t need = c->out_len + len, cap;
    uint8_t* p;

    if (c->out_off + need <= c->out_cap) return 1;
    if (need <= c->out_cap) {                   /* sliding it to the front is enough */
        memmove(c->out, c->out + c->out_off, c->out_len);
        c->out_off = 0;
        return 1;
    }
    cap = c->out_cap ? c->out_cap : OUT_KEEP;
    while (cap < need) cap = cap > ((size_t)-1) / 2 ? need : cap * 2;
    if (cap > c->out_max) cap = c->out_max;     /* need <= out_max: the caller checked */
    /* A new buffer rather than realloc: the old one is wiped, not left to the heap. */
    p = (uint8_t*)malloc(cap);
    if (!p) return 0;
    if (c->out_len) memcpy(p, c->out + c->out_off, c->out_len);
    wipe_free(c->out, c->out_cap);
    c->out = p;
    c->out_cap = cap;
    c->out_off = 0;
    return 1;
}

/*
 * Hands the queue on - to TLS, or plain to the socket - as far as it takes it. After a WANT_* the
 * retry passes the queue from the same first byte and at least as long: OpenSSL may already have
 * taken part of it into a record it could not finish sending (SSL_write(3)).
 */
static void flush(bt_tls* c)
{
    while (c->out_len) {
        size_t n = c->out_len > (size_t)INT_MAX ? (size_t)INT_MAX : c->out_len;
        int r, e, saved;

        if (c->plain) {
            ssize_t w = send(c->fd, c->out + c->out_off, n, MSG_NOSIGNAL);
            if (w < 0 && errno == EINTR) continue;
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                c->flush_wait = POLLOUT;
                return;
            }
            if (w <= 0) {
                finish(c, BT_TLS_FAILED, "write to %s: %s", c->peer, w < 0 ? strerror(errno) : "nothing taken");
                return;
            }
            consumed(c, (size_t)w);
            continue;
        }
        ERR_clear_error();
        errno = 0;
        r = SSL_write(c->ssl, c->out + c->out_off, (int)n);
        saved = errno;
        if (r > 0) {
            consumed(c, (size_t)r);
            continue;
        }
        e = SSL_get_error(c->ssl, r);
        if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) {
            c->flush_wait = e == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
            return;
        }
        ssl_failed(c, "TLS write to", e, saved);
        return;
    }
    c->flush_wait = 0;
    c->out_off = 0;
    if (c->out_cap > OUT_KEEP) {
        wipe_free(c->out, c->out_cap);
        c->out = NULL;
        c->out_cap = 0;
    }
}

/* --------------------------------------------------------------------- connecting */

/* The TCP connect is through: plain is open, TLS starts its handshake. */
static void tcp_up(bt_tls* c)
{
    if (c->plain) {
        c->state = BT_TLS_OPEN;
        c->deadline = BT_NEVER;
        flush(c);
        return;
    }
    c->state = BT_TLS_HANDSHAKE;
    handshake(c);
}

/* poll says the connect is over: through, or how it failed. */
static void tcp_check(bt_tls* c)
{
    struct sockaddr_storage ss;
    socklen_t len = sizeof(int), sl = sizeof(ss);
    int err = 0;

    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) err = errno;
    /* No error and still not connected: some stacks tell a failed connect only this way. */
    if (!err && getpeername(c->fd, (struct sockaddr*)&ss, &sl) < 0) err = errno;
    if (err) {
        finish(c, BT_TLS_FAILED, "connect %s: %s", c->peer, strerror(err));
        return;
    }
    tcp_up(c);
}

static void handshake(bt_tls* c)
{
    int r, e, saved;

    ERR_clear_error();
    errno = 0;
    r = SSL_connect(c->ssl);
    saved = errno;
    if (r == 1) {
        c->state = BT_TLS_OPEN;
        c->deadline = BT_NEVER;
        c->hs_wait = 0;
        flush(c);                       /* what was written while connecting */
        return;
    }
    e = SSL_get_error(c->ssl, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
        c->hs_wait = e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
        return;
    }
    ssl_failed(c, "TLS handshake with", e, saved);
}

/* The connection's OpenSSL half: SNI, and what the certificate must match unless pinned. */
static int ssl_prepare(bt_tls* c)
{
    char reason[128];
    int ok;

    ERR_clear_error();
    c->ssl = SSL_new(g_ctx);
    ok = c->ssl && SSL_set_app_data(c->ssl, c) && SSL_set_fd(c->ssl, c->fd);
    if (ok && !c->host_ip) ok = SSL_set_tlsext_host_name(c->ssl, c->host) == 1;
    if (ok && !c->pinned) {
        X509_VERIFY_PARAM* vp = SSL_get0_param(c->ssl);
        X509_VERIFY_PARAM_set_hostflags(vp, HOST_FLAGS);
        ok = c->host_ip ? X509_VERIFY_PARAM_set1_ip_asc(vp, c->host) : X509_VERIFY_PARAM_set1_host(vp, c->host, 0);
    }
    if (!ok) {
        ssl_reason(reason, sizeof(reason));
        finish(c, BT_TLS_FAILED, "TLS setup for %s: %s", c->peer, reason);
        return 0;
    }
    SSL_set_connect_state(c->ssl);
    return 1;
}

int bt_tls_connect(bt_tls* c, const bt_tls_params* p, int fd, uint64_t now_ns)
{
    struct sockaddr_storage ss;
    socklen_t sl;
    int fl, one = 1;

    bt_tls_free(c);
    c->fd = fd;
    c->state = BT_TLS_CONNECTING;       /* owns the fd from here: every failure below closes it */
    if (!p || (p->addr.family != 4 && p->addr.family != 6)) {
        finish(c, BT_TLS_FAILED, "connect: no IPv4 or IPv6 address given");
        return 0;
    }
    peer_text(c, &p->addr, p->port);
    c->plain = p->plain ? 1 : 0;
    c->timeout_ns = (uint64_t)(p->timeout_ms ? p->timeout_ms : BT_TLS_TIMEOUT_MS) * 1000000ULL;
    c->out_max = p->out_max ? p->out_max : BT_TLS_OUT_MAX;
    c->deadline = now_ns + c->timeout_ns;
    if (!c->plain) {
        if (!g_ctx) {
            finish(c, BT_TLS_FAILED, "%s: bt_tls_init has not run", c->peer);
            return 0;
        }
        if (!host_take(c, p->host)) {
            finish(c, BT_TLS_FAILED, "%s: the host name to verify is missing or malformed", c->peer);
            return 0;
        }
        if (p->pin && !pin_take(c, p->pin)) {
            finish(c, BT_TLS_FAILED, "%s: the pin is not %s and 64 lowercase hex digits", c->peer,
                   BT_TLS_PIN_PREFIX);
            return 0;
        }
    }

    if (c->fd < 0) {
        c->fd = socket(p->addr.family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
        if (c->fd < 0) {
            finish(c, BT_TLS_FAILED, "socket for %s: %s", c->peer, strerror(errno));
            return 0;
        }
    }
    fl = fcntl(c->fd, F_GETFL);
    if (fl < 0 || fcntl(c->fd, F_SETFL, fl | O_NONBLOCK) < 0 || fcntl(c->fd, F_SETFD, FD_CLOEXEC) < 0) {
        finish(c, BT_TLS_FAILED, "socket for %s: %s", c->peer, strerror(errno));
        return 0;
    }
    setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));    /* best effort */
    if (!c->plain && !ssl_prepare(c)) return 0;

    sl = to_sockaddr(&p->addr, p->port, &ss);
    if (connect(c->fd, (struct sockaddr*)&ss, sl) == 0) tcp_up(c);        /* loopback can be at once */
    else if (errno != EINPROGRESS && errno != EINTR)                       /* EINTR: it goes on anyway */
        finish(c, BT_TLS_FAILED, "connect %s: %s", c->peer, strerror(errno));
    return c->state != BT_TLS_FAILED;
}

/* --------------------------------------------------------------------- the loop */

int bt_tls_fd(const bt_tls* c)
{
    return active(c) ? c->fd : -1;
}

short bt_tls_events(const bt_tls* c)
{
    switch (c->state) {
    case BT_TLS_CONNECTING:
        return POLLOUT;
    case BT_TLS_HANDSHAKE:
        return c->hs_wait ? c->hs_wait : POLLIN;
    case BT_TLS_OPEN:
        /* always POLLIN: data, the server's close, a reset - the caller reads after each step */
        return (short)(POLLIN | (c->out_len ? (c->flush_wait ? c->flush_wait : POLLOUT) : 0) | c->read_wait);
    case BT_TLS_CLOSING:
        /* always POLLIN: what comes is drained (see closing) */
        if (c->out_len) return (short)(POLLIN | (c->flush_wait ? c->flush_wait : POLLOUT) | c->read_wait);
        if (!c->said_bye) return (short)(POLLIN | (c->hs_wait ? c->hs_wait : POLLOUT) | c->read_wait);
        return (short)(POLLIN | c->read_wait);
    default:
        return 0;
    }
}

/* Reads and throws away whatever is there. 0: the server may send more; GONE_CLEAN: it is done
 * (its close_notify; plain: its FIN); GONE_BROKEN: a reset, or an end without close_notify - after
 * which OpenSSL must not be asked for a shutdown (SSL_shutdown(3)). */
#define GONE_CLEAN      1
#define GONE_BROKEN     2

static int drain(bt_tls* c)
{
    uint8_t junk[4096];

    for (;;) {
        int r, e;

        if (c->plain) {
            ssize_t n = recv(c->fd, junk, sizeof(junk), 0);
            if (n > 0 || (n < 0 && errno == EINTR)) continue;
            if (n == 0) return GONE_CLEAN;
            return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : GONE_BROKEN;
        }
        ERR_clear_error();
        r = SSL_read(c->ssl, junk, (int)sizeof(junk));
        if (r > 0) continue;
        e = SSL_get_error(c->ssl, r);
        ERR_clear_error();
        c->read_wait = e == SSL_ERROR_WANT_WRITE ? POLLOUT : 0;
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return 0;
        return e == SSL_ERROR_ZERO_RETURN ? GONE_CLEAN : GONE_BROKEN;
    }
}

/*
 * The close, step by step: drain what comes (a server stuck writing to us may stop reading what we
 * still send; and anything left unread when the socket closes makes the kernel send a reset, which
 * can destroy what the server has not read of ours yet), the queue, close_notify, our FIN - and then
 * the server's end, so that the socket closes with nothing unread.
 */
static void closing(bt_tls* c)
{
    int gone = drain(c), r;

    if (gone == GONE_BROKEN && !c->said_bye) {
        finish(c, BT_TLS_FAILED, "closing %s: the connection broke before the close (%lu bytes not sent)", c->peer,
               (unsigned long)c->out_len);
        return;
    }
    if (c->out_len) {
        if (gone) {
            finish(c, BT_TLS_FAILED, "closing %s: the server closed first, %lu bytes not sent", c->peer,
                   (unsigned long)c->out_len);
            return;
        }
        flush(c);
        if (c->state != BT_TLS_CLOSING || c->out_len) return;      /* failed, or waits for poll */
    }
    if (!c->said_bye) {
        if (!c->plain && gone != GONE_BROKEN) {
            ERR_clear_error();
            r = SSL_shutdown(c->ssl);   /* 0: ours is out, the server's not here yet; 1: both */
            if (r < 0 && SSL_get_error(c->ssl, r) == SSL_ERROR_WANT_WRITE) {
                c->hs_wait = POLLOUT;
                return;
            }
            ERR_clear_error();          /* anything else: it cannot go out - the close goes on */
        }
        shutdown(c->fd, SHUT_WR);       /* the server sees the end at once and closes its side */
        c->said_bye = 1;
        c->hs_wait = 0;
    }
    if (gone) finish(c, BT_TLS_CLOSED, "closed");
}

void bt_tls_step(bt_tls* c, short revents)
{
    if (!revents || !active(c)) return;
    if (revents & POLLNVAL) {
        c->fd = -1;                     /* not ours to close any more: the number may be reused */
        finish(c, BT_TLS_FAILED, "%s: the socket was closed under the connection", c->peer);
        return;
    }
    switch (c->state) {
    case BT_TLS_CONNECTING:
        if (revents & (POLLOUT | POLLERR | POLLHUP)) tcp_check(c);
        break;
    case BT_TLS_HANDSHAKE:
        handshake(c);
        break;
    case BT_TLS_OPEN:
        /* reading is the caller's; an error or hang-up with nothing to send shows up there too */
        if (c->out_len && (revents & (c->flush_wait | POLLOUT | POLLERR | POLLHUP))) flush(c);
        break;
    case BT_TLS_CLOSING:
        closing(c);
        break;
    default:
        break;
    }
}

uint64_t bt_tls_tick(bt_tls* c, uint64_t now_ns)
{
    size_t unsent = c->out_len;

    if (c->state != BT_TLS_CONNECTING && c->state != BT_TLS_HANDSHAKE && c->state != BT_TLS_CLOSING)
        return BT_NEVER;
    if (now_ns < c->deadline) return c->deadline;
    if (c->state == BT_TLS_CONNECTING) finish(c, BT_TLS_FAILED, "connect %s: timed out", c->peer);
    else if (c->state == BT_TLS_HANDSHAKE) finish(c, BT_TLS_FAILED, "TLS handshake with %s: timed out", c->peer);
    else if (c->said_bye) finish(c, BT_TLS_CLOSED, "closed (the server did not close its side in time)");
    else finish(c, BT_TLS_FAILED, "closing %s: timed out with %lu bytes not sent", c->peer, (unsigned long)unsent);
    return BT_NEVER;
}

/* --------------------------------------------------------------------- data */

size_t bt_tls_read(bt_tls* c, uint8_t* out, size_t cap)
{
    int r, e, saved;

    if (c->state != BT_TLS_OPEN || !cap) return 0;
    if (cap > (size_t)INT_MAX) cap = (size_t)INT_MAX;
    if (c->plain) {
        for (;;) {
            ssize_t n = recv(c->fd, out, cap, 0);
            if (n > 0) return (size_t)n;
            if (n == 0) {
                finish(c, BT_TLS_CLOSED, "%s closed the connection", c->peer);
                return 0;
            }
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                finish(c, BT_TLS_FAILED, "read from %s: %s", c->peer, strerror(errno));
            return 0;
        }
    }
    ERR_clear_error();
    errno = 0;
    r = SSL_read(c->ssl, out, (int)cap);
    saved = errno;
    if (r > 0) {
        c->read_wait = 0;
        return (size_t)r;
    }
    e = SSL_get_error(c->ssl, r);
    if (e == SSL_ERROR_WANT_READ) {
        c->read_wait = 0;
        return 0;
    }
    if (e == SSL_ERROR_WANT_WRITE) {    /* a TLS 1.3 KeyUpdate to answer, the socket full */
        c->read_wait = POLLOUT;
        return 0;
    }
    if (e == SSL_ERROR_ZERO_RETURN) {
        /* The server's close_notify: ours back as far as the socket takes it at once. */
        ERR_clear_error();
        SSL_shutdown(c->ssl);
        ERR_clear_error();
        finish(c, BT_TLS_CLOSED, "%s closed the connection (close_notify)", c->peer);
        return 0;
    }
    ssl_failed(c, "TLS read from", e, saved);
    return 0;
}

int bt_tls_pending(const bt_tls* c)
{
    return c->state == BT_TLS_OPEN && c->ssl && (SSL_pending(c->ssl) > 0 || SSL_has_pending(c->ssl));
}

int bt_tls_write(bt_tls* c, const uint8_t* data, size_t len)
{
    if (c->state != BT_TLS_CONNECTING && c->state != BT_TLS_HANDSHAKE && c->state != BT_TLS_OPEN) return 0;
    if (!len) return 1;
    if (len > c->out_max || c->out_len > c->out_max - len) return 0;
    if (!queue_room(c, len)) {
        finish(c, BT_TLS_FAILED, "%s: out of memory for %lu bytes to send", c->peer,
               (unsigned long)(c->out_len + len));
        return 0;
    }
    memcpy(c->out + c->out_off + c->out_len, data, len);
    c->out_len += len;
    if (c->state == BT_TLS_OPEN && !c->flush_wait) flush(c);   /* waiting for poll: poll says when */
    return c->state != BT_TLS_FAILED;
}

size_t bt_tls_queued(const bt_tls* c)
{
    return c->out_len;
}

void bt_tls_close(bt_tls* c, uint64_t now_ns)
{
    if (c->state == BT_TLS_CONNECTING || c->state == BT_TLS_HANDSHAKE) {
        finish(c, BT_TLS_CLOSED, "closed before the connection was open");
        return;
    }
    if (c->state != BT_TLS_OPEN) return;
    c->state = BT_TLS_CLOSING;
    c->deadline = now_ns + c->timeout_ns;
    c->read_wait = 0;
    c->hs_wait = 0;
    c->said_bye = 0;
    closing(c);
}

void bt_tls_free(bt_tls* c)
{
    release(c);
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

/* --------------------------------------------------------------------- words */

const char* bt_tls_state_name(bt_tls_state s)
{
    switch (s) {
    case BT_TLS_IDLE:       return "idle";
    case BT_TLS_CONNECTING: return "connecting";
    case BT_TLS_HANDSHAKE:  return "handshake";
    case BT_TLS_OPEN:       return "open";
    case BT_TLS_CLOSING:    return "closing";
    case BT_TLS_CLOSED:     return "closed";
    case BT_TLS_FAILED:     return "failed";
    }
    return "?";
}

const char* bt_tls_version(const bt_tls* c)
{
    if (!c->ssl || (c->state != BT_TLS_OPEN && c->state != BT_TLS_CLOSING)) return "";
    return SSL_get_version(c->ssl);
}

const char* bt_tls_cipher(const bt_tls* c)
{
    const SSL_CIPHER* s;
    const char* name;

    if (!c->ssl || (c->state != BT_TLS_OPEN && c->state != BT_TLS_CLOSING)) return "";
    s = SSL_get_current_cipher(c->ssl);
    name = s ? SSL_CIPHER_get_name(s) : NULL;
    return name ? name : "";
}
