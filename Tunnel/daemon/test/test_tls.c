/*
 * bt_tls against real peers, through a poll loop like the daemon's:
 *
 *   - openssl s_server with a test PKI (tls/certs.sh, tls/server.sh): a chain to the test root with
 *     the right name, a wrong name, an IP literal, wildcards, an expired certificate, a CN without
 *     SANs, no root to chain to; the sha256-raw pin as Tailscale's tlsdial has it - a self-signed
 *     certificate opens with its pin and only with it, the name still counts but not for an IP
 *     literal, the dates count, one certificate only, derper's meta certificate skipped; SNI; TLS 1.3
 *     with ChaCha20 first, TLS 1.2, nothing older; data both ways in volume to a server that reads
 *     slowly (the queue fills, its limit holds, POLLOUT empties it), our close, the server's
 *     close_notify mid-stream, the server dying mid-stream;
 *   - plain TCP against a listener of the test's own: the same data both ways, the server's close, a
 *     reset, our close;
 *   - a refused connect, a handshake that never comes, a server that is not TLS, bad parameters:
 *     errors, never a hang.
 *
 *   test_tls [certdir]           everything; the PKI is made fresh into certdir (default: tls_certs/
 *                                next to this binary), s_server's own words go to certdir/s_server.log
 *   test_tls --live host...      the built-in roots alone against real servers (needs the network):
 *                                host[:port] must open, -host[:port] must fail
 *
 * The scripts are found next to this source file (__FILE__). Without them (the phone, a moved tree)
 * the s_server parts are skipped, and the output says so.
 */

#include "test_util.h"
#include "../src/bt_tls.h"
#include "../src/bt_roots.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define SEC         BT_NSEC_PER_SEC
#define MSEC        1000000ULL
#define CHUNK       16384
#define UP_SEED     0x5eedu             /* client -> server */
#define DOWN_SEED   0xd0e5u             /* server -> client */

static char scripts[384];               /* tls/ next to this source */
static char certs[384];                 /* the test PKI */
static char server_log[448];

/* ------------------------------------------------------------------ small things */

static uint64_t mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * SEC + (uint64_t)ts.tv_nsec;
}

/* A file of the test PKI; four names at a time. */
static const char* at(const char* name)
{
    static char buf[4][448];
    static int k;

    k = (k + 1) % 4;
    snprintf(buf[k], sizeof(buf[k]), "%s/%s", certs, name);
    return buf[k];
}

static void read_pin(const char* name, char* out, size_t cap)
{
    FILE* f = fopen(at(name), "r");

    out[0] = '\0';
    if (!f) return;
    if (fgets(out, (int)cap, f)) out[strcspn(out, "\r\n")] = '\0';
    fclose(f);
}

static uint8_t pat(uint32_t seed, size_t i)
{
    uint32_t x = (uint32_t)i * 2654435761u + seed * 0x9e3779b9u;
    x ^= x >> 15;
    x *= 0x2c1b3c6du;
    x ^= x >> 12;
    return (uint8_t)x;
}

static void fill(uint8_t* p, uint32_t seed, size_t off, size_t n)
{
    size_t k;
    for (k = 0; k < n; k++) p[k] = pat(seed, off + k);
}

static int matches(const uint8_t* p, uint32_t seed, size_t off, size_t n)
{
    size_t k;
    for (k = 0; k < n; k++)
        if (p[k] != pat(seed, off + k)) return 0;
    return 1;
}

static void nonblock(int fd)
{
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static bt_addr loopback(int family)
{
    bt_addr a;

    memset(&a, 0, sizeof(a));
    a.family = (uint8_t)family;
    if (family == 4) {
        a.addr[0] = 127;
        a.addr[3] = 1;
    } else {
        a.addr[15] = 1;
    }
    return a;
}

static socklen_t loopback_sa(int family, uint16_t port, struct sockaddr_storage* ss)
{
    memset(ss, 0, sizeof(*ss));
    if (family == 6) {
        struct sockaddr_in6* s = (struct sockaddr_in6*)ss;
        s->sin6_family = AF_INET6;
        s->sin6_port = htons(port);
        s->sin6_addr = in6addr_loopback;
        return (socklen_t)sizeof(*s);
    }
    {
        struct sockaddr_in* s = (struct sockaddr_in*)ss;
        s->sin_family = AF_INET;
        s->sin_port = htons(port);
        s->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return (socklen_t)sizeof(*s);
    }
}

/* A loopback listener on any port: the fd, -1 when the family is not there. A small receive buffer
 * when asked - a slow reader then fills it soon, not after megabytes of autotuning. */
static int listener(int family, uint16_t* port, int small)
{
    struct sockaddr_storage ss;
    socklen_t sl = loopback_sa(family, 0, &ss);
    int fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0), one = 1, sz = 16384;

    if (fd < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (small) setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    if (bind(fd, (struct sockaddr*)&ss, sl) < 0 || listen(fd, 8) < 0) {
        close(fd);
        return -1;
    }
    sl = sizeof(ss);
    getsockname(fd, (struct sockaddr*)&ss, &sl);
    *port = ntohs(family == 6 ? ((struct sockaddr_in6*)&ss)->sin6_port : ((struct sockaddr_in*)&ss)->sin_port);
    nonblock(fd);
    return fd;
}

/* A port nothing listens on (as far as anyone can tell a moment later). */
static uint16_t free_port(int family)
{
    uint16_t port = 0;
    int fd = listener(family, &port, 0);

    if (fd < 0) return 0;
    close(fd);
    return port;
}

/* A socket of the test's own with a small send buffer, handed to bt_tls: the queue then fills soon. */
static int small_socket(int family)
{
    int fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0), sz = 8192;

    if (fd >= 0) setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    return fd;
}

static bt_tls_params to(int family, uint16_t port, const char* host, const char* pin)
{
    bt_tls_params p;

    memset(&p, 0, sizeof(p));
    p.addr = loopback(family);
    p.port = port;
    p.host = host;
    p.pin = pin;
    p.timeout_ms = 5000;
    return p;
}

/* The loop until the connection is open, closed or failed (10 s at most). */
static void settle(bt_tls* c)
{
    uint64_t end = mono() + 10 * SEC;

    while ((c->state == BT_TLS_CONNECTING || c->state == BT_TLS_HANDSHAKE || c->state == BT_TLS_CLOSING) &&
           mono() < end) {
        struct pollfd p;
        uint64_t now = mono(), next = bt_tls_tick(c, now);
        int ms = 50;

        if (bt_tls_fd(c) < 0) break;
        if (next != BT_NEVER) ms = next <= now ? 0 : (int)((next - now) / MSEC) + 1;
        if (ms > 50) ms = 50;
        p.fd = bt_tls_fd(c);
        p.events = bt_tls_events(c);
        p.revents = 0;
        if (poll(&p, 1, ms) > 0) bt_tls_step(c, p.revents);
    }
}

/* ------------------------------------------------------------------ s_server */

typedef struct {
    pid_t    pid;
    int      in, out;                   /* its stdin (ours to write), its stdout (ours to read) */
    int      family;
    uint16_t port;
} server;

static const char* const QUIET[] = { "-quiet", NULL };
static const char* const QUIET_EOF[] = { "-quiet", "-no_ign_eof", NULL };   /* stdin's end: close_notify */

static void server_stop(server* s)
{
    if (s->pid > 0) {
        kill(s->pid, SIGKILL);
        waitpid(s->pid, NULL, 0);
    }
    if (s->in >= 0) close(s->in);
    if (s->out >= 0) close(s->out);
    s->pid = -1;
    s->in = s->out = -1;
}

/* Is anything accepting there yet? A blocking connect on loopback answers at once. */
static int accepting(int family, uint16_t port)
{
    struct sockaddr_storage ss;
    socklen_t sl = loopback_sa(family, port, &ss);
    int fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0), ok;

    if (fd < 0) return 0;
    ok = connect(fd, (struct sockaddr*)&ss, sl) == 0;
    close(fd);
    return ok;
}

/* s_server through tls/server.sh: `kind` is the certificate setup, `extra` more flags. 1 once it
 * accepts connections (its probe connection fails its handshake - s_server logs that and goes on). */
static int server_start(server* s, const char* kind, int family, const char* const* extra)
{
    char script[448], port[8], fam[4];
    const char* argv[24];
    int in[2], out[2], n = 0, i;
    uint64_t end;

    memset(s, 0, sizeof(*s));
    s->pid = -1;
    s->in = s->out = -1;
    s->family = family;
    s->port = free_port(family);
    if (!s->port || pipe(in) < 0) return 0;
    if (pipe(out) < 0) {
        close(in[0]);
        close(in[1]);
        return 0;
    }
    snprintf(script, sizeof(script), "%s/server.sh", scripts);
    snprintf(port, sizeof(port), "%u", (unsigned)s->port);
    snprintf(fam, sizeof(fam), "%d", family);
    argv[n++] = "bash";
    argv[n++] = script;
    argv[n++] = certs;
    argv[n++] = kind;
    argv[n++] = port;
    argv[n++] = fam;
    for (i = 0; extra && extra[i] && n < 23; i++) argv[n++] = extra[i];
    argv[n] = NULL;
    fflush(stdout);
    fflush(stderr);
    s->pid = fork();
    if (s->pid == 0) {
        int log = open(server_log, O_WRONLY | O_CREAT | O_APPEND, 0644);
        dup2(in[0], 0);
        dup2(out[1], 1);
        if (log >= 0) dup2(log, 2);
        close(in[0]);
        close(in[1]);
        close(out[0]);
        close(out[1]);
        execv("/bin/bash", (char* const*)argv);
        _exit(127);
    }
    close(in[0]);
    close(out[1]);
    s->in = in[1];
    s->out = out[0];
    if (s->pid < 0) {
        server_stop(s);
        return 0;
    }
    nonblock(s->in);
    nonblock(s->out);
    for (end = mono() + 5 * SEC; mono() < end;) {
        if (accepting(family, s->port)) return 1;
        if (waitpid(s->pid, NULL, WNOHANG) == s->pid) {        /* it gave up: its log says why */
            s->pid = -1;
            break;
        }
        usleep(20 * 1000);
    }
    fprintf(stderr, "  s_server %s did not start (see %s)\n", kind, server_log);
    server_stop(s);
    return 0;
}

/* A connection to `s` as `host` with `pin`: it must open (`words` NULL) or fail with `words` in its
 * error. One check, reported at the caller's line with what happened. */
static void expect(int line, const server* s, const char* host, const char* pin, const char* words)
{
    bt_tls c;
    bt_tls_params p = to(s->family, s->port, host, pin);
    int ok;

    memset(&c, 0, sizeof(c));
    bt_tls_connect(&c, &p, -1, mono());
    settle(&c);
    ok = words ? c.state == BT_TLS_FAILED && strstr(c.error, words) != NULL : c.state == BT_TLS_OPEN;
    t_checks++;
    if (!ok) {
        t_failures++;
        fprintf(stderr, "  FAIL %s:%d: %s%s: %s \"%s\" - wanted %s%s\n", __FILE__, line, host,
                pin ? " (pinned)" : "", bt_tls_state_name(c.state), c.error, words ? "a failure with " : "open",
                words ? words : "");
    }
    bt_tls_free(&c);
}

#define OPENS(s, host, pin)         expect(__LINE__, s, host, pin, NULL)
#define FAILS(s, host, pin, words)  expect(__LINE__, s, host, pin, words)

/* Opens and keeps it for a look. */
static int open_kept(bt_tls* c, const server* s, const char* host, const char* pin)
{
    bt_tls_params p = to(s->family, s->port, host, pin);

    memset(c, 0, sizeof(*c));
    bt_tls_connect(c, &p, -1, mono());
    settle(c);
    if (c->state != BT_TLS_OPEN) fprintf(stderr, "    %s: %s\n", host, c->error);
    return c->state == BT_TLS_OPEN;
}

/* ------------------------------------------------------------------ data through the loop */

enum { END_NEVER = 0, END_WHEN_DONE, END_WHEN_FED };

/*
 * One client and its far end, turned like the daemon turns its loop. The far end is s_server (its
 * stdin is sent to the client, its stdout is what it received) or a listener of ours (the accepted
 * socket both ways). It reads 4 KiB per `slow_ns` when slow.
 */
typedef struct {
    bt_tls*  c;
    server*  s;
    int      lfd, srv;
    size_t   up_total, up_queued, up_seen;      /* client -> far end */
    size_t   down_total, down_fed, down_got;    /* far end -> client */
    int      up_bad, down_bad;                  /* a byte out of place */
    uint64_t slow_ns, slow_next;
    int      end;                               /* when the far end closes cleanly */
    size_t   cut_at;                            /* the client has this much: the far end dies */
    int      cut;
    int      close_when_queued;                 /* the client closes once all of its data is queued */
    int      refused;                           /* bt_tls_write found the queue full */
    int      waited_out;                        /* polled POLLOUT while open with a queue */
} flow;

static int far_in(const flow* f)
{
    return f->s ? f->s->in : f->srv;
}

static int far_out(const flow* f)
{
    return f->s ? f->s->out : f->srv;
}

/* A clean end: s_server's stdin ends (it sends close_notify), ours closes its socket. */
static void far_close(flow* f)
{
    if (f->s) {
        if (f->s->in >= 0) close(f->s->in);
        f->s->in = -1;
    } else if (f->srv >= 0) {
        close(f->srv);
        f->srv = -1;
    }
}

/* Gone mid-stream: s_server is killed, ours resets. */
static void far_cut(flow* f)
{
    f->cut = 1;
    if (f->s) {
        if (f->s->pid > 0) kill(f->s->pid, SIGKILL);
    } else if (f->srv >= 0) {
        struct linger lg;
        lg.l_onoff = 1;
        lg.l_linger = 0;
        setsockopt(f->srv, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        close(f->srv);
        f->srv = -1;
    }
}

static void turn(flow* f)
{
    static uint8_t buf[CHUNK];
    struct pollfd p[5];
    uint64_t now = mono(), next = bt_tls_tick(f->c, now);
    int n = 0, ic = -1, il = -1, iin = -1, iout = -1, ms = 20, i;

    if (bt_tls_fd(f->c) >= 0) {
        ic = n;
        p[n].fd = bt_tls_fd(f->c);
        p[n++].events = bt_tls_events(f->c);
        if (f->c->state == BT_TLS_OPEN && (p[ic].events & POLLOUT) && bt_tls_queued(f->c)) f->waited_out++;
    }
    if (!f->s && f->lfd >= 0 && f->srv < 0) {
        il = n;
        p[n].fd = f->lfd;
        p[n++].events = POLLIN;
    }
    if (far_in(f) >= 0 && f->down_fed < f->down_total) {
        iin = n;
        p[n].fd = far_in(f);
        p[n++].events = POLLOUT;
    }
    if (far_out(f) >= 0) {
        if (now >= f->slow_next) {
            iout = n;
            p[n].fd = far_out(f);
            p[n++].events = POLLIN;
        } else if (f->slow_next - now < (uint64_t)ms * MSEC) {
            ms = (int)((f->slow_next - now) / MSEC) + 1;
        }
    }
    if (next != BT_NEVER && next > now && next - now < (uint64_t)ms * MSEC) ms = (int)((next - now) / MSEC) + 1;
    for (i = 0; i < n; i++) p[i].revents = 0;
    if (poll(p, (nfds_t)n, ms) < 0) return;

    if (ic >= 0) bt_tls_step(f->c, p[ic].revents);
    for (;;) {                                  /* the contract: read until 0 after each step */
        size_t got = bt_tls_read(f->c, buf, sizeof(buf));
        if (!got) break;
        if (!matches(buf, DOWN_SEED, f->down_got, got)) f->down_bad = 1;
        f->down_got += got;
    }
    if (f->cut_at && !f->cut && f->down_got >= f->cut_at) far_cut(f);
    while (f->up_queued < f->up_total) {
        size_t len = f->up_total - f->up_queued < CHUNK ? f->up_total - f->up_queued : CHUNK;
        fill(buf, UP_SEED, f->up_queued, len);
        if (!bt_tls_write(f->c, buf, len)) {
            if (f->c->state == BT_TLS_OPEN) f->refused++;
            break;
        }
        f->up_queued += len;
    }
    if (f->close_when_queued && f->up_queued == f->up_total && f->c->state == BT_TLS_OPEN) bt_tls_close(f->c, mono());

    if (il >= 0 && (p[il].revents & POLLIN)) {
        f->srv = accept(f->lfd, NULL, NULL);
        if (f->srv >= 0) nonblock(f->srv);
    }
    if (iin >= 0 && (p[iin].revents & (POLLOUT | POLLERR | POLLHUP)) && far_in(f) >= 0) {
        size_t len = f->down_total - f->down_fed < CHUNK ? f->down_total - f->down_fed : CHUNK;
        ssize_t w;
        fill(buf, DOWN_SEED, f->down_fed, len);
        w = write(far_in(f), buf, len);
        if (w > 0) f->down_fed += (size_t)w;
    }
    if (iout >= 0 && (p[iout].revents & (POLLIN | POLLHUP | POLLERR)) && far_out(f) >= 0) {
        ssize_t r = read(far_out(f), buf, f->slow_ns ? 4096 : sizeof(buf));
        if (r > 0) {
            if (!matches(buf, UP_SEED, f->up_seen, (size_t)r)) f->up_bad = 1;
            f->up_seen += (size_t)r;
        } else if (r == 0 || (errno != EAGAIN && errno != EINTR)) {
            if (f->s) {
                close(f->s->out);
                f->s->out = -1;
            } else {
                close(f->srv);
                f->srv = -1;
            }
        }
        if (f->slow_ns) f->slow_next = mono() + f->slow_ns;
    }
    if (f->end == END_WHEN_FED && f->down_fed == f->down_total) far_close(f);
    if (f->end == END_WHEN_DONE && f->down_fed == f->down_total && f->down_got == f->down_total &&
        f->up_seen == f->up_total)
        far_close(f);
}

/* Turns until the client is through (closed or failed) and the far end has nothing more coming, or
 * `limit` passes. */
static void run(flow* f, uint64_t limit)
{
    uint64_t end = mono() + limit;

    while (mono() < end) {
        turn(f);
        if (bt_tls_fd(f->c) < 0 && (far_out(f) < 0 || f->up_seen >= f->up_queued)) break;
    }
}

static void flow_init(flow* f, bt_tls* c, server* s, int lfd)
{
    memset(f, 0, sizeof(*f));
    f->c = c;
    f->s = s;
    f->lfd = lfd;
    f->srv = -1;
}

/* What a data test saw, when it failed. */
static void flow_report(const char* name, const flow* f)
{
    fprintf(stderr, "    %s: up %lu/%lu queued %lu%s, down %lu/%lu fed %lu%s, refused %d, waited %d, client %s: %s\n",
            name, (unsigned long)f->up_seen, (unsigned long)f->up_total, (unsigned long)f->up_queued,
            f->up_bad ? " BAD" : "", (unsigned long)f->down_got, (unsigned long)f->down_total,
            (unsigned long)f->down_fed, f->down_bad ? " BAD" : "", f->refused, f->waited_out,
            bt_tls_state_name(f->c->state), f->c->error);
}

/* ------------------------------------------------------------------ without a server */

TEST(before_init)
{
    bt_tls c;
    bt_tls_params p = to(4, 9, "server.test", NULL);

    memset(&c, 0, sizeof(c));
    CHECK(bt_tls_connect(&c, &p, -1, mono()) == 0);
    CHECK(c.state == BT_TLS_FAILED);
    CHECK(strstr(c.error, "bt_tls_init") != NULL);
    bt_tls_free(&c);
}

TEST(roots)
{
    /* X1 and X2 as Let's Encrypt publishes them (and Ubuntu's ca-certificates carries them); YE and
     * YR as the reference has them - `--live` shows real servers chain to them. */
    static const struct {
        const char* name;
        const char* sha256;
    } want[] = {
        { "ISRG Root X1", "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6" },
        { "ISRG Root X2", "69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470" },
        { "Root YE",      "e14ffcad5b0025731006caa43a121a22d8e9700f4fb9cf852f02a708aa5d5666" },
        { "Root YR",      "e57b7e6f150c419102e8d5c055729ff967b9d1a829bf00cec89ca604ebf4a86f" },
    };
    size_t i;

    CHECK(BT_ROOTS_N == 4);
    for (i = 0; i < BT_ROOTS_N && i < 4; i++) {
        BIO* b = BIO_new_mem_buf(bt_roots[i].pem, -1);
        X509* x = b ? PEM_read_bio_X509(b, NULL, NULL, NULL) : NULL;
        EVP_PKEY* key = x ? X509_get0_pubkey(x) : NULL;
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int mdlen = 0, k;
        char cn[80] = "", hex[65] = "";

        CHECK(x != NULL);
        if (x) {
            X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, cn, sizeof(cn));
            CHECK(strcmp(cn, bt_roots[i].name) == 0);
            CHECK(strcmp(bt_roots[i].name, want[i].name) == 0);
            CHECK(key && X509_verify(x, key) == 1);            /* signed by its own key */
            CHECK(X509_check_issued(x, x) == X509_V_OK);       /* its own issuer: a root */
            CHECK(X509_cmp_current_time(X509_get0_notBefore(x)) < 0);
            CHECK(X509_cmp_current_time(X509_get0_notAfter(x)) > 0);
            if (X509_digest(x, EVP_sha256(), md, &mdlen) && mdlen == 32)
                for (k = 0; k < 32; k++) snprintf(hex + 2 * k, 3, "%02x", md[k]);
            CHECK(strcmp(hex, want[i].sha256) == 0);
        }
        X509_free(x);
        BIO_free(b);
    }
}

TEST(init)
{
    char err[256] = "";
    size_t added = 99;

    CHECK(bt_tls_init(err, sizeof(err)) == 1);
    CHECK(bt_tls_init(err, sizeof(err)) == 1);                 /* again: nothing happens */
    CHECK(bt_tls_add_ca_file("/nonexistent/cacert.pem", &added, err, sizeof(err)) == 0);
    CHECK(added == 0);
    CHECK(strstr(err, "/nonexistent/cacert.pem") != NULL);     /* the journal says which file */
}

TEST(bad_parameters)
{
    static const char* hosts[] = { NULL, "", "...", "a b", "tab\there", "new\nline", "[not-an-ip]", "x/y",
                                   "fe80::1%eth0", "under\x01" };
    static const char hex[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    char longest[300], pins[8][128];
    bt_tls c;
    bt_tls_params p;
    size_t i;

    memset(&c, 0, sizeof(c));
    for (i = 0; i < sizeof(hosts) / sizeof(hosts[0]); i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        p = to(4, 9, hosts[i], NULL);
        CHECK(bt_tls_connect(&c, &p, fd, mono()) == 0);
        CHECK(c.state == BT_TLS_FAILED && strstr(c.error, "host name") != NULL);
        CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);     /* handed over: closed with the failure */
    }
    memset(longest, 'a', 254);
    longest[254] = '\0';
    p = to(4, 9, longest, NULL);
    CHECK(bt_tls_connect(&c, &p, -1, mono()) == 0);
    CHECK(strstr(c.error, "host name") != NULL);

    /* Go compares the pin with fmt's %02x text: anything but lowercase never matches. */
    snprintf(pins[0], sizeof(pins[0]), "sha256-raw:%s", hex);
    for (i = 11; pins[0][i]; i++)
        if (pins[0][i] >= 'a') pins[0][i] = (char)(pins[0][i] - 'a' + 'A');
    snprintf(pins[1], sizeof(pins[1]), "sha256-raw:%.63s", hex);
    snprintf(pins[2], sizeof(pins[2]), "sha256-raw:%s0", hex);
    snprintf(pins[3], sizeof(pins[3]), "%s", hex);
    snprintf(pins[4], sizeof(pins[4]), "sha256:%s", hex);
    snprintf(pins[5], sizeof(pins[5]), "sha256-raw:%.63sg", hex);
    snprintf(pins[6], sizeof(pins[6]), "sha256-raw: %s", hex);
    snprintf(pins[7], sizeof(pins[7]), "%s", "");
    for (i = 0; i < 8; i++) {
        p = to(4, 9, "server.test", pins[i]);
        CHECK(bt_tls_connect(&c, &p, -1, mono()) == 0);
        CHECK(c.state == BT_TLS_FAILED && strstr(c.error, "pin") != NULL);
    }
    p = to(4, 9, "server.test", NULL);
    p.addr.family = 0;
    CHECK(bt_tls_connect(&c, &p, -1, mono()) == 0);
    CHECK(strstr(c.error, "address") != NULL);
    CHECK(bt_tls_connect(&c, NULL, -1, mono()) == 0);
    bt_tls_free(&c);
    CHECK(c.state == BT_TLS_IDLE && bt_tls_fd(&c) == -1 && bt_tls_events(&c) == 0);
    CHECK(strcmp(bt_tls_state_name(BT_TLS_OPEN), "open") == 0);
}

TEST(refused)
{
    int plain;

    for (plain = 0; plain <= 1; plain++) {
        bt_tls c;
        bt_tls_params p = to(4, free_port(4), "server.test", NULL);
        uint8_t b[16];
        uint64_t t0 = mono();

        p.plain = plain;
        memset(&c, 0, sizeof(c));
        bt_tls_connect(&c, &p, -1, t0);
        settle(&c);
        CHECK(c.state == BT_TLS_FAILED);
        CHECK(strstr(c.error, "refused") != NULL);
        CHECK(mono() - t0 < 2 * SEC);                          /* at once, not on a timeout */
        CHECK(bt_tls_fd(&c) == -1 && bt_tls_events(&c) == 0);
        CHECK(bt_tls_write(&c, (const uint8_t*)"x", 1) == 0);
        CHECK(bt_tls_read(&c, b, sizeof(b)) == 0);
        CHECK(bt_tls_tick(&c, mono()) == BT_NEVER);
        bt_tls_free(&c);
    }
}

TEST(handshake_never_comes)
{
    bt_tls c;
    uint16_t port = 0;
    int lfd = listener(4, &port, 0);            /* takes the connection, never says a word */
    bt_tls_params p = to(4, port, "server.test", NULL);
    uint64_t t0 = mono(), took;

    REQUIRE(lfd >= 0);
    p.timeout_ms = 300;
    memset(&c, 0, sizeof(c));
    CHECK(bt_tls_connect(&c, &p, -1, t0) == 1);
    settle(&c);
    took = mono() - t0;
    CHECK(c.state == BT_TLS_FAILED);
    CHECK(strstr(c.error, "TLS handshake") != NULL && strstr(c.error, "timed out") != NULL);
    CHECK(took >= 250 * MSEC && took < 3 * SEC);
    bt_tls_free(&c);
    close(lfd);
}

TEST(queue_before_open)
{
    static uint8_t b[1100];
    bt_tls c;
    uint16_t port = 0;
    int lfd = listener(4, &port, 0);            /* the handshake waits forever: writes queue up */
    bt_tls_params p = to(4, port, "server.test", NULL);

    REQUIRE(lfd >= 0);
    p.out_max = 1000;
    memset(&c, 0, sizeof(c));
    REQUIRE(bt_tls_connect(&c, &p, -1, mono()) == 1);
    CHECK(c.state == BT_TLS_CONNECTING || c.state == BT_TLS_HANDSHAKE);
    CHECK(bt_tls_write(&c, b, 600) == 1);
    CHECK(bt_tls_queued(&c) == 600);
    CHECK(bt_tls_write(&c, b, 500) == 0);                      /* past the limit: none of it */
    CHECK(bt_tls_queued(&c) == 600);
    CHECK(c.state == BT_TLS_CONNECTING || c.state == BT_TLS_HANDSHAKE);    /* a full queue is no failure */
    CHECK(bt_tls_write(&c, b, 400) == 1);
    CHECK(bt_tls_queued(&c) == 1000);
    CHECK(bt_tls_write(&c, b, 1) == 0);
    CHECK(bt_tls_write(&c, b, 0) == 1);
    CHECK(bt_tls_write(&c, b, 1001) == 0);
    bt_tls_close(&c, mono());                  /* not open yet: closed at once, the queue dropped */
    CHECK(c.state == BT_TLS_CLOSED && bt_tls_queued(&c) == 0 && bt_tls_fd(&c) == -1);
    bt_tls_free(&c);
    close(lfd);
}

TEST(not_tls)
{
    static const char http[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
    bt_tls c;
    uint16_t port = 0;
    int lfd = listener(4, &port, 0), srv = -1;
    bt_tls_params p = to(4, port, "server.test", NULL);
    uint64_t end;

    REQUIRE(lfd >= 0);
    memset(&c, 0, sizeof(c));
    bt_tls_connect(&c, &p, -1, mono());
    for (end = mono() + 5 * SEC; mono() < end && bt_tls_fd(&c) >= 0;) {
        struct pollfd q[2];
        q[0].fd = bt_tls_fd(&c);
        q[0].events = bt_tls_events(&c);
        q[1].fd = srv < 0 ? lfd : -1;
        q[1].events = POLLIN;
        q[0].revents = q[1].revents = 0;
        poll(q, 2, 50);
        if (q[1].revents & POLLIN) {
            srv = accept(lfd, NULL, NULL);
            if (srv >= 0 && write(srv, http, sizeof(http) - 1) < 0) {}   /* and stays open */
        }
        bt_tls_step(&c, q[0].revents);
        bt_tls_tick(&c, mono());
    }
    CHECK(c.state == BT_TLS_FAILED);
    CHECK(strstr(c.error, "TLS handshake with") != NULL);
    bt_tls_free(&c);
    if (srv >= 0) close(srv);
    close(lfd);
}

/* ------------------------------------------------------------------ plain TCP */

TEST(plain_both_ways)
{
    bt_tls c;
    flow f;
    uint16_t port = 0;
    int lfd = listener(4, &port, 1);
    bt_tls_params p = to(4, port, NULL, NULL);     /* plain: no host to verify */
    int before = t_failures;

    REQUIRE(lfd >= 0);
    p.plain = 1;
    p.out_max = 64 * 1024;
    memset(&c, 0, sizeof(c));
    REQUIRE(bt_tls_connect(&c, &p, small_socket(4), mono()) == 1);
    flow_init(&f, &c, NULL, lfd);
    f.up_total = 4 << 20;
    f.down_total = 2 << 20;
    f.slow_ns = 1 * MSEC;
    f.end = END_WHEN_DONE;
    run(&f, 60 * SEC);
    CHECK(f.up_seen == f.up_total && !f.up_bad);
    CHECK(f.down_got == f.down_total && !f.down_bad);
    CHECK(f.refused > 0);                       /* the queue filled: its limit held ... */
    CHECK(f.waited_out > 0);                    /* ... and POLLOUT emptied it */
    CHECK(c.state == BT_TLS_CLOSED && strstr(c.error, "closed the connection") != NULL);
    CHECK(strcmp(bt_tls_version(&c), "") == 0 && strcmp(bt_tls_cipher(&c), "") == 0);
    if (t_failures != before) flow_report("plain both ways", &f);
    bt_tls_free(&c);
    if (f.srv >= 0) close(f.srv);
    close(lfd);
}

TEST(plain_server_closes)
{
    bt_tls c;
    flow f;
    uint16_t port = 0;
    int lfd = listener(4, &port, 0);
    bt_tls_params p = to(4, port, NULL, NULL);
    int before = t_failures;

    REQUIRE(lfd >= 0);
    p.plain = 1;
    memset(&c, 0, sizeof(c));
    REQUIRE(bt_tls_connect(&c, &p, -1, mono()) == 1);
    flow_init(&f, &c, NULL, lfd);
    f.down_total = 1 << 20;
    f.end = END_WHEN_FED;                       /* all of it, then its FIN */
    run(&f, 30 * SEC);
    CHECK(f.down_got == f.down_total && !f.down_bad);
    CHECK(c.state == BT_TLS_CLOSED && strstr(c.error, "closed the connection") != NULL);
    if (t_failures != before) flow_report("plain server closes", &f);
    bt_tls_free(&c);
    if (f.srv >= 0) close(f.srv);
    close(lfd);
}

TEST(plain_reset)
{
    bt_tls c;
    flow f;
    uint16_t port = 0;
    int lfd = listener(4, &port, 1);
    bt_tls_params p = to(4, port, NULL, NULL);
    int before = t_failures;

    REQUIRE(lfd >= 0);
    p.plain = 1;
    memset(&c, 0, sizeof(c));
    REQUIRE(bt_tls_connect(&c, &p, -1, mono()) == 1);
    flow_init(&f, &c, NULL, lfd);
    f.up_total = 64 << 20;                      /* both ways, without end ... */
    f.down_total = 64 << 20;
    f.slow_ns = 1 * MSEC;
    f.cut_at = 256 * 1024;                      /* ... until a reset */
    run(&f, 10 * SEC);
    CHECK(c.state == BT_TLS_FAILED && strstr(c.error, "reset") != NULL);
    CHECK(f.down_got >= f.cut_at && !f.down_bad && !f.up_bad);
    CHECK(bt_tls_fd(&c) == -1);
    if (t_failures != before) flow_report("plain reset", &f);
    bt_tls_free(&c);
    close(lfd);
}

TEST(plain_our_close)
{
    bt_tls c;
    flow f;
    uint16_t port = 0;
    int lfd = listener(4, &port, 1);
    bt_tls_params p = to(4, port, NULL, NULL);
    int before = t_failures;

    REQUIRE(lfd >= 0);
    p.plain = 1;
    p.out_max = 512 * 1024;
    memset(&c, 0, sizeof(c));
    REQUIRE(bt_tls_connect(&c, &p, small_socket(4), mono()) == 1);
    flow_init(&f, &c, NULL, lfd);
    f.up_total = 300 * 1024;
    f.slow_ns = 1 * MSEC;
    f.close_when_queued = 1;                    /* the queue goes out first, then the FIN */
    run(&f, 30 * SEC);
    CHECK(f.up_seen == f.up_total && !f.up_bad);
    CHECK(c.state == BT_TLS_CLOSED && strcmp(c.error, "closed") == 0);
    if (t_failures != before) flow_report("plain our close", &f);
    bt_tls_free(&c);
    if (f.srv >= 0) close(f.srv);
    close(lfd);
}

/*
 * Our close while the far end still talks, its window full: what it sends must be read and thrown
 * away, and the socket must not close before the far end's end. A close() with unread bytes is
 * answered with a reset, and the reset throws away what our kernel had not sent yet - the tail.
 */
TEST(plain_close_while_server_talks)
{
    bt_tls c;
    flow f;
    uint16_t port = 0;
    int lfd = listener(4, &port, 1);
    bt_tls_params p = to(4, port, NULL, NULL);
    int before = t_failures;

    REQUIRE(lfd >= 0);
    p.plain = 1;
    p.out_max = 512 * 1024;
    memset(&c, 0, sizeof(c));
    REQUIRE(bt_tls_connect(&c, &p, small_socket(4), mono()) == 1);
    flow_init(&f, &c, NULL, lfd);
    f.up_total = 300 * 1024;
    f.down_total = 64 << 20;                    /* it never stops talking */
    f.slow_ns = 1 * MSEC;
    f.close_when_queued = 1;
    run(&f, 30 * SEC);
    CHECK(f.up_seen == f.up_total && !f.up_bad);               /* the tail too */
    CHECK(c.state == BT_TLS_CLOSED && strcmp(c.error, "closed") == 0);
    if (t_failures != before) flow_report("plain close while it talks", &f);
    bt_tls_free(&c);
    if (f.srv >= 0) close(f.srv);
    close(lfd);
}

/* ------------------------------------------------------------------ s_server: verification */

TEST(chain_and_names)
{
    char err[256] = "";
    size_t added = 0;
    server s;

    bt_tls_fini();                              /* the built-in roots only, to start with */
    REQUIRE(bt_tls_init(err, sizeof(err)));
    REQUIRE(server_start(&s, "good", 4, QUIET));
    FAILS(&s, "server.test", NULL, "unable to get local issuer certificate");
    CHECK(bt_tls_add_ca_file(at("root.pem"), &added, err, sizeof(err)) == 1);
    CHECK(added == 1);
    OPENS(&s, "server.test", NULL);
    OPENS(&s, "server.test.", NULL);            /* the trailing dot goes, as in Go */
    OPENS(&s, "Server.TEST", NULL);             /* names match whatever their case */
    OPENS(&s, "127.0.0.1", NULL);               /* an IP literal against the IP SANs */
    OPENS(&s, "x.wild.test", NULL);
    FAILS(&s, "x.y.wild.test", NULL, "hostname mismatch");     /* a wildcard is one whole label */
    FAILS(&s, "wild.test", NULL, "hostname mismatch");
    FAILS(&s, "wx.part.test", NULL, "hostname mismatch");      /* never part of one (w*.part.test) */
    FAILS(&s, "other.test", NULL, "hostname mismatch");
    FAILS(&s, "10.1.2.3", NULL, "IP address mismatch");
    server_stop(&s);
}

TEST(expired_and_cn_only)
{
    server s;

    REQUIRE(server_start(&s, "expired", 4, QUIET));
    FAILS(&s, "server.test", NULL, "certificate has expired");
    server_stop(&s);
    REQUIRE(server_start(&s, "cnonly", 4, QUIET));
    FAILS(&s, "cnonly.test", NULL, "hostname mismatch");      /* never the CN, as Go */
    server_stop(&s);
}

TEST(pin)
{
    char self[128], srv[128], expired[128];
    server s;

    read_pin("self.pin", self, sizeof(self));
    read_pin("server.pin", srv, sizeof(srv));
    read_pin("expired.pin", expired, sizeof(expired));
    REQUIRE(strlen(self) == 75 && strlen(srv) == 75 && strlen(expired) == 75);

    REQUIRE(server_start(&s, "self", 4, QUIET));
    FAILS(&s, "self.test", NULL, "signed certificate");        /* no pin: nothing vouches for it */
    OPENS(&s, "self.test", self);                               /* the pin is the trust, no root needed */
    OPENS(&s, "alt.test", self);
    FAILS(&s, "self.test", srv, "not the pinned one");         /* another certificate's pin */
    FAILS(&s, "other.test", self, "not for this name");        /* the name still counts ... */
    OPENS(&s, "127.0.0.1", self);               /* ... but not for an IP literal: no SNI, no name check */
    server_stop(&s);

    REQUIRE(server_start(&s, "self_meta", 4, QUIET));
    OPENS(&s, "self.test", self);                               /* derper's meta certificate is skipped */
    server_stop(&s);

    REQUIRE(server_start(&s, "self_extra", 4, QUIET));
    FAILS(&s, "self.test", self, "more than one certificate"); /* nothing else may come with it */
    server_stop(&s);

    REQUIRE(server_start(&s, "good", 4, QUIET));
    /* a CA's leaf pinned, with its intermediate sent along: refused, as Go refuses it */
    FAILS(&s, "server.test", srv, "more than one certificate");
    server_stop(&s);

    REQUIRE(server_start(&s, "expired", 4, QUIET));
    FAILS(&s, "server.test", expired, "has expired");          /* the dates count under a pin too */
    server_stop(&s);
}

TEST(sni)
{
    char self[128];
    server s;

    read_pin("self.pin", self, sizeof(self));
    REQUIRE(server_start(&s, "self_sni", 4, QUIET));
    OPENS(&s, "self.test", self);
    FAILS(&s, "alt.test", self, "unrecognized name");          /* SNI is the host; this one wants self.test */
    OPENS(&s, "127.0.0.1", self);                               /* and an IP literal sends none */
    server_stop(&s);
}

TEST(ipv6)
{
    uint16_t port;
    int probe = listener(6, &port, 0);
    server s;

    if (probe < 0) {
        printf("  (no IPv6 loopback here: ipv6 skipped)\n");
        return;
    }
    close(probe);
    REQUIRE(server_start(&s, "good", 6, QUIET));
    OPENS(&s, "server.test", NULL);
    OPENS(&s, "::1", NULL);
    OPENS(&s, "[::1]", NULL);
    server_stop(&s);
}

TEST(protocols)
{
    static const char* const tls12[] = { "-quiet", "-tls1_2", NULL };
    static const char* const tls11[] = { "-quiet", "-tls1_1", "-cipher", "DEFAULT@SECLEVEL=0", NULL };
    server s;
    bt_tls c;

    REQUIRE(server_start(&s, "good", 4, QUIET));
    CHECK(open_kept(&c, &s, "server.test", NULL));
    CHECK(strcmp(bt_tls_version(&c), "TLSv1.3") == 0);
    /* ChaCha20 first, and s_server goes by the client's order */
    CHECK(strcmp(bt_tls_cipher(&c), "TLS_CHACHA20_POLY1305_SHA256") == 0);
    bt_tls_free(&c);
    server_stop(&s);

    REQUIRE(server_start(&s, "good", 4, tls12));
    CHECK(open_kept(&c, &s, "server.test", NULL));
    CHECK(strcmp(bt_tls_version(&c), "TLSv1.2") == 0);
    CHECK(strcmp(bt_tls_cipher(&c), "ECDHE-ECDSA-CHACHA20-POLY1305") == 0);
    bt_tls_free(&c);
    server_stop(&s);

    REQUIRE(server_start(&s, "good", 4, tls11));
    FAILS(&s, "server.test", NULL, "protocol");                /* nothing older than TLS 1.2 */
    server_stop(&s);
}

/* ------------------------------------------------------------------ s_server: data */

TEST(both_ways_slow_server)
{
    server s;
    bt_tls c;
    flow f;
    bt_tls_params p;
    int before = t_failures;

    REQUIRE(server_start(&s, "good", 4, QUIET_EOF));
    p = to(4, s.port, "server.test", NULL);
    p.out_max = 64 * 1024;
    memset(&c, 0, sizeof(c));
    REQUIRE(bt_tls_connect(&c, &p, small_socket(4), mono()) == 1);    /* our own socket, handed over */
    flow_init(&f, &c, &s, -1);
    f.up_total = 4 << 20;
    f.down_total = 2 << 20;
    f.slow_ns = 1 * MSEC;
    f.end = END_WHEN_DONE;                      /* then s_server's stdin ends: close_notify */
    run(&f, 60 * SEC);
    CHECK(f.up_seen == f.up_total && !f.up_bad);               /* every byte, in order */
    CHECK(f.down_got == f.down_total && !f.down_bad);
    CHECK(f.refused > 0);                       /* the queue filled: its limit held ... */
    CHECK(f.waited_out > 0);                    /* ... and POLLOUT emptied it */
    CHECK(c.state == BT_TLS_CLOSED && strstr(c.error, "close_notify") != NULL);
    if (t_failures != before) flow_report("both ways", &f);
    bt_tls_free(&c);
    server_stop(&s);
}

TEST(our_close)
{
    server s;
    bt_tls c;
    flow f;
    bt_tls_params p;
    int before = t_failures;

    REQUIRE(server_start(&s, "good", 4, QUIET));
    p = to(4, s.port, "server.test", NULL);
    p.out_max = 512 * 1024;
    memset(&c, 0, sizeof(c));
    REQUIRE(bt_tls_connect(&c, &p, small_socket(4), mono()) == 1);
    flow_init(&f, &c, &s, -1);
    f.up_total = 300 * 1024;
    f.down_total = 64 << 20;                    /* s_server keeps talking meanwhile */
    f.slow_ns = 1 * MSEC;
    f.close_when_queued = 1;                    /* the queue goes out first, then close_notify */
    run(&f, 30 * SEC);
    CHECK(f.up_seen == f.up_total && !f.up_bad);
    CHECK(c.state == BT_TLS_CLOSED && strcmp(c.error, "closed") == 0);
    if (t_failures != before) flow_report("our close", &f);
    bt_tls_free(&c);
    server_stop(&s);
}

TEST(server_closes_mid_stream)
{
    server s;
    bt_tls c;
    flow f;
    bt_tls_params p;
    uint8_t one = 0;
    int before = t_failures;

    REQUIRE(server_start(&s, "good", 4, QUIET_EOF));
    p = to(4, s.port, "server.test", NULL);
    memset(&c, 0, sizeof(c));
    REQUIRE(bt_tls_connect(&c, &p, -1, mono()) == 1);
    settle(&c);
    REQUIRE(c.state == BT_TLS_OPEN);
    /* What OpenSSL decrypted and the caller did not take yet is invisible to poll: bt_tls_pending. */
    REQUIRE(write(s.in, "0123456789", 10) == 10);
    while (c.state == BT_TLS_OPEN && !bt_tls_pending(&c)) {
        struct pollfd q;
        q.fd = bt_tls_fd(&c);
        q.events = bt_tls_events(&c);
        q.revents = 0;
        if (poll(&q, 1, 2000) <= 0) break;
        bt_tls_step(&c, q.revents);
        if (bt_tls_read(&c, &one, 1) == 1) break;
    }
    CHECK(one == '0');
    CHECK(bt_tls_pending(&c));
    flow_init(&f, &c, &s, -1);                  /* the other nine are not the pattern: */
    {
        uint8_t rest[16];
        CHECK(bt_tls_read(&c, rest, sizeof(rest)) == 9 && memcmp(rest, "123456789", 9) == 0);
    }
    CHECK(!bt_tls_pending(&c));
    f.down_total = 1 << 20;
    f.end = END_WHEN_FED;                       /* a megabyte, then its stdin ends: close_notify */
    run(&f, 30 * SEC);
    CHECK(f.down_got == f.down_total && !f.down_bad);           /* exactly all of it ... */
    CHECK(c.state == BT_TLS_CLOSED && strstr(c.error, "close_notify") != NULL);    /* ... then a clean end */
    if (t_failures != before) flow_report("server closes", &f);
    bt_tls_free(&c);
    server_stop(&s);
}

TEST(server_dies_mid_stream)
{
    server s;
    bt_tls c;
    flow f;
    bt_tls_params p;
    uint64_t t0;
    int before = t_failures;

    REQUIRE(server_start(&s, "good", 4, QUIET));
    p = to(4, s.port, "server.test", NULL);
    memset(&c, 0, sizeof(c));
    REQUIRE(bt_tls_connect(&c, &p, -1, mono()) == 1);
    flow_init(&f, &c, &s, -1);
    f.up_total = 64 << 20;                      /* both ways, without end ... */
    f.down_total = 64 << 20;
    f.slow_ns = 1 * MSEC;
    f.cut_at = 512 * 1024;                      /* ... until s_server is killed */
    t0 = mono();
    run(&f, 15 * SEC);
    CHECK(c.state == BT_TLS_FAILED && c.error[0]);
    CHECK(f.cut && mono() - t0 < 10 * SEC);    /* an error, not a hang */
    CHECK(f.down_got >= f.cut_at && !f.down_bad && !f.up_bad);
    CHECK(bt_tls_fd(&c) == -1);
    if (t_failures != before) flow_report("server dies", &f);
    else printf("    (the client said: %s)\n", c.error);
    bt_tls_free(&c);
    server_stop(&s);
}

/* ------------------------------------------------------------------ --live */

/* The built-in roots alone against real servers: host[:port] must open, -host[:port] must fail. */
static int live(int n, char** hosts)
{
    char err[256];
    int i, bad = 0;

    if (!bt_tls_init(err, sizeof(err))) {
        printf("%s\n", err);
        return 1;
    }
    for (i = 0; i < n; i++) {
        const char* arg = hosts[i];
        int want_fail = arg[0] == '-';
        char host[256], port[8] = "443";
        const char* colon;
        struct addrinfo hints, *res = NULL, *a;
        bt_tls c;
        bt_tls_params p;
        int ok;

        if (want_fail) arg++;
        colon = strchr(arg, ':');
        snprintf(host, sizeof(host), "%.*s", colon ? (int)(colon - arg) : (int)strlen(arg), arg);
        if (colon) snprintf(port, sizeof(port), "%s", colon + 1);
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, port, &hints, &res) != 0 || !res) {
            printf("  %-44s no address\n", arg);
            bad = 1;
            continue;
        }
        for (a = res; a && a->ai_family != AF_INET; a = a->ai_next) {}    /* IPv4 first: WSL may lack v6 */
        if (!a) a = res;
        memset(&p, 0, sizeof(p));
        if (a->ai_family == AF_INET) {
            p.addr.family = 4;
            memcpy(p.addr.addr, &((struct sockaddr_in*)a->ai_addr)->sin_addr, 4);
        } else {
            p.addr.family = 6;
            memcpy(p.addr.addr, &((struct sockaddr_in6*)a->ai_addr)->sin6_addr, 16);
        }
        freeaddrinfo(res);
        p.port = (uint16_t)atoi(port);
        p.host = host;
        p.timeout_ms = 10000;
        memset(&c, 0, sizeof(c));
        bt_tls_connect(&c, &p, -1, mono());
        settle(&c);
        ok = want_fail ? c.state == BT_TLS_FAILED : c.state == BT_TLS_OPEN;
        if (c.state == BT_TLS_OPEN)
            printf("  %-44s %s  %s %s\n", arg, ok ? "ok" : "OPENED (wanted a failure)", bt_tls_version(&c),
                   bt_tls_cipher(&c));
        else
            printf("  %-44s %s  %s\n", arg, ok ? "refused, as wanted:" : "FAILED", c.error);
        if (!ok) bad = 1;
        bt_tls_free(&c);
    }
    bt_tls_fini();
    return bad;
}

/* ------------------------------------------------------------------ main */

/* The scripts next to this source; the PKI made fresh. 1 when s_server can be used. */
static int prepare(const char* argv0, const char* certdir)
{
    const char* slash = strrchr(__FILE__, '/');
    char cmd[1024], probe[448];

    if (!slash) return 0;
    snprintf(scripts, sizeof(scripts), "%.*s/tls", (int)(slash - __FILE__), __FILE__);
    snprintf(probe, sizeof(probe), "%s/certs.sh", scripts);
    if (access(probe, R_OK) != 0) return 0;
    if (certdir) {
        snprintf(certs, sizeof(certs), "%s", certdir);
    } else {
        const char* s = strrchr(argv0, '/');
        snprintf(certs, sizeof(certs), "%.*s/tls_certs", s ? (int)(s - argv0) : 1, s ? argv0 : ".");
    }
    snprintf(server_log, sizeof(server_log), "%s/s_server.log", certs);
    snprintf(cmd, sizeof(cmd), "bash '%s' '%s'", probe, certs);
    if (system(cmd) != 0) {
        fprintf(stderr, "  certs.sh failed\n");
        return 0;
    }
    return 1;
}

int main(int argc, char** argv)
{
    signal(SIGPIPE, SIG_IGN);                   /* as the daemon: OpenSSL writes with write() */
    if (argc > 1 && strcmp(argv[1], "--live") == 0) return live(argc - 2, argv + 2);

    printf("test_tls\n");
    RUN(before_init);
    RUN(roots);
    RUN(init);
    RUN(bad_parameters);
    RUN(refused);
    RUN(handshake_never_comes);
    RUN(queue_before_open);
    RUN(not_tls);
    RUN(plain_both_ways);
    RUN(plain_server_closes);
    RUN(plain_reset);
    RUN(plain_our_close);
    RUN(plain_close_while_server_talks);
    if (prepare(argv[0], argc > 1 ? argv[1] : NULL)) {
        RUN(chain_and_names);
        RUN(expired_and_cn_only);
        RUN(pin);
        RUN(sni);
        RUN(ipv6);
        RUN(protocols);
        RUN(both_ways_slow_server);
        RUN(our_close);
        RUN(server_closes_mid_stream);
        RUN(server_dies_mid_stream);
    } else {
        printf("  SKIPPED: everything against s_server (no tls/certs.sh next to %s, or it failed)\n", __FILE__);
    }
    bt_tls_fini();
    return t_summary("test_tls");
}
