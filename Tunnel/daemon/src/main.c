/*
 * bbtunneld - the root daemon (docs/DAEMON.md). One thread, one poll loop:
 *
 *   the control socket and its clients  -> bt_ctl
 *   each tunnel's tun, UDP and DNS fds  -> bt_tunnel
 *   the platform's network-change fds   -> after 500 ms of quiet, bt_tunnels_net_changed
 *
 * At start: the crash journal is replayed (routes of a tun device that outlived us, host routes to
 * the servers, the system's DNS back), then the always-on profile comes up. SIGTERM / SIGINT take
 * everything down cleanly; so does daemon.restart, after which whoever started the daemon starts
 * it again (section 12).
 *
 *   bbtunneld --state DIR --socket PATH [--log FILE.txt] [--owner UID:GID] [--dns-file PATH]
 *             [--egress auto|fib|bind|hostroute] [--ca-file PEM] [--foreground] [--debug]
 *             [--clock-offset SECONDS]
 *
 * --dns-file is the resolv.conf the Linux backend owns; --egress, how our own sockets stay out of
 * the tunnels (section 5; fib is QNX only); --clock-offset moves the wall clock the handshakes see
 * (a test of the timestamp ceiling, section 9); --ca-file adds roots to Tailscale's TLS beside the
 * built-in ones (the .bar's cacert.pem; a test CA on the stand).
 */

#include "bt_ctl.h"
#include "bt_log.h"
#include "bt_plat.h"
#include "bt_store.h"
#include "bt_tls.h"
#include "bt_tunnel.h"
#include "bt_version.h"
#include "wg_crypto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEBOUNCE_NS     (500 * 1000000ULL)
#define JOURNAL         "applied"
#define MAX_FDS         192             /* a Tailscale tunnel alone may poll its control, relays and probes */

static volatile sig_atomic_t stop_signal;
static int restart_asked;
static bt_store store;

static void on_signal(int sig)
{
    stop_signal = sig;
}

static void on_restart(void)
{
    restart_asked = 1;
}

/* --------------------------------------------------------------------- the crash journal */

static void journal_write(void)
{
    static char buf[BT_DNS_TEXT_MAX * 2 + 1024 + BT_BYPASS_MAX * 64];
    bt_writer w;

    bt_writer_init(&w, buf, sizeof(buf));
    bt_put(&w, "applied", "1");
    bt_tunnels_journal(&w);
    if (w.failed) {
        BT_E("journal: too large");
        return;
    }
    if (w.len == strlen("applied=1\n")) {
        bt_store_remove(&store, JOURNAL);
        return;
    }
    if (!bt_store_put(&store, JOURNAL, buf, w.len)) BT_W("journal: cannot write: %s", strerror(errno));
}

static void journal_replay(void)
{
    static bt_block b;
    size_t len, i;
    char* text = bt_store_get(&store, JOURNAL, &len);

    if (!text) return;
    BT_W("the last run did not end cleanly: undoing what it left");
    if (bt_block_parse(&b, text, len, NULL, 0) && bt_block_kind(&b) && strcmp(bt_block_kind(&b), "applied") == 0) {
        for (i = bt_find(&b, "tunnel", 0); i < b.n; i = bt_find(&b, "tunnel", i + 1)) {
            if (!bt_routes_flush(b.kv[i].val)) BT_W("journal: routes of %s: %s", b.kv[i].val, strerror(errno));
            else BT_I("journal: routes of %s gone", b.kv[i].val);
        }
        for (i = bt_find(&b, "bypass", 0); i < b.n; i = bt_find(&b, "bypass", i + 1)) {
            bt_addr a;
            memset(&a, 0, sizeof(a));
            if (inet_pton(AF_INET, b.kv[i].val, a.addr) == 1) a.family = 4;
            else if (inet_pton(AF_INET6, b.kv[i].val, a.addr) == 1) a.family = 6;
            else continue;
            if (!bt_bypass_drop(&a)) BT_W("journal: the host route to %s: %s", b.kv[i].val, strerror(errno));
            else BT_I("journal: the host route to %s gone", b.kv[i].val);
        }
        i = bt_find(&b, "dns", 0);
        if (i < b.n) {
            if (bt_dns_restore_text(b.kv[i].val)) BT_I("journal: the system's DNS is back");
            else BT_W("journal: cannot restore the system's DNS: %s", strerror(errno));
        }
    } else {
        BT_W("journal: unreadable, ignored");
    }
    free(text);
    bt_store_remove(&store, JOURNAL);
}

/*
 * One daemon per state directory: a second one would fight the first over the socket, the tun
 * devices, the routes and the journal. A write lock on state/lock, held for life (the kernel drops
 * it with the process, whatever way it ends).
 */
static int single_instance(const bt_store* s)
{
    char path[BT_PATH_MAX + 8];
    struct flock fl;
    int fd;

    snprintf(path, sizeof(path), "%s/lock", s->dir);
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        BT_E("lock %s: %s", path, strerror(errno));
        return 0;
    }
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    if (fcntl(fd, F_SETLK, &fl) < 0) {
        BT_E("another bbtunneld runs on %s", s->dir);
        close(fd);
        return 0;
    }
    return 1;                           /* the fd stays open: the lock lives with us */
}

static void on_tunnel_changed(bt_tunnel* t)
{
    bt_ctl_event_tunnel(t);
}

/* Before 1.1.0 one profile of any kind was always on, in always_on. A Tailscale one moves to its own
 * place: always_on is for the others now. */
static void always_on_settle(bt_settings* st)
{
    bt_meta m;

    if (!st->always_on[0] || !bt_store_load_meta(&store, st->always_on, &m)) return;
    if (strcmp(m.type, BT_TYPE_TAILSCALE) != 0) return;
    memcpy(st->always_on_tailscale, st->always_on, sizeof(st->always_on_tailscale));
    st->always_on[0] = '\0';
    if (!bt_store_save_settings(&store, st)) BT_W("always-on: cannot save the settings: %s", strerror(errno));
}

static void always_on_up(const char* id)
{
    char err[160] = "";

    if (!id[0]) return;
    BT_I("always-on: %s", id);
    if (!bt_tunnel_up(id, err, sizeof(err)) && err[0]) BT_W("always-on %s: %s", id, err);
}

/*
 * The log's folder when it is missing: on the phone the app's data/logs, which the service writes its
 * own log into too - so it goes to the app's uid. The launcher may start us before the app or its
 * service ever ran, and then there is no folder (docs/APP.md, section 15). One level only: above it
 * is the app's sandbox, which is there or the socket would not be either.
 */
static void log_dir_make(const char* log_path, int uid, int gid)
{
    char dir[BT_PATH_MAX];
    char* slash;

    if (strlen(log_path) >= sizeof(dir)) return;
    strcpy(dir, log_path);
    slash = strrchr(dir, '/');
    if (!slash || slash == dir) return;
    *slash = '\0';
    if (mkdir(dir, 0700) < 0) return;                   /* there already, or nowhere to make it */
    if ((uid >= 0 || gid >= 0) && chown(dir, (uid_t)uid, (gid_t)gid) < 0) {
        /* not fatal: the service then has no log file of its own; ours goes on */
    }
}

/* --------------------------------------------------------------------- arguments */

static void usage(void)
{
    fprintf(stderr,
            "usage: bbtunneld --state DIR --socket PATH [--log FILE.txt] [--owner UID:GID]\n"
            "                 [--dns-file PATH] [--egress auto|fib|bind|hostroute] [--ca-file PEM]\n"
            "                 [--foreground] [--debug] [--clock-offset SECONDS]\n");
    exit(2);
}

int main(int argc, char** argv)
{
    const char* state_dir = NULL;
    const char* sock = NULL;
    const char* log_path = NULL;
    const char* dns_file = NULL;
    const char* egress = NULL;
    const char* ca_file = NULL;
    int owner_uid = -1, owner_gid = -1, foreground = 0, debug = 0, i;
    char old_log[512];
    bt_plat_opts po;
    bt_ctl_opts co;
    bt_tunnel_hooks hooks;
    bt_settings st;
    uint64_t net_due = BT_NEVER;
    struct sigaction sa;

    for (i = 1; i < argc; i++) {
        const char* a = argv[i];
        const char* v = i + 1 < argc ? argv[i + 1] : NULL;
        if (strcmp(a, "--state") == 0 && v) state_dir = argv[++i];
        else if (strcmp(a, "--socket") == 0 && v) sock = argv[++i];
        else if (strcmp(a, "--log") == 0 && v) log_path = argv[++i];
        else if (strcmp(a, "--dns-file") == 0 && v) dns_file = argv[++i];
        else if (strcmp(a, "--egress") == 0 && v) egress = argv[++i];
        else if (strcmp(a, "--ca-file") == 0 && v) ca_file = argv[++i];
        else if (strcmp(a, "--owner") == 0 && v) {
            if (sscanf(argv[++i], "%d:%d", &owner_uid, &owner_gid) != 2) usage();
        } else if (strcmp(a, "--clock-offset") == 0 && v) bt_clock_offset_sec = strtoll(argv[++i], NULL, 10);
        else if (strcmp(a, "--foreground") == 0) foreground = 1;
        else if (strcmp(a, "--debug") == 0) debug = 1;
        else usage();
    }
    if (!state_dir || !sock) usage();

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    umask(077);

    bt_log_set_stderr(foreground);
    bt_log_set_level(debug ? BT_LOG_DEBUG : BT_LOG_INFO);
    if (log_path) {
        /* daemon.txt -> daemon.1.txt */
        const char* dot = strrchr(log_path, '.');
        size_t base = dot ? (size_t)(dot - log_path) : strlen(log_path);
        snprintf(old_log, sizeof(old_log), "%.*s.1%s", (int)base, log_path, dot ? dot : "");
        log_dir_make(log_path, owner_uid, owner_gid);
        if (!bt_log_open(log_path, old_log, 256 * 1024, owner_uid, owner_gid))
            fprintf(stderr, "bbtunneld: cannot open the log %s: %s\n", log_path, strerror(errno));
    }
    BT_I("bbtunneld %s starting%s", BT_VERSION, bt_clock_offset_sec ? " (clock offset for a test)" : "");

    if (!wg_crypto_init()) {
        BT_E("crypto: OpenSSL has no algorithms we need");
        return 1;
    }
    {
        char err[256];
        size_t added = 0;
        /* Tailscale's TLS: the built-in roots, and the file's beside them. Neither failing stops
         * the daemon - WireGuard needs no TLS - but every Tailscale connection would fail. */
        if (!bt_tls_init(err, sizeof(err))) BT_E("TLS: %s", err);
        else if (ca_file && !bt_tls_add_ca_file(ca_file, &added, err, sizeof(err))) BT_W("TLS: %s: %s", ca_file, err);
        else if (ca_file) BT_I("TLS: %u root(s) from %s", (unsigned)added, ca_file);
    }
    if (!bt_store_open(&store, state_dir)) {
        BT_E("state %s: %s", state_dir, strerror(errno));
        return 1;
    }
    if (!single_instance(&store)) return 1;
    if (bt_store_sweep(&store)) BT_I("state: leftovers of an interrupted write removed");
    memset(&po, 0, sizeof(po));
    po.dns_file = dns_file;
    po.egress = egress;
    if (!bt_plat_init(&po)) {
        BT_E("platform: %s", strerror(errno));
        return 1;
    }
    journal_replay();

    memset(&hooks, 0, sizeof(hooks));
    hooks.changed = on_tunnel_changed;
    hooks.applied = journal_write;
    bt_tunnels_init(&store, &hooks);

    memset(&co, 0, sizeof(co));
    co.store = &store;
    co.version = BT_VERSION;
    co.owner_uid = owner_uid;
    co.owner_gid = owner_gid;
    co.restart = on_restart;
    if (!bt_ctl_listen(sock, &co)) {
        BT_E("control socket %s: %s", sock, strerror(errno));
        return 1;
    }

    bt_store_load_settings(&store, &st);
    always_on_settle(&st);
    /* The WireGuard one first: Tailscale's own connections then go inside it when it takes all traffic. */
    always_on_up(st.always_on);
    always_on_up(st.always_on_tailscale);

    while (!stop_signal) {
        struct pollfd pfd[MAX_FDS];
        void* owner[MAX_FDS];
        int n = 0, n_ctl, n_net, k, timeout;
        uint64_t now = bt_now_ns(), next, d;

        if (restart_asked && bt_ctl_idle()) break;

        next = bt_tunnels_tick(now);
        d = bt_ctl_tick(now);
        if (d < next) next = d;
        if (net_due < next) next = net_due;
        d = bt_net_deadline();
        if (d < next) next = d;
        if (restart_asked) next = now + 20 * 1000000ULL;

        n_ctl = bt_ctl_pollfds(pfd, MAX_FDS);
        n = n_ctl;
        n_net = bt_net_fds(pfd + n, MAX_FDS - n);
        n += n_net;
        n += bt_tunnels_pollfds(pfd + n, owner + n, MAX_FDS - n);

        now = bt_now_ns();
        if (next == BT_NEVER) timeout = 60 * 1000;
        else if (next <= now) timeout = 0;
        else {
            uint64_t ms = (next - now + 999999) / 1000000;
            timeout = ms > 60 * 1000 ? 60 * 1000 : (int)ms;
        }
        if (poll(pfd, (nfds_t)n, timeout) < 0 && errno != EINTR) {
            BT_E("poll: %s", strerror(errno));
            break;
        }
        now = bt_now_ns();
        for (k = 0; k < n; k++) {
            if (!pfd[k].revents) continue;
            if (k < n_ctl) bt_ctl_io(&pfd[k]);
            else if (k < n_ctl + n_net) {
                if (bt_net_event(&pfd[k])) net_due = now + DEBOUNCE_NS;
            } else {
                bt_tunnels_io(&pfd[k], owner[k]);
            }
        }
        if (bt_now_ns() >= bt_net_deadline() && bt_net_check(bt_now_ns())) net_due = bt_now_ns() + DEBOUNCE_NS;
        if (net_due != BT_NEVER && bt_now_ns() >= net_due) {
            net_due = BT_NEVER;
            BT_D("network changed");
            bt_tunnels_net_changed(bt_now_ns());
            bt_ctl_event_network();
        }
    }

    BT_I("stopping%s", stop_signal ? " (signal)" : restart_asked ? " for a restart" : "");
    bt_tunnels_down_all();
    bt_store_remove(&store, JOURNAL);
    bt_ctl_close();
    bt_plat_fini();
    bt_tls_fini();
    BT_I("stopped");
    bt_log_close();
    wg_crypto_cleanup();
    return 0;
}
