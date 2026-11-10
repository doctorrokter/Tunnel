/*
 * btctl - a command-line client of bbtunneld's control socket: the e2e tests drive the daemon with
 * it, and on the phone it is the way to talk to the daemon over SSH before the app can.
 *
 *   btctl [-s SOCKET] [-t SECONDS] [-k KEY] <command> [key=value ...]
 *       sends one request and prints every block that comes back up to its reply; a value
 *       @FILE is the file's contents (a .conf); -k KEY prints only that key of the reply, unescaped
 *       (log.tail: -k text). Exit 0 when errno=0, 1 when the daemon refused, 2 when it could not
 *       be asked.
 *
 *   btctl [-s SOCKET] [-t SECONDS] wait <profile> <state>
 *       watches until the profile's tunnel is in that state (up, connecting, down...): exit 0, or 1
 *       at the timeout (default 20 s).
 *
 *   btctl [-s SOCKET] [-t SECONDS] watch [stats]
 *       prints events for that long (default: until interrupted).
 */

#include "bt_proto.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_SOCKET  "/var/run/bbtunneld.sock"

static char rbuf[BT_BLOCK_MAX + 4];
static char wbuf[BT_BLOCK_MAX + 4096];
static bt_block blk;
static bt_reader reader;
static int fd = -1;

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int connect_to(const char* path)
{
    struct sockaddr_un sa;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    return connect(fd, (struct sockaddr*)&sa, sizeof(sa)) == 0;
}

static int send_all(const char* p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return 0;
        p += w;
        n -= (size_t)w;
    }
    return 1;
}

static char* slurp(const char* path, size_t* len)
{
    FILE* f = fopen(path, "rb");
    char* buf;
    long n;

    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0 || n > BT_BLOCK_MAX) {
        fclose(f);
        return NULL;
    }
    buf = (char*)malloc((size_t)n + 1);
    if (buf && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    if (buf) {
        buf[n] = '\0';
        *len = (size_t)n;
    }
    return buf;
}

/* The next block, waiting until `deadline` (ms, monotonic): 1, or 0 at the deadline / on EOF. */
static int next_block(long long deadline)
{
    for (;;) {
        int rc = bt_reader_next(&reader, &blk, NULL, 0);
        struct pollfd p;
        long long left;
        size_t room;
        char* space;
        ssize_t n;

        if (rc == 1) return 1;
        if (rc < 0) return 0;
        left = deadline - now_ms();
        if (deadline >= 0 && left <= 0) return 0;
        p.fd = fd;
        p.events = POLLIN;
        if (poll(&p, 1, deadline < 0 ? -1 : (int)left) <= 0) continue;
        space = bt_reader_space(&reader, &room);
        n = read(fd, space, room);
        if (n <= 0) return 0;
        bt_reader_commit(&reader, (size_t)n);
    }
}

static void print_block(void)
{
    size_t i, j;
    for (i = 0; i < blk.n; i++) {
        printf("%s=", blk.kv[i].key);
        for (j = 0; j < blk.kv[i].val_len; j++) {
            char c = blk.kv[i].val[j];
            if (c == '\n') fputs("\\n", stdout);
            else if (c == '\r') fputs("\\r", stdout);
            else if (c == '\\') fputs("\\\\", stdout);
            else putchar(c);
        }
        putchar('\n');
    }
    putchar('\n');
    fflush(stdout);
}

static int request(const char* cmd, const char* id, int nargs, char** args)
{
    bt_writer w;
    int i;

    bt_writer_init(&w, wbuf, sizeof(wbuf));
    bt_put(&w, "cmd", cmd);
    bt_put(&w, "id", id);
    for (i = 0; i < nargs; i++) {
        char* eq = strchr(args[i], '=');
        if (!eq) {
            fprintf(stderr, "btctl: %s: not key=value\n", args[i]);
            return 0;
        }
        *eq = '\0';
        if (eq[1] == '@') {
            size_t len;
            char* text = slurp(eq + 2, &len);
            if (!text) {
                fprintf(stderr, "btctl: cannot read %s\n", eq + 2);
                return 0;
            }
            bt_put_n(&w, args[i], text, len);
            free(text);
        } else {
            bt_put(&w, args[i], eq + 1);
        }
    }
    if (!bt_end(&w)) {
        fprintf(stderr, "btctl: request too large or malformed\n");
        return 0;
    }
    return send_all(w.buf, w.len);
}

static int is_reply_to(const char* id)
{
    const char* kind = bt_block_kind(&blk);
    const char* rid = bt_get(&blk, "id");
    return kind && strcmp(kind, "reply") == 0 && rid && strcmp(rid, id) == 0;
}

int main(int argc, char** argv)
{
    const char* sock = DEFAULT_SOCKET;
    const char* only = NULL;
    double timeout = -1;
    long long deadline;
    int i = 1;

    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) sock = argv[i + 1];
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) timeout = atof(argv[i + 1]);
        else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) only = argv[i + 1];
        else {
            fprintf(stderr, "btctl: unknown option %s\n", argv[i]);
            return 2;
        }
        i += 2;
    }
    if (i >= argc) {
        fprintf(stderr, "usage: btctl [-s SOCKET] [-t SECONDS] [-k KEY] <command> [key=value ...]\n"
                        "       btctl [-s SOCKET] [-t SECONDS] wait <profile> <state>\n"
                        "       btctl [-s SOCKET] [-t SECONDS] watch [stats]\n");
        return 2;
    }
    bt_reader_init(&reader, rbuf, sizeof(rbuf));
    if (!connect_to(sock)) {
        fprintf(stderr, "btctl: %s: %s\n", sock, strerror(errno));
        return 2;
    }

    if (strcmp(argv[i], "wait") == 0) {
        const char* profile;
        const char* want;
        if (i + 2 >= argc) return 2;
        profile = argv[i + 1];
        want = argv[i + 2];
        deadline = now_ms() + (long long)((timeout < 0 ? 20 : timeout) * 1000);
        if (!send_all("cmd=watch\nid=w\n\ncmd=status\nid=s\n\n", 34)) return 2;
        {
            int listed = 0;                 /* the status listed the profile */
            while (next_block(deadline)) {
                const char* kind = bt_block_kind(&blk);
                const char* p = bt_get(&blk, "profile");
                const char* s = bt_get(&blk, "state");
                int is_tunnel = kind && (strcmp(kind, "item") == 0 || strcmp(kind, "event") == 0) &&
                                strcmp(blk.kv[0].val, "tunnel") == 0;
                if (is_tunnel && p && s && strcmp(p, profile) == 0 && strcmp(s, want) == 0) {
                    print_block();
                    return 0;
                }
                if (is_tunnel && p && strcmp(p, profile) == 0) {
                    if (strcmp(kind, "item") == 0) listed = 1;
                    print_block();
                }
                /* "down" is also a status that does not list the tunnel at all */
                if (strcmp(want, "down") == 0 && is_reply_to("s") && !listed) return 0;
            }
        }
        fprintf(stderr, "btctl: %s did not reach %s\n", profile, want);
        return 1;
    }

    if (strcmp(argv[i], "watch") == 0) {
        char req[64];
        int stats = i + 1 < argc && strcmp(argv[i + 1], "stats") == 0;
        int len = snprintf(req, sizeof(req), "cmd=watch\nid=w\nstats=%d\n\n", stats);
        deadline = timeout < 0 ? -1 : now_ms() + (long long)(timeout * 1000);
        if (!send_all(req, (size_t)len)) return 2;
        while (next_block(deadline)) print_block();
        return 0;
    }

    if (!request(argv[i], "1", argc - i - 1, argv + i + 1)) return 2;
    deadline = now_ms() + (long long)((timeout < 0 ? 30 : timeout) * 1000);
    while (next_block(deadline)) {
        if (is_reply_to("1")) {
            uint64_t code = 0;
            if (only) {
                const char* v = bt_get(&blk, only);
                if (v) fputs(v, stdout);
                if (v && only[0] && v[0] && v[strlen(v) - 1] != '\n') putchar('\n');
            } else {
                print_block();
            }
            if (bt_get_u64(&blk, "errno", 1000, &code) != 1) return 2;
            if (code && only) {
                const char* e = bt_get(&blk, "error");
                fprintf(stderr, "btctl: errno=%u %s\n", (unsigned)code, e ? e : "");
            }
            return code ? 1 : 0;
        }
        if (!only) print_block();
    }
    fprintf(stderr, "btctl: no reply\n");
    return 2;
}
