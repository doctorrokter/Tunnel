/*
 * bt_log - see bt_log.h.
 */

#include "bt_log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static struct {
    int          fd;
    char         path[512];
    char         old_path[512];
    size_t       cap;
    size_t       size;              /* of the current file */
    int          uid, gid;
    bt_log_level level;
    int          to_stderr;
    uint64_t   (*now_ms)(void);
    char         ring[BT_LOG_RING];
    size_t       ring_len;          /* whole lines, oldest first */
} g = { -1, "", "", 0, 0, -1, -1, BT_LOG_INFO, 0, NULL, "", 0 };

static uint64_t real_now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

static int open_file(void)
{
    struct stat st;

    g.fd = open(g.path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g.fd < 0) return 0;
    if ((g.uid >= 0 || g.gid >= 0) && fchown(g.fd, (uid_t)g.uid, (gid_t)g.gid) < 0) {
        /* not fatal: the app then cannot read the file, the daemon still logs */
    }
    g.size = fstat(g.fd, &st) == 0 ? (size_t)st.st_size : 0;
    return 1;
}

int bt_log_open(const char* path, const char* old_path, size_t cap, int uid, int gid)
{
    bt_log_close();
    if (!path) return 0;
    if (strlen(path) >= sizeof(g.path) || !old_path || strlen(old_path) >= sizeof(g.old_path)) return 0;
    strcpy(g.path, path);
    strcpy(g.old_path, old_path);
    g.cap = cap < 4096 ? 4096 : cap;
    g.uid = uid;
    g.gid = gid;
    return open_file();
}

void bt_log_close(void)
{
    if (g.fd >= 0) close(g.fd);
    g.fd = -1;
}

void bt_log_set_level(bt_log_level max)
{
    g.level = max;
}

bt_log_level bt_log_get_level(void)
{
    return g.level;
}

void bt_log_set_stderr(int on)
{
    g.to_stderr = on;
}

void bt_log_set_clock(uint64_t (*now_ms)(void))
{
    g.now_ms = now_ms;
}

static void write_all(int fd, const char* p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return;
        p += w;
        n -= (size_t)w;
    }
}

static void ring_append(const char* line, size_t n)
{
    if (n > BT_LOG_RING) return;
    if (g.ring_len + n > BT_LOG_RING) {
        /* Drop the oldest lines: at least what is needed, and at least a quarter of the ring, so
         * the memmove is rare. */
        size_t need = g.ring_len + n - BT_LOG_RING, drop;
        const char* nl;

        if (need < BT_LOG_RING / 4) need = BT_LOG_RING / 4;
        if (need > g.ring_len) need = g.ring_len;
        nl = (const char*)memchr(g.ring + need - 1, '\n', g.ring_len - need + 1);
        drop = nl ? (size_t)(nl - g.ring) + 1 : g.ring_len;
        memmove(g.ring, g.ring + drop, g.ring_len - drop);
        g.ring_len -= drop;
    }
    memcpy(g.ring + g.ring_len, line, n);
    g.ring_len += n;
}

void bt_log(bt_log_level level, const char* fmt, ...)
{
    static const char tag[] = "EWID";
    char line[BT_LOG_LINE_MAX + 1];
    uint64_t ms;
    time_t sec;
    struct tm tm;
    size_t n, i;
    va_list ap;
    int k;

    if (level > g.level) return;
    ms = (g.now_ms ? g.now_ms : real_now_ms)();
    sec = (time_t)(ms / 1000);
    localtime_r(&sec, &tm);
    k = snprintf(line, sizeof(line), "%04d-%02d-%02d %02d:%02d:%02d.%03u %c ", tm.tm_year + 1900,
                 tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, (unsigned)(ms % 1000),
                 tag[level]);
    n = k > 0 ? (size_t)k : 0;
    va_start(ap, fmt);
    k = vsnprintf(line + n, sizeof(line) - n, fmt, ap);
    va_end(ap);
    if (k < 0) k = 0;
    if ((size_t)k >= sizeof(line) - n) {
        n = BT_LOG_LINE_MAX - 4;
        memcpy(line + n, "...", 3);
        n += 3;
    } else {
        n += (size_t)k;
    }
    /* One line stays one line whatever the message holds. */
    for (i = 0; i < n; i++)
        if (line[i] == '\n' || line[i] == '\r') line[i] = ' ';
    line[n++] = '\n';

    ring_append(line, n);
    if (g.to_stderr) write_all(2, line, n);
    if (g.fd >= 0) {
        if (g.size + n > g.cap) {
            close(g.fd);
            g.fd = -1;
            rename(g.path, g.old_path);
            if (!open_file()) return;
        }
        write_all(g.fd, line, n);
        g.size += n;
    }
}

size_t bt_log_tail(char* out, size_t cap, unsigned lines)
{
    size_t start = g.ring_len, len;
    unsigned count = 0;

    if (!cap) return 0;
    /* Walk back over `lines` line ends (the last byte is always a line end). */
    while (start > 0 && count < lines) {
        size_t j = start - 1;                       /* g.ring[j] ends the line before `start` */
        while (j > 0 && g.ring[j - 1] != '\n') j--;
        if (g.ring_len - j > cap - 1) break;        /* with this line it would not fit */
        start = j;
        count++;
    }
    len = g.ring_len - start;
    memcpy(out, g.ring + start, len);
    out[len] = '\0';
    return len;
}
