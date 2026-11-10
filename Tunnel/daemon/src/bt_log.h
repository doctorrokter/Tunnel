/*
 * bt_log - the daemon's journal (docs/DAEMON.md, section 11).
 *
 * One line per call: "2026-09-30 14:03:12.345 I tunnel: up, handshake in 41 ms". Lines go
 *   - to a file, written at once (a crash loses nothing), rotated to a second file when it
 *     reaches its size: at most two files of `cap` bytes. The files are .txt - BB10's viewer will
 *     not open .log - and are given to the app's uid, so the app can show and share them;
 *   - to a ring in memory, which bt_log_tail reads for the Diagnostics screen without touching
 *     the file;
 *   - to stderr as well, when asked (running in the foreground).
 *
 * Never log a private key, a PSK or a HeaderProtectionKey. Single-threaded, like the daemon.
 */

#ifndef BT_LOG_H
#define BT_LOG_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    BT_LOG_ERROR = 0,
    BT_LOG_WARN,
    BT_LOG_INFO,
    BT_LOG_DEBUG
} bt_log_level;

#define BT_LOG_LINE_MAX     512         /* longer lines are cut, ending in "..." */
#define BT_LOG_RING         (32 * 1024)

/*
 * Starts logging to `path`, rotating it to `old_path` at `cap` bytes; the files get `uid`:`gid`
 * (-1: leave them to whoever runs the daemon). `path` NULL: memory (and stderr) only. 1 when the
 * file opened; the memory ring works either way.
 */
int  bt_log_open(const char* path, const char* old_path, size_t cap, int uid, int gid);
void bt_log_close(void);

void bt_log_set_level(bt_log_level max);            /* default INFO */
bt_log_level bt_log_get_level(void);
void bt_log_set_stderr(int on);

/* The clock, for tests: unix milliseconds. NULL restores the real one. */
void bt_log_set_clock(uint64_t (*now_ms)(void));

void bt_log(bt_log_level level, const char* fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

#define BT_E(...) bt_log(BT_LOG_ERROR, __VA_ARGS__)
#define BT_W(...) bt_log(BT_LOG_WARN, __VA_ARGS__)
#define BT_I(...) bt_log(BT_LOG_INFO, __VA_ARGS__)
#define BT_D(...) bt_log(BT_LOG_DEBUG, __VA_ARGS__)

/* The last `lines` lines (fewer when the ring holds fewer), oldest first, into `out` as text ending
 * in a NUL. When they do not fit, the oldest of them are left out. Returns the length. */
size_t bt_log_tail(char* out, size_t cap, unsigned lines);

#endif /* BT_LOG_H */
