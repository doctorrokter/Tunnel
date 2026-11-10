/*
 * bt_store - the profiles on disk (docs/DAEMON.md, section 2), in a directory only root can read.
 *
 *   <id>.conf    the configuration exactly as imported - the source of truth, parsed again by the
 *                engine at every connect; it holds the private key. A Tailscale profile keeps its
 *                keys and login here instead, as ts_profile text (ts_profile.h)
 *   <id>.meta    what the daemon keeps about it: name, type, order, handshake timestamp ceiling,
 *                the last addresses its endpoint names resolved to (bt_proto key=value lines)
 *   settings     daemon-wide: the always-on profile, the kill switch
 *
 * A profile exists when its .meta does. Every file is replaced atomically (a temporary file, fsync,
 * rename), .conf before .meta on save and .meta before .conf on delete, so a crash leaves at worst
 * an orphan .conf or a .tmp that bt_store_sweep removes. Files are 0600, the directory 0700.
 *
 * An id is 8 lowercase hex characters and is checked on every call: it comes from a client and
 * becomes part of a path.
 */

#ifndef BT_STORE_H
#define BT_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "wg_crypto.h"

#define BT_ID_LEN           8
#define BT_NAME_MAX         64          /* bytes of UTF-8 */
#define BT_CONF_MAX         (192 * 1024)
#define BT_HOST_MAX         253
#define BT_ADDR_TEXT_MAX    46          /* INET6_ADDRSTRLEN */
#define BT_META_RESOLVED    8
#define BT_PATH_MAX         512

/* A profile type: what the UI shows, taken from the .conf at import. */
#define BT_TYPE_WIREGUARD   "wireguard"
#define BT_TYPE_AMNEZIAWG   "amneziawg"
#define BT_TYPE_TAILSCALE   "tailscale"         /* the .conf is ts_profile text, not WireGuard's */

typedef struct {
    char host[BT_HOST_MAX + 1];
    char addr[BT_ADDR_TEXT_MAX];
} bt_resolved;

typedef struct {
    char        id[BT_ID_LEN + 1];
    char        name[BT_NAME_MAX + 1];
    char        type[16];
    uint64_t    created;                /* unix seconds */
    uint32_t    order;                  /* the user's order in the list */
    /* Handshake timestamps (TAI64N) are never sent below this, across restarts (section 9). Unix
     * seconds; 0 = none yet. */
    uint64_t    ts_ceiling;
    bt_resolved resolved[BT_META_RESOLVED];
    size_t      n_resolved;
} bt_meta;

typedef struct {
    char always_on[BT_ID_LEN + 1];      /* a WireGuard or AmneziaWG profile, "" = none */
    char always_on_tailscale[BT_ID_LEN + 1];    /* a Tailscale profile, "" = none */
    int  kill_switch;
    /* The highest ts_ceiling any profile has had, deleted ones too (unix seconds; 0 = none). A
     * profile's handshake timestamps start above it after a restart: its key may have been another
     * profile's, and that server remembers the newest timestamp it saw (section 9). */
    uint64_t ts_floor;
} bt_settings;

typedef struct {
    char dir[BT_PATH_MAX];
} bt_store;

/* Uses `dir`, creating it (0700) when missing; its parent must exist. Refuses a path that is not
 * a directory, such as a symlink. 1 on success. */
int bt_store_open(bt_store* s, const char* dir);

/* Removes what an interrupted write left behind: *.tmp and a .conf without its .meta. Returns the
 * number of files removed. */
int bt_store_sweep(bt_store* s);

/*
 * Every profile, sorted by order, then creation time, then id. Up to `cap` into `out`; *n is how
 * many there are in all. A .meta that cannot be read is skipped and counted in *bad (may be NULL).
 * 1 on success, 0 when the directory cannot be read.
 */
int bt_store_list(bt_store* s, bt_meta* out, size_t cap, size_t* n, size_t* bad);

int bt_store_load_meta(bt_store* s, const char* id, bt_meta* m);

/* The .conf text, NUL-terminated, in a buffer to hand back to bt_store_free_conf (it holds the
 * private key: the buffer is wiped). NULL when missing or larger than BT_CONF_MAX. */
char* bt_store_load_conf(bt_store* s, const char* id, size_t* len);
void  bt_store_free_conf(char* conf, size_t len);

/* Writes the profile: its .conf when `conf` is not NULL, then its .meta. 1 on success. */
int bt_store_save(bt_store* s, const bt_meta* m, const char* conf, size_t len);

/* 1 when the profile was there and is gone. */
int bt_store_delete(bt_store* s, const char* id);

/* A fresh id no profile has. 1 on success. */
int bt_store_new_id(bt_store* s, const wg_rng* rng, char out[BT_ID_LEN + 1]);

/* Missing settings read as the defaults (no always-on, kill switch off): 1. 0 when the file is
 * there but broken - the defaults are still filled in. */
int bt_store_load_settings(bt_store* s, bt_settings* st);
int bt_store_save_settings(bt_store* s, const bt_settings* st);

/* The daemon's own files next to the profiles (the crash journal): `name` is 1-16 of [a-z_];
 * written atomically like the rest. get: NUL-terminated, malloc'd, NULL when missing or larger
 * than 64 KB. */
int   bt_store_put(bt_store* s, const char* name, const char* data, size_t len);
char* bt_store_get(bt_store* s, const char* name, size_t* len);
int   bt_store_remove(bt_store* s, const char* name);

/* --- the rules, also for the control socket ---------------------------------------------- */

/* 8 lowercase hex characters. */
int bt_id_valid(const char* id);

/* 1-64 bytes of well-formed UTF-8 with no control characters. */
int bt_name_valid(const char* name, size_t len);

/* The .meta text form, for tests and the fuzzer: into `buf`, returns its length (0 when it does
 * not fit). Parsing works in place and needs text[len] writable. */
size_t bt_meta_format(const bt_meta* m, char* buf, size_t cap);
int    bt_meta_parse(bt_meta* m, char* text, size_t len);

#endif /* BT_STORE_H */
