/*
 * bt_store - see bt_store.h.
 */

#include "bt_store.h"
#include "bt_proto.h"
#include "wg_conf.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define META_MAX        8192
#define SETTINGS_MAX    1024

/* --------------------------------------------------------------------- rules */

int bt_id_valid(const char* id)
{
    size_t i;

    if (!id) return 0;
    for (i = 0; i < BT_ID_LEN; i++)
        if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) return 0;
    return id[BT_ID_LEN] == '\0';
}

int bt_name_valid(const char* name, size_t len)
{
    const unsigned char* s = (const unsigned char*)name;
    size_t i = 0;

    if (!len || len > BT_NAME_MAX) return 0;
    while (i < len) {
        unsigned c = s[i], cp, need, k;

        if (c < 0x80) {
            if (c < 0x20 || c == 0x7f) return 0;
            i++;
            continue;
        }
        if (c >= 0xc2 && c <= 0xdf) { need = 1; cp = c & 0x1f; }
        else if (c >= 0xe0 && c <= 0xef) { need = 2; cp = c & 0x0f; }
        else if (c >= 0xf0 && c <= 0xf4) { need = 3; cp = c & 0x07; }
        else return 0;
        if (len - i - 1 < need) return 0;
        for (k = 1; k <= need; k++) {
            if ((s[i + k] & 0xc0) != 0x80) return 0;
            cp = (cp << 6) | (s[i + k] & 0x3f);
        }
        if ((need == 2 && cp < 0x800) || (need == 3 && (cp < 0x10000 || cp > 0x10ffff))) return 0;
        if (cp >= 0xd800 && cp <= 0xdfff) return 0;     /* surrogates */
        if (cp >= 0x80 && cp <= 0x9f) return 0;         /* C1 controls */
        i += need + 1;
    }
    return 1;
}

static int host_valid(const char* h, size_t len)
{
    size_t i;

    if (!len || len > BT_HOST_MAX) return 0;
    for (i = 0; i < len; i++)
        if ((unsigned char)h[i] <= ' ' || (unsigned char)h[i] >= 0x7f) return 0;
    return 1;
}

/* --------------------------------------------------------------------- .meta text */

size_t bt_meta_format(const bt_meta* m, char* buf, size_t cap)
{
    bt_writer w;
    size_t i;

    bt_writer_init(&w, buf, cap);
    bt_put(&w, "profile", "1");
    bt_put(&w, "id", m->id);
    bt_put(&w, "name", m->name);
    bt_put(&w, "type", m->type);
    bt_put_u64(&w, "created", m->created);
    bt_put_u64(&w, "order", m->order);
    bt_put_u64(&w, "ts_ceiling", m->ts_ceiling);
    for (i = 0; i < m->n_resolved && i < BT_META_RESOLVED; i++) {
        char line[BT_HOST_MAX + 1 + BT_ADDR_TEXT_MAX];
        snprintf(line, sizeof(line), "%s %s", m->resolved[i].host, m->resolved[i].addr);
        bt_put(&w, "resolved", line);
    }
    return w.failed ? 0 : w.len;
}

int bt_meta_parse(bt_meta* m, char* text, size_t len)
{
    static bt_block b;          /* 6 KB; the daemon is single-threaded */
    const char* v;
    size_t vlen, i;
    uint64_t u;

    memset(m, 0, sizeof(*m));
    if (!bt_block_parse(&b, text, len, NULL, 0)) return 0;
    if (!bt_block_kind(&b) || strcmp(bt_block_kind(&b), "profile") != 0 || strcmp(b.kv[0].val, "1") != 0)
        return 0;

    v = bt_get(&b, "id");
    if (!v || !bt_id_valid(v)) return 0;
    memcpy(m->id, v, BT_ID_LEN + 1);

    v = bt_get_len(&b, "name", &vlen);
    if (!v || !bt_name_valid(v, vlen)) return 0;
    memcpy(m->name, v, vlen + 1);

    v = bt_get(&b, "type");
    if (!v || (strcmp(v, BT_TYPE_WIREGUARD) != 0 && strcmp(v, BT_TYPE_AMNEZIAWG) != 0 &&
               strcmp(v, BT_TYPE_TAILSCALE) != 0))
        return 0;
    snprintf(m->type, sizeof(m->type), "%s", v);

    if (bt_get_u64(&b, "created", ~0ULL, &m->created) != 1) return 0;
    if (bt_get_u64(&b, "order", 0xffffffffULL, &u) != 1) return 0;
    m->order = (uint32_t)u;
    if (bt_get_u64(&b, "ts_ceiling", ~0ULL, &m->ts_ceiling) != 1) return 0;

    for (i = bt_find(&b, "resolved", 0); i < b.n; i = bt_find(&b, "resolved", i + 1)) {
        const char* sp = strchr(b.kv[i].val, ' ');
        size_t hlen, alen;
        int family;
        uint8_t addr[16];

        if (!sp || m->n_resolved == BT_META_RESOLVED) return 0;
        hlen = (size_t)(sp - b.kv[i].val);
        alen = b.kv[i].val_len - hlen - 1;
        if (!host_valid(b.kv[i].val, hlen) || alen >= BT_ADDR_TEXT_MAX ||
            !wg_addr_parse(sp + 1, alen, &family, addr))
            return 0;
        memcpy(m->resolved[m->n_resolved].host, b.kv[i].val, hlen);
        m->resolved[m->n_resolved].host[hlen] = '\0';
        memcpy(m->resolved[m->n_resolved].addr, sp + 1, alen);
        m->resolved[m->n_resolved].addr[alen] = '\0';
        m->n_resolved++;
    }
    return 1;
}

/* --------------------------------------------------------------------- files */

static int path_of(const bt_store* s, const char* name, const char* ext, char* out)
{
    int n = snprintf(out, BT_PATH_MAX, "%s/%s%s", s->dir, name, ext);
    return n > 0 && n < BT_PATH_MAX;
}

/* The whole file plus a NUL, in a malloc'd buffer; NULL when missing or larger than `max`. */
static char* read_file(const char* path, size_t max, size_t* len)
{
    struct stat st;
    char* buf;
    size_t got = 0;
    int fd = open(path, O_RDONLY);

    if (fd < 0) return NULL;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || (uint64_t)st.st_size > max) {
        close(fd);
        return NULL;
    }
    buf = (char*)malloc((size_t)st.st_size + 1);
    if (!buf) {
        close(fd);
        return NULL;
    }
    while (got < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + got, (size_t)st.st_size - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (got != (size_t)st.st_size) {
        wg_wipe(buf, got);
        free(buf);
        return NULL;
    }
    buf[got] = '\0';
    *len = got;
    return buf;
}

static void sync_dir(const bt_store* s)
{
    int fd = open(s->dir, O_RDONLY);
    if (fd >= 0) {
        fsync(fd);              /* not every filesystem syncs a directory; best effort */
        close(fd);
    }
}

/* name+ext replaced atomically by `data`. */
static int write_file(const bt_store* s, const char* name, const char* ext, const char* data, size_t len)
{
    char path[BT_PATH_MAX], tmp[BT_PATH_MAX], tmpext[24];
    size_t put = 0;
    int fd, ok = 1;

    snprintf(tmpext, sizeof(tmpext), "%s.tmp", ext);
    if (!path_of(s, name, ext, path) || !path_of(s, name, tmpext, tmp)) return 0;
    unlink(tmp);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return 0;
    fchmod(fd, 0600);           /* whatever the umask */
    while (put < len) {
        ssize_t w = write(fd, data + put, len - put);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) {
            ok = 0;
            break;
        }
        put += (size_t)w;
    }
    if (ok && fsync(fd) < 0) ok = 0;
    if (close(fd) < 0) ok = 0;
    if (ok && rename(tmp, path) < 0) ok = 0;
    if (!ok) {
        unlink(tmp);
        return 0;
    }
    sync_dir(s);
    return 1;
}

static int exists(const char* path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

/* --------------------------------------------------------------------- the store */

int bt_store_open(bt_store* s, const char* dir)
{
    struct stat st;
    size_t n = strlen(dir);

    if (!n || n >= sizeof(s->dir) - 32) return 0;       /* room for "/<id>.conf.tmp" */
    memcpy(s->dir, dir, n + 1);
    while (n > 1 && s->dir[n - 1] == '/') s->dir[--n] = '\0';

    if (mkdir(s->dir, 0700) < 0 && errno != EEXIST) return 0;
    if (lstat(s->dir, &st) < 0 || !S_ISDIR(st.st_mode)) return 0;
    if ((st.st_mode & 0777) != 0700 && chmod(s->dir, 0700) < 0) return 0;
    return 1;
}

static int ends_with(const char* s, const char* suffix)
{
    size_t n = strlen(s), k = strlen(suffix);
    return n >= k && strcmp(s + n - k, suffix) == 0;
}

int bt_store_sweep(bt_store* s)
{
    DIR* d = opendir(s->dir);
    struct dirent* e;
    int removed = 0;

    if (!d) return 0;
    while ((e = readdir(d)) != NULL) {
        char path[BT_PATH_MAX], meta[BT_PATH_MAX], id[BT_ID_LEN + 1];

        if (!path_of(s, e->d_name, "", path)) continue;
        if (ends_with(e->d_name, ".tmp")) {
            if (unlink(path) == 0) removed++;
        } else if (strlen(e->d_name) == BT_ID_LEN + 5 && ends_with(e->d_name, ".conf")) {
            memcpy(id, e->d_name, BT_ID_LEN);
            id[BT_ID_LEN] = '\0';
            if (bt_id_valid(id) && path_of(s, id, ".meta", meta) && !exists(meta) && unlink(path) == 0)
                removed++;
        }
    }
    closedir(d);
    return removed;
}

int bt_store_load_meta(bt_store* s, const char* id, bt_meta* m)
{
    char path[BT_PATH_MAX];
    size_t len;
    char* text;
    int ok;

    if (!bt_id_valid(id) || !path_of(s, id, ".meta", path)) return 0;
    text = read_file(path, META_MAX, &len);
    if (!text) return 0;
    ok = bt_meta_parse(m, text, len) && strcmp(m->id, id) == 0;
    free(text);
    return ok;
}

static int meta_cmp(const void* pa, const void* pb)
{
    const bt_meta* a = (const bt_meta*)pa;
    const bt_meta* b = (const bt_meta*)pb;

    if (a->order != b->order) return a->order < b->order ? -1 : 1;
    if (a->created != b->created) return a->created < b->created ? -1 : 1;
    return strcmp(a->id, b->id);
}

int bt_store_list(bt_store* s, bt_meta* out, size_t cap, size_t* n, size_t* bad)
{
    DIR* d = opendir(s->dir);
    struct dirent* e;
    size_t count = 0, broken = 0;

    if (!d) return 0;
    while ((e = readdir(d)) != NULL) {
        char id[BT_ID_LEN + 1];
        bt_meta m;

        if (strlen(e->d_name) != BT_ID_LEN + 5 || !ends_with(e->d_name, ".meta")) continue;
        memcpy(id, e->d_name, BT_ID_LEN);
        id[BT_ID_LEN] = '\0';
        if (!bt_id_valid(id) || !bt_store_load_meta(s, id, &m)) {
            broken++;
            continue;
        }
        if (count < cap) out[count] = m;
        count++;
    }
    closedir(d);
    qsort(out, count < cap ? count : cap, sizeof(bt_meta), meta_cmp);
    *n = count;
    if (bad) *bad = broken;
    return 1;
}

char* bt_store_load_conf(bt_store* s, const char* id, size_t* len)
{
    char path[BT_PATH_MAX];

    if (!bt_id_valid(id) || !path_of(s, id, ".conf", path)) return NULL;
    return read_file(path, BT_CONF_MAX, len);
}

void bt_store_free_conf(char* conf, size_t len)
{
    if (!conf) return;
    wg_wipe(conf, len + 1);
    free(conf);
}

int bt_store_save(bt_store* s, const bt_meta* m, const char* conf, size_t len)
{
    char text[META_MAX];
    size_t tlen;

    if (!bt_id_valid(m->id) || !bt_name_valid(m->name, strlen(m->name))) return 0;
    if (conf && (len > BT_CONF_MAX || memchr(conf, '\0', len))) return 0;
    tlen = bt_meta_format(m, text, sizeof(text));
    if (!tlen) return 0;
    if (conf && !write_file(s, m->id, ".conf", conf, len)) return 0;
    return write_file(s, m->id, ".meta", text, tlen);
}

int bt_store_delete(bt_store* s, const char* id)
{
    char meta[BT_PATH_MAX], conf[BT_PATH_MAX];

    if (!bt_id_valid(id) || !path_of(s, id, ".meta", meta) || !path_of(s, id, ".conf", conf)) return 0;
    if (unlink(meta) < 0) return 0;
    unlink(conf);
    sync_dir(s);
    return 1;
}

int bt_store_new_id(bt_store* s, const wg_rng* rng, char out[BT_ID_LEN + 1])
{
    static const char hex[] = "0123456789abcdef";
    int attempt;

    for (attempt = 0; attempt < 16; attempt++) {
        uint8_t r[BT_ID_LEN / 2];
        char path[BT_PATH_MAX];
        size_t i;

        if (!wg_rng_bytes(rng, r, sizeof(r))) return 0;
        for (i = 0; i < sizeof(r); i++) {
            out[2 * i] = hex[r[i] >> 4];
            out[2 * i + 1] = hex[r[i] & 15];
        }
        out[BT_ID_LEN] = '\0';
        if (!path_of(s, out, ".meta", path)) return 0;
        if (!exists(path)) return 1;
    }
    return 0;
}

static int plain_name(const char* name)
{
    size_t i, n = strlen(name);

    if (!n || n > 16) return 0;
    for (i = 0; i < n; i++)
        if (!((name[i] >= 'a' && name[i] <= 'z') || name[i] == '_')) return 0;
    return 1;
}

int bt_store_put(bt_store* s, const char* name, const char* data, size_t len)
{
    return plain_name(name) && write_file(s, name, "", data, len);
}

char* bt_store_get(bt_store* s, const char* name, size_t* len)
{
    char path[BT_PATH_MAX];

    if (!plain_name(name) || !path_of(s, name, "", path)) return NULL;
    return read_file(path, 64 * 1024, len);
}

int bt_store_remove(bt_store* s, const char* name)
{
    char path[BT_PATH_MAX];

    if (!plain_name(name) || !path_of(s, name, "", path)) return 0;
    if (unlink(path) < 0 && errno != ENOENT) return 0;
    sync_dir(s);
    return 1;
}

int bt_store_load_settings(bt_store* s, bt_settings* st)
{
    static bt_block b;
    char path[BT_PATH_MAX];
    const char* v;
    size_t len;
    char* text;
    int ok = 0, ks;

    memset(st, 0, sizeof(*st));
    if (!path_of(s, "settings", "", path)) return 0;
    if (!exists(path)) return 1;
    text = read_file(path, SETTINGS_MAX, &len);
    if (!text) return 0;
    if (bt_block_parse(&b, text, len, NULL, 0) && bt_block_kind(&b) &&
        strcmp(bt_block_kind(&b), "settings") == 0 && strcmp(b.kv[0].val, "1") == 0) {
        ok = 1;
        v = bt_get(&b, "always_on");
        if (v && *v) {
            if (bt_id_valid(v)) memcpy(st->always_on, v, BT_ID_LEN + 1);
            else ok = 0;
        }
        v = bt_get(&b, "always_on_tailscale");
        if (v && *v) {
            if (bt_id_valid(v)) memcpy(st->always_on_tailscale, v, BT_ID_LEN + 1);
            else ok = 0;
        }
        switch (bt_get_bool(&b, "kill_switch", &ks)) {
        case 1:  st->kill_switch = ks; break;
        case -1: ok = 0; break;
        default: break;
        }
        if (bt_get_u64(&b, "ts_floor", ~0ULL, &st->ts_floor) < 0) ok = 0;
    }
    free(text);
    return ok;
}

int bt_store_save_settings(bt_store* s, const bt_settings* st)
{
    char text[SETTINGS_MAX];
    bt_writer w;

    if (st->always_on[0] && !bt_id_valid(st->always_on)) return 0;
    if (st->always_on_tailscale[0] && !bt_id_valid(st->always_on_tailscale)) return 0;
    bt_writer_init(&w, text, sizeof(text));
    bt_put(&w, "settings", "1");
    bt_put(&w, "always_on", st->always_on);
    bt_put(&w, "always_on_tailscale", st->always_on_tailscale);
    bt_put_u64(&w, "kill_switch", st->kill_switch ? 1 : 0);
    bt_put_u64(&w, "ts_floor", st->ts_floor);
    if (w.failed) return 0;
    return write_file(s, "settings", "", text, w.len);
}
