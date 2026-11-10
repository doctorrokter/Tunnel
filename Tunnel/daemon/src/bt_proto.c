/*
 * bt_proto - see bt_proto.h.
 */

#include "bt_proto.h"

#include <stdio.h>
#include <string.h>

static void set_err(char* err, size_t errlen, const char* msg)
{
    if (err && errlen) snprintf(err, errlen, "%s", msg);
}

int bt_key_valid(const char* key, size_t len)
{
    size_t i;

    if (!len || len > BT_KEY_MAX) return 0;
    for (i = 0; i < len; i++) {
        char c = key[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.')) return 0;
    }
    return 1;
}

/* --------------------------------------------------------------------- parsing a block */

/*
 * text[len] is written to when the last line has no line end: the value needs its NUL. Every
 * caller has that byte (the reader: the empty line after the block; the store: one spare byte).
 */
int bt_block_parse(bt_block* b, char* text, size_t len, char* err, size_t errlen)
{
    size_t pos = 0;

    b->n = 0;
    if (memchr(text, '\0', len)) {
        set_err(err, errlen, "NUL byte in block");
        return 0;
    }
    while (pos < len) {
        char* line = text + pos;
        char* nl = (char*)memchr(line, '\n', len - pos);
        size_t end = nl ? (size_t)(nl - text) : len;    /* the line is text[pos, end) */
        size_t line_len = end - pos;
        char *eq, *in, *out, *stop;

        if (line_len && line[line_len - 1] == '\r') line_len--;
        if (!line_len) {
            set_err(err, errlen, "empty line inside block");
            return 0;
        }
        if (b->n == BT_BLOCK_MAX_LINES) {
            set_err(err, errlen, "too many lines");
            return 0;
        }
        eq = (char*)memchr(line, '=', line_len);
        if (!eq) {
            set_err(err, errlen, "line without '='");
            return 0;
        }
        if (!bt_key_valid(line, (size_t)(eq - line))) {
            set_err(err, errlen, "bad key");
            return 0;
        }

        /* Unescape the value where it lies; it only gets shorter. */
        in = eq + 1;
        out = eq + 1;
        stop = line + line_len;
        while (in < stop) {
            char c = *in++;
            if (c == '\r') {
                set_err(err, errlen, "raw CR in value");
                return 0;
            }
            if (c == '\\') {
                if (in == stop) {
                    set_err(err, errlen, "backslash at end of value");
                    return 0;
                }
                c = *in++;
                if (c == 'n') c = '\n';
                else if (c == 'r') c = '\r';
                else if (c != '\\') {
                    set_err(err, errlen, "unknown escape");
                    return 0;
                }
            }
            *out++ = c;
        }
        *eq = '\0';
        *out = '\0';                    /* at most text + end: the line end, or text[len] */

        b->kv[b->n].key = line;
        b->kv[b->n].val = eq + 1;
        b->kv[b->n].val_len = (size_t)(out - (eq + 1));
        b->n++;
        pos = end + 1;
    }
    return 1;
}

const char* bt_block_kind(const bt_block* b)
{
    return b->n ? b->kv[0].key : NULL;
}

size_t bt_find(const bt_block* b, const char* key, size_t from)
{
    size_t i;

    for (i = from; i < b->n; i++)
        if (strcmp(b->kv[i].key, key) == 0) return i;
    return b->n;
}

const char* bt_get_len(const bt_block* b, const char* key, size_t* len)
{
    size_t i = bt_find(b, key, 0);

    if (i == b->n) return NULL;
    if (len) *len = b->kv[i].val_len;
    return b->kv[i].val;
}

const char* bt_get(const bt_block* b, const char* key)
{
    return bt_get_len(b, key, NULL);
}

int bt_get_u64(const bt_block* b, const char* key, uint64_t max, uint64_t* out)
{
    size_t len, i;
    const char* s = bt_get_len(b, key, &len);
    uint64_t v = 0;

    if (!s) return 0;
    if (!len || len > 20) return -1;
    for (i = 0; i < len; i++) {
        unsigned d;
        if (s[i] < '0' || s[i] > '9') return -1;
        d = (unsigned)(s[i] - '0');
        if (v > max / 10 || (v == max / 10 && d > max % 10)) return -1;     /* v * 10 + d > max */
        v = v * 10 + d;
    }
    *out = v;
    return 1;
}

int bt_get_bool(const bt_block* b, const char* key, int* out)
{
    uint64_t v;
    int r = bt_get_u64(b, key, 1, &v);

    if (r == 1) *out = (int)v;
    return r;
}

/* --------------------------------------------------------------------- the stream */

void bt_reader_init(bt_reader* r, char* buf, size_t cap)
{
    r->buf = buf;
    r->cap = cap;
    r->len = 0;
    r->scanned = 0;
    r->consumed = 0;
}

static void reader_drop(bt_reader* r, size_t n)
{
    memmove(r->buf, r->buf + n, r->len - n);
    r->len -= n;
}

char* bt_reader_space(bt_reader* r, size_t* room)
{
    if (r->consumed) {
        reader_drop(r, r->consumed);
        r->consumed = 0;
    }
    *room = r->cap - r->len;
    return r->buf + r->len;
}

void bt_reader_commit(bt_reader* r, size_t n)
{
    r->len += n;
}

int bt_reader_next(bt_reader* r, bt_block* b, char* err, size_t errlen)
{
    size_t pos;

    if (r->consumed) {
        reader_drop(r, r->consumed);
        r->consumed = 0;
    }

    /* Empty lines between blocks are skipped. */
    while (r->scanned == 0 && r->len) {
        if (r->buf[0] == '\n') reader_drop(r, 1);
        else if (r->len >= 2 && r->buf[0] == '\r' && r->buf[1] == '\n') reader_drop(r, 2);
        else break;
    }

    /* `scanned` is always the start of a line not yet complete. */
    pos = r->scanned;
    for (;;) {
        char* nl = (char*)memchr(r->buf + pos, '\n', r->len - pos);
        size_t line_len;

        if (!nl) break;
        line_len = (size_t)(nl - (r->buf + pos));
        if (line_len && r->buf[pos + line_len - 1] == '\r') line_len--;
        if (!line_len && pos) {
            /* The block is buf[0, pos); its lines end with '\n', so buf[pos] may take a NUL. */
            r->consumed = (size_t)(nl - r->buf) + 1;
            r->scanned = 0;
            if (!bt_block_parse(b, r->buf, pos, err, errlen)) return -1;
            return 1;
        }
        pos = (size_t)(nl - r->buf) + 1;
        if (pos > BT_BLOCK_MAX) {
            set_err(err, errlen, "block too long");
            return -1;
        }
    }
    r->scanned = pos;
    /* The largest block with its "\r\n" ending would have been found by now. */
    if (r->len > BT_BLOCK_MAX + 2 || r->len == r->cap) {
        set_err(err, errlen, "block too long");
        return -1;
    }
    return 0;
}

/* --------------------------------------------------------------------- building */

void bt_writer_init(bt_writer* w, char* buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->failed = 0;
}

void bt_put_n(bt_writer* w, const char* key, const char* val, size_t len)
{
    size_t klen = strlen(key), need = klen + 2, i;
    char* p;

    if (w->failed) return;
    if (!bt_key_valid(key, klen) || memchr(val, '\0', len)) {
        w->failed = 1;
        return;
    }
    for (i = 0; i < len; i++)
        need += (val[i] == '\\' || val[i] == '\n' || val[i] == '\r') ? 2 : 1;
    if (need > w->cap - w->len) {
        w->failed = 1;
        return;
    }
    p = w->buf + w->len;
    memcpy(p, key, klen);
    p += klen;
    *p++ = '=';
    for (i = 0; i < len; i++) {
        char c = val[i];
        if (c == '\\' || c == '\n' || c == '\r') {
            *p++ = '\\';
            c = c == '\n' ? 'n' : c == '\r' ? 'r' : '\\';
        }
        *p++ = c;
    }
    *p++ = '\n';
    w->len = (size_t)(p - w->buf);
}

void bt_put(bt_writer* w, const char* key, const char* val)
{
    bt_put_n(w, key, val, strlen(val));
}

void bt_put_u64(bt_writer* w, const char* key, uint64_t v)
{
    char s[24];
    size_t i = sizeof(s);

    do {
        s[--i] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    bt_put_n(w, key, s + i, sizeof(s) - i);
}

void bt_put_i64(bt_writer* w, const char* key, int64_t v)
{
    char s[24];
    size_t i = sizeof(s);
    uint64_t u = v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;

    do {
        s[--i] = (char)('0' + u % 10);
        u /= 10;
    } while (u);
    if (v < 0) s[--i] = '-';
    bt_put_n(w, key, s + i, sizeof(s) - i);
}

int bt_end(bt_writer* w)
{
    if (w->failed) return 0;
    if (w->len == w->cap) {
        w->failed = 1;
        return 0;
    }
    w->buf[w->len++] = '\n';
    return 1;
}
