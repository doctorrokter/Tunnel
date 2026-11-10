/*
 * ts_h2 - see ts_h2.h. RFC 9113 (HTTP/2) and RFC 7541 (HPACK). The reference for behaviour is
 * golang.org/x/net/http2 v0.56 (frame.go, transport.go, flow.go, hpack/): the server at the other
 * end is Go's, and tailscaled's own client is Go's too.
 */

#include "ts_h2.h"

#include <string.h>

/* ===================================================================== HPACK */

/* The static table (RFC 7541 Appendix A); index i is [i - 1]. test_ts_h2.c holds it against Go's. */
static const char* const hp_static[61][2] = {
    { ":authority", "" },
    { ":method", "GET" },
    { ":method", "POST" },
    { ":path", "/" },
    { ":path", "/index.html" },
    { ":scheme", "http" },
    { ":scheme", "https" },
    { ":status", "200" },
    { ":status", "204" },
    { ":status", "206" },
    { ":status", "304" },
    { ":status", "400" },
    { ":status", "404" },
    { ":status", "500" },
    { "accept-charset", "" },
    { "accept-encoding", "gzip, deflate" },
    { "accept-language", "" },
    { "accept-ranges", "" },
    { "accept", "" },
    { "access-control-allow-origin", "" },
    { "age", "" },
    { "allow", "" },
    { "authorization", "" },
    { "cache-control", "" },
    { "content-disposition", "" },
    { "content-encoding", "" },
    { "content-language", "" },
    { "content-length", "" },
    { "content-location", "" },
    { "content-range", "" },
    { "content-type", "" },
    { "cookie", "" },
    { "date", "" },
    { "etag", "" },
    { "expect", "" },
    { "expires", "" },
    { "from", "" },
    { "host", "" },
    { "if-match", "" },
    { "if-modified-since", "" },
    { "if-none-match", "" },
    { "if-range", "" },
    { "if-unmodified-since", "" },
    { "last-modified", "" },
    { "link", "" },
    { "location", "" },
    { "max-forwards", "" },
    { "proxy-authenticate", "" },
    { "proxy-authorization", "" },
    { "range", "" },
    { "referer", "" },
    { "refresh", "" },
    { "retry-after", "" },
    { "server", "" },
    { "set-cookie", "" },
    { "strict-transport-security", "" },
    { "transfer-encoding", "" },
    { "user-agent", "" },
    { "vary", "" },
    { "via", "" },
    { "www-authenticate", "" },
};

/*
 * The Huffman code of RFC 7541 Appendix B, for canonical decoding: how many codes each length (in
 * bits) has, and the symbols in code order (by length, then code; 256 is EOS). The code is
 * canonical - the codes of one length are consecutive, right after the shorter ones - so these two
 * tables are all of it. Taken from Go's hpack; test_ts_h2.c decodes every symbol of Go's code
 * table (kat_huff) and Go's encodings of strings through them.
 */
static const uint8_t huff_count[31] = {
    0, 0, 0, 0, 0, 10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3,
    0, 0, 0, 3, 8, 13, 26, 29, 12, 4, 15, 19, 29, 0, 4,
};

static const uint16_t huff_sym[257] = {
     48,  49,  50,  97,  99, 101, 105, 111, 115, 116,  32,  37,
     45,  46,  47,  51,  52,  53,  54,  55,  56,  57,  61,  65,
     95,  98, 100, 102, 103, 104, 108, 109, 110, 112, 114, 117,
     58,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,
     77,  78,  79,  80,  81,  82,  83,  84,  85,  86,  87,  89,
    106, 107, 113, 118, 119, 120, 121, 122,  38,  42,  44,  59,
     88,  90,  33,  34,  40,  41,  63,  39,  43, 124,  35,  62,
      0,  36,  64,  91,  93, 126,  94, 125,  60,  96, 123,  92,
    195, 208, 128, 130, 131, 162, 184, 194, 224, 226, 153, 161,
    167, 172, 176, 177, 179, 209, 216, 217, 227, 229, 230, 129,
    132, 133, 134, 136, 146, 154, 156, 160, 163, 164, 169, 170,
    173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232,
    233,   1, 135, 137, 138, 139, 140, 141, 143, 147, 149, 150,
    151, 152, 155, 157, 158, 165, 166, 168, 174, 175, 180, 182,
    183, 188, 191, 197, 231, 239,   9, 142, 144, 145, 148, 159,
    171, 206, 215, 225, 236, 237, 199, 207, 234, 235, 192, 193,
    200, 201, 202, 205, 210, 213, 218, 219, 238, 240, 242, 243,
    255, 203, 204, 211, 212, 214, 221, 222, 223, 241, 244, 245,
    246, 247, 248, 250, 251, 252, 253, 254,   2,   3,   4,   5,
      6,   7,   8,  11,  12,  14,  15,  16,  17,  18,  19,  20,
     21,  23,  24,  25,  26,  27,  28,  29,  30,  31, 127, 220,
    249,  10,  13,  22, 256,
};

/*
 * Bit by bit, as zlib's puff: `code` is the bits so far, `first` the first code of that length,
 * `index` where its symbols start. A code of this length is one below first + count; past the
 * last code of a length, the bits only lead to longer codes.
 */
size_t ts_hpack_huffman_decode(const uint8_t* in, size_t len, uint8_t* out, size_t cap)
{
    uint32_t code = 0, first = 0;
    unsigned index = 0, bits = 0, ones = 1;
    size_t n = 0, i;

    for (i = 0; i < len; i++) {
        int b;

        for (b = 7; b >= 0; b--) {
            unsigned bit = (in[i] >> b) & 1u, count;

            code |= bit;
            ones &= bit;
            count = huff_count[++bits];
            if (code - first < count) {
                unsigned sym = huff_sym[index + (code - first)];
                if (sym == 256) return (size_t)-1;      /* EOS inside a string (5.2) */
                if (n < cap) out[n] = (uint8_t)sym;
                n++;
                code = first = 0;
                index = bits = 0;
                ones = 1;
                continue;
            }
            if (bits == 30) return (size_t)-1;          /* no code is longer */
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
    }
    /* What is left is padding: fewer than 8 bits, all ones - the start of EOS (5.2). */
    if (bits > 7 || !ones) return (size_t)-1;
    return n;
}

int ts_hpack_get_int(const uint8_t* b, size_t len, size_t* pos, unsigned n, uint64_t* out)
{
    uint64_t v, mask;
    unsigned m = 0;

    if (n < 1 || n > 8 || *pos >= len) return 0;
    mask = ((uint64_t)1 << n) - 1;
    v = b[(*pos)++] & mask;
    if (v < mask) {
        *out = v;
        return 1;
    }
    for (;;) {
        uint8_t c;

        if (*pos >= len) return 0;
        c = b[(*pos)++];
        v += (uint64_t)(c & 127) << m;
        if (!(c & 128)) break;
        m += 7;
        if (m >= 63) return 0;                          /* as Go's readVarInt; no overflow before */
    }
    *out = v;
    return 1;
}

size_t ts_hpack_put_int(uint8_t* out, size_t cap, uint8_t first, unsigned n, uint64_t v)
{
    uint64_t mask;
    size_t i = 0;

    if (n < 1 || n > 8 || !cap) return 0;
    mask = ((uint64_t)1 << n) - 1;
    if (v < mask) {
        out[0] = (uint8_t)(first | v);
        return 1;
    }
    out[i++] = (uint8_t)(first | mask);
    v -= mask;
    while (v >= 128) {
        if (i == cap) return 0;
        out[i++] = (uint8_t)(0x80 | (v & 127));
        v >>= 7;
    }
    if (i == cap) return 0;
    out[i++] = (uint8_t)v;
    return i;
}

void ts_hpack_init(ts_hpack* h, uint32_t limit)
{
    memset(h, 0, sizeof(*h));
    if (limit > TS_HPACK_TABLE_MAX) limit = TS_HPACK_TABLE_MAX;
    h->limit = limit;
    h->max_size = limit;
}

static void evict_oldest(ts_hpack* h)
{
    size_t k = h->oldest, n = (size_t)h->ent[k].nlen + h->ent[k].vlen;

    h->start += n;
    h->size -= (uint32_t)(n + 32);
    h->oldest = (h->oldest + 1) % TS_HPACK_ENTRIES_MAX;
    if (!--h->count) h->start = h->end = 0;
}

/* Evicts the oldest entries until the table is at most `max` (4.3). */
static void evict_to(ts_hpack* h, uint32_t max)
{
    while (h->count && h->size > max) evict_oldest(h);
}

/*
 * A new entry (4.4): the oldest go until it fits; one larger than the table empties it and is not
 * added - not an error. The name and value are never in the table's own bytes (the decoder copied
 * them out first), so an eviction cannot pull them from under the copy.
 */
static void table_add(ts_hpack* h, const char* name, size_t nlen, const char* value, size_t vlen)
{
    size_t need = nlen + vlen, k, i;

    if (need + 32 > h->max_size) {
        evict_to(h, 0);
        return;
    }
    evict_to(h, h->max_size - (uint32_t)(need + 32));
    if (h->end + need > TS_HPACK_TABLE_MAX) {
        /* The run of bytes hit the end: move it to the front. It fits - the entries' bytes are
         * under the table's size, and the size is at most TS_HPACK_TABLE_MAX. */
        memmove(h->bytes, h->bytes + h->start, h->end - h->start);
        for (i = 0; i < h->count; i++)
            h->ent[(h->oldest + i) % TS_HPACK_ENTRIES_MAX].off -= (uint16_t)h->start;
        h->end -= h->start;
        h->start = 0;
    }
    k = (h->oldest + h->count) % TS_HPACK_ENTRIES_MAX;
    h->ent[k].off = (uint16_t)h->end;
    h->ent[k].nlen = (uint16_t)nlen;
    h->ent[k].vlen = (uint16_t)vlen;
    memcpy(h->bytes + h->end, name, nlen);
    memcpy(h->bytes + h->end + nlen, value, vlen);
    h->end += need;
    h->size += (uint32_t)(need + 32);
    h->count++;
}

/* Field i of the one index space (2.3.3): 1-61 static, then the dynamic table newest first. */
static int table_get(const ts_hpack* h, uint64_t i, const uint8_t** name, size_t* nlen,
                     const uint8_t** value, size_t* vlen)
{
    size_t k;

    if (!i) return 0;
    if (i <= 61) {
        *name = (const uint8_t*)hp_static[i - 1][0];
        *nlen = strlen(hp_static[i - 1][0]);
        *value = (const uint8_t*)hp_static[i - 1][1];
        *vlen = strlen(hp_static[i - 1][1]);
        return 1;
    }
    i -= 62;
    if (i >= h->count) return 0;
    k = (h->oldest + h->count - 1 - (size_t)i) % TS_HPACK_ENTRIES_MAX;
    *name = h->bytes + h->ent[k].off;
    *nlen = h->ent[k].nlen;
    *value = *name + *nlen;
    *vlen = h->ent[k].vlen;
    return 1;
}

int ts_hpack_entry(const ts_hpack* h, size_t i, const uint8_t** name, size_t* nlen,
                   const uint8_t** value, size_t* vlen)
{
    return table_get(h, (uint64_t)i + 62, name, nlen, value, vlen);
}

/* A string literal (5.2) at b[*pos], decoded into dst[0, cap): *n is its decoded length, also
 * when that is over cap. 0 when it is malformed or runs past the block. */
static int get_string(const uint8_t* b, size_t len, size_t* pos, uint8_t* dst, size_t cap, size_t* n)
{
    uint64_t slen;
    int huff;

    if (*pos >= len) return 0;
    huff = (b[*pos] & 0x80) != 0;
    if (!ts_hpack_get_int(b, len, pos, 7, &slen) || slen > len - *pos) return 0;
    if (huff) {
        size_t d = ts_hpack_huffman_decode(b + *pos, (size_t)slen, dst, cap);
        if (d == (size_t)-1) return 0;
        *n = d;
    } else {
        if (slen && slen <= cap) memcpy(dst, b + *pos, (size_t)slen);
        *n = (size_t)slen;
    }
    *pos += (size_t)slen;
    return 1;
}

/* The field just decoded at L->buf + L->used (the name and the value, each followed by a NUL) joins
 * the list - unless it was not decoded whole (`fits` 0) or the list is over its limits: then it is
 * dropped and the list marked, as Go's decoder stops emitting past the limit. */
static void list_commit(ts_hpack_list* L, int fits, size_t nlen, size_t vlen)
{
    ts_h2_field* f;

    L->size += (uint64_t)nlen + vlen + 32;
    if (!fits || L->overflow || L->n == TS_H2_FIELDS_MAX || L->size > TS_H2_HEADER_LIST_MAX) {
        L->overflow = 1;
        return;
    }
    f = &L->fields[L->n++];
    f->name = L->buf + L->used;
    f->name_len = nlen;
    f->value = L->buf + L->used + nlen + 1;
    f->value_len = vlen;
    L->used += nlen + vlen + 2;
}

/* An indexed field (6.1): a copy of the table's. */
static void list_copy(ts_hpack_list* L, const uint8_t* name, size_t nlen, const uint8_t* value, size_t vlen)
{
    char* p = L->buf + L->used;
    int fits = nlen + vlen + 2 <= sizeof(L->buf) - L->used;

    if (fits) {
        memcpy(p, name, nlen);
        p[nlen] = '\0';
        memcpy(p + nlen + 1, value, vlen);
        p[nlen + 1 + vlen] = '\0';
    }
    list_commit(L, fits, nlen, vlen);
}

/*
 * A literal (6.2) after its first integer: the name from the table (idx) or a string, then the
 * value. Both are decoded into the list's free room; there is always more of it than the dynamic
 * table holds (ts_h2.h), so a field that does not fit could never enter the table - indexing it
 * only empties the table, and its bytes are not needed.
 */
static int literal(ts_hpack* h, const uint8_t* b, size_t len, size_t* pos, uint64_t idx, int indexing,
                   ts_hpack_list* L)
{
    char* p = L->buf + L->used;
    size_t avail = sizeof(L->buf) - L->used, nlen, vlen;
    int fits = 1;

    if (idx) {
        const uint8_t *nm, *vl;
        size_t vll;

        if (!table_get(h, idx, &nm, &nlen, &vl, &vll)) return 0;
        if (nlen + 1 <= avail) memcpy(p, nm, nlen);
        else fits = 0;
    } else {
        if (!get_string(b, len, pos, (uint8_t*)p, avail, &nlen)) return 0;
        if (nlen + 1 > avail) fits = 0;
    }
    if (fits) {
        p[nlen] = '\0';
        if (!get_string(b, len, pos, (uint8_t*)p + nlen + 1, avail - nlen - 1, &vlen)) return 0;
        if (vlen + 1 > avail - nlen - 1) fits = 0;
        else p[nlen + 1 + vlen] = '\0';
    } else if (!get_string(b, len, pos, NULL, 0, &vlen)) {
        return 0;
    }
    if (indexing) {
        if (fits) table_add(h, p, nlen, p + nlen + 1, vlen);
        else evict_to(h, 0);
    }
    list_commit(L, fits, nlen, vlen);
    return 1;
}

int ts_hpack_decode(ts_hpack* h, const uint8_t* b, size_t len, ts_hpack_list* L)
{
    size_t pos = 0;
    int field_seen = 0;

    L->n = 0;
    L->size = 0;
    L->overflow = 0;
    L->used = 0;
    while (pos < len) {
        uint8_t c = b[pos];
        uint64_t idx;

        if (c & 0x80) {
            /* 6.1: an indexed field */
            const uint8_t *nm, *vl;
            size_t nl, vlen;

            if (!ts_hpack_get_int(b, len, &pos, 7, &idx) || !table_get(h, idx, &nm, &nl, &vl, &vlen)) return 0;
            list_copy(L, nm, nl, vl, vlen);
            field_seen = 1;
        } else if ((c & 0xe0) == 0x20) {
            /* 6.3: a dynamic table size update - before the block's first field only (4.2); two
             * in a row are fine (the smallest, then the final size), as RFC 7541 says. Go's own
             * decoder refuses the second while its table is not empty - we follow the RFC. */
            if (field_seen || !ts_hpack_get_int(b, len, &pos, 5, &idx) || idx > h->limit) return 0;
            h->max_size = (uint32_t)idx;
            evict_to(h, h->max_size);
        } else {
            /* 6.2: a literal with incremental indexing (01), without (0000), never indexed (0001) */
            int indexing = (c & 0xc0) == 0x40;

            if (!ts_hpack_get_int(b, len, &pos, indexing ? 6 : 4, &idx)) return 0;
            if (!literal(h, b, len, &pos, idx, indexing, L)) return 0;
            field_seen = 1;
        }
    }
    return 1;
}

/* ===================================================================== HTTP/2 */

/* Frame types and flags (RFC 9113 section 6). */
#define F_DATA          0x0
#define F_HEADERS       0x1
#define F_PRIORITY      0x2
#define F_RST_STREAM    0x3
#define F_SETTINGS      0x4
#define F_PUSH_PROMISE  0x5
#define F_PING          0x6
#define F_GOAWAY        0x7
#define F_WINDOW_UPDATE 0x8
#define F_CONTINUATION  0x9

#define FL_END_STREAM   0x01
#define FL_ACK          0x01
#define FL_END_HEADERS  0x04
#define FL_PADDED       0x08
#define FL_PRIORITY     0x20

#define S_HEADER_TABLE_SIZE      0x1
#define S_ENABLE_PUSH            0x2
#define S_MAX_CONCURRENT_STREAMS 0x3
#define S_INITIAL_WINDOW_SIZE    0x4
#define S_MAX_FRAME_SIZE         0x5
#define S_MAX_HEADER_LIST_SIZE   0x6

#define WINDOW_MAX      0x7fffffffLL    /* 6.9.1 */
#define CONTROL_RESERVE 1024            /* output that DATA leaves free for control frames */
#define MAX_INTERIM     5               /* 1xx heads on one stream, as Go's transport */

/* An empty output must take a whole DATA frame and the reserve, or a body could wait forever;
 * and a request's HEADERS (one frame, TS_H2_REQ_BLOCK_MAX at most) likewise. */
typedef char ts_h2_out_holds_a_frame[TS_H2_OUT_MAX >= 9 + TS_H2_FRAME_MAX + CONTROL_RESERVE &&
                                     TS_H2_OUT_MAX >= 9 + TS_H2_REQ_BLOCK_MAX + CONTROL_RESERVE ? 1 : -1];

enum { RX_EARLY = 0, RX_EARLY_BODY, RX_HEADER, RX_PAYLOAD, RX_DEAD };

#define ST_LOCAL_END    0x01            /* our END_STREAM went out (or there was no body) */
#define ST_GOT_HEAD     0x02            /* the final response head came */

static void put32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* A frame into the output, keeping `reserve` bytes free after it; 0 when there is no room. */
static int put_frame(ts_h2* c, uint8_t type, uint8_t flags, uint32_t stream, const uint8_t* payload,
                     size_t len, size_t reserve)
{
    uint8_t* p;

    if (TS_H2_OUT_MAX - c->out_len < 9 + len + reserve) return 0;
    p = c->out + c->out_len;
    p[0] = (uint8_t)(len >> 16);
    p[1] = (uint8_t)(len >> 8);
    p[2] = (uint8_t)len;
    p[3] = type;
    p[4] = flags;
    put32(p + 5, stream & 0x7fffffff);
    if (len) memcpy(p + 9, payload, len);
    c->out_len += 9 + len;
    return 1;
}

/* --------------------------------------------------------------------- events */

static ts_h2_event* ev_push(ts_h2* c, ts_h2_event_type type, uint32_t stream)
{
    ts_h2_event* e = &c->ev_spare;

    if (c->ev_n < TS_H2_EVQ) {
        e = &c->evq[(c->ev_head + c->ev_n) % TS_H2_EVQ];
        c->ev_n++;
    }
    memset(e, 0, sizeof(*e));
    e->type = type;
    e->stream = stream;
    return e;
}

static int ev_pop(ts_h2* c, ts_h2_event* ev)
{
    if (!c->ev_n) return 0;
    *ev = c->evq[c->ev_head];
    c->ev_head = (c->ev_head + 1) % TS_H2_EVQ;
    c->ev_n--;
    return 1;
}

/* --------------------------------------------------------------------- streams */

static int slot_of(const ts_h2* c, uint32_t id)
{
    int i;

    if (!id) return -1;
    for (i = 0; i < TS_H2_MAX_STREAMS; i++)
        if (c->st[i].id == id) return i;
    return -1;
}

/* Never opened by us: even (the server's - push is off), or above the last id we used. */
static int idle_stream(const ts_h2* c, uint32_t id)
{
    return !(id & 1) || id >= c->next_id;
}

/* The stream's unsent body leaves send[]; the bodies behind it move down. */
static void body_release(ts_h2* c, ts_h2_stream* s)
{
    size_t off = s->body_off, n = s->body_len;
    int i;

    if (!n) return;
    memmove(c->send + off, c->send + off + n, c->send_used - off - n);
    c->send_used -= n;
    for (i = 0; i < TS_H2_MAX_STREAMS; i++)
        if (c->st[i].id && c->st[i].body_len && c->st[i].body_off > off) c->st[i].body_off -= n;
    s->body_off = s->body_len = s->body_sent = 0;
}

/* The stream is over - its last event queued, or none wanted. What the caller still holds of it
 * goes back to the connection's window at once: no more comes on this stream to pace. */
static void stream_free(ts_h2* c, int slot)
{
    ts_h2_stream* s = &c->st[slot];

    c->conn_recv_unsent += s->recv_held;
    body_release(c, s);
    memset(s, 0, sizeof(*s));
}

static void close_all(ts_h2* c, uint32_t code, int local)
{
    ts_h2_event* e;
    int i;

    for (i = 0; i < TS_H2_MAX_STREAMS; i++) {
        if (!c->st[i].id) continue;
        e = ev_push(c, TS_H2_EV_RESET, c->st[i].id);
        e->error = code;
        e->local = local;
        stream_free(c, i);
    }
    e = ev_push(c, TS_H2_EV_CLOSED, 0);
    e->error = code;
    e->local = local;
    c->dead = 1;
    c->phase = RX_DEAD;
}

/* A connection error (5.4.1): GOAWAY if there is room for it, every stream reset, CLOSED. */
static int conn_error(ts_h2* c, uint32_t code)
{
    uint8_t p[8];

    if (c->dead) return 0;
    put32(p, 0);                        /* the last stream of the server's we took: none */
    put32(p + 4, code);
    (void)put_frame(c, F_GOAWAY, 0, 0, p, 8, 0);
    close_all(c, code, 1);
    return 0;
}

/* A stream error of ours (5.4.2): RST_STREAM to the server, RESET to the caller. */
static void stream_reset_local(ts_h2* c, int slot, uint32_t code)
{
    ts_h2_stream* s = &c->st[slot];
    ts_h2_event* e;
    uint8_t p[4];
    int sent;

    put32(p, code);
    sent = put_frame(c, F_RST_STREAM, 0, s->id, p, 4, 0);
    e = ev_push(c, TS_H2_EV_RESET, s->id);
    e->error = code;
    e->local = 1;
    stream_free(c, slot);
    /* No room even for that: the output is full of control frames - a flood. */
    if (!sent) conn_error(c, TS_H2_ENHANCE_YOUR_CALM);
}

/* --------------------------------------------------------------------- the response */

static int is_digit(char c)
{
    return c >= '0' && c <= '9';
}

/* A field name byte HTTP/2 allows (8.2.1): a tchar, not uppercase (Go's validWireHeaderFieldName). */
static int name_byte(unsigned char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) return 1;
    return c && strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

/* A field value byte: no control but HTAB (Go's httpguts.ValidHeaderFieldValue). */
static int value_byte(unsigned char c)
{
    return c == '\t' || (c >= 0x20 && c != 0x7f);
}

/*
 * A response's fields (8.3.2): names lowercase tokens, values without controls; one pseudo-field,
 * :status, before the rest. *status is its value, -1 when there is none (trailers). Go's client
 * checks the same and no more: connection-specific fields are let through, as there.
 */
static int fields_valid(const ts_hpack_list* L, int* status)
{
    size_t i, j;
    int regular = 0;

    *status = -1;
    for (i = 0; i < L->n; i++) {
        const ts_h2_field* f = &L->fields[i];

        if (!f->name_len) return 0;
        for (j = 0; j < f->value_len; j++)
            if (!value_byte((unsigned char)f->value[j])) return 0;
        if (f->name[0] == ':') {
            if (regular || *status >= 0 || f->name_len != 7 || memcmp(f->name, ":status", 7) != 0) return 0;
            if (f->value_len != 3 || !is_digit(f->value[0]) || !is_digit(f->value[1]) || !is_digit(f->value[2]))
                return 0;
            *status = (f->value[0] - '0') * 100 + (f->value[1] - '0') * 10 + (f->value[2] - '0');
            if (*status < 100 || *status > 599) return 0;
            continue;
        }
        regular = 1;
        for (j = 0; j < f->name_len; j++)
            if (!name_byte((unsigned char)f->name[j])) return 0;
    }
    return 1;
}

/* content-length: enforced when there is exactly one, of digits (as Go's transport); -1 when not. */
static int64_t content_length(const ts_hpack_list* L)
{
    int64_t v = -1;
    size_t i, j, seen = 0;

    for (i = 0; i < L->n; i++) {
        const ts_h2_field* f = &L->fields[i];

        if (f->name_len != 14 || memcmp(f->name, "content-length", 14) != 0) continue;
        if (++seen > 1 || !f->value_len || f->value_len > 18) return -1;
        v = 0;
        for (j = 0; j < f->value_len; j++) {
            if (!is_digit(f->value[j])) return -1;
            v = v * 10 + (f->value[j] - '0');
        }
    }
    return v;
}

static int no_content(int status)
{
    return status == 204 || status == 304;
}

/* END_STREAM from the server: the response is whole, if it is as long as it said (8.1.1). */
static void remote_end(ts_h2* c, int slot)
{
    ts_h2_stream* s = &c->st[slot];
    uint8_t p[4];

    if (s->content_length >= 0 && !no_content(s->status) && s->data_got != (uint64_t)s->content_length) {
        stream_reset_local(c, slot, TS_H2_PROTOCOL_ERROR);
        return;
    }
    ev_push(c, TS_H2_EV_END, s->id);
    if (!(s->flags & ST_LOCAL_END)) {
        /* The whole response came before the whole request (8.1): the rest is not wanted. */
        put32(p, TS_H2_CANCEL);
        if (!put_frame(c, F_RST_STREAM, 0, s->id, p, 4, 0)) {
            stream_free(c, slot);
            conn_error(c, TS_H2_ENHANCE_YOUR_CALM);
            return;
        }
    }
    stream_free(c, slot);
}

/* A whole header block of the server's: decoded always - the table must stay in step - and
 * delivered when its stream is still ours. */
static void header_block(ts_h2* c)
{
    int slot = slot_of(c, c->block_stream), status;
    ts_h2_stream* s;
    ts_h2_event* e;

    if (!ts_hpack_decode(&c->hpack, c->block, c->block_len, &c->list)) {
        conn_error(c, TS_H2_COMPRESSION_ERROR);
        return;
    }
    if (slot < 0) return;
    s = &c->st[slot];
    if (c->list.overflow) {
        /* Over our advertised limit (10.5.1): not this response, but the connection can go on. */
        stream_reset_local(c, slot, TS_H2_CANCEL);
        return;
    }
    if (!fields_valid(&c->list, &status)) {
        stream_reset_local(c, slot, TS_H2_PROTOCOL_ERROR);
        return;
    }
    if (s->flags & ST_GOT_HEAD) {
        /* Trailers: they end the stream and carry no pseudo-field (8.1). Dropped. */
        if (!c->block_end_stream || status >= 0) stream_reset_local(c, slot, TS_H2_PROTOCOL_ERROR);
        else remote_end(c, slot);
        return;
    }
    if (status < 0) {
        stream_reset_local(c, slot, TS_H2_PROTOCOL_ERROR);
        return;
    }
    if (status < 200) {
        /* 1xx: the real head follows. 101 has no place in HTTP/2 (8.6), and an interim head
         * cannot end the stream (8.1). */
        if (status == 101 || c->block_end_stream || ++s->interim > MAX_INTERIM)
            stream_reset_local(c, slot, TS_H2_PROTOCOL_ERROR);
        return;
    }
    s->flags |= ST_GOT_HEAD;
    s->status = status;
    s->content_length = content_length(&c->list);
    e = ev_push(c, TS_H2_EV_HEADERS, s->id);
    e->status = status;
    e->fields = c->list.fields + 1;     /* :status is the first: fields_valid saw to it */
    e->n_fields = c->list.n - 1;
    if (c->block_end_stream) remote_end(c, slot);
}

/* --------------------------------------------------------------------- frames */

static int apply_setting(ts_h2* c)
{
    unsigned id = ((unsigned)c->setting[0] << 8) | c->setting[1];
    uint32_t v = get32(c->setting + 2);
    int64_t delta;
    int i;

    switch (id) {
    case S_HEADER_TABLE_SIZE:
        /* The server's decoder table. Our encoder never adds to it, but a smaller limit is still
         * owed a size update at the start of our next header block (RFC 7541 4.2). */
        if (v < c->enc_table_size) {
            c->enc_table_size = v;
            c->enc_update = 1;
        }
        return 1;
    case S_ENABLE_PUSH:
        if (v > 1) return conn_error(c, TS_H2_PROTOCOL_ERROR);
        return 1;
    case S_MAX_CONCURRENT_STREAMS:
        c->peer_max_streams = v;
        return 1;
    case S_INITIAL_WINDOW_SIZE:
        /* Applies to the open streams too, by the difference (6.9.2). */
        if (v > WINDOW_MAX) return conn_error(c, TS_H2_FLOW_CONTROL_ERROR);
        delta = (int64_t)v - c->peer_initial_window;
        for (i = 0; i < TS_H2_MAX_STREAMS; i++) {
            if (!c->st[i].id) continue;
            c->st[i].send_window += delta;
            if (c->st[i].send_window > WINDOW_MAX) return conn_error(c, TS_H2_FLOW_CONTROL_ERROR);
        }
        c->peer_initial_window = v;
        return 1;
    case S_MAX_FRAME_SIZE:
        if (v < 16384 || v > 16777215) return conn_error(c, TS_H2_PROTOCOL_ERROR);
        c->peer_max_frame = v;
        return 1;
    default:
        /* MAX_HEADER_LIST_SIZE is advice our small requests never come near; unknown settings,
         * such as Go's ENABLE_CONNECT_PROTOCOL and NO_RFC7540_PRIORITIES, are ignored (6.5.2). */
        return 1;
    }
}

/* Checks a frame header in hdr[] and sets up the reading of its payload. 0 when the connection is
 * lost over it. */
static int frame_header(ts_h2* c)
{
    uint32_t len = ((uint32_t)c->hdr[0] << 16) | ((uint32_t)c->hdr[1] << 8) | c->hdr[2];
    uint32_t id = get32(c->hdr + 5) & 0x7fffffff;      /* the reserved bit is ignored (4.1) */
    uint8_t type = c->hdr[3], flags = c->hdr[4];
    int slot;

    c->f_len = len;
    c->f_type = type;
    c->f_flags = flags;
    c->f_stream = id;
    c->f_slot = -1;
    c->f_prefix = 0;
    c->fixed_got = 0;
    c->prefix_done = 0;
    c->f_body_left = 0;
    c->f_pad_left = 0;
    c->setting_got = 0;
    c->debug_got = 0;

    if (len > TS_H2_FRAME_MAX) return conn_error(c, TS_H2_FRAME_SIZE_ERROR);
    /* The server's preface is a SETTINGS frame, before anything else (3.4). */
    if (!c->got_settings && (type != F_SETTINGS || (flags & FL_ACK))) return conn_error(c, TS_H2_PROTOCOL_ERROR);
    /* A header block is one piece: only its own CONTINUATION frames may come in between (6.10). */
    if (c->in_block && (type != F_CONTINUATION || id != c->block_stream)) return conn_error(c, TS_H2_PROTOCOL_ERROR);
    if (!c->in_block && type == F_CONTINUATION) return conn_error(c, TS_H2_PROTOCOL_ERROR);

    switch (type) {
    case F_DATA:
        if (!id || idle_stream(c, id)) return conn_error(c, TS_H2_PROTOCOL_ERROR);
        c->f_prefix = (flags & FL_PADDED) ? 1 : 0;
        if (c->f_prefix > len) return conn_error(c, TS_H2_FRAME_SIZE_ERROR);
        /* The whole payload counts against the windows, padding included (6.9.1). */
        if (len > c->conn_recv_window) return conn_error(c, TS_H2_FLOW_CONTROL_ERROR);
        c->conn_recv_window -= len;
        slot = slot_of(c, id);
        if (slot >= 0) {
            ts_h2_stream* s = &c->st[slot];

            if ((int64_t)len > s->recv_window) return conn_error(c, TS_H2_FLOW_CONTROL_ERROR);
            s->recv_window -= len;
            if (!(s->flags & ST_GOT_HEAD)) {
                /* DATA before the response's head: malformed (8.1) */
                stream_reset_local(c, slot, TS_H2_PROTOCOL_ERROR);
                if (c->dead) return 0;
                slot = -1;
            }
        }
        /* A stream we no longer keep: its data goes nowhere, its share of the connection's
         * window comes back at once (as Go's server does for streams it reset). */
        if (slot < 0) c->conn_recv_unsent += len;
        c->f_slot = slot;
        if (!c->f_prefix) c->f_body_left = len;
        return 1;
    case F_HEADERS:
        if (!id || idle_stream(c, id)) return conn_error(c, TS_H2_PROTOCOL_ERROR);
        c->f_prefix = ((flags & FL_PADDED) ? 1 : 0) + ((flags & FL_PRIORITY) ? 5 : 0);
        if (c->f_prefix > len) return conn_error(c, TS_H2_FRAME_SIZE_ERROR);
        c->block_len = 0;
        c->block_stream = id;
        c->block_end_stream = (flags & FL_END_STREAM) != 0;
        if (!c->f_prefix) c->f_body_left = len;
        return 1;
    case F_CONTINUATION:
        c->f_body_left = len;
        return 1;
    case F_PRIORITY:
        /* Read and ignored, on any stream (5.3 is deprecated; Go's server never sends it). */
        if (!id) return conn_error(c, TS_H2_PROTOCOL_ERROR);
        if (len != 5) return conn_error(c, TS_H2_FRAME_SIZE_ERROR);
        c->f_prefix = 5;
        return 1;
    case F_RST_STREAM:
        if (!id || idle_stream(c, id)) return conn_error(c, TS_H2_PROTOCOL_ERROR);
        if (len != 4) return conn_error(c, TS_H2_FRAME_SIZE_ERROR);
        c->f_prefix = 4;
        return 1;
    case F_SETTINGS:
        if (id) return conn_error(c, TS_H2_PROTOCOL_ERROR);
        if ((flags & FL_ACK) ? len != 0 : len % 6 != 0) return conn_error(c, TS_H2_FRAME_SIZE_ERROR);
        c->f_body_left = len;
        return 1;
    case F_PUSH_PROMISE:
        return conn_error(c, TS_H2_PROTOCOL_ERROR);    /* we said SETTINGS_ENABLE_PUSH = 0 (8.4) */
    case F_PING:
        if (id) return conn_error(c, TS_H2_PROTOCOL_ERROR);
        if (len != 8) return conn_error(c, TS_H2_FRAME_SIZE_ERROR);
        c->f_prefix = 8;
        return 1;
    case F_GOAWAY:
        if (id) return conn_error(c, TS_H2_PROTOCOL_ERROR);
        if (len < 8) return conn_error(c, TS_H2_FRAME_SIZE_ERROR);
        c->f_prefix = 8;
        c->f_body_left = len - 8;
        return 1;
    case F_WINDOW_UPDATE:
        if (len != 4) return conn_error(c, TS_H2_FRAME_SIZE_ERROR);
        if (id && idle_stream(c, id)) return conn_error(c, TS_H2_PROTOCOL_ERROR);
        c->f_prefix = 4;
        return 1;
    default:
        c->f_body_left = len;           /* a type we do not know: skipped (5.5) */
        return 1;
    }
}

/* The fixed bytes at the start of the payload are in: act on them. 0 when the connection is lost. */
static int prefix_done(ts_h2* c)
{
    uint32_t pad = 0, inc, code;
    ts_h2_event* e;
    int slot;

    switch (c->f_type) {
    case F_DATA:
        if (c->f_flags & FL_PADDED) {
            pad = c->fixed[0];
            if (pad >= c->f_len) return conn_error(c, TS_H2_PROTOCOL_ERROR);   /* 6.1 */
            /* The pad length and the padding are never the caller's to take: back at once, as
             * Go's transport gives them. */
            if (c->f_slot >= 0) {
                c->st[c->f_slot].recv_unsent += 1 + pad;
                c->conn_recv_unsent += 1 + pad;
            }
        }
        c->f_body_left = c->f_len - c->f_prefix - pad;
        c->f_pad_left = pad;
        if (c->f_slot >= 0) {
            ts_h2_stream* s = &c->st[c->f_slot];

            /* More than the declared content-length, or content where none can be: malformed. */
            if ((no_content(s->status) && c->f_body_left) ||
                (s->content_length >= 0 && s->data_got + c->f_body_left > (uint64_t)s->content_length)) {
                c->conn_recv_unsent += c->f_body_left;
                stream_reset_local(c, c->f_slot, TS_H2_PROTOCOL_ERROR);
                c->f_slot = -1;
                if (c->dead) return 0;
            }
        }
        return 1;
    case F_HEADERS:
        if (c->f_flags & FL_PADDED) {
            pad = c->fixed[0];
            if (pad > c->f_len - c->f_prefix) return conn_error(c, TS_H2_PROTOCOL_ERROR);    /* 6.2 */
        }
        c->f_body_left = c->f_len - c->f_prefix - pad;
        c->f_pad_left = pad;
        return 1;
    case F_RST_STREAM:
        code = get32(c->fixed);
        slot = slot_of(c, c->f_stream);
        if (slot >= 0) {
            e = ev_push(c, TS_H2_EV_RESET, c->f_stream);
            e->error = code;
            e->refused = code == TS_H2_REFUSED_STREAM;
            stream_free(c, slot);
        }
        return 1;
    case F_PING:
        /* An ACK answers nothing of ours - we never ping - and is ignored. */
        if (!(c->f_flags & FL_ACK) && !put_frame(c, F_PING, FL_ACK, 0, c->fixed, 8, 0))
            return conn_error(c, TS_H2_ENHANCE_YOUR_CALM);
        return 1;
    case F_WINDOW_UPDATE:
        inc = get32(c->fixed) & 0x7fffffff;
        if (!c->f_stream) {
            if (!inc) return conn_error(c, TS_H2_PROTOCOL_ERROR);
            if (c->conn_send_window + inc > WINDOW_MAX) return conn_error(c, TS_H2_FLOW_CONTROL_ERROR);
            c->conn_send_window += inc;
            return 1;
        }
        slot = slot_of(c, c->f_stream);
        if (slot < 0) return 1;         /* a stream that is over: nothing to grow */
        if (!inc) stream_reset_local(c, slot, TS_H2_PROTOCOL_ERROR);
        else if (c->st[slot].send_window + inc > WINDOW_MAX) stream_reset_local(c, slot, TS_H2_FLOW_CONTROL_ERROR);
        else c->st[slot].send_window += inc;
        return !c->dead;
    default:
        return 1;                       /* PRIORITY: ignored; GOAWAY: once its debug data is in */
    }
}

/* GOAWAY (6.8): no new streams; the ones above its last stream were never processed - reset as
 * refused, safe to send again on a new connection. The rest may still finish. */
static void goaway(ts_h2* c)
{
    uint32_t last = get32(c->fixed) & 0x7fffffff, code = get32(c->fixed + 4);
    ts_h2_event* e;
    int i;

    if (c->goaway && last > c->goaway_last) last = c->goaway_last;  /* it may only go down */
    c->goaway = 1;
    c->goaway_last = last;
    e = ev_push(c, TS_H2_EV_GOAWAY, 0);
    e->last_stream = last;
    e->error = code;
    e->data = c->goaway_data;
    e->len = c->debug_got;
    for (i = 0; i < TS_H2_MAX_STREAMS; i++) {
        if (!c->st[i].id || c->st[i].id <= last) continue;
        e = ev_push(c, TS_H2_EV_RESET, c->st[i].id);
        e->error = TS_H2_REFUSED_STREAM;
        e->refused = 1;
        stream_free(c, i);
    }
}

/* Content bytes of the payload (after the fixed prefix, before the padding). */
static void body_bytes(ts_h2* c, const uint8_t* p, size_t n, ts_h2_event* ev)
{
    size_t i;

    switch (c->f_type) {
    case F_DATA:
        if (c->f_slot >= 0) {
            ts_h2_stream* s = &c->st[c->f_slot];

            s->recv_held += (uint32_t)n;
            s->data_got += n;
            ev->type = TS_H2_EV_DATA;
            ev->stream = s->id;
            ev->data = p;
            ev->len = n;
        }
        return;
    case F_HEADERS:
    case F_CONTINUATION:
        /* A block we cannot hold cannot be decoded, and one not decoded puts the table out of
         * step: the connection goes (Go's framer ends it with PROTOCOL_ERROR the same way). */
        if (n > TS_H2_HEADER_BLOCK_MAX - c->block_len) {
            conn_error(c, TS_H2_PROTOCOL_ERROR);
            return;
        }
        memcpy(c->block + c->block_len, p, n);
        c->block_len += n;
        return;
    case F_SETTINGS:
        for (i = 0; i < n; i++) {
            c->setting[c->setting_got++] = p[i];
            if (c->setting_got < 6) continue;
            c->setting_got = 0;
            if (!apply_setting(c)) return;
        }
        return;
    case F_GOAWAY:
        for (i = 0; i < n && c->debug_got < sizeof(c->goaway_data); i++) c->goaway_data[c->debug_got++] = p[i];
        return;
    default:
        return;
    }
}

/* The payload is all in: finish the frame. */
static void frame_done(ts_h2* c)
{
    switch (c->f_type) {
    case F_DATA:
        if (c->f_slot >= 0 && (c->f_flags & FL_END_STREAM)) remote_end(c, c->f_slot);
        return;
    case F_HEADERS:
    case F_CONTINUATION:
        if (!(c->f_flags & FL_END_HEADERS)) {
            c->in_block = 1;
            return;
        }
        c->in_block = 0;
        header_block(c);
        return;
    case F_SETTINGS:
        if (c->f_flags & FL_ACK) return;
        c->got_settings = 1;
        if (!put_frame(c, F_SETTINGS, FL_ACK, 0, NULL, 0, 0)) conn_error(c, TS_H2_ENHANCE_YOUR_CALM);
        return;
    case F_GOAWAY:
        goaway(c);
        return;
    default:
        return;
    }
}

/* Reads into the current frame's payload; returns the bytes taken. A DATA event may come out. */
static size_t rx_payload(ts_h2* c, const uint8_t* in, size_t len, ts_h2_event* ev)
{
    size_t pos = 0, n;

    while (c->fixed_got < c->f_prefix && pos < len) c->fixed[c->fixed_got++] = in[pos++];
    if (c->fixed_got < c->f_prefix) return pos;
    if (!c->prefix_done) {
        c->prefix_done = 1;
        if (!prefix_done(c)) return pos;
    }
    if (c->f_body_left) {
        n = len - pos;
        if (n > c->f_body_left) n = c->f_body_left;
        if (!n) return pos;
        body_bytes(c, in + pos, n, ev);
        c->f_body_left -= (uint32_t)n;
        pos += n;
        if (c->dead || c->f_body_left) return pos;
    }
    n = len - pos;
    if (n > c->f_pad_left) n = c->f_pad_left;
    c->f_pad_left -= (uint32_t)n;
    pos += n;
    if (c->f_pad_left) return pos;
    /* Whole: finished right away, so a DATA event that took its last bytes has the END behind it. */
    c->phase = RX_HEADER;
    c->hdr_got = 0;
    frame_done(c);
    return pos;
}

/* The 9-byte header is in hdr[]: check it, then read what of the payload is here. */
static size_t frame_begin(ts_h2* c, const uint8_t* in, size_t len, ts_h2_event* ev)
{
    c->hdr_got = 0;
    if (!frame_header(c)) return 0;
    c->phase = RX_PAYLOAD;
    return rx_payload(c, in, len, ev);
}

/* One step on the input: some bytes taken, or a frame finished. */
static size_t rx_step(ts_h2* c, const uint8_t* in, size_t len, ts_h2_event* ev)
{
    size_t pos = 0, n;
    ts_h2_event* e;

    switch (c->phase) {
    case RX_EARLY:
        while (c->hdr_got < 9 && pos < len) c->hdr[c->hdr_got++] = in[pos++];
        if (c->hdr_got < 9) return pos;
        if (memcmp(c->hdr, "\xff\xff\xffTS", 5) != 0) {
            /* No EarlyNoise: these 9 bytes are the first frame's header (ts2021/conn.go puts
             * them back in front of the HTTP/2 stream the same way). */
            c->phase = RX_HEADER;
            return pos + frame_begin(c, in + pos, len - pos, ev);
        }
        c->early_len = get32(c->hdr + 5);
        c->hdr_got = 0;
        if (c->early_len > TS_H2_EARLY_MAX) {
            conn_error(c, TS_H2_PROTOCOL_ERROR);
            return pos;
        }
        c->block_len = 0;
        c->phase = RX_EARLY_BODY;
        if (!c->early_len) {
            /* Empty: whole already. The caller's JSON parser has the say on it, as Go's has. */
            e = ev_push(c, TS_H2_EV_EARLY, 0);
            e->data = c->block;
            c->phase = RX_HEADER;
        }
        return pos;
    case RX_EARLY_BODY:
        n = len - pos;
        if (n > c->early_len - c->block_len) n = c->early_len - c->block_len;
        if (n) memcpy(c->block + c->block_len, in + pos, n);
        c->block_len += n;
        pos += n;
        if (c->block_len == c->early_len) {
            e = ev_push(c, TS_H2_EV_EARLY, 0);
            e->data = c->block;
            e->len = c->early_len;
            c->phase = RX_HEADER;
        }
        return pos;
    case RX_HEADER:
        while (c->hdr_got < 9 && pos < len) c->hdr[c->hdr_got++] = in[pos++];
        if (c->hdr_got < 9) return pos;
        return pos + frame_begin(c, in + pos, len - pos, ev);
    case RX_PAYLOAD:
        return rx_payload(c, in, len, ev);
    default:
        return len;
    }
}

size_t ts_h2_input(ts_h2* c, const uint8_t* in, size_t len, ts_h2_event* ev)
{
    size_t pos = 0;

    memset(ev, 0, sizeof(*ev));
    for (;;) {
        if (ev_pop(c, ev)) return pos;
        if (pos == len) return pos;
        if (c->phase == RX_DEAD) return len;
        pos += rx_step(c, in + pos, len - pos, ev);
        if (ev->type != TS_H2_EV_NONE) return pos;
    }
}

void ts_h2_eof(ts_h2* c)
{
    if (!c->dead) close_all(c, TS_H2_ERR_EOF, 0);
}

/* --------------------------------------------------------------------- the output */

/* Window updates owed (Go's inflow.add): when at least 4 KiB is owed, or enough to double what
 * the server has left. Without room they wait for the next call. */
static void flush_window_updates(ts_h2* c)
{
    uint8_t p[4];
    int i;

    if (c->conn_recv_unsent && (c->conn_recv_unsent >= 4096 || c->conn_recv_unsent >= c->conn_recv_window)) {
        put32(p, c->conn_recv_unsent);
        if (!put_frame(c, F_WINDOW_UPDATE, 0, 0, p, 4, 0)) return;
        c->conn_recv_window += c->conn_recv_unsent;
        c->conn_recv_unsent = 0;
    }
    for (i = 0; i < TS_H2_MAX_STREAMS; i++) {
        ts_h2_stream* s = &c->st[i];

        if (!s->id || !s->recv_unsent || (s->recv_unsent < 4096 && s->recv_unsent < s->recv_window)) continue;
        put32(p, s->recv_unsent);
        if (!put_frame(c, F_WINDOW_UPDATE, 0, s->id, p, 4, 0)) return;
        s->recv_window += s->recv_unsent;
        s->recv_unsent = 0;
    }
}

/*
 * Request bodies as DATA, as far as the server's windows go. A frame is as large as the body, the
 * windows and 16 KiB allow (as Go's client frames it), and goes out whole: without room for it now
 * it waits for the caller to take the output - an empty output always has room for one.
 */
static void flush_data(ts_h2* c)
{
    int i;

    for (i = 0; i < TS_H2_MAX_STREAMS; i++) {
        ts_h2_stream* s = &c->st[i];

        while (s->id && !(s->flags & ST_LOCAL_END)) {
            size_t n = s->body_len - s->body_sent;
            int64_t win = c->conn_send_window < s->send_window ? c->conn_send_window : s->send_window;
            uint8_t* p;
            int end;

            if (win <= 0) break;
            if (n > c->peer_max_frame) n = c->peer_max_frame;
            if (n > TS_H2_FRAME_MAX) n = TS_H2_FRAME_MAX;
            if ((int64_t)n > win) n = (size_t)win;
            if (TS_H2_OUT_MAX - c->out_len < 9 + n + CONTROL_RESERVE) return;
            end = s->body_sent + n == s->body_len;
            p = c->out + c->out_len;
            p[0] = (uint8_t)(n >> 16);
            p[1] = (uint8_t)(n >> 8);
            p[2] = (uint8_t)n;
            p[3] = F_DATA;
            p[4] = end ? FL_END_STREAM : 0;
            put32(p + 5, s->id);
            memcpy(p + 9, c->send + s->body_off + s->body_sent, n);
            c->out_len += 9 + n;
            s->body_sent += n;
            s->send_window -= (int64_t)n;
            c->conn_send_window -= (int64_t)n;
            if (end) {
                s->flags |= ST_LOCAL_END;
                body_release(c, s);
            }
        }
    }
}

const uint8_t* ts_h2_output(ts_h2* c, size_t* len)
{
    if (!c->dead) {
        flush_window_updates(c);
        flush_data(c);
    }
    *len = c->out_len;
    return c->out;
}

void ts_h2_output_done(ts_h2* c, size_t n)
{
    if (n > c->out_len) n = c->out_len;
    memmove(c->out, c->out + n, c->out_len - n);
    c->out_len -= n;
}

/* --------------------------------------------------------------------- requests */

static int tchar(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           (c && strchr("!#$%&'*+-.^_`|~", c) != NULL);
}

static int token_ok(const char* s)
{
    if (!*s) return 0;
    for (; *s; s++)
        if (!tchar(*s)) return 0;
    return 1;
}

static int scheme_ok(const char* s)
{
    if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z'))) return 0;
    for (s++; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || is_digit(*s) || *s == '+' || *s == '-' || *s == '.'))
            return 0;
    return 1;
}

/* host[:port] or [v6]:port - what goes into :authority. */
static int authority_ok(const char* s)
{
    if (!*s) return 0;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || is_digit(*s) || strchr(".-_~:[]", *s)))
            return 0;
    return 1;
}

/* An origin-form path: "/" and visible ASCII, no space. */
static int path_ok(const char* s)
{
    if (*s != '/') return 0;
    for (; *s; s++)
        if ((unsigned char)*s <= 0x20 || (unsigned char)*s >= 0x7f) return 0;
    return 1;
}

static int value_ok(const char* s)
{
    for (; *s; s++)
        if (!value_byte((unsigned char)*s)) return 0;
    return 1;
}

/* A regular request field: a lowercase token, none of the connection-specific ones HTTP/2 forbids
 * (8.2.2), not content-length (it is ours) or host (that is :authority). */
static int request_field_ok(const ts_h2_pair* f)
{
    static const char* const banned[] = {
        "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host",
        "content-length",
    };
    const char* s;
    size_t i;

    if (!f->name || !f->value || !*f->name || !value_ok(f->value)) return 0;
    for (s = f->name; *s; s++)
        if (!name_byte((unsigned char)*s)) return 0;
    for (i = 0; i < sizeof(banned) / sizeof(banned[0]); i++)
        if (strcmp(f->name, banned[i]) == 0) return 0;
    if (strcmp(f->name, "te") == 0 && strcmp(f->value, "trailers") != 0) return 0;
    return 1;
}

typedef struct {
    uint8_t* p;
    size_t   cap;
    size_t   len;
    int      failed;
} enc;

static void enc_int(enc* e, uint8_t first, unsigned n, uint64_t v)
{
    size_t k;

    if (e->failed) return;
    k = ts_hpack_put_int(e->p + e->len, e->cap - e->len, first, n, v);
    if (!k) e->failed = 1;
    else e->len += k;
}

/* A string literal, raw (H = 0): our values are short and Huffman would only cost code. */
static void enc_str(enc* e, const char* s)
{
    size_t n = strlen(s);

    enc_int(e, 0x00, 7, n);
    if (e->failed) return;
    if (n > e->cap - e->len) {
        e->failed = 1;
        return;
    }
    memcpy(e->p + e->len, s, n);
    e->len += n;
}

/* A literal without indexing (6.2.2): the name by its static index when it has one. */
static void enc_field(enc* e, unsigned name_index, const char* name, const char* value)
{
    enc_int(e, 0x00, 4, name_index);
    if (!name_index) enc_str(e, name);
    enc_str(e, value);
}

static unsigned static_name(const char* name)
{
    unsigned i;

    for (i = 0; i < 61; i++)
        if (strcmp(hp_static[i][0], name) == 0) return i + 1;
    return 0;
}

uint32_t ts_h2_request(ts_h2* c, const ts_h2_req* r)
{
    int slot = -1, i;
    unsigned open = 0;
    size_t k, room;
    char clen[24];
    ts_h2_stream* s;
    uint8_t* p;
    enc e;

    if (!r || !ts_h2_usable(c) || c->next_id > 0x7fffffff) return 0;
    if (!r->method || !r->scheme || !r->authority || !r->path || (r->n_fields && !r->fields) ||
        (r->body_len && !r->body))
        return 0;
    if (!token_ok(r->method) || !scheme_ok(r->scheme) || !authority_ok(r->authority) || !path_ok(r->path))
        return 0;
    for (k = 0; k < r->n_fields; k++)
        if (!request_field_ok(&r->fields[k])) return 0;
    for (i = 0; i < TS_H2_MAX_STREAMS; i++) {
        if (c->st[i].id) open++;
        else if (slot < 0) slot = i;
    }
    if (slot < 0 || open >= c->peer_max_streams) return 0;
    if (r->body_len > TS_H2_SEND_MAX - c->send_used) return 0;
    if (TS_H2_OUT_MAX - c->out_len <= 9 + CONTROL_RESERVE) return 0;
    room = TS_H2_OUT_MAX - c->out_len - 9 - CONTROL_RESERVE;
    if (room > TS_H2_REQ_BLOCK_MAX) room = TS_H2_REQ_BLOCK_MAX;

    /* The block straight into the output, behind room for the frame header. */
    p = c->out + c->out_len;
    e.p = p + 9;
    e.cap = room;
    e.len = 0;
    e.failed = 0;
    if (c->enc_update) enc_int(&e, 0x20, 5, c->enc_table_size);
    /* The pseudo-fields in Go's order (transport.go, encodeHeaders): authority, method, path, scheme. */
    enc_field(&e, 1, NULL, r->authority);
    enc_field(&e, 2, NULL, r->method);
    enc_field(&e, 4, NULL, r->path);
    enc_field(&e, 6, NULL, r->scheme);
    for (k = 0; k < r->n_fields; k++)
        enc_field(&e, static_name(r->fields[k].name), r->fields[k].name, r->fields[k].value);
    /* content-length after the caller's fields, as Go: for any body, and for an empty one with
     * POST, PUT, PATCH (shouldSendReqContentLength). */
    if (r->body_len || !strcmp(r->method, "POST") || !strcmp(r->method, "PUT") || !strcmp(r->method, "PATCH")) {
        size_t v = r->body_len, j = sizeof(clen) - 1;

        clen[j] = '\0';
        do {
            clen[--j] = (char)('0' + v % 10);
            v /= 10;
        } while (v);
        enc_field(&e, 28, NULL, clen + j);
    }
    if (e.failed) return 0;

    s = &c->st[slot];
    memset(s, 0, sizeof(*s));
    s->id = c->next_id;
    c->next_id += 2;
    p[0] = (uint8_t)(e.len >> 16);
    p[1] = (uint8_t)(e.len >> 8);
    p[2] = (uint8_t)e.len;
    p[3] = F_HEADERS;
    p[4] = (uint8_t)(FL_END_HEADERS | (r->body_len ? 0 : FL_END_STREAM));
    put32(p + 5, s->id);
    c->out_len += 9 + e.len;
    c->enc_update = 0;
    s->send_window = c->peer_initial_window;
    s->recv_window = c->stream_window;
    s->content_length = -1;
    if (r->body_len) {
        memcpy(c->send + c->send_used, r->body, r->body_len);
        s->body_off = c->send_used;
        s->body_len = r->body_len;
        c->send_used += r->body_len;
    } else {
        s->flags |= ST_LOCAL_END;
    }
    return s->id;
}

/* --------------------------------------------------------------------- the rest */

void ts_h2_init(ts_h2* c, uint32_t stream_window, int early)
{
    uint8_t s[18], w[4];
    uint32_t total;

    memset(c, 0, sizeof(*c));
    if (!stream_window) stream_window = TS_H2_DEFAULT_WINDOW;
    if (stream_window < 1024) stream_window = 1024;
    if (stream_window > TS_H2_MAX_WINDOW) stream_window = TS_H2_MAX_WINDOW;
    c->stream_window = stream_window;
    c->early = early != 0;
    c->next_id = 1;
    c->peer_max_frame = 16384;
    c->peer_initial_window = TS_H2_DEFAULT_WINDOW;
    c->peer_max_streams = 0xffffffffu;
    c->enc_table_size = TS_HPACK_TABLE_MAX;
    c->conn_send_window = TS_H2_DEFAULT_WINDOW;
    c->conn_recv_window = TS_H2_DEFAULT_WINDOW;
    c->phase = c->early ? RX_EARLY : RX_HEADER;
    c->f_slot = -1;
    ts_hpack_init(&c->hpack, TS_HPACK_TABLE_MAX);

    memcpy(c->out, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
    c->out_len = 24;
    /* As Go's client: push off and our stream window; and our header list limit. */
    s[0] = 0;
    s[1] = S_ENABLE_PUSH;
    put32(s + 2, 0);
    s[6] = 0;
    s[7] = S_INITIAL_WINDOW_SIZE;
    put32(s + 8, stream_window);
    s[12] = 0;
    s[13] = S_MAX_HEADER_LIST_SIZE;
    put32(s + 14, TS_H2_HEADER_LIST_MAX);
    put_frame(c, F_SETTINGS, 0, 0, s, sizeof(s), 0);
    /* The connection's window covers every stream's, so one stream held up by the caller never
     * blocks another (Go's client goes further: 1 GiB). */
    total = stream_window * TS_H2_MAX_STREAMS;
    if (total > TS_H2_DEFAULT_WINDOW) {
        put32(w, total - TS_H2_DEFAULT_WINDOW);
        put_frame(c, F_WINDOW_UPDATE, 0, 0, w, 4, 0);
        c->conn_recv_window = total;
    }
}

void ts_h2_consume(ts_h2* c, uint32_t stream, size_t n)
{
    int slot = slot_of(c, stream);
    ts_h2_stream* s;

    if (slot < 0 || !n) return;
    s = &c->st[slot];
    if (n > s->recv_held) n = s->recv_held;
    s->recv_held -= (uint32_t)n;
    s->recv_unsent += (uint32_t)n;
    c->conn_recv_unsent += (uint32_t)n;
}

void ts_h2_cancel(ts_h2* c, uint32_t stream)
{
    int slot = slot_of(c, stream);
    size_t i, n = c->ev_n, kept = 0;
    ts_h2_event keep[TS_H2_EVQ];
    uint8_t p[4];

    if (slot >= 0) {
        int sent;

        put32(p, TS_H2_CANCEL);
        sent = put_frame(c, F_RST_STREAM, 0, stream, p, 4, 0);
        stream_free(c, slot);
        /* Without it the server would go on sending: a full output means a flood. */
        if (!sent) conn_error(c, TS_H2_ENHANCE_YOUR_CALM);
    }
    /* Events already waiting for it are dropped. */
    for (i = 0; i < n; i++) {
        ts_h2_event* e = &c->evq[(c->ev_head + i) % TS_H2_EVQ];
        if (!stream || e->stream != stream) keep[kept++] = *e;
    }
    for (i = 0; i < kept; i++) c->evq[i] = keep[i];
    c->ev_head = 0;
    c->ev_n = kept;
}

int ts_h2_usable(const ts_h2* c)
{
    return !c->dead && !c->goaway;
}

const char* ts_h2_field_value(const ts_h2_event* ev, const char* name, size_t* len)
{
    size_t i, n = strlen(name);

    if (ev->type != TS_H2_EV_HEADERS) return NULL;
    for (i = 0; i < ev->n_fields; i++) {
        const ts_h2_field* f = &ev->fields[i];
        if (f->name_len == n && memcmp(f->name, name, n) == 0) {
            if (len) *len = f->value_len;
            return f->value;
        }
    }
    return NULL;
}

const char* ts_h2_error_text(uint32_t code)
{
    switch (code) {
    case TS_H2_NO_ERROR:            return "no error";
    case TS_H2_PROTOCOL_ERROR:      return "protocol error";
    case TS_H2_INTERNAL_ERROR:      return "internal error";
    case TS_H2_FLOW_CONTROL_ERROR:  return "flow-control error";
    case TS_H2_SETTINGS_TIMEOUT:    return "settings timeout";
    case TS_H2_STREAM_CLOSED:       return "stream closed";
    case TS_H2_FRAME_SIZE_ERROR:    return "frame size error";
    case TS_H2_REFUSED_STREAM:      return "refused stream";
    case TS_H2_CANCEL:              return "cancel";
    case TS_H2_COMPRESSION_ERROR:   return "compression error";
    case TS_H2_CONNECT_ERROR:       return "connect error";
    case TS_H2_ENHANCE_YOUR_CALM:   return "enhance your calm";
    case TS_H2_INADEQUATE_SECURITY: return "inadequate security";
    case TS_H2_HTTP_1_1_REQUIRED:   return "HTTP/1.1 required";
    case TS_H2_ERR_EOF:             return "connection closed";
    }
    return "unknown error";
}
