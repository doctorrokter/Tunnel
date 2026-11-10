/*
 * bt_resolve - see bt_resolve.h. The wire format is RFC 1035 section 4; nothing was taken from an
 * existing resolver.
 */

#include "bt_resolve.h"

#include <string.h>

#define HEADER_LEN      12
#define FLAG_QR         0x8000
#define FLAG_TC         0x0200
#define FLAG_RD         0x0100
#define CLASS_IN        1
#define MAX_RECORDS     24
#define MAX_CNAME_HOPS  8
#define MAX_POINTERS    32

int bt_addr_equal(const bt_addr* a, const bt_addr* b)
{
    if (a->family != b->family) return 0;
    return memcmp(a->addr, b->addr, a->family == 4 ? 4 : 16) == 0;
}

static char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

static int label_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

int bt_dns_name_valid(const char* name)
{
    size_t len = strlen(name), i, label = 0;

    if (len && name[len - 1] == '.') len--;
    if (!len || len > BT_DNS_NAME_MAX) return 0;
    for (i = 0; i < len; i++) {
        if (name[i] == '.') {
            if (!label) return 0;
            label = 0;
        } else {
            if (!label_char(name[i]) || ++label > 63) return 0;
        }
    }
    return label > 0;
}

/* lowercase, without the trailing dot; the name is valid */
static void normalize(char* out, const char* name)
{
    size_t len = strlen(name), i;

    if (len && name[len - 1] == '.') len--;
    for (i = 0; i < len; i++) out[i] = lower(name[i]);
    out[len] = '\0';
}

static void put16(uint8_t* p, unsigned v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static unsigned get16(const uint8_t* p)
{
    return ((unsigned)p[0] << 8) | p[1];
}

size_t bt_dns_query(uint8_t* out, size_t cap, uint16_t id, const char* name, uint16_t qtype)
{
    char norm[BT_DNS_NAME_MAX + 1];
    size_t len, pos, i, start;

    if (!bt_dns_name_valid(name)) return 0;
    normalize(norm, name);
    len = strlen(norm);
    if (cap < HEADER_LEN + len + 2 + 4) return 0;

    memset(out, 0, HEADER_LEN);
    put16(out, id);
    put16(out + 2, FLAG_RD);
    put16(out + 4, 1);                  /* one question */
    pos = HEADER_LEN;
    start = 0;
    for (i = 0; i <= len; i++) {
        if (i == len || norm[i] == '.') {
            out[pos++] = (uint8_t)(i - start);
            memcpy(out + pos, norm + start, i - start);
            pos += i - start;
            start = i + 1;
        }
    }
    out[pos++] = 0;
    put16(out + pos, qtype);
    put16(out + pos + 2, CLASS_IN);
    return pos + 4;
}

/*
 * The name at msg[off], dotted and lowercase, into out (BT_DNS_NAME_MAX + 1 bytes; "" for the
 * root); *next is where the name ends in the message (after its first pointer, if any). A pointer
 * must point strictly backwards from where it stands, so no chain of them can loop.
 */
static int read_name(const uint8_t* msg, size_t len, size_t off, char* out, size_t* next)
{
    size_t pos = off, olen = 0;
    int jumped = 0, pointers = 0;

    for (;;) {
        unsigned c;

        if (pos >= len) return 0;
        c = msg[pos];
        if (c == 0) {
            if (!jumped) *next = pos + 1;
            break;
        }
        if ((c & 0xc0) == 0xc0) {
            size_t target;
            if (pos + 1 >= len || ++pointers > MAX_POINTERS) return 0;
            target = ((c & 0x3f) << 8) | msg[pos + 1];
            if (target >= pos) return 0;
            if (!jumped) *next = pos + 2;
            jumped = 1;
            pos = target;
            continue;
        }
        if (c & 0xc0) return 0;         /* 0x40 / 0x80: label types nobody uses */
        if (pos + 1 + c > len) return 0;
        if (olen + (olen ? 1 : 0) + c > BT_DNS_NAME_MAX) return 0;
        if (olen) out[olen++] = '.';
        {
            size_t i;
            for (i = 0; i < c; i++) {
                char ch = (char)msg[pos + 1 + i];
                if (ch == '\0' || ch == '.') return 0;  /* not a name we can compare as text */
                out[olen++] = lower(ch);
            }
        }
        pos += 1 + c;
    }
    out[olen] = '\0';
    return 1;
}

typedef struct {
    char     owner[BT_DNS_NAME_MAX + 1];
    unsigned type;
    uint32_t ttl;
    size_t   rdata;
    size_t   rdlen;
} record;

int bt_dns_parse(const uint8_t* msg, size_t len, uint16_t id, const char* name, uint16_t qtype,
                 bt_dns_answer* out)
{
    static record rec[MAX_RECORDS];     /* 6 KB; single-threaded */
    char qname[BT_DNS_NAME_MAX + 1], got[BT_DNS_NAME_MAX + 1], cur[BT_DNS_NAME_MAX + 1];
    unsigned flags, ancount, i, hops;
    size_t pos, nrec = 0;
    uint32_t ttl = 0xffffffffu;
    int any = 0;

    memset(out, 0, sizeof(*out));
    if (!bt_dns_name_valid(name) || len < HEADER_LEN) return 0;
    normalize(qname, name);
    flags = get16(msg + 2);
    if (get16(msg) != id || !(flags & FLAG_QR) || ((flags >> 11) & 0xf) != 0) return 0;
    if (get16(msg + 4) != 1) return 0;

    if (!read_name(msg, len, HEADER_LEN, got, &pos) || pos + 4 > len) return 0;
    if (strcmp(got, qname) != 0 || get16(msg + pos) != qtype || get16(msg + pos + 2) != CLASS_IN) return 0;
    pos += 4;

    out->rcode = (int)(flags & 0xf);
    out->truncated = (flags & FLAG_TC) != 0;
    if (out->rcode != 0) return 1;

    /* The answer section; a truncated reply keeps the records that arrived whole. */
    ancount = get16(msg + 6);
    for (i = 0; i < ancount && nrec < MAX_RECORDS; i++) {
        record* r = &rec[nrec];
        size_t next;

        if (!read_name(msg, len, pos, r->owner, &next) || next + 10 > len) {
            if (out->truncated) break;
            return 0;
        }
        r->type = get16(msg + next);
        r->ttl = ((uint32_t)get16(msg + next + 4) << 16) | get16(msg + next + 6);
        r->rdlen = get16(msg + next + 8);
        r->rdata = next + 10;
        if (r->rdata + r->rdlen > len) {
            if (out->truncated) break;
            return 0;
        }
        pos = r->rdata + r->rdlen;
        if (get16(msg + next + 2) == CLASS_IN) nrec++;
    }

    /* Follow the CNAME chain from the question's name. */
    strcpy(cur, qname);
    for (hops = 0; hops < MAX_CNAME_HOPS; hops++) {
        size_t k, dummy;
        int moved = 0;
        for (k = 0; k < nrec; k++) {
            if (rec[k].type == BT_DNS_TYPE_CNAME && strcmp(rec[k].owner, cur) == 0) {
                if (!read_name(msg, rec[k].rdata + rec[k].rdlen, rec[k].rdata, got, &dummy)) return 0;
                if (rec[k].ttl < ttl) ttl = rec[k].ttl;
                strcpy(cur, got);
                moved = 1;
                break;
            }
        }
        if (!moved) break;
    }

    for (i = 0; i < nrec && out->n < BT_DNS_MAX_ADDRS; i++) {
        record* r = &rec[i];
        size_t want = qtype == BT_DNS_TYPE_A ? 4 : 16;

        if (r->type != qtype || r->rdlen != want || strcmp(r->owner, cur) != 0) continue;
        out->addrs[out->n].family = qtype == BT_DNS_TYPE_A ? 4 : 6;
        memset(out->addrs[out->n].addr, 0, 16);
        memcpy(out->addrs[out->n].addr, msg + r->rdata, want);
        out->n++;
        if (r->ttl < ttl) ttl = r->ttl;
        any = 1;
    }
    out->ttl = any ? ttl : 0;
    return 1;
}

/* --------------------------------------------------------------------- a lookup */

static void finish(bt_lookup* l)
{
    size_t i;

    l->n = 0;
    for (i = 0; i < l->n4 && l->n < BT_DNS_MAX_ADDRS; i++) l->addrs[l->n++] = l->v4[i];
    for (i = 0; i < l->n6 && l->n < BT_DNS_MAX_ADDRS; i++) l->addrs[l->n++] = l->v6[i];
    if (l->n) {
        l->state = BT_LOOKUP_DONE;
        l->error = BT_LOOKUP_OK;
        l->ttl = l->n4 && l->n6 ? (l->ttl4 < l->ttl6 ? l->ttl4 : l->ttl6) : l->n4 ? l->ttl4 : l->ttl6;
    } else {
        l->state = BT_LOOKUP_FAILED;
    }
    l->deadline = BT_NEVER;
}

static void fail(bt_lookup* l, bt_lookup_error e)
{
    l->state = BT_LOOKUP_FAILED;
    l->error = e;
    l->deadline = BT_NEVER;
}

int bt_lookup_start(bt_lookup* l, const char* name, const bt_addr* servers, size_t n_servers,
                    int want4, int want6, const wg_rng* rng, uint64_t now_ns)
{
    uint8_t r[4];
    size_t i;

    memset(l, 0, sizeof(*l));
    l->state = BT_LOOKUP_RUNNING;
    l->want[0] = want4 != 0;
    l->want[1] = want6 != 0;
    if (!bt_dns_name_valid(name) || (!want4 && !want6)) {
        fail(l, BT_LOOKUP_ERR_NAME);
        return 0;
    }
    normalize(l->name, name);
    for (i = 0; i < n_servers && l->n_servers < BT_LOOKUP_SERVERS; i++)
        if (servers[i].family == 4 || servers[i].family == 6) l->servers[l->n_servers++] = servers[i];
    if (!l->n_servers) {
        fail(l, BT_LOOKUP_ERR_NO_SERVERS);
        return 0;
    }
    if (!wg_rng_bytes(rng, r, sizeof(r))) {
        fail(l, BT_LOOKUP_ERR_TIMEOUT);
        return 0;
    }
    l->id[0] = (uint16_t)((r[0] << 8) | r[1]);
    l->id[1] = (uint16_t)((r[2] << 8) | r[3]);
    if (l->id[1] == l->id[0]) l->id[1] ^= 1;
    l->deadline = now_ns;
    return 1;
}

uint64_t bt_lookup_tick(bt_lookup* l, uint64_t now_ns, bt_lookup_send_fn send, void* ctx)
{
    static const uint16_t qtype[2] = { BT_DNS_TYPE_A, BT_DNS_TYPE_AAAA };
    const bt_addr* server;
    int k;

    if (l->state != BT_LOOKUP_RUNNING) return BT_NEVER;
    if (now_ns < l->deadline) return l->deadline;
    if (l->attempt == BT_LOOKUP_ATTEMPTS) {
        /* Out of rounds: what arrived is the answer, if anything did. */
        finish(l);
        if (l->state == BT_LOOKUP_FAILED)
            l->error = (l->answered[0] || l->answered[1]) ? BT_LOOKUP_ERR_NODATA : BT_LOOKUP_ERR_TIMEOUT;
        return BT_NEVER;
    }
    server = &l->servers[l->attempt % l->n_servers];
    for (k = 0; k < 2; k++) {
        uint8_t q[HEADER_LEN + BT_DNS_NAME_MAX + 2 + 4];
        size_t qlen;

        if (!l->want[k] || l->answered[k]) continue;
        qlen = bt_dns_query(q, sizeof(q), l->id[k], l->name, qtype[k]);
        if (qlen) send(ctx, server, q, qlen);
    }
    l->attempt++;
    l->deadline = now_ns + BT_LOOKUP_RETRY_NS;
    return l->deadline;
}

int bt_lookup_receive(bt_lookup* l, const bt_addr* from, uint16_t from_port, const uint8_t* msg,
                      size_t len, uint64_t now_ns)
{
    static const uint16_t qtype[2] = { BT_DNS_TYPE_A, BT_DNS_TYPE_AAAA };
    bt_dns_answer a;
    size_t i;
    int k, known = 0;

    if (l->state != BT_LOOKUP_RUNNING || from_port != BT_DNS_PORT) return 0;
    for (i = 0; i < l->n_servers; i++)
        if (bt_addr_equal(&l->servers[i], from)) known = 1;
    if (!known) return 0;

    for (k = 0; k < 2; k++) {
        if (!l->want[k] || l->answered[k]) continue;
        if (!bt_dns_parse(msg, len, l->id[k], l->name, qtype[k], &a)) continue;

        if (a.rcode == 3) {
            fail(l, BT_LOOKUP_ERR_NXDOMAIN);
            return 1;
        }
        if (a.rcode != 0) {
            /* This server cannot help: the next one, now - unless the other type is still out. */
            l->deadline = now_ns;
            return 1;
        }
        l->answered[k] = 1;
        if (k == 0) {
            memcpy(l->v4, a.addrs, a.n * sizeof(bt_addr));
            l->n4 = a.n;
            l->ttl4 = a.ttl;
        } else {
            memcpy(l->v6, a.addrs, a.n * sizeof(bt_addr));
            l->n6 = a.n;
            l->ttl6 = a.ttl;
        }

        /* IPv4 preferred: its addresses end the lookup at once. Otherwise wait for every type asked. */
        if (l->n4 || ((!l->want[0] || l->answered[0]) && (!l->want[1] || l->answered[1]))) {
            finish(l);
            if (l->state == BT_LOOKUP_FAILED) l->error = BT_LOOKUP_ERR_NODATA;
        }
        return 1;
    }
    return 0;
}

const char* bt_lookup_error_text(bt_lookup_error e)
{
    switch (e) {
    case BT_LOOKUP_OK:              return "ok";
    case BT_LOOKUP_ERR_NAME:        return "bad name";
    case BT_LOOKUP_ERR_NO_SERVERS:  return "no DNS servers";
    case BT_LOOKUP_ERR_NXDOMAIN:    return "no such name";
    case BT_LOOKUP_ERR_NODATA:      return "no address for the name";
    case BT_LOOKUP_ERR_TIMEOUT:     return "no answer from DNS";
    }
    return "?";
}
