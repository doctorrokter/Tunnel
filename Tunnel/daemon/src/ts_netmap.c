/*
 * ts_netmap - see ts_netmap.h. Where a rule comes from Tailscale v1.102.5, the function it comes
 * from is named next to it.
 */

#include "ts_netmap.h"

#include <string.h>

#define SLOT_NONE       0xffffu
#define SLOTS_MAX       65534u
#define REC_HDR         6               /* an arena record: owner slot (2 bytes), payload size (4) */
#define PFX             sizeof(wg_prefix)
#define KEYTEXT_MAX     80              /* the longest key text that can parse is 73 */
#define ADDRTEXT_MAX    64              /* the longest address or prefix text that can parse is 49 */

/* A slot's state: free, holding a peer, or holding one removed by the message being applied. */
enum { S_FREE = 0, S_LIVE, S_GONE };

/* The message's plan for a slot that holds a peer from before the message. */
enum { PLAN_NONE = 0, PLAN_LISTED, PLAN_DONE, PLAN_UPSERT, PLAN_PATCH, PLAN_SKIP };

/* What the patch made of a PeersChanged node carries, of the fields we keep (patchifyPeer). */
#define M_KEY           0x01
#define M_EXPIRY        0x02
#define M_DISCO         0x04
#define M_DERP          0x08
#define M_ONLINE        0x10
#define M_SEEN          0x20

/* A slot as it was before the message: removeUnwantedDiscoUpdates looks at that. */
#define SNAP_OLD        0x01
#define SNAP_SEEN       0x02

/* The flags patchifyPeer compares (any difference: the whole node is replaced). */
#define FLAGS_COMPARED  (TS_NODE_EXPIRED | TS_NODE_AUTHORIZED | TS_NODE_UNSIGNED | TS_NODE_WG_ONLY)

static int refuse(ts_netmap_result* res, ts_netmap_err e, const ts_json* d, int t)
{
    if (res) {
        res->err = e;
        res->err_at = d ? ts_json_offset(d, t) : 0;
    }
    return 0;
}

static int is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int key_zero(const wg_key* k)
{
    static const uint8_t zero[WG_KEY_LEN];
    return memcmp(k->b, zero, WG_KEY_LEN) == 0;
}

/* --------------------------------------------------------------------- time */

ts_time ts_time_zero(void)
{
    ts_time t;
    t.sec = TS_TIME_ZERO_SEC;
    t.nsec = 0;
    return t;
}

int ts_time_is_zero(ts_time t)
{
    return t.sec == TS_TIME_ZERO_SEC && t.nsec == 0;
}

int ts_time_cmp(ts_time a, ts_time b)
{
    if (a.sec != b.sec) return a.sec < b.sec ? -1 : 1;
    if (a.nsec != b.nsec) return a.nsec < b.nsec ? -1 : 1;
    return 0;
}

static int num(const char* s, size_t n, int* v)
{
    size_t i;
    int x = 0;

    for (i = 0; i < n; i++) {
        if (!is_digit(s[i])) return 0;
        x = x * 10 + (s[i] - '0');
    }
    *v = x;
    return 1;
}

static int leap(int y)
{
    return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static int days_in(int m, int y)
{
    static const int dm[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    return m == 2 && leap(y) ? 29 : dm[m - 1];
}

/* Days from 1970-01-01 in the proleptic Gregorian calendar (H. Hinnant's days_from_civil). */
static int64_t days_from_civil(int64_t y, int m, int d)
{
    int64_t era, yoe, doy, doe;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* time.parseRFC3339, the strict form Go writes (and its fast path reads). */
int ts_time_parse(const char* s, size_t len, ts_time* t)
{
    int year, mon, day, hh, mi, ss, ns = 0;
    int64_t off = 0;
    size_t i;

    if (len < 20) return 0;
    if (!num(s, 4, &year) || s[4] != '-' || !num(s + 5, 2, &mon) || s[7] != '-' ||
        !num(s + 8, 2, &day) || s[10] != 'T' || !num(s + 11, 2, &hh) || s[13] != ':' ||
        !num(s + 14, 2, &mi) || s[16] != ':' || !num(s + 17, 2, &ss))
        return 0;
    if (mon < 1 || mon > 12 || day < 1 || day > days_in(mon, year) || hh > 23 || mi > 59 || ss > 59)
        return 0;
    i = 19;
    if (len - i >= 2 && s[i] == '.' && is_digit(s[i + 1])) {
        int digits = 0;
        for (i++; i < len && is_digit(s[i]); i++) {
            if (digits < 9) {                   /* parseNanoseconds: the first nine count */
                ns = ns * 10 + (s[i] - '0');
                digits++;
            }
        }
        for (; digits < 9; digits++) ns *= 10;
    }
    if (len - i == 1 && s[i] == 'Z') {
        off = 0;
    } else {
        int zh, zm;
        if (len - i != 6 || (s[i] != '+' && s[i] != '-') || !num(s + i + 1, 2, &zh) || s[i + 3] != ':' ||
            !num(s + i + 4, 2, &zm) || zh > 23 || zm > 59)
            return 0;
        off = (int64_t)(zh * 60 + zm) * 60;
        if (s[i] == '-') off = -off;
    }
    t->sec = days_from_civil(year, mon, day) * 86400 + hh * 3600 + mi * 60 + ss - off;
    t->nsec = ns;
    return 1;
}

/* --------------------------------------------------------------------- addresses, prefixes, keys */

/* netip.parseIPv4Fields: four decimal fields, no leading zeros, each at most 255. */
static int parse_v4(const char* s, size_t n, uint8_t out[4])
{
    size_t i;
    unsigned val = 0;
    int pos = 0, dig = 0;

    for (i = 0; i < n; i++) {
        char c = s[i];
        if (is_digit(c)) {
            if (dig == 1 && val == 0) return 0;
            val = val * 10 + (unsigned)(c - '0');
            dig++;
            if (val > 255) return 0;
        } else if (c == '.') {
            if (i == 0 || i == n - 1 || s[i - 1] == '.' || pos == 3) return 0;
            out[pos++] = (uint8_t)val;
            val = 0;
            dig = 0;
        } else {
            return 0;
        }
    }
    if (pos < 3) return 0;
    out[3] = (uint8_t)val;
    return 1;
}

/* netip.parseIPv6, without zones. */
static int parse_v6(const char* s, size_t n, uint8_t ip[16])
{
    size_t p = 0;
    int ellipsis = -1, i = 0;

    memset(ip, 0, 16);
    if (n >= 2 && s[0] == ':' && s[1] == ':') {
        ellipsis = 0;
        p = 2;
        if (p == n) return 1;                   /* "::" */
    }
    while (i < 16) {
        size_t off = 0;
        uint32_t acc = 0;

        while (p + off < n) {
            int h = hex_val(s[p + off]);
            if (h < 0) break;
            acc = (acc << 4) + (uint32_t)h;
            if (off > 3 || acc > 0xffff) return 0;
            off++;
        }
        if (off == 0) return 0;
        if (p + off < n && s[p + off] == '.') {
            /* an IPv4 tail: in the last two groups, or after "::" */
            if ((ellipsis < 0 && i != 12) || i + 4 > 16) return 0;
            if (!parse_v4(s + p, n - p, ip + i)) return 0;
            p = n;
            i += 4;
            break;
        }
        ip[i] = (uint8_t)(acc >> 8);
        ip[i + 1] = (uint8_t)acc;
        i += 2;
        p += off;
        if (p == n) break;
        if (s[p] != ':' || p + 1 == n) return 0;
        p++;
        if (s[p] == ':') {
            if (ellipsis >= 0) return 0;
            ellipsis = i;
            p++;
            if (p == n) break;
        }
    }
    if (p != n) return 0;
    if (i < 16) {
        int k, shift = 16 - i;
        if (ellipsis < 0) return 0;
        for (k = i - 1; k >= ellipsis; k--) ip[k + shift] = ip[k];
        memset(ip + ellipsis, 0, (size_t)shift);
    } else if (ellipsis >= 0) {
        return 0;                               /* "::" must stand for at least one group */
    }
    return 1;
}

int ts_addr_parse(const char* s, size_t len, int* family, uint8_t addr[16])
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (s[i] == '.') {
            memset(addr, 0, 16);
            if (!parse_v4(s, len, addr)) return 0;
            *family = 4;
            return 1;
        }
        if (s[i] == ':') {
            if (memchr(s, '%', len)) return 0;  /* a zone: Go takes it, we have no use for one */
            if (!parse_v6(s, len, addr)) return 0;
            *family = 6;
            return 1;
        }
        if (s[i] == '%') return 0;
    }
    return 0;
}

int ts_prefix_parse(const char* s, size_t len, wg_prefix* p)
{
    size_t slash, i;
    unsigned bits = 0;
    int family;

    memset(p, 0, sizeof(*p));
    if (len == 0) return 1;                     /* Prefix.UnmarshalText(""): the zero prefix */
    for (slash = len; slash > 0 && s[slash - 1] != '/'; slash--) {}
    if (slash == 0) return 0;
    slash--;
    if (!ts_addr_parse(s, slash, &family, p->addr)) return 0;
    /* the bits: decimal, no sign, no leading zero */
    if (slash + 1 >= len || (len - slash - 1 > 1 && (s[slash + 1] < '1' || s[slash + 1] > '9'))) return 0;
    for (i = slash + 1; i < len; i++) {
        if (!is_digit(s[i])) return 0;
        bits = bits * 10 + (unsigned)(s[i] - '0');
        if (bits > 128) return 0;
    }
    if (bits > (family == 4 ? 32u : 128u)) return 0;
    p->family = (uint8_t)family;
    p->cidr = (uint8_t)bits;
    return 1;
}

int ts_key_parse(const char* s, size_t len, const char* prefix, uint8_t out[32])
{
    size_t plen = strlen(prefix), i;

    if (len != plen + 64 || memcmp(s, prefix, plen) != 0) return 0;
    for (i = 0; i < 32; i++) {
        int a = hex_val(s[plen + 2 * i]), b = hex_val(s[plen + 2 * i + 1]);
        if (a < 0 || b < 0) return 0;
        out[i] = (uint8_t)((a << 4) | b);
    }
    return 1;
}

/* strconv.Atoi: an optional sign, decimal digits (leading zeros fine), in range. */
static int atoi64(const char* s, size_t n, int64_t* v)
{
    size_t i = 0;
    uint64_t u = 0, limit;
    int neg = 0;

    if (n > 0 && (s[0] == '+' || s[0] == '-')) {
        neg = s[0] == '-';
        i = 1;
    }
    if (i == n) return 0;
    limit = neg ? 9223372036854775808ULL : 9223372036854775807ULL;
    for (; i < n; i++) {
        unsigned dig;
        if (!is_digit(s[i])) return 0;
        dig = (unsigned)(s[i] - '0');
        if (u > (limit - dig) / 10) return 0;
        u = u * 10 + dig;
    }
    *v = neg ? (u == 9223372036854775808ULL ? -9223372036854775807LL - 1 : -(int64_t)u) : (int64_t)u;
    return 1;
}

/* upgradeNode's reading of the legacy DERP field: net.SplitHostPort, the host exactly
 * tailcfg.DerpMagicIP (bracketed or not), the port through strconv.Atoi. */
static int legacy_derp(const char* s, size_t n, int64_t* region)
{
    static const char magic[] = "127.3.3.40";
    size_t m = sizeof(magic) - 1;

    if (n > m && memcmp(s, magic, m) == 0 && s[m] == ':') return atoi64(s + m + 1, n - m - 1, region);
    if (n > m + 2 && s[0] == '[' && memcmp(s + 1, magic, m) == 0 && s[m + 1] == ']' && s[m + 2] == ':')
        return atoi64(s + m + 3, n - m - 3, region);
    return 0;
}

/* --------------------------------------------------------------------- reading fields */

/* Matches key `k` against `names` the way Go matches struct fields: the index, or -1. */
static int field_of(const ts_json* d, int k, const char* const* names, int count)
{
    char f[48];
    int i;

    if (!ts_json_key_fold(d, k, f, sizeof(f))) return -1;
    for (i = 0; i < count; i++) {
        const char* a = f;
        const char* b = names[i];
        while (*a && *b) {
            char c = *b;
            if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
            if (*a != c) break;
            a++;
            b++;
        }
        if (*a == '\0' && *b == '\0') return i;
    }
    return -1;
}

/* An integer field: absent or null leave the zero value. */
static int get_i64(const ts_json* d, int v, int64_t* out, ts_netmap_result* res)
{
    ts_json_type ty = ts_json_type_of(d, v);

    if (ty == TS_JSON_NULL) return 1;
    if (ty != TS_JSON_NUMBER) return refuse(res, TS_NM_ERR_TYPE, d, v);
    if (!ts_json_i64(d, v, out)) return refuse(res, TS_NM_ERR_VALUE, d, v);
    return 1;
}

/* A bool field: 1 and *set (and *val) when true/false; 1 without *set for null. */
static int get_bool(const ts_json* d, int v, int* set, int* val, ts_netmap_result* res)
{
    *set = 0;
    if (ts_json_is_null(d, v)) return 1;
    if (!ts_json_bool(d, v, val)) return refuse(res, TS_NM_ERR_TYPE, d, v);
    *set = 1;
    return 1;
}

/* A key field (nodekey:..., discokey:..., mkey:...): 1 and *set when a valid key, 1 without for
 * null; refused for anything else - Go's key.parseHex fails the message. */
static int get_key(const ts_json* d, int v, const char* prefix, uint8_t out[32], int* set,
                   ts_netmap_result* res)
{
    char buf[KEYTEXT_MAX];
    size_t len;

    *set = 0;
    if (ts_json_is_null(d, v)) return 1;
    if (ts_json_type_of(d, v) != TS_JSON_STRING) return refuse(res, TS_NM_ERR_TYPE, d, v);
    if (!ts_json_str(d, v, buf, sizeof(buf), &len) || !ts_key_parse(buf, len, prefix, out))
        return refuse(res, TS_NM_ERR_VALUE, d, v);
    *set = 1;
    return 1;
}

/* A time field: Time.UnmarshalJSON parses the bytes between the quotes as they are - escapes are
 * not undone. 1 and *set for a time, 1 without for null. */
static int get_time(const ts_json* d, int v, ts_time* out, int* set, ts_netmap_result* res)
{
    const char* s;
    size_t len;

    *set = 0;
    if (ts_json_is_null(d, v)) return 1;
    if (ts_json_type_of(d, v) != TS_JSON_STRING) return refuse(res, TS_NM_ERR_TYPE, d, v);
    s = ts_json_raw(d, v, &len);
    if (!ts_time_parse(s, len, out)) return refuse(res, TS_NM_ERR_VALUE, d, v);
    *set = 1;
    return 1;
}

/* A prefix (array element or field): null and "" are Go's zero prefix. */
static int get_prefix(const ts_json* d, int v, wg_prefix* p, ts_netmap_result* res)
{
    char buf[ADDRTEXT_MAX];
    size_t len;

    if (ts_json_is_null(d, v)) {
        memset(p, 0, sizeof(*p));
        return 1;
    }
    if (ts_json_type_of(d, v) != TS_JSON_STRING) return refuse(res, TS_NM_ERR_TYPE, d, v);
    if (!ts_json_str(d, v, buf, sizeof(buf), &len) || !ts_prefix_parse(buf, len, p))
        return refuse(res, TS_NM_ERR_VALUE, d, v);
    return 1;
}

/* A string we keep: 1 read whole into out, 2 present but beyond our limit or holding a NUL - the
 * item cannot be kept -, 0 refused (not a string). Null reads as "". */
static int get_text(const ts_json* d, int v, char* out, size_t cap, size_t* len, ts_netmap_result* res)
{
    out[0] = '\0';
    *len = 0;
    if (ts_json_is_null(d, v)) return 1;
    if (ts_json_type_of(d, v) != TS_JSON_STRING) return refuse(res, TS_NM_ERR_TYPE, d, v);
    if (!ts_json_str(d, v, out, cap, len)) {
        out[0] = '\0';
        *len = 0;
        return 2;
    }
    return memchr(out, '\0', *len) ? 2 : 1;
}

/* --------------------------------------------------------------------- a node's fingerprint */

#define FNV_OFFSET  0xcbf29ce484222325ULL
#define FNV_PRIME   0x100000001b3ULL

static uint64_t fnv(uint64_t h, const void* p, size_t n)
{
    const uint8_t* b = (const uint8_t*)p;
    size_t i;

    for (i = 0; i < n; i++) {
        h ^= b[i];
        h *= FNV_PRIME;
    }
    return h;
}

static uint64_t mix64(uint64_t z)
{
    z ^= z >> 30;
    z *= 0xbf58476d1ce4e5b9ULL;
    z ^= z >> 27;
    z *= 0x94d049bb133111ebULL;
    z ^= z >> 31;
    return z;
}

/*
 * The part of patchifyPeer's comparison we cannot make on kept fields: StableID, Sharer, Machine,
 * Hostinfo, Created, Tags, PrimaryRoutes, IsJailed, the masquerade addresses and
 * ExitNodeDNSResolvers go into one hash - a field's name with its value's tokens, summed over the
 * fields so their order does not matter. A value Go cannot tell from absent (null, false, 0, "",
 * []) adds nothing. A server writes equal values the same way, so equal fields hash equal; two
 * spellings of one value only make a node replaced where Go would have patched it.
 */
static uint64_t fp_value(const ts_json* d, unsigned field, int t)
{
    ts_json_type ty = ts_json_type_of(d, t);
    uint8_t f = (uint8_t)field;
    uint64_t h;
    int j, end;
    size_t n;
    const char* s;

    if (ty == TS_JSON_NULL || ty == TS_JSON_FALSE) return 0;
    if (ty == TS_JSON_NUMBER) {
        s = ts_json_raw(d, t, &n);
        if ((n == 1 && s[0] == '0') || (n == 2 && s[0] == '-' && s[1] == '0')) return 0;
    }
    if (ty == TS_JSON_STRING) {
        ts_json_raw(d, t, &n);
        if (n == 0) return 0;
    }
    if (ty == TS_JSON_ARRAY && ts_json_size(d, t) == 0) return 0;

    h = fnv(FNV_OFFSET, &f, 1);
    end = ts_json_skip(d, t);
    for (j = t; j < end; j++) {
        uint8_t type = (uint8_t)d->tok[j].type;
        uint32_t len;

        h = fnv(h, &type, 1);
        if (d->tok[j].type == JSMN_STRING || d->tok[j].type == JSMN_PRIMITIVE) {
            s = ts_json_raw(d, j, &n);
            len = (uint32_t)n;
            h = fnv(h, &len, sizeof(len));
            h = fnv(h, s, n);
        } else {
            len = (uint32_t)d->tok[j].size;
            h = fnv(h, &len, sizeof(len));
        }
    }
    return mix64(h);
}

/* --------------------------------------------------------------------- a node from the wire */

enum {
    NF_ID, NF_STABLEID, NF_NAME, NF_USER, NF_SHARER, NF_KEY, NF_KEYEXPIRY, NF_MACHINE, NF_DISCOKEY,
    NF_ADDRESSES, NF_ALLOWEDIPS, NF_DERP, NF_HOMEDERP, NF_HOSTINFO, NF_CREATED, NF_TAGS,
    NF_PRIMARYROUTES, NF_LASTSEEN, NF_ONLINE, NF_AUTHORIZED, NF_UNSIGNED, NF_EXPIRED, NF_MASQ4,
    NF_MASQ6, NF_WGONLY, NF_JAILED, NF_EXITDNS, NF_COUNT
};

static const char* const node_fields[NF_COUNT] = {
    "ID", "StableID", "Name", "User", "Sharer", "Key", "KeyExpiry", "Machine", "DiscoKey",
    "Addresses", "AllowedIPs", "DERP", "HomeDERP", "Hostinfo", "Created", "Tags",
    "PrimaryRoutes", "LastSeen", "Online", "MachineAuthorized", "UnsignedPeerAPIOnly", "Expired",
    "SelfNodeV4MasqAddrForThisPeer", "SelfNodeV6MasqAddrForThisPeer", "IsWireGuardOnly", "IsJailed",
    "ExitNodeDNSResolvers"
};

/* Reads a prefix array into out[0 .. cap), counting all of them in *count. */
static int get_prefixes(const ts_json* d, int v, wg_prefix* out, size_t cap, size_t* count,
                        ts_netmap_result* res)
{
    int e;
    wg_prefix p;

    *count = 0;
    if (ts_json_is_null(d, v)) return 1;
    if (ts_json_type_of(d, v) != TS_JSON_ARRAY) return refuse(res, TS_NM_ERR_TYPE, d, v);
    for (e = ts_json_first(d, v); e >= 0; e = ts_json_next(d, e)) {
        if (!get_prefix(d, e, &p, res)) return 0;
        if (*count < cap) out[*count] = p;
        (*count)++;
    }
    return 1;
}

static int node_storable(const ts_node_in* in)
{
    return in->name_ok && in->n_addrs <= TS_NODE_ADDRS_MAX &&
           ((in->n.flags & TS_NODE_ALLOWED_ADDRS) || in->n_allowed <= TS_NODE_ALLOWED_MAX);
}

/*
 * Node `t` into nm->in, with upgradeNode applied. 0 when the message must be refused; a node that
 * is read but beyond our limits is marked by node_storable.
 */
static int node_read(ts_netmap* nm, const ts_json* d, int t, ts_netmap_result* res)
{
    ts_node_in* in = &nm->in;
    char legacy[ADDRTEXT_MAX];
    size_t legacy_len = 0;
    uint32_t seen = 0;
    int k, has_legacy = 0, set, val;

    memset(&in->n, 0, sizeof(in->n));
    in->n.key_expiry = ts_time_zero();
    in->name[0] = '\0';
    in->name_len = 0;
    in->name_ok = 1;
    in->n_addrs = 0;
    in->n_allowed = 0;
    in->allowed_nil = 1;

    for (k = ts_json_first(d, t); k >= 0; k = ts_json_next(d, k)) {
        int f = field_of(d, k, node_fields, NF_COUNT), v = k + 1, r;

        if (f < 0) continue;
        if (seen & (1u << f)) return refuse(res, TS_NM_ERR_DUPLICATE, d, k);
        seen |= 1u << f;
        switch (f) {
        case NF_ID:
            if (!get_i64(d, v, &in->n.id, res)) return 0;
            break;
        case NF_USER:
            if (!get_i64(d, v, &in->n.user, res)) return 0;
            break;
        case NF_HOMEDERP:
            if (!get_i64(d, v, &in->n.home_derp, res)) return 0;
            break;
        case NF_NAME:
            r = get_text(d, v, in->name, sizeof(in->name), &in->name_len, res);
            if (!r) return 0;
            if (r == 2) in->name_ok = 0;
            break;
        case NF_KEY:
            if (!get_key(d, v, "nodekey:", in->n.key.b, &set, res)) return 0;
            break;
        case NF_DISCOKEY:
            if (!get_key(d, v, "discokey:", in->n.disco.b, &set, res)) return 0;
            break;
        case NF_KEYEXPIRY:
            if (!get_time(d, v, &in->n.key_expiry, &set, res)) return 0;
            break;
        case NF_LASTSEEN:
            if (!get_time(d, v, &in->n.last_seen, &set, res)) return 0;
            if (set) in->n.flags |= TS_NODE_SEEN;
            break;
        case NF_ADDRESSES:
            if (!get_prefixes(d, v, in->addrs, TS_NODE_ADDRS_MAX, &in->n_addrs, res)) return 0;
            break;
        case NF_ALLOWEDIPS:
            if (!get_prefixes(d, v, in->allowed, TS_NODE_ALLOWED_MAX, &in->n_allowed, res)) return 0;
            in->allowed_nil = ts_json_is_null(d, v);
            break;
        case NF_DERP:
            if (ts_json_is_null(d, v)) break;
            if (ts_json_type_of(d, v) != TS_JSON_STRING) return refuse(res, TS_NM_ERR_TYPE, d, v);
            /* longer than any "127.3.3.40:N" we take - Go would still read one padded with zeros */
            has_legacy = ts_json_str(d, v, legacy, sizeof(legacy), &legacy_len);
            break;
        case NF_ONLINE:
            if (!get_bool(d, v, &set, &val, res)) return 0;
            if (set) in->n.flags |= TS_NODE_ONLINE_KNOWN | (val ? TS_NODE_ONLINE : 0);
            break;
        case NF_AUTHORIZED:
        case NF_UNSIGNED:
        case NF_EXPIRED:
        case NF_WGONLY:
            if (!get_bool(d, v, &set, &val, res)) return 0;
            if (set && val)
                in->n.flags |= f == NF_AUTHORIZED ? TS_NODE_AUTHORIZED : f == NF_UNSIGNED ? TS_NODE_UNSIGNED :
                               f == NF_EXPIRED ? TS_NODE_EXPIRED : TS_NODE_WG_ONLY;
            break;
        default:                                /* compared by patchifyPeer, not kept */
            in->n.fp += fp_value(d, (unsigned)f, v);
            break;
        }
    }

    /* upgradeNode */
    if (has_legacy && in->n.home_derp == 0) {
        int64_t region;
        if (legacy_derp(legacy, legacy_len, &region)) in->n.home_derp = region;
    }
    {
        int fits = in->n_addrs <= TS_NODE_ADDRS_MAX && in->n_allowed <= TS_NODE_ALLOWED_MAX;
        int equal = fits && in->n_addrs == in->n_allowed &&
                    memcmp(in->addrs, in->allowed, in->n_addrs * PFX) == 0;
        /* nil AllowedIPs are its Addresses; an unsigned node gets no more than those; and a list
         * equal to Addresses is kept once */
        if (in->allowed_nil || equal || (in->n.flags & TS_NODE_UNSIGNED)) in->n.flags |= TS_NODE_ALLOWED_ADDRS;
    }
    return 1;
}

/* The lists of nm->in as stored: AllowedIPs may be Addresses. */
static const wg_prefix* in_allowed(const ts_node_in* in, size_t* n)
{
    if (in->n.flags & TS_NODE_ALLOWED_ADDRS) {
        *n = in->n_addrs;
        return in->addrs;
    }
    *n = in->n_allowed;
    return in->allowed;
}

/* --------------------------------------------------------------------- a patch from the wire */

enum {
    PF_NODEID, PF_DERPREGION, PF_KEY, PF_DISCOKEY, PF_ONLINE, PF_LASTSEEN, PF_KEYEXPIRY, PF_COUNT
};

static const char* const patch_fields[PF_COUNT] = {
    "NodeID", "DERPRegion", "Key", "DiscoKey", "Online", "LastSeen", "KeyExpiry"
};

typedef struct {
    int64_t id;
    int64_t derp;                       /* 0: unchanged */
    int     has_key, has_disco, has_online, online, has_seen, has_expiry;
    wg_key  key, disco;
    ts_time seen, expiry;
} patch_in;

static int patch_read(const ts_json* d, int t, patch_in* p, ts_netmap_result* res)
{
    uint32_t seen = 0;
    int k;

    memset(p, 0, sizeof(*p));
    for (k = ts_json_first(d, t); k >= 0; k = ts_json_next(d, k)) {
        int f = field_of(d, k, patch_fields, PF_COUNT), v = k + 1;

        if (f < 0) continue;                    /* Cap, CapMap, Endpoints, KeySignature: not ours */
        if (seen & (1u << f)) return refuse(res, TS_NM_ERR_DUPLICATE, d, k);
        seen |= 1u << f;
        switch (f) {
        case PF_NODEID:
            if (!get_i64(d, v, &p->id, res)) return 0;
            break;
        case PF_DERPREGION:
            if (!get_i64(d, v, &p->derp, res)) return 0;
            break;
        case PF_KEY:
            if (!get_key(d, v, "nodekey:", p->key.b, &p->has_key, res)) return 0;
            break;
        case PF_DISCOKEY:
            if (!get_key(d, v, "discokey:", p->disco.b, &p->has_disco, res)) return 0;
            break;
        case PF_ONLINE:
            if (!get_bool(d, v, &p->has_online, &p->online, res)) return 0;
            break;
        case PF_LASTSEEN:
            if (!get_time(d, v, &p->seen, &p->has_seen, res)) return 0;
            break;
        case PF_KEYEXPIRY:
            if (!get_time(d, v, &p->expiry, &p->has_expiry, res)) return 0;
            break;
        }
    }
    return 1;
}

/* --------------------------------------------------------------------- the arena */

static void rec_put(uint8_t* p, unsigned owner, uint32_t size)
{
    p[0] = (uint8_t)owner;
    p[1] = (uint8_t)(owner >> 8);
    p[2] = (uint8_t)size;
    p[3] = (uint8_t)(size >> 8);
    p[4] = (uint8_t)(size >> 16);
    p[5] = (uint8_t)(size >> 24);
}

static unsigned rec_owner(const uint8_t* p)
{
    return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static uint32_t rec_size(const uint8_t* p)
{
    return (uint32_t)p[2] | ((uint32_t)p[3] << 8) | ((uint32_t)p[4] << 16) | ((uint32_t)p[5] << 24);
}

static void arena_free(ts_netmap* nm, ts_node* x)
{
    uint8_t* h = nm->arena + x->blob - REC_HDR;
    uint32_t size = rec_size(h);

    rec_put(h, SLOT_NONE, size);
    nm->arena_garbage += REC_HDR + size;
}

/* Slides the live records down over the freed ones, in arena order. */
static void arena_compact(ts_netmap* nm)
{
    size_t r = 0, w = 0;

    while (r < nm->arena_used) {
        unsigned owner = rec_owner(nm->arena + r);
        size_t total = REC_HDR + rec_size(nm->arena + r);

        if (owner != SLOT_NONE) {
            if (w != r) memmove(nm->arena + w, nm->arena + r, total);
            nm->nodes[owner].blob = (uint32_t)(w + REC_HDR);
            w += total;
        }
        r += total;
    }
    nm->arena_used = w;
    nm->arena_garbage = 0;
}

static int arena_alloc(ts_netmap* nm, unsigned owner, size_t size, uint32_t* blob)
{
    size_t total = REC_HDR + size;

    if (total > nm->arena_size) return 0;
    if (nm->arena_size - nm->arena_used < total) {
        if (nm->arena_size - nm->arena_used + nm->arena_garbage < total) return 0;
        arena_compact(nm);
    }
    rec_put(nm->arena + nm->arena_used, owner, (uint32_t)size);
    *blob = (uint32_t)(nm->arena_used + REC_HDR);
    nm->arena_used += total;
    return 1;
}

/* --------------------------------------------------------------------- slots and indexes */

/* The first position in by_id whose node's id is not below `id`. */
static size_t id_lower(const ts_netmap* nm, int64_t id)
{
    size_t lo = 0, hi = nm->n;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (nm->nodes[nm->by_id[mid]].id < id) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

/* The slot holding `id` (live, or removed by the message being applied), or -1. */
static int slot_find(const ts_netmap* nm, int64_t id)
{
    size_t i = id_lower(nm, id);

    if (i < nm->n && nm->nodes[nm->by_id[i]].id == id) return nm->by_id[i];
    return -1;
}

static int slot_live(const ts_netmap* nm, int64_t id)
{
    int s = slot_find(nm, id);

    return s >= 0 && nm->nodes[s].state == S_LIVE ? s : -1;
}

/* A free slot, not yet in by_id; -1 when the table is full. */
static int slot_new(ts_netmap* nm)
{
    size_t i;

    if (nm->n >= nm->cap) return -1;
    for (i = 0; i < nm->cap; i++) {
        size_t s = (nm->free_hint + i) % nm->cap;
        if (nm->nodes[s].state == S_FREE) {
            nm->free_hint = s + 1;
            memset(&nm->nodes[s], 0, sizeof(ts_node));
            return (int)s;
        }
    }
    return -1;
}

static void id_insert(ts_netmap* nm, unsigned slot)
{
    size_t i = id_lower(nm, nm->nodes[slot].id);

    memmove(nm->by_id + i + 1, nm->by_id + i, (nm->n - i) * sizeof(uint16_t));
    nm->by_id[i] = (uint16_t)slot;
    nm->n++;
}

/* Frees the slot at position i of by_id, with its arena record. */
static void slot_remove_at(ts_netmap* nm, size_t i)
{
    ts_node* x = &nm->nodes[nm->by_id[i]];

    arena_free(nm, x);
    x->state = S_FREE;
    memmove(nm->by_id + i, nm->by_id + i + 1, (nm->n - i - 1) * sizeof(uint16_t));
    nm->n--;
}

static void slot_remove(ts_netmap* nm, unsigned slot)
{
    size_t i = id_lower(nm, nm->nodes[slot].id);

    while (i < nm->n && nm->by_id[i] != slot) i++;
    if (i < nm->n) slot_remove_at(nm, i);
}

static int key_less(const ts_netmap* nm, unsigned a, unsigned b)
{
    int c = memcmp(nm->nodes[a].key.b, nm->nodes[b].key.b, WG_KEY_LEN);

    if (c != 0) return c < 0;
    return nm->nodes[a].id < nm->nodes[b].id;
}

static void key_sift(ts_netmap* nm, size_t i, size_t n)
{
    uint16_t* v = nm->by_key;

    for (;;) {
        size_t c = 2 * i + 1, m = i;
        uint16_t tmp;

        if (c < n && key_less(nm, v[m], v[c])) m = c;
        if (c + 1 < n && key_less(nm, v[m], v[c + 1])) m = c + 1;
        if (m == i) return;
        tmp = v[i];
        v[i] = v[m];
        v[m] = tmp;
        i = m;
    }
}

/* by_key from scratch: the live slots, heap-sorted by key, then id. */
static void keys_rebuild(ts_netmap* nm)
{
    size_t i, n = 0;

    for (i = 0; i < nm->n; i++)
        if (nm->nodes[nm->by_id[i]].state == S_LIVE) nm->by_key[n++] = nm->by_id[i];
    nm->n_keyed = n;
    if (n < 2) return;
    for (i = n / 2; i-- > 0;) key_sift(nm, i, n);
    for (i = n - 1; i > 0; i--) {
        uint16_t tmp = nm->by_key[0];
        nm->by_key[0] = nm->by_key[i];
        nm->by_key[i] = tmp;
        key_sift(nm, 0, i);
    }
}

/*
 * nm->in into `slot` - a fresh one from slot_new (`fresh`) or one held. 0 when it cannot be kept
 * (beyond the limits, or no room in the arena): the slot is freed and the peer counted as dropped.
 * A held slot keeps its place in by_id and its plan and snapshot; a removed one comes back.
 */
static int node_put(ts_netmap* nm, unsigned slot, int fresh, ts_netmap_result* res)
{
    ts_node* x = &nm->nodes[slot];
    ts_node_in* in = &nm->in;
    const wg_prefix* allowed;
    size_t n_allowed, size;
    uint32_t blob;
    uint8_t plan, mask, snap, *p;
    ts_time snap_seen;

    if (!fresh) arena_free(nm, x);
    allowed = in_allowed(in, &n_allowed);
    size = (in->n_addrs + ((in->n.flags & TS_NODE_ALLOWED_ADDRS) ? 0 : n_allowed)) * PFX + in->name_len + 1;
    if (!node_storable(in) || !arena_alloc(nm, slot, size, &blob)) {
        if (!fresh) {
            /* the record is already freed: just the slot */
            size_t i = id_lower(nm, x->id);
            while (i < nm->n && nm->by_id[i] != slot) i++;
            if (i < nm->n) {
                memmove(nm->by_id + i, nm->by_id + i + 1, (nm->n - i - 1) * sizeof(uint16_t));
                nm->n--;
            }
        }
        x->state = S_FREE;
        nm->incomplete = 1;
        if (res) res->peers_dropped++;
        return 0;
    }

    plan = x->plan;
    mask = x->mask;
    snap = x->snap;
    snap_seen = x->snap_seen;
    *x = in->n;
    x->state = S_LIVE;
    x->plan = fresh ? PLAN_NONE : plan;
    x->mask = fresh ? 0 : mask;
    x->snap = fresh ? 0 : snap;
    x->snap_seen = snap_seen;
    x->blob = blob;
    x->n_addrs = (uint16_t)in->n_addrs;
    x->n_allowed = (uint16_t)n_allowed;
    x->name_len = (uint16_t)in->name_len;
    x->gen = nm->gen;

    p = nm->arena + blob;
    memcpy(p, in->addrs, in->n_addrs * PFX);
    p += in->n_addrs * PFX;
    if (!(in->n.flags & TS_NODE_ALLOWED_ADDRS)) {
        memcpy(p, allowed, n_allowed * PFX);
        p += n_allowed * PFX;
    }
    memcpy(p, in->name, in->name_len);
    p[in->name_len] = '\0';
    if (fresh) id_insert(nm, slot);
    return 1;
}

/* --------------------------------------------------------------------- the DERP map */

enum { DF_HOMEPARAMS, DF_REGIONS, DF_OMIT, DF_COUNT };
static const char* const derp_fields[DF_COUNT] = { "HomeParams", "Regions", "omitDefaultRegions" };

enum { HF_SCORE, HF_COUNT };
static const char* const home_fields[HF_COUNT] = { "RegionScore" };

enum { RF_ID, RF_CODE, RF_NAME, RF_AVOID, RF_NOHOME, RF_NODES, RF_COUNT };
static const char* const region_fields[RF_COUNT] = {
    "RegionID", "RegionCode", "RegionName", "Avoid", "NoMeasureNoHome", "Nodes"
};

enum {
    DN_NAME, DN_REGION, DN_HOST, DN_CERT, DN_V4, DN_V6, DN_STUNPORT, DN_STUNONLY, DN_PORT,
    DN_INSECURE, DN_PORT80, DN_COUNT
};
static const char* const dnode_fields[DN_COUNT] = {
    "Name", "RegionID", "HostName", "CertName", "IPv4", "IPv6", "STUNPort", "STUNOnly", "DERPPort",
    "InsecureForTests", "CanPort80"
};

typedef struct {
    int hp, scores, regions;            /* tokens, -1 when absent or null */
    int omit;
} derp_top;

static int derp_top_read(const ts_json* d, int t, derp_top* m, ts_netmap_result* res)
{
    uint32_t seen = 0;
    int k, set;

    m->hp = m->scores = m->regions = -1;
    m->omit = 0;
    for (k = ts_json_first(d, t); k >= 0; k = ts_json_next(d, k)) {
        int f = field_of(d, k, derp_fields, DF_COUNT), v = k + 1;
        ts_json_type ty = ts_json_type_of(d, v);

        if (f < 0) continue;
        if (seen & (1u << f)) return refuse(res, TS_NM_ERR_DUPLICATE, d, k);
        seen |= 1u << f;
        if (f == DF_OMIT) {
            if (!get_bool(d, v, &set, &m->omit, res)) return 0;
            continue;
        }
        if (ty == TS_JSON_NULL) continue;
        if (ty != TS_JSON_OBJECT) return refuse(res, TS_NM_ERR_TYPE, d, v);
        if (f == DF_REGIONS) {
            m->regions = v;
        } else {
            int hk;
            uint32_t hseen = 0;
            m->hp = v;
            for (hk = ts_json_first(d, v); hk >= 0; hk = ts_json_next(d, hk)) {
                int hv = hk + 1;
                if (field_of(d, hk, home_fields, HF_COUNT) != HF_SCORE) continue;
                if (hseen) return refuse(res, TS_NM_ERR_DUPLICATE, d, hk);
                hseen = 1;
                if (ts_json_is_null(d, hv)) continue;
                if (ts_json_type_of(d, hv) != TS_JSON_OBJECT) return refuse(res, TS_NM_ERR_TYPE, d, hv);
                m->scores = hv;
            }
        }
    }
    return 1;
}

typedef struct {
    int64_t region_id;
    char    code[TS_DERPMAP_NAME_MAX + 1], name[TS_DERPMAP_NAME_MAX + 1];
    size_t  code_len, name_len;
    int     avoid, no_home, ok;
    int     nodes;                      /* the Nodes array, -1 when absent or null */
} region_in;

static int region_read(const ts_json* d, int t, region_in* r, ts_netmap_result* res)
{
    uint32_t seen = 0;
    int k, set, x;

    memset(r, 0, sizeof(*r));
    r->ok = 1;
    r->nodes = -1;
    for (k = ts_json_first(d, t); k >= 0; k = ts_json_next(d, k)) {
        int f = field_of(d, k, region_fields, RF_COUNT), v = k + 1;

        if (f < 0) continue;
        if (seen & (1u << f)) return refuse(res, TS_NM_ERR_DUPLICATE, d, k);
        seen |= 1u << f;
        switch (f) {
        case RF_ID:
            if (!get_i64(d, v, &r->region_id, res)) return 0;
            break;
        case RF_CODE:
            x = get_text(d, v, r->code, sizeof(r->code), &r->code_len, res);
            if (!x) return 0;
            if (x == 2) r->ok = 0;
            break;
        case RF_NAME:
            x = get_text(d, v, r->name, sizeof(r->name), &r->name_len, res);
            if (!x) return 0;
            if (x == 2) r->ok = 0;
            break;
        case RF_AVOID:
            if (!get_bool(d, v, &set, &r->avoid, res)) return 0;
            break;
        case RF_NOHOME:
            if (!get_bool(d, v, &set, &r->no_home, res)) return 0;
            break;
        case RF_NODES:
            if (ts_json_is_null(d, v)) break;
            if (ts_json_type_of(d, v) != TS_JSON_ARRAY) return refuse(res, TS_NM_ERR_TYPE, d, v);
            r->nodes = v;
            break;
        }
    }
    return 1;
}

typedef struct {
    ts_derpmap_node n;
    char   name[TS_DERPMAP_NAME_MAX + 1], host[TS_DERPMAP_NAME_MAX + 1], cert[TS_DERPMAP_NAME_MAX + 1];
    size_t name_len, host_len, cert_len;
    int    ok;
} dnode_in;

/* The IPv4 / IPv6 field (derphttp's shouldDialProto): "" - by DNS; an address of the family - it;
 * anything else - not over this family. */
static int derp_ip(const ts_json* d, int v, int family, ts_derpmap_ip* ip, ts_netmap_result* res)
{
    char buf[ADDRTEXT_MAX];
    size_t len;
    int f;

    memset(ip, 0, sizeof(*ip));
    if (ts_json_is_null(d, v)) return 1;
    if (ts_json_type_of(d, v) != TS_JSON_STRING) return refuse(res, TS_NM_ERR_TYPE, d, v);
    if (!ts_json_str(d, v, buf, sizeof(buf), &len)) {
        ip->mode = TS_DERPMAP_IP_OFF;           /* too long to be an address */
        return 1;
    }
    if (len == 0) return 1;
    if (ts_addr_parse(buf, len, &f, ip->addr.addr) && f == family) {
        ip->mode = TS_DERPMAP_IP_ADDR;
        ip->addr.family = (uint8_t)f;
    } else {
        memset(&ip->addr, 0, sizeof(ip->addr));
        ip->mode = TS_DERPMAP_IP_OFF;
    }
    return 1;
}

static int dnode_read(const ts_json* d, int t, dnode_in* r, ts_netmap_result* res)
{
    uint32_t seen = 0;
    int k, set, val, x;

    memset(r, 0, sizeof(*r));
    r->ok = 1;
    for (k = ts_json_first(d, t); k >= 0; k = ts_json_next(d, k)) {
        int f = field_of(d, k, dnode_fields, DN_COUNT), v = k + 1;

        if (f < 0) continue;
        if (seen & (1u << f)) return refuse(res, TS_NM_ERR_DUPLICATE, d, k);
        seen |= 1u << f;
        switch (f) {
        case DN_NAME:
            x = get_text(d, v, r->name, sizeof(r->name), &r->name_len, res);
            if (!x) return 0;
            if (x == 2) r->ok = 0;
            break;
        case DN_HOST:
            x = get_text(d, v, r->host, sizeof(r->host), &r->host_len, res);
            if (!x) return 0;
            if (x == 2) r->ok = 0;
            break;
        case DN_CERT:
            x = get_text(d, v, r->cert, sizeof(r->cert), &r->cert_len, res);
            if (!x) return 0;
            if (x == 2) r->ok = 0;
            break;
        case DN_REGION:
            if (!get_i64(d, v, &r->n.region_id, res)) return 0;
            break;
        case DN_STUNPORT:
            if (!get_i64(d, v, &r->n.stun_port, res)) return 0;
            break;
        case DN_PORT:
            if (!get_i64(d, v, &r->n.derp_port, res)) return 0;
            break;
        case DN_V4:
            if (!derp_ip(d, v, 4, &r->n.v4, res)) return 0;
            break;
        case DN_V6:
            if (!derp_ip(d, v, 6, &r->n.v6, res)) return 0;
            break;
        case DN_STUNONLY:
        case DN_INSECURE:
        case DN_PORT80:
            if (!get_bool(d, v, &set, &val, res)) return 0;
            if (set) {
                uint8_t b = (uint8_t)(val != 0);
                if (f == DN_STUNONLY) r->n.stun_only = b;
                else if (f == DN_INSECURE) r->n.insecure_for_tests = b;
                else r->n.can_port80 = b;
            }
            break;
        }
    }
    return 1;
}

/* The whole DERPMap value checked, as the first pass does it. */
static int derp_check(const ts_json* d, int t, ts_netmap_result* res)
{
    derp_top m;
    region_in r;
    dnode_in dn;
    int k, e;
    int64_t id;
    double score;

    if (!derp_top_read(d, t, &m, res)) return 0;
    for (k = ts_json_first(d, m.scores); k >= 0; k = ts_json_next(d, k)) {
        int v = k + 1;
        if (!ts_json_key_i64(d, k, &id)) return refuse(res, TS_NM_ERR_VALUE, d, k);
        if (ts_json_is_null(d, v)) continue;
        if (ts_json_type_of(d, v) != TS_JSON_NUMBER) return refuse(res, TS_NM_ERR_TYPE, d, v);
        if (!ts_json_f64(d, v, &score)) return refuse(res, TS_NM_ERR_VALUE, d, v);
    }
    for (k = ts_json_first(d, m.regions); k >= 0; k = ts_json_next(d, k)) {
        int v = k + 1;
        if (!ts_json_key_i64(d, k, &id)) return refuse(res, TS_NM_ERR_VALUE, d, k);
        if (ts_json_is_null(d, v)) continue;
        if (ts_json_type_of(d, v) != TS_JSON_OBJECT) return refuse(res, TS_NM_ERR_TYPE, d, v);
        if (!region_read(d, v, &r, res)) return 0;
        for (e = ts_json_first(d, r.nodes); e >= 0; e = ts_json_next(d, e)) {
            if (ts_json_is_null(d, e)) return refuse(res, TS_NM_ERR_NULL_ITEM, d, e);
            if (ts_json_type_of(d, e) != TS_JSON_OBJECT) return refuse(res, TS_NM_ERR_TYPE, d, e);
            if (!dnode_read(d, e, &dn, res)) return 0;
        }
    }
    return 1;
}

/* A string into the map's pool: its offset, or -1 when the pool is full. */
static long str_add(ts_derpmap* m, const char* s, size_t len)
{
    long off;

    if (len == 0) return 0;
    if (TS_DERPMAP_STR_MAX - m->str_used < len + 1 || m->str_used + len + 1 > 0xffff) return -1;
    off = (long)m->str_used;
    memcpy(m->str + m->str_used, s, len);
    m->str[m->str_used + len] = '\0';
    m->str_used += len + 1;
    return off;
}

/* Drops region `id` and its nodes (a later entry for the same id wins, as in a Go map). */
static void region_drop(ts_derpmap* m, int64_t id)
{
    size_t i, j;

    for (i = 0; i < m->n_regions && m->regions[i].id != id; i++) {}
    if (i == m->n_regions) return;
    {
        size_t first = m->regions[i].first, cnt = m->regions[i].n_nodes;
        memmove(m->nodes + first, m->nodes + first + cnt, (m->n_nodes - first - cnt) * sizeof(ts_derpmap_node));
        m->n_nodes -= cnt;
        for (j = 0; j < m->n_regions; j++)
            if (m->regions[j].first > first) m->regions[j].first = (uint16_t)(m->regions[j].first - cnt);
    }
    memmove(m->regions + i, m->regions + i + 1, (m->n_regions - i - 1) * sizeof(ts_derpmap_region));
    m->n_regions--;
}

static void region_add(ts_derpmap* m, const ts_json* d, int v, int64_t id, ts_netmap_result* res)
{
    ts_derpmap_region* g;
    region_in r;
    dnode_in dn;
    long code, name;
    int e;

    region_read(d, v, &r, NULL);
    code = r.ok ? str_add(m, r.code, r.code_len) : -1;
    name = code >= 0 ? str_add(m, r.name, r.name_len) : -1;
    if (m->n_regions == TS_DERPMAP_REGIONS_MAX || code < 0 || name < 0) {
        res->derp_dropped++;
        return;
    }
    g = &m->regions[m->n_regions++];
    memset(g, 0, sizeof(*g));
    g->id = id;
    g->region_id = r.region_id;
    g->code = (uint16_t)code;
    g->name = (uint16_t)name;
    g->avoid = (uint8_t)(r.avoid != 0);
    g->no_measure_no_home = (uint8_t)(r.no_home != 0);
    g->first = (uint16_t)m->n_nodes;
    for (e = ts_json_first(d, r.nodes); e >= 0; e = ts_json_next(d, e)) {
        long nm_, host, cert;
        dnode_read(d, e, &dn, NULL);
        if (!dn.ok || m->n_nodes == TS_DERPMAP_NODES_MAX) {
            res->derp_dropped++;
            continue;
        }
        nm_ = str_add(m, dn.name, dn.name_len);
        host = nm_ >= 0 ? str_add(m, dn.host, dn.host_len) : -1;
        cert = host >= 0 ? str_add(m, dn.cert, dn.cert_len) : -1;
        if (cert < 0) {
            res->derp_dropped++;
            continue;
        }
        dn.n.name = (uint16_t)nm_;
        dn.n.host = (uint16_t)host;
        dn.n.cert = (uint16_t)cert;
        m->nodes[m->n_nodes++] = dn.n;
        g->n_nodes++;
    }
}

static void regions_sort(ts_derpmap* m)
{
    size_t i, j;

    for (i = 1; i < m->n_regions; i++) {
        ts_derpmap_region r = m->regions[i];
        for (j = i; j > 0 && m->regions[j - 1].id > r.id; j--) m->regions[j] = m->regions[j - 1];
        m->regions[j] = r;
    }
}

static void scores_set(ts_derpmap* m, const ts_json* d, int t, ts_netmap_result* res)
{
    size_t i, j;
    int k;

    m->scores_set = 1;
    m->n_scores = 0;
    for (k = ts_json_first(d, t); k >= 0; k = ts_json_next(d, k)) {
        int64_t id;
        double score = 0;
        ts_json_key_i64(d, k, &id);
        if (!ts_json_is_null(d, k + 1)) ts_json_f64(d, k + 1, &score);
        for (i = 0; i < m->n_scores && m->scores[i].region != id; i++) {}
        if (i == m->n_scores) {
            if (m->n_scores == TS_DERPMAP_SCORES_MAX) {
                res->derp_dropped++;
                continue;
            }
            m->n_scores++;
        }
        m->scores[i].region = id;
        m->scores[i].score = score;
    }
    for (i = 1; i < m->n_scores; i++) {
        ts_derpmap_score s = m->scores[i];
        for (j = i; j > 0 && m->scores[j - 1].region > s.region; j--) m->scores[j] = m->scores[j - 1];
        m->scores[j] = s;
    }
}

/* The DERPMap of a message, after the first pass (mapSession.updateStateFromResponse). */
static void derp_commit(ts_netmap* nm, const ts_json* d, int t, ts_netmap_result* res)
{
    ts_derpmap* m = &nm->derp;
    int prev = m->present;
    derp_top top;
    int k;

    derp_top_read(d, t, &top, NULL);
    if (top.regions >= 0) {
        m->n_regions = 0;
        m->n_nodes = 0;
        m->str[0] = '\0';
        m->str_used = 1;
        for (k = ts_json_first(d, top.regions); k >= 0; k = ts_json_next(d, k)) {
            int64_t id;
            ts_json_key_i64(d, k, &id);
            region_drop(m, id);
            if (!ts_json_is_null(d, k + 1)) region_add(m, d, k + 1, id, res);
        }
        regions_sort(m);
        m->omit_default_regions = top.omit;
    } else if (!prev) {
        /* nothing to keep: no regions */
        m->n_regions = 0;
        m->n_nodes = 0;
        m->str[0] = '\0';
        m->str_used = 1;
        m->omit_default_regions = top.omit;
    }
    if (top.hp >= 0) {
        if (top.scores >= 0) {
            scores_set(m, d, top.scores, res);
        } else if (!(prev && m->home_params)) {
            m->scores_set = 0;
            m->n_scores = 0;
        }
        m->home_params = 1;
    } else if (!prev) {
        m->home_params = 0;
        m->scores_set = 0;
        m->n_scores = 0;
    }
    m->present = 1;
}

/* --------------------------------------------------------------------- DNSConfig */

enum { DC_RESOLVERS, DC_DOMAINS, DC_PROXIED, DC_EXTRA, DC_ROUTES, DC_COUNT };
static const char* const dnsconf_fields[DC_COUNT] = { "Resolvers", "Domains", "Proxied", "ExtraRecords", "Routes" };

enum { RS_ADDR, RS_COUNT };
static const char* const resolver_fields[RS_COUNT] = { "Addr" };

enum { ER_NAME, ER_TYPE, ER_VALUE, ER_COUNT };
static const char* const record_fields[ER_COUNT] = { "Name", "Type", "Value" };

/* dnstype.Resolver.Addr that is a plain DNS server: an address, or address:53 ([v6]:53). DoH
 * ("https://..."), DoT and other ports are not. */
static int plain_resolver(const char* s, size_t len, bt_addr* out)
{
    int family = 0;

    memset(out, 0, sizeof(*out));
    if (ts_addr_parse(s, len, &family, out->addr)) {
        out->family = (uint8_t)family;
        return 1;
    }
    if (len > 3 && memcmp(s + len - 3, ":53", 3) == 0) {
        size_t n = len - 3;
        if (n > 2 && s[0] == '[' && s[n - 1] == ']') {
            if (ts_addr_parse(s + 1, n - 2, &family, out->addr) && family == 6) {
                out->family = 6;
                return 1;
            }
            return 0;
        }
        if (ts_addr_parse(s, n, &family, out->addr) && family == 4) {
            out->family = 4;
            return 1;
        }
    }
    return 0;
}

/* A DNS name we keep: read whole, not empty, one trailing dot taken off. */
static int dns_name(char* s, size_t* len)
{
    if (*len > 0 && s[*len - 1] == '.') s[--*len] = '\0';
    return *len > 0 && *len <= TS_DNS_NAME_MAX;
}

/* One dnstype.Resolver: refused as Go's Unmarshal would refuse it (0); else *named when it names a
 * server at all (null, or an empty Addr, does not), *plain with the server in `a` when that is a plain
 * DNS server. */
static int resolver_get(const ts_json* d, int e, bt_addr* a, int* plain, int* named, ts_netmap_result* res)
{
    char addr[TS_DNS_NAME_MAX + 8];
    size_t len = 0;
    uint32_t seen = 0;
    int k, x = 1;

    *plain = *named = 0;
    if (ts_json_is_null(d, e)) return 1;
    if (ts_json_type_of(d, e) != TS_JSON_OBJECT) return refuse(res, TS_NM_ERR_TYPE, d, e);
    addr[0] = '\0';
    for (k = ts_json_first(d, e); k >= 0; k = ts_json_next(d, k)) {
        int f = field_of(d, k, resolver_fields, RS_COUNT);
        if (f < 0) continue;
        if (seen & (1u << f)) return refuse(res, TS_NM_ERR_DUPLICATE, d, k);
        seen |= 1u << f;
        x = get_text(d, k + 1, addr, sizeof(addr), &len, res);
        if (!x) return 0;
    }
    *named = len > 0 || x == 2;
    *plain = x == 1 && len > 0 && plain_resolver(addr, len, a);
    return 1;
}

/* One Resolvers element: refused as Go's Unmarshal would refuse it; else kept into `out` when it is
 * a plain DNS server and there is room. */
static int resolver_read(const ts_json* d, int e, ts_dnsconf* out, ts_netmap_result* res)
{
    bt_addr a;
    int plain, named;

    if (!resolver_get(d, e, &a, &plain, &named, res)) return 0;
    if (!out) return 1;
    if (!plain || out->n_resolvers == TS_DNS_RESOLVERS_MAX) {
        if (named) out->left_out++;
        return 1;
    }
    out->resolvers[out->n_resolvers++] = a;
    return 1;
}

/*
 * Routes: {"suffix": [Resolver...] | null, ...} - refused as Go's Unmarshal would refuse it (not an
 * object, a value that is not an array or null, a bad Resolver); else each route kept, its suffix in
 * lower case without a trailing dot (a key given twice: the last one, as a Go map ends up). A route
 * that names servers with no plain one among them is kept unusable; beyond our room, or a suffix we
 * cannot keep, it is left out (counted).
 */
static int routes_read(const ts_json* d, int v, ts_dnsconf* out, ts_netmap_result* res)
{
    int k, e;

    if (ts_json_is_null(d, v)) return 1;
    if (ts_json_type_of(d, v) != TS_JSON_OBJECT) return refuse(res, TS_NM_ERR_TYPE, d, v);
    for (k = ts_json_first(d, v); k >= 0; k = ts_json_next(d, k)) {
        char suffix[TS_DNS_NAME_MAX + 2];
        size_t len = 0, i;
        int x = get_text(d, k, suffix, sizeof(suffix), &len, res), val = k + 1, named_any = 0;
        ts_dns_route route;

        if (!x) return 0;
        if (!ts_json_is_null(d, val) && ts_json_type_of(d, val) != TS_JSON_ARRAY) return refuse(res, TS_NM_ERR_TYPE, d, val);
        memset(&route, 0, sizeof(route));
        for (e = ts_json_is_null(d, val) ? -1 : ts_json_first(d, val); e >= 0; e = ts_json_next(d, e)) {
            bt_addr a;
            int plain, named;
            if (!resolver_get(d, e, &a, &plain, &named, res)) return 0;
            if (named) named_any = 1;
            if (!out) continue;
            if (!plain) {
                if (named) out->left_out++;             /* DoH and the like: not ours to ask */
                continue;
            }
            if (route.n_servers < TS_DNS_ROUTE_SERVERS) route.servers[route.n_servers++] = a;
            else out->left_out++;
        }
        if (!out) continue;
        if (x != 1 || !dns_name(suffix, &len)) {
            out->left_out++;
            continue;
        }
        for (i = 0; i < len; i++)
            if (suffix[i] >= 'A' && suffix[i] <= 'Z') suffix[i] = (char)(suffix[i] + ('a' - 'A'));
        memcpy(route.suffix, suffix, len + 1);
        route.unusable = named_any && route.n_servers == 0;
        for (i = 0; i < out->n_routes && strcmp(out->routes[i].suffix, route.suffix) != 0; i++) {}
        if (i < out->n_routes) out->routes[i] = route;             /* given twice: the last one */
        else if (out->n_routes < TS_DNS_ROUTES_MAX) out->routes[out->n_routes++] = route;
        else out->left_out++;
    }
    return 1;
}

/* One ExtraRecords element: an A or AAAA is kept (Type "" takes the kind from Value). */
static int record_read(const ts_json* d, int e, ts_dnsconf* out, ts_netmap_result* res)
{
    char name[TS_DNS_NAME_MAX + 2], type[16], value[64];
    size_t name_len = 0, type_len = 0, value_len = 0;
    uint32_t seen = 0;
    int k, ok = 1, family = 0;
    uint8_t addr[16];

    if (ts_json_is_null(d, e)) return 1;
    if (ts_json_type_of(d, e) != TS_JSON_OBJECT) return refuse(res, TS_NM_ERR_TYPE, d, e);
    name[0] = type[0] = value[0] = '\0';
    for (k = ts_json_first(d, e); k >= 0; k = ts_json_next(d, k)) {
        int f = field_of(d, k, record_fields, ER_COUNT), x;
        if (f < 0) continue;
        if (seen & (1u << f)) return refuse(res, TS_NM_ERR_DUPLICATE, d, k);
        seen |= 1u << f;
        if (f == ER_NAME) x = get_text(d, k + 1, name, sizeof(name), &name_len, res);
        else if (f == ER_TYPE) x = get_text(d, k + 1, type, sizeof(type), &type_len, res);
        else x = get_text(d, k + 1, value, sizeof(value), &value_len, res);
        if (!x) return 0;
        if (x == 2) ok = 0;
    }
    if (!out) return 1;
    if (ok && dns_name(name, &name_len) && ts_addr_parse(value, value_len, &family, addr) &&
        (type_len == 0 || (strcmp(type, "A") == 0 && family == 4) || (strcmp(type, "AAAA") == 0 && family == 6)) &&
        out->n_extra < TS_DNS_EXTRA_MAX) {
        ts_dns_record* r = &out->extra[out->n_extra++];
        memcpy(r->name, name, name_len + 1);
        r->family = family;
        memcpy(r->addr, addr, 16);
    } else {
        out->left_out++;
    }
    return 1;
}

/*
 * DNSConfig: checked with `out` NULL (refused as Go's Unmarshal would refuse it - a field we read
 * of the wrong type, read twice), read into `out` with res NULL. Only Proxied, Resolvers, Domains,
 * ExtraRecords and Routes (split DNS) are read; everything else is skipped.
 */
static int dns_read(const ts_json* d, int t, ts_dnsconf* out, ts_netmap_result* res)
{
    uint32_t seen = 0;
    int k, e, set;

    if (out) {
        memset(out, 0, sizeof(*out));
        out->present = 1;
    }
    for (k = ts_json_first(d, t); k >= 0; k = ts_json_next(d, k)) {
        int f = field_of(d, k, dnsconf_fields, DC_COUNT), v = k + 1, proxied = 0;
        ts_json_type ty = ts_json_type_of(d, v);

        if (f < 0) continue;
        if (seen & (1u << f)) return refuse(res, TS_NM_ERR_DUPLICATE, d, k);
        seen |= 1u << f;
        if (f == DC_PROXIED) {
            if (!get_bool(d, v, &set, &proxied, res)) return 0;
            if (out && set) out->proxied = proxied;
            continue;
        }
        if (f == DC_ROUTES) {
            if (!routes_read(d, v, out, res)) return 0;
            continue;
        }
        if (ty == TS_JSON_NULL) continue;
        if (ty != TS_JSON_ARRAY) return refuse(res, TS_NM_ERR_TYPE, d, v);
        for (e = ts_json_first(d, v); e >= 0; e = ts_json_next(d, e)) {
            if (f == DC_RESOLVERS) {
                if (!resolver_read(d, e, out, res)) return 0;
            } else if (f == DC_EXTRA) {
                if (!record_read(d, e, out, res)) return 0;
            } else {
                char name[TS_DNS_NAME_MAX + 2];
                size_t len = 0;
                int x = get_text(d, e, name, sizeof(name), &len, res);
                if (!x) return 0;
                if (!out) continue;
                if (x == 1 && dns_name(name, &len) && out->n_domains < TS_DNS_DOMAINS_MAX)
                    memcpy(out->domains[out->n_domains++], name, len + 1);
                else if (len > 0 || x == 2)
                    out->left_out++;
            }
        }
    }
    return 1;
}

/* --------------------------------------------------------------------- a message */

enum {
    MF_KEEPALIVE, MF_CONTROLTIME, MF_NODE, MF_DERPMAP, MF_PEERS, MF_CHANGED, MF_REMOVED, MF_PATCH,
    MF_SEEN, MF_ONLINE, MF_DOMAIN, MF_DNS, MF_COUNT
};

static const char* const msg_fields[MF_COUNT] = {
    "KeepAlive", "ControlTime", "Node", "DERPMap", "Peers", "PeersChanged", "PeersRemoved",
    "PeersChangedPatch", "PeerSeenChange", "OnlineChange", "Domain", "DNSConfig"
};

typedef struct {
    int     tok[MF_COUNT];              /* the values, -1 when absent or null */
    int     keepalive;
    int     has_time;
    ts_time time;
    int     self_ok;                    /* Node is within our limits */
} msg_in;

static int msg_scan(const ts_json* d, msg_in* m, ts_netmap_result* res)
{
    uint32_t seen = 0;
    int k, set;

    memset(m, 0, sizeof(*m));
    for (k = 0; k < MF_COUNT; k++) m->tok[k] = -1;
    for (k = ts_json_first(d, 0); k >= 0; k = ts_json_next(d, k)) {
        int f = field_of(d, k, msg_fields, MF_COUNT), v = k + 1;
        ts_json_type ty = ts_json_type_of(d, v), want;

        if (f < 0) continue;
        if (seen & (1u << f)) return refuse(res, TS_NM_ERR_DUPLICATE, d, k);
        seen |= 1u << f;
        if (f == MF_KEEPALIVE) {
            if (!get_bool(d, v, &set, &m->keepalive, res)) return 0;
            continue;
        }
        if (f == MF_CONTROLTIME) {
            if (!get_time(d, v, &m->time, &m->has_time, res)) return 0;
            continue;
        }
        if (ty == TS_JSON_NULL) continue;
        switch (f) {
        case MF_NODE: case MF_DERPMAP: case MF_SEEN: case MF_ONLINE: case MF_DNS:
            want = TS_JSON_OBJECT;
            break;
        case MF_DOMAIN:
            want = TS_JSON_STRING;
            break;
        default:
            want = TS_JSON_ARRAY;
            break;
        }
        if (ty != want) return refuse(res, TS_NM_ERR_TYPE, d, v);
        m->tok[f] = v;
    }
    return 1;
}

/* Elements of a list of nodes or patches: objects; null is refused (Go would crash on it). */
static int item_ok(const ts_json* d, int e, ts_netmap_result* res)
{
    if (ts_json_is_null(d, e)) return refuse(res, TS_NM_ERR_NULL_ITEM, d, e);
    if (ts_json_type_of(d, e) != TS_JSON_OBJECT) return refuse(res, TS_NM_ERR_TYPE, d, e);
    return 1;
}

/* A map from node IDs to bools (PeerSeenChange, OnlineChange). */
static int idmap_check(const ts_json* d, int t, ts_netmap_result* res)
{
    int k;
    int64_t id;

    for (k = ts_json_first(d, t); k >= 0; k = ts_json_next(d, k)) {
        ts_json_type ty = ts_json_type_of(d, k + 1);
        if (!ts_json_key_i64(d, k, &id)) return refuse(res, TS_NM_ERR_VALUE, d, k);
        if (ty != TS_JSON_NULL && ty != TS_JSON_TRUE && ty != TS_JSON_FALSE)
            return refuse(res, TS_NM_ERR_TYPE, d, k + 1);
    }
    return 1;
}

/* The first pass: every value the message carries for us, read and checked, nothing changed. */
static int msg_check(ts_netmap* nm, const ts_json* d, msg_in* m, ts_netmap_result* res)
{
    patch_in p;
    int e, list;

    if (m->tok[MF_NODE] >= 0) {
        ts_node_in* in = &nm->in;
        size_t n_allowed;
        if (!node_read(nm, d, m->tok[MF_NODE], res)) return 0;
        in_allowed(in, &n_allowed);
        m->self_ok = in->name_ok && in->n_addrs <= TS_NODE_ADDRS_MAX && n_allowed <= TS_NODE_ADDRS_MAX;
    }
    for (list = MF_PEERS; list <= MF_CHANGED; list++) {
        for (e = ts_json_first(d, m->tok[list]); e >= 0; e = ts_json_next(d, e))
            if (!item_ok(d, e, res) || !node_read(nm, d, e, res)) return 0;
    }
    for (e = ts_json_first(d, m->tok[MF_REMOVED]); e >= 0; e = ts_json_next(d, e)) {
        int64_t id;
        if (ts_json_is_null(d, e)) continue;
        if (!get_i64(d, e, &id, res)) return 0;
    }
    for (e = ts_json_first(d, m->tok[MF_PATCH]); e >= 0; e = ts_json_next(d, e))
        if (!item_ok(d, e, res) || !patch_read(d, e, &p, res)) return 0;
    if (m->tok[MF_SEEN] >= 0 && !idmap_check(d, m->tok[MF_SEEN], res)) return 0;
    if (m->tok[MF_ONLINE] >= 0 && !idmap_check(d, m->tok[MF_ONLINE], res)) return 0;
    if (m->tok[MF_DERPMAP] >= 0 && !derp_check(d, m->tok[MF_DERPMAP], res)) return 0;
    if (m->tok[MF_DNS] >= 0 && !dns_read(d, m->tok[MF_DNS], NULL, res)) return 0;
    return 1;
}

/* patchifyPeer: whether node nm->in differs from `was` only in fields a patch carries, and then
 * which of ours; mapSession.removeUnwantedDiscoUpdates on the patch made. */
static int patchify(const ts_netmap* nm, const ts_node* was, uint8_t* mask)
{
    const ts_node_in* in = &nm->in;
    const ts_node* n = &in->n;
    const wg_prefix* allowed;
    size_t n_allowed;
    uint8_t m = 0;

    if (!node_storable(in)) return 0;
    allowed = in_allowed(in, &n_allowed);
    if (was->user != n->user || was->fp != n->fp ||
        (was->flags & FLAGS_COMPARED) != (n->flags & FLAGS_COMPARED) ||
        was->name_len != in->name_len || memcmp(ts_node_name(nm, was), in->name, in->name_len) != 0 ||
        was->n_addrs != in->n_addrs || memcmp(ts_node_addrs(nm, was), in->addrs, in->n_addrs * PFX) != 0 ||
        was->n_allowed != n_allowed || memcmp(ts_node_allowed(nm, was), allowed, n_allowed * PFX) != 0)
        return 0;
    if (memcmp(was->key.b, n->key.b, WG_KEY_LEN) != 0) m |= M_KEY;
    if (ts_time_cmp(was->key_expiry, n->key_expiry) != 0) m |= M_EXPIRY;
    if (memcmp(was->disco.b, n->disco.b, WG_KEY_LEN) != 0) m |= M_DISCO;
    if (was->home_derp != n->home_derp && n->home_derp != 0) m |= M_DERP;
    if ((was->flags & TS_NODE_ONLINE_KNOWN) && (n->flags & TS_NODE_ONLINE_KNOWN) &&
        (was->flags & TS_NODE_ONLINE) != (n->flags & TS_NODE_ONLINE))
        m |= M_ONLINE;
    if ((was->flags & TS_NODE_SEEN) && (n->flags & TS_NODE_SEEN) && ts_time_cmp(was->last_seen, n->last_seen) != 0)
        m |= M_SEEN;
    /* a patch with a disco key, Online=false and a LastSeen that is not newer is dropped whole */
    if ((m & (M_DISCO | M_ONLINE | M_SEEN)) == (M_DISCO | M_ONLINE | M_SEEN) && !(n->flags & TS_NODE_ONLINE) &&
        ts_time_cmp(n->last_seen, was->last_seen) <= 0)
        m = 0;
    *mask = m;
    return 1;
}

/*
 * Before anything changes: a snapshot of every peer, the peers a full list keeps, and what becomes
 * of each PeersChanged node held - all against the peers as the message found them, the way Go
 * decides before it applies. Refuses a list naming a held node twice.
 */
static int msg_plan(ts_netmap* nm, const ts_json* d, const msg_in* m, ts_netmap_result* res)
{
    int full = m->tok[MF_PEERS] >= 0 && ts_json_size(d, m->tok[MF_PEERS]) > 0;
    int list = full ? MF_PEERS : MF_CHANGED;
    size_t i;
    int e;

    for (i = 0; i < nm->n; i++) {
        ts_node* x = &nm->nodes[nm->by_id[i]];
        x->plan = PLAN_NONE;
        x->mask = 0;
        x->snap = (uint8_t)(SNAP_OLD | ((x->flags & TS_NODE_SEEN) ? SNAP_SEEN : 0));
        x->snap_seen = x->last_seen;
    }
    if (nm->fresh) return 1;                    /* a new session holds nothing yet */
    for (e = ts_json_first(d, m->tok[list]); e >= 0; e = ts_json_next(d, e)) {
        int s;
        ts_node* x;
        uint8_t mask;

        node_read(nm, d, e, NULL);
        s = slot_live(nm, nm->in.n.id);
        if (s < 0) continue;
        x = &nm->nodes[s];
        if (x->plan != PLAN_NONE) return refuse(res, TS_NM_ERR_DUP_PEER, d, e);
        if (full) {
            x->plan = PLAN_LISTED;
        } else if (patchify(nm, x, &mask)) {
            x->plan = mask ? PLAN_PATCH : PLAN_SKIP;
            x->mask = mask;
        } else {
            x->plan = PLAN_UPSERT;
        }
    }
    return 1;
}

/* mapSession.removeUnwantedDiscoUpdatesFromFullNetmapUpdate, for one node of a full list against
 * the copy held: an offline node does not move to another disco key without a newer LastSeen. */
static void disco_keep(const ts_node* was, ts_node_in* in)
{
    ts_node* n = &in->n;

    if (key_zero(&n->disco) || memcmp(was->disco.b, n->disco.b, WG_KEY_LEN) == 0) return;
    if ((n->flags & TS_NODE_ONLINE_KNOWN) && (n->flags & TS_NODE_ONLINE)) return;
    if (!(was->flags & TS_NODE_SEEN)) return;
    if ((n->flags & TS_NODE_SEEN) && ts_time_cmp(n->last_seen, was->last_seen) > 0) return;
    n->disco = was->disco;
    n->last_seen = was->last_seen;
    n->flags |= TS_NODE_SEEN;
}

static void reset_all(ts_netmap* nm)
{
    size_t i;

    for (i = 0; i < nm->cap; i++) nm->nodes[i].state = S_FREE;
    nm->n = 0;
    nm->n_keyed = 0;
    nm->free_hint = 0;
    nm->arena_used = 0;
    nm->arena_garbage = 0;
    nm->has_self = 0;
    memset(&nm->self, 0, sizeof(nm->self));
    nm->self_name[0] = '\0';
    nm->domain[0] = '\0';
    memset(&nm->derp, 0, sizeof(nm->derp));
    nm->derp.str_used = 1;
    memset(&nm->dns, 0, sizeof(nm->dns));
    nm->incomplete = 0;
}

static void self_put(ts_netmap* nm)
{
    ts_node_in* in = &nm->in;
    const wg_prefix* allowed;
    size_t n_allowed;

    allowed = in_allowed(in, &n_allowed);
    nm->self = in->n;
    nm->self.n_addrs = (uint16_t)in->n_addrs;
    nm->self.n_allowed = (uint16_t)n_allowed;
    nm->self.name_len = (uint16_t)in->name_len;
    nm->self.gen = nm->gen;
    memcpy(nm->self_name, in->name, in->name_len + 1);
    memcpy(nm->self_addrs, in->addrs, in->n_addrs * PFX);
    if (!(in->n.flags & TS_NODE_ALLOWED_ADDRS)) memcpy(nm->self_allowed, allowed, n_allowed * PFX);
    nm->has_self = 1;
}

/* Peers carries the whole list (updatePeersStateFromResponse, first branch). */
static void commit_full(ts_netmap* nm, const ts_json* d, int list, ts_netmap_result* res)
{
    size_t i;
    int e;

    /* those not listed go first: their room is free for the rest */
    for (i = nm->n; i-- > 0;)
        if (nm->nodes[nm->by_id[i]].plan != PLAN_LISTED) slot_remove_at(nm, i);
    nm->incomplete = 0;
    for (e = ts_json_first(d, list); e >= 0; e = ts_json_next(d, e)) {
        int s;

        node_read(nm, d, e, NULL);
        s = slot_live(nm, nm->in.n.id);
        if (s >= 0) {
            ts_node* x = &nm->nodes[s];
            if (x->plan == PLAN_LISTED) {
                disco_keep(x, &nm->in);
                x->plan = PLAN_DONE;
            }
            node_put(nm, (unsigned)s, 0, res);
            continue;
        }
        s = slot_new(nm);
        if (s < 0) {
            nm->incomplete = 1;
            res->peers_dropped++;
            continue;
        }
        node_put(nm, (unsigned)s, 1, res);
    }
    res->full = 1;
}

static void patch_put(ts_netmap* nm, ts_node* x, const patch_in* p)
{
    if (p->derp != 0) x->home_derp = p->derp;
    if (p->has_key) x->key = p->key;
    if (p->has_disco) x->disco = p->disco;
    if (p->has_online)
        x->flags = (uint16_t)((x->flags & ~TS_NODE_ONLINE) | TS_NODE_ONLINE_KNOWN | (p->online ? TS_NODE_ONLINE : 0));
    if (p->has_seen) {
        x->last_seen = p->seen;
        x->flags |= TS_NODE_SEEN;
    }
    if (p->has_expiry) x->key_expiry = p->expiry;
    x->gen = nm->gen;
}

/* The deltas, in Go's order (updatePeersStateFromResponse, second branch). */
static void commit_delta(ts_netmap* nm, const ts_json* d, const msg_in* m, ts_time now,
                         ts_netmap_result* res)
{
    patch_in p;
    size_t i;
    int e, k, s, changed = 0;

    /* PeersRemoved. One PeersChanged does not name goes at once (its room may be needed below);
     * one it names is kept aside to the end - replaced, it comes back; made a patch, it stays
     * gone (the patch finds nothing) */
    for (e = ts_json_first(d, m->tok[MF_REMOVED]); e >= 0; e = ts_json_next(d, e)) {
        int64_t id = 0;
        get_i64(d, e, &id, NULL);
        s = slot_live(nm, id);
        if (s < 0) continue;
        if (nm->nodes[s].plan == PLAN_NONE) slot_remove(nm, (unsigned)s);
        else nm->nodes[s].state = S_GONE;
        changed = 1;
    }

    /* PeersChanged: added or replaced, those patchifyPeer made patches of come later */
    for (e = ts_json_first(d, m->tok[MF_CHANGED]); e >= 0; e = ts_json_next(d, e)) {
        node_read(nm, d, e, NULL);
        s = slot_find(nm, nm->in.n.id);
        changed = 1;
        if (s >= 0) {
            uint8_t plan = nm->nodes[s].plan;
            if (plan == PLAN_PATCH || plan == PLAN_SKIP) continue;
            node_put(nm, (unsigned)s, 0, res);
            continue;
        }
        s = slot_new(nm);
        if (s < 0) {
            nm->incomplete = 1;
            res->peers_dropped++;
            continue;
        }
        node_put(nm, (unsigned)s, 1, res);
    }

    /* PeerSeenChange: now, or never */
    for (k = ts_json_first(d, m->tok[MF_SEEN]); k >= 0; k = ts_json_next(d, k)) {
        int64_t id;
        int val = 0;
        ts_json_key_i64(d, k, &id);
        ts_json_bool(d, k + 1, &val);
        s = slot_live(nm, id);
        if (s < 0) continue;
        if (val) {
            nm->nodes[s].last_seen = now;
            nm->nodes[s].flags |= TS_NODE_SEEN;
        } else {
            nm->nodes[s].flags &= (uint16_t)~TS_NODE_SEEN;
        }
        nm->nodes[s].gen = nm->gen;
        changed = 1;
    }

    /* OnlineChange */
    for (k = ts_json_first(d, m->tok[MF_ONLINE]); k >= 0; k = ts_json_next(d, k)) {
        int64_t id;
        int val = 0;
        ts_json_key_i64(d, k, &id);
        ts_json_bool(d, k + 1, &val);
        s = slot_live(nm, id);
        if (s < 0) continue;
        nm->nodes[s].flags = (uint16_t)((nm->nodes[s].flags & ~TS_NODE_ONLINE) | TS_NODE_ONLINE_KNOWN |
                                        (val ? TS_NODE_ONLINE : 0));
        nm->nodes[s].gen = nm->gen;
        changed = 1;
    }

    /* PeersChangedPatch, judged by removeUnwantedDiscoUpdates against the node as it was */
    for (e = ts_json_first(d, m->tok[MF_PATCH]); e >= 0; e = ts_json_next(d, e)) {
        ts_node* x;
        patch_read(d, e, &p, NULL);
        s = slot_live(nm, p.id);
        if (s < 0) continue;
        x = &nm->nodes[s];
        if (p.has_disco && p.has_online && p.has_seen && !p.online && (x->snap & SNAP_OLD) &&
            (x->snap & SNAP_SEEN) && ts_time_cmp(p.seen, x->snap_seen) <= 0)
            continue;
        patch_put(nm, x, &p);
        changed = 1;
    }

    /* the patches patchifyPeer made, after the explicit ones */
    for (e = ts_json_first(d, m->tok[MF_CHANGED]); e >= 0; e = ts_json_next(d, e)) {
        ts_node* x;
        const ts_node* n = &nm->in.n;
        node_read(nm, d, e, NULL);
        s = slot_live(nm, n->id);
        if (s < 0 || nm->nodes[s].plan != PLAN_PATCH) continue;
        x = &nm->nodes[s];
        if (x->mask & M_KEY) x->key = n->key;
        if (x->mask & M_EXPIRY) x->key_expiry = n->key_expiry;
        if (x->mask & M_DISCO) x->disco = n->disco;
        if (x->mask & M_DERP) x->home_derp = n->home_derp;
        if (x->mask & M_ONLINE)
            x->flags = (uint16_t)((x->flags & ~TS_NODE_ONLINE) | (n->flags & TS_NODE_ONLINE) | TS_NODE_ONLINE_KNOWN);
        if (x->mask & M_SEEN) {
            x->last_seen = n->last_seen;
            x->flags |= TS_NODE_SEEN;
        }
        x->plan = PLAN_DONE;
        x->gen = nm->gen;
    }

    /* the removed ones go now */
    for (i = nm->n; i-- > 0;)
        if (nm->nodes[nm->by_id[i]].state == S_GONE) slot_remove_at(nm, i);
    if (changed) res->changed |= TS_NM_CHANGED_PEERS;
}

static void msg_commit(ts_netmap* nm, const ts_json* d, const msg_in* m, ts_time now, ts_netmap_result* res)
{
    int full = m->tok[MF_PEERS] >= 0 && ts_json_size(d, m->tok[MF_PEERS]) > 0;

    nm->gen++;
    if (nm->fresh) {
        reset_all(nm);
        nm->fresh = 0;
        res->changed |= TS_NM_CHANGED_RESET | TS_NM_CHANGED_PEERS | TS_NM_CHANGED_DERP | TS_NM_CHANGED_DOMAIN |
                        TS_NM_CHANGED_DNS;
    }
    if (m->tok[MF_NODE] >= 0) {
        node_read(nm, d, m->tok[MF_NODE], NULL);
        self_put(nm);
        res->changed |= TS_NM_CHANGED_SELF;
    }
    if (full) {
        commit_full(nm, d, m->tok[MF_PEERS], res);
        res->changed |= TS_NM_CHANGED_PEERS;
    } else {
        commit_delta(nm, d, m, now, res);
    }
    if (res->changed & TS_NM_CHANGED_PEERS) keys_rebuild(nm);
    if (m->tok[MF_DERPMAP] >= 0) {
        derp_commit(nm, d, m->tok[MF_DERPMAP], res);
        res->changed |= TS_NM_CHANGED_DERP;
    }
    if (m->tok[MF_DOMAIN] >= 0) {
        char buf[TS_NM_DOMAIN_MAX + 1];
        size_t len;
        /* "" means unchanged; one beyond our limit, or holding a NUL, is not taken */
        if (ts_json_str(d, m->tok[MF_DOMAIN], buf, sizeof(buf), &len) && len > 0 && !memchr(buf, '\0', len) &&
            strcmp(buf, nm->domain) != 0) {
            memcpy(nm->domain, buf, len + 1);
            res->changed |= TS_NM_CHANGED_DOMAIN;
        }
    }
    if (m->tok[MF_DNS] >= 0) {
        dns_read(d, m->tok[MF_DNS], &nm->dns, NULL);
        res->changed |= TS_NM_CHANGED_DNS;
    }
}

/* --------------------------------------------------------------------- the public face */

void ts_netmap_init(ts_netmap* nm, ts_node* nodes, uint16_t* index, size_t cap, uint8_t* arena,
                    size_t arena_size)
{
    memset(nm, 0, sizeof(*nm));
    if (cap > SLOTS_MAX) cap = SLOTS_MAX;
    nm->nodes = nodes;
    nm->by_id = index;
    nm->by_key = index + cap;
    nm->cap = cap;
    nm->arena = arena;
    nm->arena_size = arena_size;
    if (nodes) memset(nodes, 0, cap * sizeof(ts_node));
    nm->derp.str_used = 1;
    nm->fresh = 1;
}

void ts_netmap_session_start(ts_netmap* nm)
{
    nm->fresh = 1;
}

int ts_netmap_apply(ts_netmap* nm, const ts_json* d, ts_time now, ts_netmap_result* res)
{
    msg_in m;

    memset(res, 0, sizeof(*res));
    if (!d || d->n < 1 || ts_json_type_of(d, 0) != TS_JSON_OBJECT) return refuse(res, TS_NM_ERR_NOT_OBJECT, NULL, 0);
    if (!msg_scan(d, &m, res) || !msg_check(nm, d, &m, res)) return 0;
    if (m.has_time) {
        res->has_control_time = 1;
        res->control_time = m.time;
    }
    if (m.keepalive) {
        /* direct.go: a KeepAlive is not looked at further */
        res->keepalive = 1;
        return 1;
    }
    if (nm->fresh && m.tok[MF_NODE] < 0) return refuse(res, TS_NM_ERR_NO_SELF, d, 0);
    if (m.tok[MF_NODE] >= 0 && !m.self_ok) return refuse(res, TS_NM_ERR_SELF_LIMIT, d, m.tok[MF_NODE]);
    if (!msg_plan(nm, d, &m, res)) return 0;
    msg_commit(nm, d, &m, now, res);
    return 1;
}

const char* ts_netmap_err_text(ts_netmap_err e)
{
    switch (e) {
    case TS_NM_OK:                  return "ok";
    case TS_NM_ERR_NOT_OBJECT:      return "not a JSON object";
    case TS_NM_ERR_TYPE:            return "a field of the wrong type";
    case TS_NM_ERR_VALUE:           return "a malformed value";
    case TS_NM_ERR_DUPLICATE:       return "a field given twice";
    case TS_NM_ERR_NULL_ITEM:       return "null in a list of nodes";
    case TS_NM_ERR_DUP_PEER:        return "a node listed twice";
    case TS_NM_ERR_NO_SELF:         return "the first netmap has no node of ours";
    case TS_NM_ERR_SELF_LIMIT:      return "our node is beyond the limits";
    case TS_NM_ERR_NO_NOISE_KEY:    return "no ts2021 key: control server too old";
    case TS_NM_ERR_TOO_LONG:        return "a value too long";
    }
    return "?";
}

const ts_node* ts_netmap_self(const ts_netmap* nm)
{
    return nm->has_self ? &nm->self : NULL;
}

const char* ts_netmap_domain(const ts_netmap* nm)
{
    return nm->domain;
}

const ts_dnsconf* ts_netmap_dns(const ts_netmap* nm)
{
    return &nm->dns;
}

/* netmap.MagicDNSSuffixOfNodeName on our own name: after its first label, no dots at either end.
 * *suffix points into nm->self_name; the length, 0 without our node. */
static size_t self_suffix(const ts_netmap* nm, const char** suffix)
{
    const char* s = nm->self_name;
    size_t sl = nm->self.name_len;
    const char* dot;

    *suffix = "";
    if (!nm->has_self) return 0;
    while (sl && s[0] == '.') {
        s++;
        sl--;
    }
    while (sl && s[sl - 1] == '.') sl--;
    dot = (const char*)memchr(s, '.', sl);
    *suffix = dot ? dot + 1 : s;
    return dot ? sl - (size_t)(dot + 1 - s) : sl;
}

size_t ts_netmap_magic_suffix(const ts_netmap* nm, char* out, size_t cap)
{
    const char* suffix;
    size_t len = self_suffix(nm, &suffix);

    if (cap == 0) return 0;
    if (len >= cap) len = 0;            /* cut, it would be another name: none */
    memcpy(out, suffix, len);
    out[len] = '\0';
    return len;
}

size_t ts_netmap_count(const ts_netmap* nm)
{
    return nm->n;
}

const ts_node* ts_netmap_at(const ts_netmap* nm, size_t i)
{
    return i < nm->n ? &nm->nodes[nm->by_id[i]] : NULL;
}

const ts_node* ts_netmap_find_id(const ts_netmap* nm, int64_t id)
{
    int s = slot_live(nm, id);

    return s >= 0 ? &nm->nodes[s] : NULL;
}

const ts_node* ts_netmap_find_key(const ts_netmap* nm, const uint8_t key[32])
{
    size_t lo = 0, hi = nm->n_keyed;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (memcmp(nm->nodes[nm->by_key[mid]].key.b, key, WG_KEY_LEN) < 0) lo = mid + 1;
        else hi = mid;
    }
    if (lo < nm->n_keyed && memcmp(nm->nodes[nm->by_key[lo]].key.b, key, WG_KEY_LEN) == 0)
        return &nm->nodes[nm->by_key[lo]];
    return NULL;
}

size_t ts_netmap_online(const ts_netmap* nm, const ts_node** out, size_t cap)
{
    size_t i, n = 0;

    for (i = 0; i < nm->n; i++) {
        const ts_node* x = &nm->nodes[nm->by_id[i]];
        if (ts_node_online(x) != 1) continue;
        if (n < cap) out[n] = x;
        n++;
    }
    return n;
}

const char* ts_node_name(const ts_netmap* nm, const ts_node* n)
{
    if (n == &nm->self) return nm->self_name;
    return (const char*)nm->arena + n->blob +
           (n->n_addrs + ((n->flags & TS_NODE_ALLOWED_ADDRS) ? 0 : n->n_allowed)) * PFX;
}

const wg_prefix* ts_node_addrs(const ts_netmap* nm, const ts_node* n)
{
    if (n == &nm->self) return nm->self_addrs;
    return (const wg_prefix*)(const void*)(nm->arena + n->blob);
}

const wg_prefix* ts_node_allowed(const ts_netmap* nm, const ts_node* n)
{
    if (n->flags & TS_NODE_ALLOWED_ADDRS) return ts_node_addrs(nm, n);
    if (n == &nm->self) return nm->self_allowed;
    return (const wg_prefix*)(const void*)(nm->arena + n->blob + n->n_addrs * PFX);
}

int ts_node_online(const ts_node* n)
{
    if (!(n->flags & TS_NODE_ONLINE_KNOWN)) return -1;
    return (n->flags & TS_NODE_ONLINE) ? 1 : 0;
}

/* expiryManager.flagExpiredPeers: before this, a clock is not to be trusted (2023-01-10). */
#define EXPIRY_EPOCH    1673373066LL

int ts_node_expired(const ts_node* n, ts_time now)
{
    if (n->flags & TS_NODE_EXPIRED) return 1;
    if (ts_time_is_zero(n->key_expiry) || now.sec < EXPIRY_EPOCH) return 0;
    return ts_time_cmp(n->key_expiry, now) <= 0;
}

/* InitDisplayNames with dnsname.TrimSuffix and netmap.MagicDNSSuffixOfNodeName. */
size_t ts_node_display_name(const ts_netmap* nm, const ts_node* n, char* out, size_t cap)
{
    const char* name = ts_node_name(nm, n);
    const char* suffix;
    size_t len = n->name_len, slen = self_suffix(nm, &suffix);

    if (cap == 0) return 0;
    if (len && name[len - 1] == '.') len--;
    /* dnsname.HasSuffix: the name minus the suffix is not empty and ends with a dot */
    if (slen && len > slen && memcmp(name + len - slen, suffix, slen) == 0 && name[len - slen - 1] == '.')
        len -= slen + 1;
    if (len >= cap) len = cap - 1;
    memcpy(out, name, len);
    out[len] = '\0';
    return len;
}

/* --------------------------------------------------------------------- routing */

static int pfx_single(const wg_prefix* p)
{
    return (p->family == 4 && p->cidr == 32) || (p->family == 6 && p->cidr == 128);
}

/* tsaddr.IsTailscaleIP: 100.64.0.0/10 without ChromeOS's 100.115.92.0/23, fd7a:115c:a1e0::/48;
 * an IPv4-mapped address as its IPv4. */
static int is_tailscale_ip(int family, const uint8_t* a)
{
    static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    static const uint8_t ula[6] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0 };

    if (family == 6) {
        if (memcmp(a, mapped, 12) == 0) return is_tailscale_ip(4, a + 12);
        return memcmp(a, ula, 6) == 0;
    }
    if (a[0] != 100 || (a[1] & 0xc0) != 0x40) return 0;
    return !(a[1] == 115 && (a[2] & 0xfe) == 92);
}

static int pfx_contains(const wg_prefix* p, int family, const uint8_t* addr)
{
    unsigned bits = p->cidr, i;

    if (p->family != family) return 0;
    for (i = 0; i < bits / 8; i++)
        if (p->addr[i] != addr[i]) return 0;
    if (bits % 8) {
        uint8_t mask = (uint8_t)(0xff << (8 - bits % 8));
        if ((p->addr[i] ^ addr[i]) & mask) return 0;
    }
    return 1;
}

static int pfx_same_net(const wg_prefix* a, const wg_prefix* b)
{
    return a->family == b->family && a->cidr == b->cidr && pfx_contains(a, b->family, b->addr);
}

static void pfx_mask(wg_prefix* p)
{
    unsigned i, len = p->family == 4 ? 4 : 16;

    for (i = 0; i < len; i++) {
        unsigned have = p->cidr > i * 8 ? p->cidr - i * 8 : 0;
        if (have >= 8) continue;
        p->addr[i] &= (uint8_t)(0xff << (8 - have));
    }
}

/* tsaddr.IsExitRoute: exactly 0.0.0.0/0 or ::/0. */
static int pfx_exit(const wg_prefix* p)
{
    static const uint8_t zero[16];
    return (p->family == 4 || p->family == 6) && p->cidr == 0 && memcmp(p->addr, zero, 16) == 0;
}

/* routemanager.peerViewOf: a peer we cannot reach contributes no prefixes. */
static int routable(const ts_node* n, ts_time now)
{
    if (ts_node_expired(n, now)) return 0;
    if (key_zero(&n->disco) && n->home_derp == 0 && !(n->flags & TS_NODE_WG_ONLY)) return 0;
    return 1;
}

/* The self-or-route split of peerViewOf: a single Tailscale IP, or one of its Addresses. */
static int pfx_self(const ts_netmap* nm, const ts_node* n, const wg_prefix* p)
{
    const wg_prefix* a = ts_node_addrs(nm, n);
    size_t i;

    if (pfx_single(p) && is_tailscale_ip(p->family, p->addr)) return 1;
    for (i = 0; i < n->n_addrs; i++)
        if (memcmp(&a[i], p, PFX) == 0) return 1;
    return 0;
}

/* RouteManager.eligible. */
static int eligible(const ts_netmap* nm, const ts_node* n, const wg_prefix* p, unsigned flags, int64_t exit_node)
{
    if (p->family != 4 && p->family != 6) return 0;
    if (pfx_self(nm, n, p)) return 1;
    if (pfx_exit(p)) return exit_node != 0 && n->id == exit_node;
    return (flags & TS_ROUTE_SUBNETS) != 0;
}

const ts_node* ts_netmap_route(const ts_netmap* nm, int family, const uint8_t* addr, unsigned flags,
                               int64_t exit_node, ts_time now)
{
    const ts_node* best = NULL;
    int best_bits = -1;
    size_t i, j;

    for (i = 0; i < nm->n; i++) {
        const ts_node* x = &nm->nodes[nm->by_id[i]];
        const wg_prefix* a;
        if (x->state != S_LIVE || !routable(x, now)) continue;
        a = ts_node_allowed(nm, x);
        for (j = 0; j < x->n_allowed; j++) {
            /* ascending IDs: on the same prefix the first one found keeps it */
            if ((int)a[j].cidr <= best_bits || !pfx_contains(&a[j], family, addr) ||
                !eligible(nm, x, &a[j], flags, exit_node))
                continue;
            best = x;
            best_bits = a[j].cidr;
        }
    }
    return best;
}

/* Whether a peer with a lower ID than `n` has prefix p eligible too (desiredFor: it wins it). */
static int taken_below(const ts_netmap* nm, const ts_node* n, const wg_prefix* p, unsigned flags,
                       int64_t exit_node, ts_time now, int self_too)
{
    size_t i, j;

    for (i = 0; i < nm->n; i++) {
        const ts_node* x = &nm->nodes[nm->by_id[i]];
        const wg_prefix* a;
        if (x->id >= n->id) break;
        if (x->state != S_LIVE || !routable(x, now)) continue;
        a = ts_node_allowed(nm, x);
        for (j = 0; j < x->n_allowed; j++)
            if (pfx_same_net(&a[j], p) && eligible(nm, x, &a[j], flags, exit_node) &&
                (self_too || !pfx_self(nm, x, &a[j])))
                return 1;
    }
    return 0;
}

/* Whether a[j] repeats an earlier prefix of n's own list that counts already. */
static int repeated(const ts_netmap* nm, const ts_node* n, const wg_prefix* a, size_t j, unsigned flags,
                    int64_t exit_node, int self_too)
{
    size_t i;

    for (i = 0; i < j; i++)
        if (pfx_same_net(&a[i], &a[j]) && eligible(nm, n, &a[i], flags, exit_node) &&
            (self_too || !pfx_self(nm, n, &a[i])))
            return 1;
    return 0;
}

size_t ts_netmap_node_routes(const ts_netmap* nm, const ts_node* n, unsigned flags, int64_t exit_node,
                             ts_time now, wg_prefix* out, size_t cap)
{
    const wg_prefix* a;
    size_t j, count = 0;

    if (!routable(n, now)) return 0;
    a = ts_node_allowed(nm, n);
    for (j = 0; j < n->n_allowed; j++) {
        if (!eligible(nm, n, &a[j], flags, exit_node) || repeated(nm, n, a, j, flags, exit_node, 1) ||
            taken_below(nm, n, &a[j], flags, exit_node, now, 1))
            continue;
        if (count < cap) out[count] = a[j];
        count++;
    }
    return count;
}

size_t ts_netmap_os_routes(const ts_netmap* nm, unsigned flags, int64_t exit_node, ts_time now,
                           wg_prefix* out, size_t cap)
{
    size_t i, j, count = 0;

    for (i = 0; i < nm->n; i++) {
        const ts_node* x = &nm->nodes[nm->by_id[i]];
        const wg_prefix* a;
        if (x->state != S_LIVE || !routable(x, now)) continue;
        a = ts_node_allowed(nm, x);
        for (j = 0; j < x->n_allowed; j++) {
            if (!eligible(nm, x, &a[j], flags, exit_node) || pfx_self(nm, x, &a[j]) ||
                repeated(nm, x, a, j, flags, exit_node, 0) || taken_below(nm, x, &a[j], flags, exit_node, now, 0))
                continue;
            if (count < cap) {
                out[count] = a[j];
                pfx_mask(&out[count]);
            }
            count++;
        }
    }
    return count;
}

/* --------------------------------------------------------------------- the DERP map, read */

const ts_derpmap_region* ts_derpmap_find(const ts_netmap* nm, int64_t id)
{
    size_t lo = 0, hi = nm->derp.n_regions;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (nm->derp.regions[mid].id < id) lo = mid + 1;
        else hi = mid;
    }
    return lo < nm->derp.n_regions && nm->derp.regions[lo].id == id ? &nm->derp.regions[lo] : NULL;
}

const ts_derpmap_node* ts_derpmap_nodes(const ts_netmap* nm, const ts_derpmap_region* r)
{
    return &nm->derp.nodes[r->first];
}

const char* ts_derpmap_str(const ts_netmap* nm, uint16_t off)
{
    return off < nm->derp.str_used ? nm->derp.str + off : "";
}

uint16_t ts_derpmap_port(const ts_derpmap_node* n)
{
    if (n->derp_port == 0) return 443;
    if (n->derp_port < 0 || n->derp_port > 65535) return 0;
    return (uint16_t)n->derp_port;
}

size_t ts_derpmap_home_candidates(const ts_netmap* nm, int64_t current, int64_t* out, size_t cap)
{
    size_t i, j, count = 0;

    for (i = 0; i < nm->derp.n_regions; i++) {
        const ts_derpmap_region* r = &nm->derp.regions[i];
        const ts_derpmap_node* nodes = ts_derpmap_nodes(nm, r);
        int derp = 0;
        if (r->no_measure_no_home || (r->avoid && r->id != current)) continue;
        for (j = 0; j < r->n_nodes; j++)
            if (!nodes[j].stun_only) derp = 1;
        if (!derp) continue;
        if (count < cap) out[count] = r->id;
        count++;
    }
    return count;
}

#define MS_NS           1000000ULL
#define SCALED_MAX      (1ULL << 62)

int64_t ts_derpmap_pick_home(const ts_netmap* nm, const int64_t* region, const uint64_t* latency_ns,
                             size_t n, int64_t current, uint64_t current_heard_ns)
{
    const ts_derpmap_region* cur = current ? ts_derpmap_find(nm, current) : NULL;
    int64_t best = 0, cur_lat = 0, best_lat = 0;
    size_t i, j;

    for (i = 0; i < n; i++) {
        const ts_derpmap_region* r;
        uint64_t lat = latency_ns[i];
        int64_t d;
        if (lat == 0) continue;
        r = ts_derpmap_find(nm, region[i]);
        if (!r || r->no_measure_no_home) continue;
        for (j = 0; j < nm->derp.n_scores; j++) {
            if (nm->derp.scores[j].region != r->id || !(nm->derp.scores[j].score > 0)) continue;
            {
                double scaled = (double)lat * nm->derp.scores[j].score;
                lat = scaled >= (double)SCALED_MAX ? SCALED_MAX : (uint64_t)scaled;
            }
        }
        if (lat > SCALED_MAX) lat = SCALED_MAX;
        d = (int64_t)lat;
        if (r->id == current) cur_lat = d;
        if (best == 0 || d < best_lat || (d == best_lat && r->id < best)) {
            best = r->id;
            best_lat = d;
        }
    }
    /* A home that is not in the map any more, or never to be home, is given up. */
    if (!cur || cur->no_measure_no_home) return best;
    if (best != current && (cur_lat != 0 || current_heard_ns <= 8000 * MS_NS)) {
        /* stickiness: an old home still reachable stays unless the new one is clearly better */
        if (cur_lat - best_lat < (int64_t)(10 * MS_NS) || best_lat > cur_lat / 3 * 2) best = current;
    }
    if (best == 0 && current_heard_ns <= 120000 * MS_NS) best = current;
    return best;
}

/* --------------------------------------------------------------------- /key and register */

int ts_server_keys_parse(const ts_json* d, ts_server_keys* out, ts_netmap_err* err)
{
    static const char* const names[2] = { "legacyPublicKey", "publicKey" };
    ts_netmap_result res;
    uint32_t seen = 0;
    int k, set;

    memset(out, 0, sizeof(*out));
    memset(&res, 0, sizeof(res));
    if (!d || d->n < 1 || ts_json_type_of(d, 0) != TS_JSON_OBJECT) {
        *err = TS_NM_ERR_NOT_OBJECT;
        return 0;
    }
    for (k = ts_json_first(d, 0); k >= 0; k = ts_json_next(d, k)) {
        int f = field_of(d, k, names, 2);
        if (f < 0) continue;
        if (seen & (1u << f)) {
            *err = TS_NM_ERR_DUPLICATE;
            return 0;
        }
        seen |= 1u << f;
        if (!get_key(d, k + 1, "mkey:", f == 0 ? out->legacy_public_key.b : out->public_key.b, &set, &res)) {
            *err = res.err;
            return 0;
        }
    }
    if (key_zero(&out->public_key)) {
        *err = TS_NM_ERR_NO_NOISE_KEY;
        return 0;
    }
    *err = TS_NM_OK;
    return 1;
}

enum { RG_USER, RG_LOGIN, RG_EXPIRED, RG_AUTHORIZED, RG_URL, RG_NKS, RG_ERROR, RG_COUNT };
static const char* const reg_fields[RG_COUNT] = {
    "User", "Login", "NodeKeyExpired", "MachineAuthorized", "AuthURL", "NodeKeySignature", "Error"
};

/* A display text of the register answer: cut when longer than kept. */
static int reg_text(const ts_json* d, int v, char* out, size_t cap, ts_register* r, ts_netmap_result* res)
{
    size_t len;
    int x;

    out[0] = '\0';
    if (ts_json_is_null(d, v)) return 1;
    x = ts_json_str_cut(d, v, out, cap, &len);
    if (!x) return refuse(res, TS_NM_ERR_TYPE, d, v);
    if (x == 2) r->truncated = 1;
    return 1;                           /* a NUL inside just ends the text early */
}

int ts_register_parse(const ts_json* d, ts_register* out, ts_netmap_err* err)
{
    static const char* const user_fields[1] = { "ID" };
    static const char* const login_fields[2] = { "LoginName", "DisplayName" };
    ts_netmap_result res;
    uint32_t seen = 0;
    int k, set, val;

    memset(out, 0, sizeof(*out));
    memset(&res, 0, sizeof(res));
    *err = TS_NM_OK;
    if (!d || d->n < 1 || ts_json_type_of(d, 0) != TS_JSON_OBJECT) {
        *err = TS_NM_ERR_NOT_OBJECT;
        return 0;
    }
    for (k = ts_json_first(d, 0); k >= 0; k = ts_json_next(d, k)) {
        int f = field_of(d, k, reg_fields, RG_COUNT), v = k + 1, ok = 1;
        ts_json_type ty = ts_json_type_of(d, v);

        if (f < 0) continue;
        if (seen & (1u << f)) {
            *err = TS_NM_ERR_DUPLICATE;
            return 0;
        }
        seen |= 1u << f;
        switch (f) {
        case RG_USER:
        case RG_LOGIN: {
            uint32_t sub = 0;
            int j;
            if (ty == TS_JSON_NULL) break;
            if (ty != TS_JSON_OBJECT) {
                ok = refuse(&res, TS_NM_ERR_TYPE, d, v);
                break;
            }
            for (j = ts_json_first(d, v); ok && j >= 0; j = ts_json_next(d, j)) {
                int g = f == RG_USER ? field_of(d, j, user_fields, 1) : field_of(d, j, login_fields, 2);
                if (g < 0) continue;
                if (sub & (1u << g)) {
                    ok = refuse(&res, TS_NM_ERR_DUPLICATE, d, j);
                    break;
                }
                sub |= 1u << g;
                if (f == RG_USER) ok = get_i64(d, j + 1, &out->user_id, &res);
                else if (g == 0) ok = reg_text(d, j + 1, out->login_name, sizeof(out->login_name), out, &res);
                else ok = reg_text(d, j + 1, out->display_name, sizeof(out->display_name), out, &res);
            }
            break;
        }
        case RG_EXPIRED:
            ok = get_bool(d, v, &set, &val, &res);
            if (ok && set) out->node_key_expired = val;
            break;
        case RG_AUTHORIZED:
            ok = get_bool(d, v, &set, &val, &res);
            if (ok && set) out->machine_authorized = val;
            break;
        case RG_URL: {
            size_t len;
            if (ty == TS_JSON_NULL) break;
            if (ty != TS_JSON_STRING) {
                ok = refuse(&res, TS_NM_ERR_TYPE, d, v);
                break;
            }
            if (!ts_json_str(d, v, out->auth_url, sizeof(out->auth_url), &len)) {
                out->auth_url[0] = '\0';
                ok = refuse(&res, TS_NM_ERR_TOO_LONG, d, v);
            } else if (memchr(out->auth_url, '\0', len)) {
                out->auth_url[0] = '\0';
                ok = refuse(&res, TS_NM_ERR_VALUE, d, v);
            }
            break;
        }
        case RG_NKS:
            /* []byte: base64 text; we only need to know there is one */
            if (ty == TS_JSON_NULL) break;
            if (ty != TS_JSON_STRING) {
                ok = refuse(&res, TS_NM_ERR_TYPE, d, v);
                break;
            }
            out->node_key_signature = d->tok[v].end > d->tok[v].start;
            break;
        case RG_ERROR:
            ok = reg_text(d, v, out->error, sizeof(out->error), out, &res);
            break;
        }
        if (!ok) {
            *err = res.err;
            return 0;
        }
    }
    return 1;
}
