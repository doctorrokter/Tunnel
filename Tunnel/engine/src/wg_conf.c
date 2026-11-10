/*
 * wg_conf - see wg_conf.h. Where a file could be read two ways, it is read as wireguard-tools'
 * config.c and wg-quick read it; no code was taken from either.
 */

#include "wg_conf.h"
#include "wg_device.h"

#include <string.h>

/* --------------------------------------------------------------------- text spans */

typedef struct {
    const char* s;
    size_t      n;
} span;

static span mkspan(const char* s, size_t n)
{
    span x;
    x.s = s;
    x.n = n;
    return x;
}

static int is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

static span trim(span x)
{
    while (x.n && is_space(x.s[0])) {
        x.s++;
        x.n--;
    }
    while (x.n && is_space(x.s[x.n - 1])) x.n--;
    return x;
}

static char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

static int ieq(span x, const char* lit)
{
    size_t i, n = strlen(lit);

    if (x.n != n) return 0;
    for (i = 0; i < n; i++)
        if (lower(x.s[i]) != lower(lit[i])) return 0;
    return 1;
}

/* The next comma-separated item of `list`, trimmed (possibly empty); 0 when the list is used up. */
static int next_item(span* list, span* item)
{
    const char* comma;

    if (!list->n) return 0;
    comma = (const char*)memchr(list->s, ',', list->n);
    if (comma) {
        *item = mkspan(list->s, (size_t)(comma - list->s));
        list->n -= item->n + 1;
        list->s = comma + 1;
    } else {
        *item = *list;
        list->n = 0;
    }
    *item = trim(*item);
    return 1;
}

/* A plain decimal number no larger than `max`. */
static int parse_uint(span x, uint32_t max, uint32_t* out)
{
    uint64_t v = 0;
    size_t i;

    if (!x.n || x.n > 10) return 0;
    for (i = 0; i < x.n; i++) {
        if (x.s[i] < '0' || x.s[i] > '9') return 0;
        v = v * 10 + (uint64_t)(x.s[i] - '0');
    }
    if (v > max) return 0;
    *out = (uint32_t)v;
    return 1;
}

/* --------------------------------------------------------------------- keys */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int wg_key_from_base64(wg_key* k, const char* s, size_t len)
{
    uint8_t out[WG_KEY_LEN];
    uint32_t acc = 0;
    size_t i, n = 0;
    int bits = 0, v, ok = 0;

    /* 32 bytes are 43 characters and one '='; the 2 bits left over must be zero, as wg demands,
     * so every key has exactly one spelling. */
    if (len != 44 || s[43] != '=') return 0;
    for (i = 0; i < 43; i++) {
        v = b64_value(s[i]);
        if (v < 0) goto out;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[n++] = (uint8_t)(acc >> bits);
        }
    }
    if (n != WG_KEY_LEN || (acc & ((1u << bits) - 1))) goto out;
    memcpy(k->b, out, WG_KEY_LEN);
    ok = 1;
out:
    wg_wipe(out, sizeof(out));
    wg_wipe(&acc, sizeof(acc));
    return ok;
}

void wg_key_to_base64(char out[45], const wg_key* k)
{
    uint32_t acc = 0;
    size_t i, o = 0;
    int bits = 0;

    for (i = 0; i < WG_KEY_LEN; i++) {
        acc = (acc << 8) | k->b[i];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out[o++] = B64[(acc >> bits) & 63];
        }
    }
    out[o++] = B64[(acc << (6 - bits)) & 63];       /* 256 bits: 4 left over */
    out[o++] = '=';
    out[o] = 0;
    wg_wipe(&acc, sizeof(acc));
}

/* --------------------------------------------------------------------- addresses */

/* Dotted quad; no leading zeros (they read as octal to some parsers - refuse the ambiguity). */
static int parse_v4(span x, uint8_t out[4])
{
    size_t i = 0, digits;
    uint32_t v;
    int part;

    for (part = 0; part < 4; part++) {
        v = 0;
        digits = 0;
        while (i < x.n && x.s[i] >= '0' && x.s[i] <= '9') {
            if (digits && v == 0) return 0;
            v = v * 10 + (uint32_t)(x.s[i] - '0');
            digits++;
            i++;
            if (digits > 3 || v > 255) return 0;
        }
        if (!digits) return 0;
        out[part] = (uint8_t)v;
        if (part < 3) {
            if (i >= x.n || x.s[i] != '.') return 0;
            i++;
        }
    }
    return i == x.n;
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* RFC 4291 text: up to 8 groups of 1-4 hex digits, one "::", optionally a dotted quad at the end. */
static int parse_v6(span x, uint8_t out[16])
{
    uint16_t w[8];
    int nw = 0, gap = -1, k, h, tail;
    size_t i = 0, j;
    uint32_t v;
    uint8_t q[4];
    span part;

    if (x.n >= 2 && x.s[0] == ':' && x.s[1] == ':') {
        gap = 0;
        i = 2;
    } else if (x.n && x.s[0] == ':') {
        return 0;
    }
    while (i < x.n) {
        for (j = i; j < x.n && x.s[j] != ':'; j++) {}
        part = mkspan(x.s + i, j - i);
        if (memchr(part.s, '.', part.n)) {
            if (j != x.n || nw > 6 || !parse_v4(part, q)) return 0;
            w[nw++] = (uint16_t)(q[0] << 8 | q[1]);
            w[nw++] = (uint16_t)(q[2] << 8 | q[3]);
            break;
        }
        if (!part.n || part.n > 4 || nw == 8) return 0;
        v = 0;
        for (k = 0; k < (int)part.n; k++) {
            h = hex_value(part.s[k]);
            if (h < 0) return 0;
            v = v << 4 | (uint32_t)h;
        }
        w[nw++] = (uint16_t)v;
        if (j == x.n) break;
        if (j + 1 < x.n && x.s[j + 1] == ':') {
            if (gap >= 0) return 0;                 /* a second "::" */
            gap = nw;
            i = j + 2;
        } else {
            i = j + 1;
            if (i == x.n) return 0;                 /* a lone colon at the end */
        }
    }
    if (gap < 0 ? nw != 8 : nw > 7) return 0;

    memset(out, 0, 16);
    for (k = 0; k < (gap < 0 ? nw : gap); k++) {
        out[2 * k] = (uint8_t)(w[k] >> 8);
        out[2 * k + 1] = (uint8_t)w[k];
    }
    if (gap >= 0) {
        tail = nw - gap;
        for (k = 0; k < tail; k++) {
            out[2 * (8 - tail + k)] = (uint8_t)(w[gap + k] >> 8);
            out[2 * (8 - tail + k) + 1] = (uint8_t)w[gap + k];
        }
    }
    return 1;
}

int wg_addr_parse(const char* s, size_t len, int* family, uint8_t addr[16])
{
    span x = mkspan(s, len);

    memset(addr, 0, 16);
    if (len && memchr(s, ':', len)) {
        if (!parse_v6(x, addr)) return 0;
        *family = 6;
        return 1;
    }
    if (!parse_v4(x, addr)) return 0;
    *family = 4;
    return 1;
}

int wg_prefix_parse(const char* s, size_t len, wg_prefix* p)
{
    const char* slash = len ? (const char*)memchr(s, '/', len) : NULL;
    size_t alen = slash ? (size_t)(slash - s) : len;
    uint32_t cidr;
    int family;

    if (!wg_addr_parse(s, alen, &family, p->addr)) return 0;
    p->family = (uint8_t)family;
    if (!slash) {
        p->cidr = (uint8_t)(family == 4 ? 32 : 128);
        return 1;
    }
    if (!parse_uint(mkspan(slash + 1, len - alen - 1), family == 4 ? 32 : 128, &cidr)) return 0;
    p->cidr = (uint8_t)cidr;
    return 1;
}

/* host:port, or [host]:port - the only way an IPv6 address can carry a port. */
static int parse_endpoint(span v, wg_conf_peer* p)
{
    span host, port;
    const char* close;
    size_t i;
    uint32_t pv;
    int family;
    uint8_t a[16];

    if (v.n && v.s[0] == '[') {
        close = (const char*)memchr(v.s, ']', v.n);
        if (!close || (size_t)(close - v.s) + 2 > v.n || close[1] != ':') return 0;
        host = mkspan(v.s + 1, (size_t)(close - v.s) - 1);
        port = mkspan(close + 2, v.n - (size_t)(close - v.s) - 2);
    } else {
        for (i = v.n; i > 0 && v.s[i - 1] != ':'; i--) {}
        if (!i) return 0;
        host = mkspan(v.s, i - 1);
        port = mkspan(v.s + i, v.n - i);
        if (memchr(host.s, ':', host.n)) return 0;
    }
    if (!host.n || host.n >= WG_CONF_TEXT_MAX || !parse_uint(port, 65535, &pv) || !pv) return 0;

    memcpy(p->endpoint_host, host.s, host.n);
    p->endpoint_host[host.n] = 0;
    p->endpoint_port = (uint16_t)pv;
    memset(&p->endpoint, 0, sizeof(p->endpoint));
    if (wg_addr_parse(host.s, host.n, &family, a)) {
        p->endpoint.family = (uint8_t)family;
        memcpy(p->endpoint.addr, a, 16);
        p->endpoint.port = (uint16_t)pv;
    }
    return 1;
}

/* --------------------------------------------------------------------- the file */

static int fail(wg_conf* c, int line, const char* what)
{
    size_t n = strlen(what);

    if (n >= sizeof(c->error)) n = sizeof(c->error) - 1;
    memcpy(c->error, what, n);
    c->error[n] = 0;
    c->error_line = line;
    return 0;
}

static void warn(wg_conf* c, int line, span key)
{
    static const char head[] = "skipped: ";
    size_t n = key.n;

    if (c->warnings++) return;
    if (n > sizeof(c->warning) - sizeof(head)) n = sizeof(c->warning) - sizeof(head);
    memcpy(c->warning, head, sizeof(head) - 1);
    memcpy(c->warning + sizeof(head) - 1, key.s, n);
    c->warning[sizeof(head) - 1 + n] = 0;
    c->warning_line = line;
}

static int add_prefixes(wg_conf* c, int line, span list, wg_prefix* arr, size_t* n, size_t cap,
                        const char* bad, const char* full)
{
    span item;

    while (next_item(&list, &item)) {
        if (!item.n) continue;                      /* "a, , b" or a trailing comma */
        if (*n == cap) return fail(c, line, full);
        if (!wg_prefix_parse(item.s, item.n, &arr[*n])) return fail(c, line, bad);
        (*n)++;
    }
    return 1;
}

static int add_dns(wg_conf* c, int line, span list)
{
    span item;
    size_t cur;
    int family;
    uint8_t a[16];

    while (next_item(&list, &item)) {
        if (!item.n) continue;
        if (wg_addr_parse(item.s, item.n, &family, a)) {
            if (c->n_dns == WG_CONF_MAX_DNS) return fail(c, line, "too many DNS servers");
            c->dns[c->n_dns].family = (uint8_t)family;
            c->dns[c->n_dns].cidr = (uint8_t)(family == 4 ? 32 : 128);
            memcpy(c->dns[c->n_dns].addr, a, 16);
            c->n_dns++;
            continue;
        }
        /* wg-quick takes whatever is not an address for a search domain */
        cur = strlen(c->dns_search);
        if (cur + 1 + item.n >= WG_CONF_TEXT_MAX) return fail(c, line, "too many DNS search domains");
        if (cur) c->dns_search[cur++] = ',';
        memcpy(c->dns_search + cur, item.s, item.n);
        c->dns_search[cur + item.n] = 0;
    }
    return 1;
}

/* "a" or "a-b" (spaces around the dash allowed), both at most `max`, a <= b; "off" is 0..0. */
static int parse_range(span v, uint32_t max, wg_range* r)
{
    const char* dash = v.n ? (const char*)memchr(v.s, '-', v.n) : NULL;
    uint32_t lo, hi;

    if (ieq(v, "off")) {
        r->lo = r->hi = 0;
        return 1;
    }
    if (!dash) {
        if (!parse_uint(v, max, &lo)) return 0;
        r->lo = r->hi = lo;
        return 1;
    }
    if (!parse_uint(trim(mkspan(v.s, (size_t)(dash - v.s))), max, &lo)) return 0;
    if (!parse_uint(trim(mkspan(dash + 1, v.n - (size_t)(dash - v.s) - 1)), max, &hi)) return 0;
    if (hi < lo) return 0;
    r->lo = lo;
    r->hi = hi;
    return 1;
}

/* awg's booleans (on/off, or a number: nonzero is on), and true/false as UAPI writes them. */
static int parse_bool(span v, int* out)
{
    uint32_t n;

    if (ieq(v, "on") || ieq(v, "true")) *out = 1;
    else if (ieq(v, "off") || ieq(v, "false")) *out = 0;
    else if (parse_uint(v, 0xffffffffu, &n)) *out = n != 0;
    else return 0;
    return 1;
}

/* "S1".."S4", "H1".."H4", "I1".."I5": the digit, or 0 */
static int indexed(span k, char letter, int max)
{
    if (k.n != 2 || lower(k.s[0]) != letter || k.s[1] < '1' || k.s[1] > '0' + max) return 0;
    return k.s[1] - '0';
}

/* AmneziaWG 3.x's timings: the key, and where it goes. */
static wg_range* timing_key(wg_conf* c, span k)
{
    if (ieq(k, "RekeyAfterTime"))       return &c->timing.rekey_after_time;
    if (ieq(k, "RekeyTimeout"))         return &c->timing.rekey_timeout;
    if (ieq(k, "RejectAfterTime"))      return &c->timing.reject_after_time;
    if (ieq(k, "KeepaliveTimeout"))     return &c->timing.keepalive_timeout;
    if (ieq(k, "MaxHandshakeAttempts")) return &c->timing.max_handshake_attempts;
    return NULL;
}

static int interface_key(wg_conf* c, int line, span k, span v)
{
    wg_awg_chain chain;                 /* only to check an I-packet's syntax, on its line */
    const char* why = NULL;
    wg_range* r;
    wg_key key;
    uint32_t n;
    int i, b;

    if (ieq(k, "PrivateKey")) {
        if (!wg_key_from_base64(&c->private_key, v.s, v.n))
            return fail(c, line, "PrivateKey is not a key (44 characters of base64)");
        c->has_private_key = 1;
        return 1;
    }
    if (ieq(k, "Address"))
        return add_prefixes(c, line, v, c->address, &c->n_address, WG_CONF_MAX_ADDRESS,
                            "Address is not an address", "too many Address entries");
    if (ieq(k, "DNS")) return add_dns(c, line, v);
    if (ieq(k, "MTU")) {
        if (!parse_uint(v, 65535, &n) || n < 576) return fail(c, line, "MTU must be 576 to 65535");
        c->mtu = (uint16_t)n;
        return 1;
    }
    if (ieq(k, "ListenPort")) {
        if (!parse_uint(v, 65535, &n)) return fail(c, line, "ListenPort must be 0 to 65535");
        c->listen_port = (uint16_t)n;
        return 1;
    }

    /* AmneziaWG: every key below marks the file as one */
    if (ieq(k, "Jc")) {
        if (!parse_uint(v, 128, &n)) return fail(c, line, "Jc must be 0 to 128");
        c->jc = (uint16_t)n;
    } else if (ieq(k, "Jmin") || ieq(k, "Jmax")) {
        if (!parse_uint(v, 65535, &n)) return fail(c, line, "Jmin and Jmax must be 0 to 65535");
        if (ieq(k, "Jmin")) c->jmin = (uint16_t)n;
        else                c->jmax = (uint16_t)n;
    } else if ((i = indexed(k, 's', 4)) != 0) {
        if (!parse_uint(v, WG_AWG_MAX_PREFIX, &n)) return fail(c, line, "S1-S4 must be 0 to 1024");
        c->s[i] = (uint16_t)n;
    } else if ((i = indexed(k, 'h', 4)) != 0) {
        if (ieq(v, "off") || !parse_range(v, 0xffffffffu, &c->h[i]))
            return fail(c, line, "H1-H4 must be a number or a range lo-hi");
    } else if ((i = indexed(k, 'i', 5)) != 0) {
        if (!wg_awg_parse_chain(&chain, v.s, v.n, &why)) return fail(c, line, why);
        c->i[i] = v.s;
        c->i_len[i] = v.n;
    } else if (ieq(k, "HeaderProtectionKey")) {
        if (!wg_key_from_base64(&key, v.s, v.n))
            return fail(c, line, "HeaderProtectionKey is not a key (44 characters of base64)");
        memcpy(c->hp_key, key.b, WG_KEY_LEN);
        wg_wipe(&key, sizeof(key));
    } else if (ieq(k, "ContentPaddingAddition")) {
        if (!parse_range(v, 65535, &c->content_padding))
            return fail(c, line, "ContentPaddingAddition must be off, a number or a range lo-hi, 0 to 65535");
    } else if (ieq(k, "RandomTrailers") || ieq(k, "DisableCookies")) {
        if (!parse_bool(v, &b)) return fail(c, line, "RandomTrailers and DisableCookies must be on or off");
        if (ieq(k, "RandomTrailers")) c->random_trailers = b;
        else                          c->disable_cookies = b;
    } else if ((r = timing_key(c, k)) != NULL) {
        if (!parse_range(v, 65535, r))
            return fail(c, line, "a timing must be off, a number or a range lo-hi, 0 to 65535");
    } else {
        /* wg-quick's scripts and routing knobs, and whatever is newer than this parser */
        warn(c, line, k);
        return 1;
    }
    c->awg = 1;
    return 1;
}

static int peer_key(wg_conf* c, wg_conf_peer* p, int line, span k, span v)
{
    wg_key psk;
    size_t before;
    int b;

    if (ieq(k, "PublicKey")) {
        if (!wg_key_from_base64(&p->public_key, v.s, v.n))
            return fail(c, line, "PublicKey is not a key (44 characters of base64)");
        p->has_public_key = 1;
        return 1;
    }
    if (ieq(k, "PresharedKey")) {
        if (!wg_key_from_base64(&psk, v.s, v.n))
            return fail(c, line, "PresharedKey is not a key (44 characters of base64)");
        memcpy(p->psk, psk.b, WG_KEY_LEN);
        wg_wipe(&psk, sizeof(psk));
        p->has_psk = 1;
        return 1;
    }
    if (ieq(k, "AllowedIPs")) {
        before = c->n_allowed;
        if (!add_prefixes(c, line, v, c->allowed, &c->n_allowed, c->cap_allowed,
                          "AllowedIPs entry is not an address/prefix", "too many AllowedIPs"))
            return 0;
        p->allowed_count += c->n_allowed - before;
        return 1;
    }
    if (ieq(k, "Endpoint")) {
        if (!parse_endpoint(v, p)) return fail(c, line, "Endpoint must be host:port or [IPv6]:port");
        return 1;
    }
    if (ieq(k, "PersistentKeepalive")) {
        if (!parse_range(v, 65535, &p->persistent_keepalive))
            return fail(c, line, "PersistentKeepalive must be off, 0 to 65535, or a range lo-hi");
        return 1;
    }
    if (ieq(k, "AdvancedSecurity")) {
        if (!parse_bool(v, &b)) return fail(c, line, "AdvancedSecurity must be on or off");
        return 1;
    }
    warn(c, line, k);
    return 1;
}

void wg_conf_init(wg_conf* c, wg_conf_peer* peers, size_t cap_peers, wg_prefix* allowed,
                  size_t cap_allowed)
{
    int t;

    memset(c, 0, sizeof(*c));
    c->peers = peers;
    c->cap_peers = peers ? cap_peers : 0;
    c->allowed = allowed;
    c->cap_allowed = allowed ? cap_allowed : 0;
    for (t = 1; t <= 4; t++) c->h[t].lo = c->h[t].hi = (uint32_t)t;    /* awg's defaults */
}

int wg_conf_parse(wg_conf* c, const char* text, size_t len)
{
    enum { NONE, INTERFACE, PEER } section = NONE;
    wg_conf_peer* peer = NULL;
    wg_awg_params awg_check;            /* ~10 KB, for the final check only */
    const char* eq;
    const char* hash;
    size_t pos = 0, end, i;
    int line = 0, seen_interface = 0;
    span l, name;

    while (pos < len) {
        for (end = pos; end < len && text[end] != '\n'; end++) {}
        l = mkspan(text + pos, end - pos);
        pos = end + 1;
        line++;

        hash = (const char*)memchr(l.s, '#', l.n);
        if (hash) l.n = (size_t)(hash - l.s);
        l = trim(l);
        if (!l.n) continue;

        if (l.s[0] == '[') {
            if (l.s[l.n - 1] != ']') return fail(c, line, "a section header must be [Interface] or [Peer]");
            name = trim(mkspan(l.s + 1, l.n - 2));
            if (ieq(name, "Interface")) {
                if (seen_interface) return fail(c, line, "a second [Interface]");
                seen_interface = 1;
                section = INTERFACE;
            } else if (ieq(name, "Peer")) {
                if (c->n_peers == c->cap_peers) return fail(c, line, "too many peers");
                peer = &c->peers[c->n_peers++];
                memset(peer, 0, sizeof(*peer));
                peer->allowed_first = c->n_allowed;
                peer->line = line;
                section = PEER;
            } else {
                return fail(c, line, "unknown section: only [Interface] and [Peer]");
            }
            continue;
        }

        eq = (const char*)memchr(l.s, '=', l.n);
        if (!eq) return fail(c, line, "expected Key = Value");
        if (section == NONE) return fail(c, line, "a key before any section");
        name = trim(mkspan(l.s, (size_t)(eq - l.s)));
        l = trim(mkspan(eq + 1, l.n - (size_t)(eq - l.s) - 1));
        if (section == INTERFACE) {
            if (!interface_key(c, line, name, l)) return 0;
        } else if (!peer_key(c, peer, line, name, l)) {
            return 0;
        }
    }

    if (!seen_interface) return fail(c, 0, "no [Interface] section");
    if (!c->has_private_key) return fail(c, 0, "no PrivateKey in [Interface]");
    if (c->jmin > c->jmax && c->jmax) return fail(c, 0, "Jmin is larger than Jmax");
    for (i = 0; i < c->n_peers; i++)
        if (!c->peers[i].has_public_key) return fail(c, c->peers[i].line, "[Peer] without PublicKey");
    /* the rules that span keys (H1-H4 apart, S1-S4 with header protection...) */
    if (c->awg && !wg_conf_awg_params(c, &awg_check, c->error, sizeof(c->error))) {
        c->error_line = 0;
        return 0;
    }
    return 1;
}

/* --------------------------------------------------------------------- onto a device */

static int apply_fail(char* err, size_t errlen, const char* what)
{
    size_t n = strlen(what);

    if (err && errlen) {
        if (n >= errlen) n = errlen - 1;
        memcpy(err, what, n);
        err[n] = 0;
    }
    return 0;
}

int wg_conf_awg_params(const wg_conf* c, wg_awg_params* p, char* err, size_t errlen)
{
    const char* why = NULL;
    int t;

    wg_awg_params_default(p);
    p->jc = c->jc;
    p->jmin = c->jmin;
    p->jmax = c->jmax;
    for (t = 1; t <= 4; t++) {
        p->s[t] = c->s[t];
        p->h[t] = c->h[t];
    }
    for (t = 1; t <= 5; t++)
        if (c->i[t] && !wg_awg_parse_chain(&p->i[t], c->i[t], c->i_len[t], &why))
            return apply_fail(err, errlen, why);
    memcpy(p->hp_key, c->hp_key, WG_KEY_LEN);
    p->content_padding = c->content_padding;
    p->random_trailers = c->random_trailers;
    if (!wg_awg_check(p, &why)) return apply_fail(err, errlen, why);
    return 1;
}

/* A timing the file sets (not 0..0) over WireGuard's. */
static void set_timing(wg_range* to, wg_range from)
{
    if (from.lo || from.hi) *to = from;
}

int wg_conf_apply(const wg_conf* c, wg_device* d, wg_awg* awg, wg_peer* peers, uint8_t* stage,
                  size_t stage_each, uint64_t now_ns, char* err, size_t errlen)
{
    wg_awg_params params;               /* ~10 KB */
    wg_timing t;
    const wg_conf_peer* cp;
    const wg_prefix* a;
    wg_peer* p;
    size_t i, j;

    if (c->awg) {
        if (!wg_conf_awg_params(c, &params, err, errlen)) return 0;
        if (!wg_awg_is_plain(&params)) {
            if (!awg) return apply_fail(err, errlen, "AmneziaWG settings, and no AmneziaWG codec to apply them");
            wg_awg_attach(awg, &params, d);
        }
        d->disable_cookies = c->disable_cookies;
        t = d->timing;
        set_timing(&t.rekey_timeout, c->timing.rekey_timeout);
        set_timing(&t.keepalive_timeout, c->timing.keepalive_timeout);
        set_timing(&t.rekey_after_time, c->timing.rekey_after_time);
        set_timing(&t.reject_after_time, c->timing.reject_after_time);
        set_timing(&t.max_handshake_attempts, c->timing.max_handshake_attempts);
        wg_device_set_timing(d, &t);
    }
    if (!c->has_private_key || !wg_device_set_private_key(d, &c->private_key))
        return apply_fail(err, errlen, "no usable PrivateKey");
    if (c->mtu) d->mtu = c->mtu;

    for (i = 0; i < c->n_peers; i++) {
        cp = &c->peers[i];
        p = &peers[i];
        if (!wg_device_add_peer(d, p, &cp->public_key, stage ? stage + i * stage_each : NULL,
                                stage ? stage_each : 0))
            return apply_fail(err, errlen, "a peer is listed twice, or is this device itself");
        if (cp->has_psk) wg_peer_set_psk(p, cp->psk);
        for (j = 0; j < cp->allowed_count; j++) {
            a = &c->allowed[cp->allowed_first + j];
            if (!wg_peer_allow(p, a->family, a->addr, a->cidr))
                return apply_fail(err, errlen, "the AllowedIPs table is full");
        }
        if (cp->endpoint.family) wg_peer_set_endpoint(p, &cp->endpoint);
        if (cp->persistent_keepalive.hi)
            wg_peer_set_persistent_keepalive_range(p, cp->persistent_keepalive, now_ns);
    }
    return 1;
}
