/*
 * ts_profile - see ts_profile.h.
 */

#include "ts_profile.h"
#include "bt_proto.h"
#include "bt_resolve.h"
#include "wg_conf.h"

#include <stdio.h>
#include <string.h>

/* --------------------------------------------------------------------- small text checks */

static int lower(int c)
{
    return c >= 'A' && c <= 'Z' ? c + 32 : c;
}

static int starts_nocase(const char* s, size_t len, const char* prefix)
{
    size_t i, n = strlen(prefix);
    if (len < n) return 0;
    for (i = 0; i < n; i++)
        if (lower((unsigned char)s[i]) != prefix[i]) return 0;
    return 1;
}

/* Printable text for the screens: no control characters, UTF-8 passes through as it came. */
static int text_valid(const char* s, size_t len, size_t max)
{
    size_t i;
    if (len > max) return 0;
    for (i = 0; i < len; i++)
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] == 0x7f) return 0;
    return 1;
}

void ts_hex32(char out[65], const uint8_t in[32])
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < 32; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
    out[64] = '\0';
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = lower(c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int ts_unhex32(uint8_t out[32], const char* hex, size_t len)
{
    size_t i;
    if (len != 64) return 0;
    for (i = 0; i < 32; i++) {
        int h = hexval((unsigned char)hex[2 * i]), l = hexval((unsigned char)hex[2 * i + 1]);
        if (h < 0 || l < 0) return 0;
        out[i] = (uint8_t)(h << 4 | l);
    }
    return 1;
}

/* --------------------------------------------------------------------- URL and auth key */

int ts_url_parse(const char* url, size_t len, ts_url* out)
{
    const char* p;
    const char* end = url + len;
    const char* host;
    size_t hlen;
    unsigned long port = 0;
    int family;
    uint8_t addr[16];

    memset(out, 0, sizeof(*out));
    if (!url || !len || len > TS_URL_MAX || memchr(url, '\0', len)) return 0;
    if (starts_nocase(url, len, "https://")) {
        out->tls = 1;
        p = url + 8;
    } else if (starts_nocase(url, len, "http://")) {
        p = url + 7;
    } else {
        return 0;
    }
    if (end > p && end[-1] == '/') end--;           /* one trailing slash */

    if (p < end && *p == '[') {                     /* [IPv6] */
        const char* close = memchr(p, ']', (size_t)(end - p));
        if (!close) return 0;
        host = p + 1;
        hlen = (size_t)(close - host);
        p = close + 1;
        if (!hlen || hlen > TS_HOST_MAX || !wg_addr_parse(host, hlen, &family, addr) || family != 6) return 0;
        out->literal = 1;
    } else {
        host = p;
        while (p < end && *p != ':') p++;
        hlen = (size_t)(p - host);
        if (!hlen || hlen > TS_HOST_MAX) return 0;
        if (wg_addr_parse(host, hlen, &family, addr)) {
            if (family != 4) return 0;              /* IPv6 only in brackets */
            out->literal = 1;
        }
    }
    memcpy(out->host, host, hlen);
    out->host[hlen] = '\0';
    if (!out->literal && !bt_dns_name_valid(out->host)) return 0;

    if (p < end) {
        if (*p != ':' || ++p == end) return 0;
        while (p < end) {
            if (*p < '0' || *p > '9') return 0;
            port = port * 10 + (unsigned long)(*p - '0');
            if (port > 65535) return 0;
            p++;
        }
        if (!port) return 0;
    }
    out->port = (uint16_t)(port ? port : (out->tls ? 443 : 80));
    return 1;
}

int ts_authkey_valid(const char* key, size_t len)
{
    size_t i;
    if (!key || !len || len > TS_AUTHKEY_MAX) return 0;
    for (i = 0; i < len; i++)
        if ((unsigned char)key[i] <= ' ' || (unsigned char)key[i] >= 0x7f) return 0;
    return 1;
}

int ts_hostname_valid(const char* name, size_t len)
{
    size_t i;
    if (!name || !len || len > TS_HOSTNAME_MAX || name[0] == '-' || name[len - 1] == '-') return 0;
    for (i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) return 0;
    }
    return 1;
}

/* --------------------------------------------------------------------- the profile */

int ts_profile_new(ts_profile* p, const char* control, const char* auth_key, const wg_rng* rng)
{
    ts_url u;
    wg_key pub;

    memset(p, 0, sizeof(*p));
    if (!control || !*control) control = TS_CONTROL_DEFAULT;
    if (!auth_key) auth_key = "";
    if (!ts_url_parse(control, strlen(control), &u) || (*auth_key && !ts_authkey_valid(auth_key, strlen(auth_key))))
        return 0;
    snprintf(p->control, sizeof(p->control), "%s", control);
    if (p->control[strlen(p->control) - 1] == '/') p->control[strlen(p->control) - 1] = '\0';
    snprintf(p->auth_key, sizeof(p->auth_key), "%s", auth_key);
    if (!wg_key_generate_rng(rng, &p->machine, &pub) || !wg_key_generate_rng(rng, &p->node, &pub)) {
        ts_profile_wipe(p);
        return 0;
    }
    wg_wipe(&pub, sizeof(pub));
    return 1;
}

int ts_profile_relogin(ts_profile* p, const char* auth_key, const wg_rng* rng)
{
    wg_key node, pub;

    if (!auth_key) auth_key = "";
    if (*auth_key && !ts_authkey_valid(auth_key, strlen(auth_key))) return 0;
    if (!wg_key_generate_rng(rng, &node, &pub)) return 0;
    /* Only a registered key is worth naming as the old one: an unregistered one never made it
     * into the tailnet, and control would not know it. */
    if (p->registered) {
        p->old_node = p->node;
        p->has_old_node = 1;
    }
    p->node = node;
    p->registered = 0;
    /* The new login may be a new node with addresses of its own (the old one gone from the tailnet,
     * the phone 2026-10-22): cached, the old ones went on the tun first, and the tailnet's routes
     * kept one of them as their source - nothing reached the nodes. The netmap brings the right ones
     * a moment after the login. */
    memset(p->address, 0, sizeof(p->address));
    p->n_address = 0;
    /* a key of an earlier attempt goes whole, not only its first byte (a login by a link: none) */
    wg_wipe(p->auth_key, sizeof(p->auth_key));
    snprintf(p->auth_key, sizeof(p->auth_key), "%s", auth_key);
    wg_wipe(&node, sizeof(node));
    wg_wipe(&pub, sizeof(pub));
    return 1;
}

static void put_key(bt_writer* w, const char* name, const wg_key* k)
{
    char hex[65];
    ts_hex32(hex, k->b);
    bt_put(w, name, hex);
    wg_wipe(hex, sizeof(hex));
}

size_t ts_profile_format(const ts_profile* p, char* buf, size_t cap)
{
    bt_writer w;
    size_t i;

    bt_writer_init(&w, buf, cap);
    bt_put(&w, "tailscale", "1");
    bt_put(&w, "control", p->control);
    put_key(&w, "machine_key", &p->machine);
    put_key(&w, "node_key", &p->node);
    if (p->has_old_node) put_key(&w, "old_node_key", &p->old_node);
    if (p->auth_key[0]) bt_put(&w, "auth_key", p->auth_key);
    bt_put(&w, "registered", p->registered ? "1" : "0");
    if (p->has_server) put_key(&w, "server_key", &p->server);
    if (p->hostname[0]) bt_put(&w, "hostname", p->hostname);
    if (p->control_addr[0]) bt_put(&w, "control_addr", p->control_addr);
    if (p->tailnet[0]) bt_put(&w, "tailnet", p->tailnet);
    if (p->node_name[0]) bt_put(&w, "node_name", p->node_name);
    for (i = 0; i < p->n_address && i < TS_PROFILE_ADDRS; i++) bt_put(&w, "address", p->address[i]);
    return w.failed ? 0 : w.len;
}

static int get_key(const bt_block* b, const char* name, wg_key* k, int required, int* has)
{
    size_t len;
    const char* v = bt_get_len(b, name, &len);

    if (has) *has = 0;
    if (!v) return !required;
    if (!ts_unhex32(k->b, v, len)) return 0;
    if (has) *has = 1;
    return 1;
}

static int get_text(const bt_block* b, const char* name, char* out, size_t cap)
{
    size_t len;
    const char* v = bt_get_len(b, name, &len);

    out[0] = '\0';
    if (!v) return 1;
    if (!text_valid(v, len, cap - 1)) return 0;
    memcpy(out, v, len);
    out[len] = '\0';
    return 1;
}

int ts_profile_parse(ts_profile* p, char* text, size_t len)
{
    static bt_block b;                  /* the daemon is single-threaded, as bt_meta_parse */
    const char* v;
    size_t vlen, i;
    ts_url u;
    int reg;

    memset(p, 0, sizeof(*p));
    if (!ts_profile_is(text, len) || !bt_block_parse(&b, text, len, NULL, 0)) goto bad;
    if (strcmp(bt_block_kind(&b), "tailscale") != 0 || strcmp(b.kv[0].val, "1") != 0) goto bad;

    v = bt_get_len(&b, "control", &vlen);
    if (!v || !ts_url_parse(v, vlen, &u) || vlen > TS_URL_MAX) goto bad;
    memcpy(p->control, v, vlen);
    p->control[vlen] = '\0';

    if (!get_key(&b, "machine_key", &p->machine, 1, NULL) || !get_key(&b, "node_key", &p->node, 1, NULL) ||
        !get_key(&b, "old_node_key", &p->old_node, 0, &p->has_old_node) ||
        !get_key(&b, "server_key", &p->server, 0, &p->has_server))
        goto bad;

    v = bt_get_len(&b, "auth_key", &vlen);
    if (v) {
        if (!ts_authkey_valid(v, vlen)) goto bad;
        memcpy(p->auth_key, v, vlen);
        p->auth_key[vlen] = '\0';
    }
    if (bt_get_bool(&b, "registered", &reg) != 1) goto bad;
    p->registered = reg;

    v = bt_get_len(&b, "hostname", &vlen);
    if (v) {
        if (!ts_hostname_valid(v, vlen)) goto bad;
        memcpy(p->hostname, v, vlen);
        p->hostname[vlen] = '\0';
    }

    v = bt_get_len(&b, "control_addr", &vlen);
    if (v) {
        int family;
        uint8_t a[16];
        if (vlen >= sizeof(p->control_addr) || !wg_addr_parse(v, vlen, &family, a)) goto bad;
        memcpy(p->control_addr, v, vlen);
        p->control_addr[vlen] = '\0';
    }
    if (!get_text(&b, "tailnet", p->tailnet, sizeof(p->tailnet)) ||
        !get_text(&b, "node_name", p->node_name, sizeof(p->node_name)))
        goto bad;
    for (i = bt_find(&b, "address", 0); i < b.n; i = bt_find(&b, "address", i + 1)) {
        wg_prefix pf;
        if (p->n_address == TS_PROFILE_ADDRS || b.kv[i].val_len >= TS_ADDR_TEXT_MAX ||
            !wg_prefix_parse(b.kv[i].val, b.kv[i].val_len, &pf))
            goto bad;
        memcpy(p->address[p->n_address], b.kv[i].val, b.kv[i].val_len + 1);
        p->n_address++;
    }
    wg_wipe(&b, sizeof(b));
    return 1;

bad:
    wg_wipe(&b, sizeof(b));
    ts_profile_wipe(p);
    return 0;
}

int ts_profile_is(const char* text, size_t len)
{
    return len >= 12 && memcmp(text, "tailscale=1", 11) == 0 && (text[11] == '\n' || text[11] == '\r');
}

void ts_profile_wipe(ts_profile* p)
{
    wg_wipe(p, sizeof(*p));
}
