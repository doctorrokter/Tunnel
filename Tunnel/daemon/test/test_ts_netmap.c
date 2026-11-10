/*
 * ts_json and ts_netmap: JSON as Go reads it (the strict grammar, escapes, the folding of names,
 * integers), the text forms of the wire (times, addresses, prefixes, keys), and the netmap -
 * replayed against Tailscale's own mapSession (vectors/netmap/kat_netmap.h), at its limits,
 * refusing without a trace, answering the queries the Tailscale side of the daemon asks. Then
 * fuzzed: mutated and random JSON, and mutated map messages applied one after another with the
 * model's invariants and the atomicity of refusals checked after each. Inputs sit in heap buffers
 * of exactly their size, so a read past one is caught.
 *
 * Seeded like the daemon's fuzzer: BT_FUZZ_SEED=<hex> picks another run.
 */

#include "test_util.h"
#include "../src/ts_json.h"
#include "../src/ts_netmap.h"
#include "vectors/netmap/kat_netmap.h"

#include <stdarg.h>

#define NTOK        65536
#define S_FREE      0                   /* the slot states of ts_netmap.c */
#define S_LIVE      1
#define REC_HDR     6

static jsmntok_t tok[NTOK];
static ts_json doc;
static ts_netmap_result res;

static ts_time at(int64_t sec)
{
    ts_time t;
    t.sec = sec;
    t.nsec = 0;
    return t;
}

static ts_time vec_now(void)
{
    return at(NM_VEC_NOW_SEC);
}

/* Room for a netmap and its memory. */
typedef struct {
    ts_netmap nm;
    ts_node   nodes[256];
    uint16_t  index[512];
    uint8_t   arena[128 * 1024];
} box;

static void box_init(box* b, size_t cap, size_t arena)
{
    ts_netmap_init(&b->nm, b->nodes, b->index, cap, b->arena, arena);
}

/* Parses and applies: -1 not JSON, 0 refused, 1 applied. */
static int apply_n(ts_netmap* nm, const char* json, size_t len, ts_time now)
{
    if (!ts_json_parse(&doc, json, len, tok, NTOK)) return -1;
    return ts_netmap_apply(nm, &doc, now, &res);
}

static int apply(ts_netmap* nm, const char* json)
{
    return apply_n(nm, json, strlen(json), vec_now());
}

/* ------------------------------------------------------------------ the dump (as the generator's) */

typedef struct {
    char*  p;
    size_t cap, len;
} dbuf;

static void put(dbuf* b, const char* fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    if (n > 0) b->len = b->len + (size_t)n < b->cap ? b->len + (size_t)n : b->cap - 1;
}

static void put_esc(dbuf* b, const char* s, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c > 0x20 && c < 0x7f && c != '\\') put(b, "%c", c);
        else put(b, "\\x%02x", c);
    }
}

static void put_hex(dbuf* b, const uint8_t* p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) put(b, "%02x", p[i]);
}

static void put_pfx(dbuf* b, const wg_prefix* a, size_t n)
{
    size_t i;

    put(b, "[");
    for (i = 0; i < n; i++) {
        if (i) put(b, ",");
        if (a[i].family == 0) {
            put(b, "-");
            continue;
        }
        put_hex(b, a[i].addr, a[i].family == 4 ? 4 : 16);
        put(b, "/%u", a[i].cidr);
    }
    put(b, "]");
}

static void put_time(dbuf* b, ts_time t)
{
    if (ts_time_is_zero(t)) put(b, "zero");
    else put(b, "%lld.%09d", (long long)t.sec, (int)t.nsec);
}

static void put_node(dbuf* b, const ts_netmap* nm, const char* kind, const ts_node* n)
{
    int online = ts_node_online(n);

    put(b, "%s id=%lld user=%lld key=", kind, (long long)n->id, (long long)n->user);
    put_hex(b, n->key.b, 32);
    put(b, " disco=");
    put_hex(b, n->disco.b, 32);
    put(b, " name=");
    put_esc(b, ts_node_name(nm, n), n->name_len);
    put(b, " addrs=");
    put_pfx(b, ts_node_addrs(nm, n), n->n_addrs);
    put(b, " allowed=");
    put_pfx(b, ts_node_allowed(nm, n), n->n_allowed);
    put(b, " derp=%lld online=", (long long)n->home_derp);
    if (online < 0) put(b, "-");
    else put(b, "%d", online);
    put(b, " seen=");
    if (n->flags & TS_NODE_SEEN) put_time(b, n->last_seen);
    else put(b, "-");
    put(b, " expiry=");
    put_time(b, n->key_expiry);
    put(b, " expired=%d auth=%d unsigned=%d wgonly=%d\n", !!(n->flags & TS_NODE_EXPIRED),
        !!(n->flags & TS_NODE_AUTHORIZED), !!(n->flags & TS_NODE_UNSIGNED), !!(n->flags & TS_NODE_WG_ONLY));
}

static void put_ip(dbuf* b, const ts_derpmap_ip* ip)
{
    if (ip->mode == TS_DERPMAP_IP_DNS) put(b, "dns");
    else if (ip->mode == TS_DERPMAP_IP_OFF) put(b, "off");
    else put_hex(b, ip->addr.addr, ip->addr.family == 4 ? 4 : 16);
}

static char dump_space[2][1 << 18];

/* The netmap as text, in buffer `which` (two, to compare before and after). */
static const char* dump_in(const ts_netmap* nm, int which)
{
    dbuf b;
    const ts_derpmap* m = &nm->derp;
    size_t i, j;

    b.p = dump_space[which];
    b.cap = sizeof(dump_space[which]);
    b.len = 0;
    b.p[0] = '\0';
    if (ts_netmap_self(nm)) put_node(&b, nm, "self", ts_netmap_self(nm));
    else put(&b, "self none\n");
    for (i = 0; i < ts_netmap_count(nm); i++) put_node(&b, nm, "peer", ts_netmap_at(nm, i));
    put(&b, "domain ");
    put_esc(&b, ts_netmap_domain(nm), strlen(ts_netmap_domain(nm)));
    put(&b, "\n");
    if (!m->present) {
        put(&b, "derp none\n");
        return b.p;
    }
    put(&b, "derp omit=%d\n", m->omit_default_regions);
    if (!m->home_params) {
        put(&b, "home none\n");
    } else if (!m->scores_set) {
        put(&b, "home scores=none\n");
    } else {
        put(&b, "home scores=%u\n", (unsigned)m->n_scores);
        for (i = 0; i < m->n_scores; i++) {
            uint64_t bits;
            memcpy(&bits, &m->scores[i].score, 8);
            put(&b, "score %lld %016llx\n", (long long)m->scores[i].region, (unsigned long long)bits);
        }
    }
    for (i = 0; i < m->n_regions; i++) {
        const ts_derpmap_region* r = &m->regions[i];
        const ts_derpmap_node* nodes = ts_derpmap_nodes(nm, r);
        put(&b, "region %lld id=%lld code=", (long long)r->id, (long long)r->region_id);
        put_esc(&b, ts_derpmap_str(nm, r->code), strlen(ts_derpmap_str(nm, r->code)));
        put(&b, " name=");
        put_esc(&b, ts_derpmap_str(nm, r->name), strlen(ts_derpmap_str(nm, r->name)));
        put(&b, " avoid=%d nomeasure=%d nodes=%u\n", r->avoid, r->no_measure_no_home, r->n_nodes);
        for (j = 0; j < r->n_nodes; j++) {
            const ts_derpmap_node* n = &nodes[j];
            put(&b, "node name=");
            put_esc(&b, ts_derpmap_str(nm, n->name), strlen(ts_derpmap_str(nm, n->name)));
            put(&b, " region=%lld host=", (long long)n->region_id);
            put_esc(&b, ts_derpmap_str(nm, n->host), strlen(ts_derpmap_str(nm, n->host)));
            put(&b, " cert=");
            put_esc(&b, ts_derpmap_str(nm, n->cert), strlen(ts_derpmap_str(nm, n->cert)));
            put(&b, " v4=");
            put_ip(&b, &n->v4);
            put(&b, " v6=");
            put_ip(&b, &n->v6);
            put(&b, " stun=%lld stunonly=%d port=%lld insecure=%d port80=%d\n", (long long)n->stun_port,
                n->stun_only, (long long)n->derp_port, n->insecure_for_tests, n->can_port80);
        }
    }
    return b.p;
}

static const char* dump(const ts_netmap* nm)
{
    return dump_in(nm, 0);
}

/* Prints the first line where two dumps part. */
static void show_diff(const char* name, const char* want, const char* got)
{
    size_t line = 1;

    while (*want && *want == *got) {
        if (*want == '\n') line++;
        want++;
        got++;
    }
    while (*want && want[-1] != '\n' && want > got - 1000) want--, got--;
    fprintf(stderr, "    %s, line %u\n      want: %.300s\n      got:  %.300s\n", name, (unsigned)line, want, got);
}

/* ------------------------------------------------------------------ the model's invariants */

static unsigned rec_owner(const uint8_t* p) { return (unsigned)p[0] | ((unsigned)p[1] << 8); }
static uint32_t rec_size(const uint8_t* p)
{
    return (uint32_t)p[2] | ((uint32_t)p[3] << 8) | ((uint32_t)p[4] << 16) | ((uint32_t)p[5] << 24);
}

static const char* prefixes_ok(const wg_prefix* a, size_t n)
{
    static const uint8_t zero[16];
    size_t i;

    for (i = 0; i < n; i++) {
        if (a[i].family == 0 && (a[i].cidr != 0 || memcmp(a[i].addr, zero, 16) != 0)) return "zero prefix not zero";
        if (a[i].family == 4 && (a[i].cidr > 32 || memcmp(a[i].addr + 4, zero, 12) != 0)) return "IPv4 prefix";
        if (a[i].family == 6 && a[i].cidr > 128) return "IPv6 prefix";
        if (a[i].family != 0 && a[i].family != 4 && a[i].family != 6) return "prefix family";
    }
    return NULL;
}

static const char* invariants(const ts_netmap* nm)
{
    static uint8_t seen[256];
    const ts_derpmap* m = &nm->derp;
    size_t i, live = 0, recs = 0, garbage = 0, r;
    const char* e;

    for (i = 0; i < nm->cap; i++) {
        if (nm->nodes[i].state == S_LIVE) live++;
        else if (nm->nodes[i].state != S_FREE) return "a slot neither free nor live after apply";
    }
    if (live != nm->n || nm->n > nm->cap) return "live slots != n";
    for (i = 0; i < nm->n; i++) {
        const ts_node* x = &nm->nodes[nm->by_id[i]];
        const char* name = ts_node_name(nm, x);
        size_t size;
        if (x->state != S_LIVE) return "by_id holds a slot not live";
        if (i && nm->nodes[nm->by_id[i - 1]].id >= x->id) return "by_id not strictly ascending";
        if (x->n_addrs > TS_NODE_ADDRS_MAX) return "too many addresses kept";
        if ((x->flags & TS_NODE_ALLOWED_ADDRS) ? x->n_allowed != x->n_addrs : x->n_allowed > TS_NODE_ALLOWED_MAX)
            return "AllowedIPs count";
        if (x->name_len > TS_NODE_NAME_MAX || name[x->name_len] != '\0' || memchr(name, '\0', x->name_len))
            return "name";
        if ((e = prefixes_ok(ts_node_addrs(nm, x), x->n_addrs)) != NULL) return e;
        if ((e = prefixes_ok(ts_node_allowed(nm, x), x->n_allowed)) != NULL) return e;
        size = (x->n_addrs + ((x->flags & TS_NODE_ALLOWED_ADDRS) ? 0 : x->n_allowed)) * sizeof(wg_prefix) + x->name_len + 1;
        if (x->blob < REC_HDR || x->blob + size > nm->arena_used) return "blob outside the arena";
        if (rec_owner(nm->arena + x->blob - REC_HDR) != nm->by_id[i] || rec_size(nm->arena + x->blob - REC_HDR) != size)
            return "blob record";
        if (ts_netmap_find_id(nm, x->id) != x) return "find_id";
    }
    if (nm->n_keyed != nm->n) return "by_key size";
    for (i = 0; i < nm->n_keyed; i++) {
        const ts_node* x = &nm->nodes[nm->by_key[i]];
        if (x->state != S_LIVE) return "by_key holds a slot not live";
        if (i) {
            const ts_node* p = &nm->nodes[nm->by_key[i - 1]];
            int c = memcmp(p->key.b, x->key.b, 32);
            if (c > 0 || (c == 0 && p->id >= x->id)) return "by_key order";
        }
        if (memcmp(ts_netmap_find_key(nm, x->key.b)->key.b, x->key.b, 32) != 0) return "find_key";
    }
    for (r = 0; r < nm->arena_used;) {
        unsigned owner = rec_owner(nm->arena + r);
        size_t total = REC_HDR + rec_size(nm->arena + r);
        if (r + total > nm->arena_used) return "arena record runs over";
        if (owner == 0xffff) {
            garbage += total;
        } else {
            if (owner >= nm->cap || nm->nodes[owner].state != S_LIVE || nm->nodes[owner].blob != r + REC_HDR)
                return "arena record owner";
            recs++;
        }
        r += total;
    }
    if (recs != nm->n || garbage != nm->arena_garbage) return "arena accounting";
    if (nm->has_self) {
        if (nm->self.name_len > TS_NODE_NAME_MAX || nm->self_name[nm->self.name_len] != '\0') return "self name";
        if (nm->self.n_addrs > TS_NODE_ADDRS_MAX || nm->self.n_allowed > TS_NODE_ADDRS_MAX) return "self lists";
    }
    if (strlen(nm->domain) > TS_NM_DOMAIN_MAX) return "domain";

    /* the DERP map */
    if (m->n_regions > TS_DERPMAP_REGIONS_MAX || m->n_nodes > TS_DERPMAP_NODES_MAX || m->n_scores > TS_DERPMAP_SCORES_MAX ||
        m->str_used > TS_DERPMAP_STR_MAX || m->str_used < 1 || m->str[0] != '\0')
        return "DERP map sizes";
    if (m->str[m->str_used - 1] != '\0') return "DERP strings end";
    memset(seen, 0, sizeof(seen));
    for (i = 0; i < m->n_regions; i++) {
        const ts_derpmap_region* g = &m->regions[i];
        size_t j;
        if (i && m->regions[i - 1].id >= g->id) return "regions not ascending";
        if (g->code >= m->str_used || g->name >= m->str_used) return "region strings";
        if ((size_t)g->first + g->n_nodes > m->n_nodes) return "region nodes outside";
        for (j = g->first; j < (size_t)g->first + g->n_nodes; j++) {
            const ts_derpmap_node* n = &m->nodes[j];
            if (seen[j]++) return "a DERP node in two regions";
            if (n->name >= m->str_used || n->host >= m->str_used || n->cert >= m->str_used) return "node strings";
            if (n->v4.mode == TS_DERPMAP_IP_ADDR && n->v4.addr.family != 4) return "v4 family";
            if (n->v6.mode == TS_DERPMAP_IP_ADDR && n->v6.addr.family != 6) return "v6 family";
        }
        if (ts_derpmap_find(nm, g->id) != g) return "derpmap_find";
    }
    for (i = 0; i < m->n_nodes; i++)
        if (!seen[i]) return "a DERP node in no region";
    for (i = 1; i < m->n_scores; i++)
        if (m->scores[i - 1].region >= m->scores[i].region) return "scores not ascending";
    return NULL;
}

#define CHECK_INV(nm)                                                                         \
    do {                                                                                      \
        const char* inv_ = invariants(nm);                                                    \
        if (inv_) fprintf(stderr, "    invariant: %s\n", inv_);                               \
        CHECK(inv_ == NULL);                                                                  \
    } while (0)

/* ------------------------------------------------------------------ JSON */

static int parse(const char* s)
{
    return ts_json_parse(&doc, s, strlen(s), tok, NTOK);
}

TEST(json_tokens_and_walk)
{
    const char* s = " {\"a\":1,\"b\":[true,false,null,\"x\"],\"c\":{\"d\":{}},\"e\":[]}\n";
    int k, v, e, n = 0;

    REQUIRE(parse(s));
    CHECK(ts_json_count(s, strlen(s)) == doc.n);
    CHECK(ts_json_type_of(&doc, 0) == TS_JSON_OBJECT && ts_json_size(&doc, 0) == 4);
    CHECK(ts_json_skip(&doc, 0) == doc.n);
    for (k = ts_json_first(&doc, 0); k >= 0; k = ts_json_next(&doc, k)) n++;
    CHECK(n == 4);
    v = ts_json_find(&doc, 0, "b");
    REQUIRE(v > 0 && ts_json_type_of(&doc, v) == TS_JSON_ARRAY && ts_json_size(&doc, v) == 4);
    e = ts_json_first(&doc, v);
    CHECK(ts_json_type_of(&doc, e) == TS_JSON_TRUE);
    e = ts_json_next(&doc, e);
    CHECK(ts_json_type_of(&doc, e) == TS_JSON_FALSE);
    e = ts_json_next(&doc, e);
    CHECK(ts_json_is_null(&doc, e));
    e = ts_json_next(&doc, e);
    CHECK(ts_json_type_of(&doc, e) == TS_JSON_STRING && ts_json_next(&doc, e) < 0);
    v = ts_json_find(&doc, 0, "c");
    CHECK(ts_json_skip(&doc, v) == ts_json_find(&doc, 0, "e") - 1);    /* to the key "e" */
    CHECK(ts_json_first(&doc, ts_json_find(&doc, 0, "e")) < 0);
    CHECK(ts_json_find(&doc, 0, "missing") == -1);
    CHECK(ts_json_find(&doc, v, "d") > 0 && ts_json_find(&doc, v, "a") == -1);  /* not inside other values */
    CHECK(ts_json_type_of(&doc, -1) == TS_JSON_NONE && ts_json_type_of(&doc, doc.n) == TS_JSON_NONE);

    /* the skip of a key covers its value */
    REQUIRE(parse("{\"x\":{\"y\":[1,2,{\"z\":3}]},\"w\":4}"));
    CHECK(ts_json_next(&doc, 1) == ts_json_skip(&doc, 1));
    CHECK(ts_json_key_is(&doc, ts_json_next(&doc, 1), "w"));
}

TEST(json_rejects)
{
    static const struct {
        const char* text;
        ts_json_err err;
    } bad[] = {
        { "", TS_JSON_ERR_TRUNCATED },
        { "  \n ", TS_JSON_ERR_TRUNCATED },
        { "{", TS_JSON_ERR_TRUNCATED },
        { "{\"a\":1", TS_JSON_ERR_TRUNCATED },
        { "{\"a\":\"abc", TS_JSON_ERR_TRUNCATED },
        { "[1,2", TS_JSON_ERR_TRUNCATED },
        { "{\"a\"}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":}", TS_JSON_ERR_SYNTAX },
        { "{\"a\" 1}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":1 \"b\":2}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":1,}", TS_JSON_ERR_SYNTAX },
        { "{,\"a\":1}", TS_JSON_ERR_SYNTAX },
        { "{\"a\"::1}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":1,,\"b\":2}", TS_JSON_ERR_SYNTAX },
        { "[1,]", TS_JSON_ERR_SYNTAX },
        { "[,1]", TS_JSON_ERR_SYNTAX },
        { "[1 2]", TS_JSON_ERR_SYNTAX },
        { "[\"a\":1]", TS_JSON_ERR_SYNTAX },
        { "[1:2]", TS_JSON_ERR_SYNTAX },
        { "{\"a\":1}{}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":1} x", TS_JSON_ERR_SYNTAX },
        { "[1]]", TS_JSON_ERR_SYNTAX },
        { "{\"a\":1]", TS_JSON_ERR_SYNTAX },
        { "[1}", TS_JSON_ERR_SYNTAX },
        { "}", TS_JSON_ERR_SYNTAX },
        { "5", TS_JSON_ERR_TRUNCATED },             /* a scalar at the top: jsmn waits for more */
        { "5 ", TS_JSON_ERR_SYNTAX },
        { "\"s\"", TS_JSON_ERR_SYNTAX },
        { "{1:2}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":tru}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":nulls}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":01}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":1.}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":.5}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":-}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":1e}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":1e+}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":+1}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":0x10}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":1-2}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":t\"x\"}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":\"x\x01y\"}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":\"\t\"}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":\"\\x\"}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":\"\\'\"}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":\"\\u12G4\"}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":\"\\u12\"}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":'x'}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":NaN}", TS_JSON_ERR_SYNTAX },
        { "{\"a\":Infinity}", TS_JSON_ERR_SYNTAX },
        { "\xef\xbb\xbf{}", TS_JSON_ERR_SYNTAX },   /* a BOM is not whitespace to Go either */
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int ok = parse(bad[i].text);
        CHECK(!ok);
        if (ok || doc.err != bad[i].err)
            fprintf(stderr, "    \"%s\": ok=%d err=%s\n", bad[i].text, ok, ts_json_err_text(doc.err));
        CHECK(doc.err == bad[i].err);
    }
    /* a NUL inside: jsmn would stop there and take the rest as nothing */
    CHECK(!ts_json_parse(&doc, "{\"a\":1}\0{", 9, tok, NTOK) && doc.err == TS_JSON_ERR_SYNTAX);
    CHECK(!ts_json_parse(&doc, "{\"a\":\"x\0\"}", 10, tok, NTOK));
    /* what is fine */
    CHECK(parse("{ \"a\" : [ 1 , -0.5e+3 , 0E0 , \"\\u00e9\\/\" ] , \"b\" : { } }\r\n"));
    CHECK(parse("[]") && parse("{}") && parse("[[],{}]") && parse("[-0,0.0,1E-7,123456789012345678901234567890]"));
}

/* `depth` containers one inside the other, a 0 innermost; objects every other level if asked. */
static void nest(char* buf, int depth, int objects)
{
    int i, n = 0;

    for (i = 0; i < depth; i++) n += sprintf(buf + n, objects && (i % 2) ? "{\"k\":" : "[");
    n += sprintf(buf + n, "0");
    for (i = depth - 1; i >= 0; i--) n += sprintf(buf + n, objects && (i % 2) ? "}" : "]");
    buf[n] = '\0';
}

TEST(json_depth_and_tokens)
{
    static char buf[200000];
    jsmntok_t small[8];
    int i;

    nest(buf, TS_JSON_MAX_DEPTH, 0);
    CHECK(parse(buf));
    nest(buf, TS_JSON_MAX_DEPTH, 1);
    CHECK(parse(buf));
    nest(buf, TS_JSON_MAX_DEPTH + 1, 0);
    CHECK(!parse(buf) && doc.err == TS_JSON_ERR_DEPTH);
    nest(buf, 30000, 0);
    CHECK(!parse(buf) && doc.err == TS_JSON_ERR_DEPTH);
    CHECK(ts_json_count(buf, strlen(buf)) == -1);

    /* tokens: exactly as counted, one fewer is refused */
    strcpy(buf, "{\"a\":[1,2,3],\"b\":\"c\"}");
    CHECK(ts_json_count(buf, strlen(buf)) == 8);
    CHECK(ts_json_parse(&doc, buf, strlen(buf), small, 8));
    CHECK(!ts_json_parse(&doc, buf, strlen(buf), small, 7) && doc.err == TS_JSON_ERR_TOKENS);

    /* a wide flat array: linear, whatever the parent walks */
    buf[0] = '[';
    for (i = 0; i < 40000; i++) memcpy(buf + 1 + 3 * i, "[],", 3);
    memcpy(buf + 1 + 3 * 40000 - 1, "]", 2);
    CHECK(parse(buf) && doc.n == 40001);
}

static int str_is(int t, const char* want, size_t wlen)
{
    char out[256];
    size_t len;

    return ts_json_str(&doc, t, out, sizeof(out), &len) && len == wlen && memcmp(out, want, wlen) == 0;
}

TEST(json_strings)
{
    char out[16];
    size_t len;

    REQUIRE(parse("[\"plain\",\"\\\"\\\\\\/\\b\\f\\n\\r\\t\",\"\\u00e9\\u20ac\",\"\\ud83d\\ude00\","
                  "\"\\ud800x\",\"\\udc00\",\"\\ud800\\ud800\\udc00\",\"a\\u0000b\",\"\xff\xc0\x80\xed\xa0\x80\","
                  "\"\xf0\x9f\x98\x80\xe2\x82\",\"\xc3\xa9\"]"));
    CHECK(str_is(1, "plain", 5));
    CHECK(str_is(2, "\"\\/\b\f\n\r\t", 8));
    CHECK(str_is(3, "\xc3\xa9\xe2\x82\xac", 5));
    CHECK(str_is(4, "\xf0\x9f\x98\x80", 4));                            /* a surrogate pair */
    CHECK(str_is(5, "\xef\xbf\xbdx", 4));                               /* a lone high half */
    CHECK(str_is(6, "\xef\xbf\xbd", 3));                                /* a lone low half */
    CHECK(str_is(7, "\xef\xbf\xbd\xf0\x90\x80\x80", 7));                /* high, then a pair */
    CHECK(str_is(8, "a\0b", 3));                                        /* \u0000 kept */
    /* invalid UTF-8: every byte that does not start a valid sequence is one U+FFFD (utf8.DecodeRune) */
    CHECK(str_is(9, "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd", 18));
    CHECK(str_is(10, "\xf0\x9f\x98\x80\xef\xbf\xbd\xef\xbf\xbd", 10));  /* a cut sequence at the end */
    CHECK(str_is(11, "\xc3\xa9", 2));

    /* the caller's limit: exactly fits, or is refused - or cut whole-character-wise */
    REQUIRE(parse("[\"abcdefghijklmno\",\"abcdefghijklmn\\u00e9\"]"));
    CHECK(ts_json_str(&doc, 1, out, 16, &len) && len == 15);
    CHECK(!ts_json_str(&doc, 1, out, 15, &len));
    CHECK(!ts_json_str(&doc, 2, out, 16, &len));
    CHECK(ts_json_str_cut(&doc, 2, out, 16, &len) == 2 && len == 14 && strcmp(out, "abcdefghijklmn") == 0);
    CHECK(ts_json_str_cut(&doc, 1, out, 16, &len) == 1 && len == 15);
    CHECK(!ts_json_str(&doc, 0, out, sizeof(out), &len));             /* not a string */
}

TEST(json_names)
{
    char f[32];

    REQUIRE(parse("{\"peers\":1,\"PEER\\u017f\":2,\"\\u212aeyExpiry\":3,\"\\u0130D\":4,\"\\u0131d\":5,"
                  "\"\\u0050eers\":6,\"Pe\xc3\xa9rs\":7,\"Peers \":8,\"Pee_rs\":9}"));
    CHECK(ts_json_key_is(&doc, 1, "Peers"));
    CHECK(ts_json_key_is(&doc, 3, "Peers"));                            /* long s */
    CHECK(ts_json_key_is(&doc, 5, "KeyExpiry"));                        /* Kelvin sign */
    CHECK(!ts_json_key_is(&doc, 7, "ID"));                              /* dotted I folds onto nothing */
    CHECK(!ts_json_key_is(&doc, 9, "ID"));                              /* nor the dotless i */
    CHECK(ts_json_key_is(&doc, 11, "Peers"));                           /* escaped */
    CHECK(!ts_json_key_is(&doc, 13, "Peers") && !ts_json_key_is(&doc, 15, "Peers") && !ts_json_key_is(&doc, 17, "Peers"));
    CHECK(!ts_json_key_is(&doc, 1, "Peer") && !ts_json_key_is(&doc, 1, "PeersX"));
    CHECK(ts_json_find(&doc, 0, "Peers") == -2);                        /* three members are Peers to Go */
    CHECK(ts_json_find(&doc, 0, "keyexpiry") == 6);
    CHECK(ts_json_key_fold(&doc, 3, f, sizeof(f)) && strcmp(f, "PEERS") == 0);
    CHECK(!ts_json_key_fold(&doc, 7, f, sizeof(f)));
    CHECK(!ts_json_key_fold(&doc, 1, f, 5));                            /* no room */
    REQUIRE(parse("{\"ID\\u0000x\":1,\"ID\":2}"));                      /* a NUL does not end a name */
    CHECK(!ts_json_key_is(&doc, 1, "ID") && !ts_json_key_fold(&doc, 1, f, sizeof(f)) && ts_json_find(&doc, 0, "ID") == 4);
}

TEST(json_numbers)
{
    int64_t v;
    uint64_t u;
    double x;
    int b;

    REQUIRE(parse("[0,-0,123,-9223372036854775808,9223372036854775807,9223372036854775808,"
                  "-9223372036854775809,1.0,1e2,18446744073709551615,18446744073709551616,-1,"
                  "1.5,0.8,1e-3,-2.5e2,1e400,1e-400,123456789012345678901234567890,true,null,\"5\"]"));
    CHECK(ts_json_i64(&doc, 1, &v) && v == 0);
    CHECK(ts_json_i64(&doc, 2, &v) && v == 0);
    CHECK(ts_json_i64(&doc, 3, &v) && v == 123);
    CHECK(ts_json_i64(&doc, 4, &v) && v == -9223372036854775807LL - 1);
    CHECK(ts_json_i64(&doc, 5, &v) && v == 9223372036854775807LL);
    CHECK(!ts_json_i64(&doc, 6, &v) && !ts_json_i64(&doc, 7, &v));
    CHECK(!ts_json_i64(&doc, 8, &v) && !ts_json_i64(&doc, 9, &v));      /* 1.0, 1e2: not integers to Go */
    CHECK(ts_json_u64(&doc, 10, &u) && u == ~0ULL);
    CHECK(!ts_json_u64(&doc, 11, &u) && !ts_json_u64(&doc, 12, &u) && !ts_json_u64(&doc, 2, &u));
    CHECK(ts_json_f64(&doc, 13, &x) && x == 1.5);
    CHECK(ts_json_f64(&doc, 14, &x) && x == 0.8);
    CHECK(ts_json_f64(&doc, 15, &x) && x == 0.001);
    CHECK(ts_json_f64(&doc, 16, &x) && x == -250);
    CHECK(!ts_json_f64(&doc, 17, &x));                                   /* out of range: Go refuses */
    CHECK(ts_json_f64(&doc, 18, &x) && x == 0);
    CHECK(ts_json_f64(&doc, 19, &x) && x > 1.2345678901234e29 && x < 1.2345678901235e29);
    CHECK(ts_json_f64(&doc, 1, &x) && x == 0);
    CHECK(!ts_json_i64(&doc, 20, &v) && !ts_json_f64(&doc, 21, &x) && !ts_json_i64(&doc, 22, &v));
    CHECK(ts_json_bool(&doc, 20, &b) && b == 1 && !ts_json_bool(&doc, 21, &b) && ts_json_is_null(&doc, 21));

    /* map keys as strconv.ParseInt reads them */
    REQUIRE(parse("{\"+5\":0,\"007\":0,\"-0\":0,\"\":0,\"+\":0,\"5a\":0,\"9223372036854775807\":0,"
                  "\"9223372036854775808\":0,\"-9223372036854775808\":0,\"\\u0035\":0,\" 5\":0}"));
    CHECK(ts_json_key_i64(&doc, 1, &v) && v == 5);
    CHECK(ts_json_key_i64(&doc, 3, &v) && v == 7);
    CHECK(ts_json_key_i64(&doc, 5, &v) && v == 0);
    CHECK(!ts_json_key_i64(&doc, 7, &v) && !ts_json_key_i64(&doc, 9, &v) && !ts_json_key_i64(&doc, 11, &v));
    CHECK(ts_json_key_i64(&doc, 13, &v) && v == 9223372036854775807LL);
    CHECK(!ts_json_key_i64(&doc, 15, &v));
    CHECK(ts_json_key_i64(&doc, 17, &v) && v == -9223372036854775807LL - 1);
    CHECK(ts_json_key_i64(&doc, 19, &v) && v == 5);
    CHECK(!ts_json_key_i64(&doc, 21, &v));
}

/* ------------------------------------------------------------------ the text forms of the wire */

TEST(time_forms)
{
    ts_time t;

    CHECK(ts_time_parse("2026-09-30T12:00:00Z", 20, &t) && t.sec == 1790769600 && t.nsec == 0);
    CHECK(ts_time_parse("2026-09-30T12:00:00.5Z", 22, &t) && t.sec == 1790769600 && t.nsec == 500000000);
    CHECK(ts_time_parse("2026-09-30T12:00:00.1234567899Z", 31, &t) && t.nsec == 123456789);   /* nine count */
    CHECK(ts_time_parse("2026-09-30T15:00:00+03:00", 25, &t) && t.sec == 1790769600);
    CHECK(ts_time_parse("2026-09-30T08:30:00-03:30", 25, &t) && t.sec == 1790769600);
    CHECK(ts_time_parse("0001-01-01T00:00:00Z", 20, &t) && ts_time_is_zero(t));
    CHECK(ts_time_parse("0001-01-01T03:00:00+03:00", 25, &t) && ts_time_is_zero(t));  /* the instant counts */
    CHECK(ts_time_parse("0000-01-01T00:00:00Z", 20, &t) && t.sec == -62167219200LL);
    CHECK(ts_time_parse("1969-12-31T23:59:59.25Z", 23, &t) && t.sec == -1 && t.nsec == 250000000);
    CHECK(ts_time_parse("2024-02-29T00:00:00Z", 20, &t));
    CHECK(ts_time_parse("9999-12-31T23:59:59Z", 20, &t));
    CHECK(!ts_time_parse("2023-02-29T00:00:00Z", 20, &t));
    CHECK(!ts_time_parse("2026-13-01T00:00:00Z", 20, &t));
    CHECK(!ts_time_parse("2026-00-01T00:00:00Z", 20, &t));
    CHECK(!ts_time_parse("2026-01-00T00:00:00Z", 20, &t));
    CHECK(!ts_time_parse("2026-01-01T24:00:00Z", 20, &t));
    CHECK(!ts_time_parse("2026-01-01T00:60:00Z", 20, &t));
    CHECK(!ts_time_parse("2026-01-01T00:00:60Z", 20, &t));      /* no leap seconds */
    CHECK(!ts_time_parse("2026-01-01t00:00:00Z", 20, &t));
    CHECK(!ts_time_parse("2026-01-01T00:00:00z", 20, &t));
    CHECK(!ts_time_parse("2026-01-01T00:00:00", 19, &t));
    CHECK(!ts_time_parse("2026-01-01T00:00:00+24:00", 25, &t));
    CHECK(!ts_time_parse("2026-01-01T00:00:00+0300", 24, &t));
    CHECK(!ts_time_parse("2026-01-01T00:00:00.Z", 21, &t));
    CHECK(!ts_time_parse("2026-01-01T0:00:00Z", 19, &t));       /* Go's lenient fallback would */
    CHECK(!ts_time_parse("+026-01-01T00:00:00Z", 20, &t));
    CHECK(ts_time_cmp(at(5), at(6)) < 0 && ts_time_cmp(at(6), at(5)) > 0 && ts_time_cmp(at(5), at(5)) == 0);
}

static int addr_is(const char* s, int fam, const char* hex)
{
    uint8_t a[16], want[16];
    int f;

    memset(want, 0, sizeof(want));
    if (!ts_addr_parse(s, strlen(s), &f, a)) return 0;
    t_hex(want, sizeof(want), hex);
    return f == fam && memcmp(a, want, fam == 4 ? 4 : 16) == 0;
}

TEST(address_forms)
{
    uint8_t a[16];
    int f, i;
    static const char* bad[] = {
        "", "1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.02.3.4", "256.1.1.1", "1..2.3", ".1.2.3", "1.2.3.",
        "1.2.3.4 ", " 1.2.3.4", "1.2.3.-4", ":::", "1:::2", "12345::", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::",
        "1::2::3", "::1.2.3.4.5", "1:2:3:4:5:1.2.3.4", "fe80::1%eth0", "%eth0", "g::", "::1:", ":1::",
        "1:2:3:4:5:6:7:8:1.2.3.4", "0x1.2.3.4",
    };

    CHECK(addr_is("1.2.3.4", 4, "01020304"));
    CHECK(addr_is("0.0.0.0", 4, "00000000"));
    CHECK(addr_is("255.255.255.255", 4, "ffffffff"));
    CHECK(addr_is("::", 6, "00000000000000000000000000000000"));
    CHECK(addr_is("::1", 6, "00000000000000000000000000000001"));
    CHECK(addr_is("1::", 6, "00010000000000000000000000000000"));
    CHECK(addr_is("2001:DB8::1", 6, "20010db8000000000000000000000001"));
    CHECK(addr_is("1:2:3:4:5:6:7:8", 6, "00010002000300040005000600070008"));
    CHECK(addr_is("1:2:3:4:5:6:7::", 6, "00010002000300040005000600070000"));
    CHECK(addr_is("::ffff:1.2.3.4", 6, "00000000000000000000ffff01020304"));
    CHECK(addr_is("::1.2.3.4", 6, "00000000000000000000000001020304"));
    CHECK(addr_is("1:2:3:4:5:6:1.2.3.4", 6, "00010002000300040005000601020304"));
    CHECK(addr_is("fd7a:115c:a1e0::0001", 6, "fd7a115ca1e000000000000000000001"));
    for (i = 0; i < (int)(sizeof(bad) / sizeof(bad[0])); i++) {
        int ok = ts_addr_parse(bad[i], strlen(bad[i]), &f, a);
        if (ok) fprintf(stderr, "    took \"%s\"\n", bad[i]);
        CHECK(!ok);
    }
}

TEST(prefix_and_key_forms)
{
    wg_prefix p;
    uint8_t k[32];
    char text[80];

    CHECK(ts_prefix_parse("100.64.0.1/32", 13, &p) && p.family == 4 && p.cidr == 32 && p.addr[0] == 100);
    CHECK(ts_prefix_parse("10.1.2.3/8", 10, &p) && p.cidr == 8 && p.addr[3] == 3);   /* host bits kept */
    CHECK(ts_prefix_parse("0.0.0.0/0", 9, &p) && p.cidr == 0);
    CHECK(ts_prefix_parse("::/0", 4, &p) && p.family == 6 && p.cidr == 0);
    CHECK(ts_prefix_parse("fd7a:115c:a1e0::1/128", 21, &p) && p.family == 6 && p.cidr == 128);
    CHECK(ts_prefix_parse("::ffff:1.2.3.4/96", 17, &p) && p.family == 6 && p.cidr == 96);
    CHECK(ts_prefix_parse("", 0, &p) && p.family == 0);                            /* Go's zero prefix */
    CHECK(!ts_prefix_parse("1.2.3.4", 7, &p));
    CHECK(!ts_prefix_parse("1.2.3.4/", 8, &p));
    CHECK(!ts_prefix_parse("1.2.3.4/33", 10, &p));
    CHECK(!ts_prefix_parse("::/129", 6, &p));
    CHECK(!ts_prefix_parse("1.2.3.4/08", 10, &p));
    CHECK(!ts_prefix_parse("1.2.3.4/+8", 10, &p));
    CHECK(!ts_prefix_parse("1.2.3.4/-1", 10, &p));
    CHECK(!ts_prefix_parse("1.2.3.4/1000", 12, &p));
    CHECK(!ts_prefix_parse("1.2.3.4/8/8", 11, &p));
    CHECK(!ts_prefix_parse("fe80::1%eth0/64", 15, &p));
    CHECK(!ts_prefix_parse("/8", 2, &p));

    strcpy(text, "nodekey:");
    memset(text + 8, 'a', 64);
    text[72] = '\0';
    CHECK(ts_key_parse(text, 72, "nodekey:", k) && k[0] == 0xaa && k[31] == 0xaa);
    memset(text + 8, 'F', 64);
    CHECK(ts_key_parse(text, 72, "nodekey:", k) && k[0] == 0xff);
    CHECK(!ts_key_parse(text, 72, "discokey:", k));
    CHECK(!ts_key_parse(text, 71, "nodekey:", k));
    text[40] = 'g';
    CHECK(!ts_key_parse(text, 72, "nodekey:", k));
    text[40] = 'F';
    text[0] = 'N';
    CHECK(!ts_key_parse(text, 72, "nodekey:", k));
}

/* ------------------------------------------------------------------ Tailscale's own mapSession */

static box vbox;

TEST(vectors_map_sessions)
{
    size_t i, n = sizeof(nm_vec_steps) / sizeof(nm_vec_steps[0]);

    box_init(&vbox, 64, 64 * 1024);
    CHECK(strcmp(dump(&vbox.nm), "self none\ndomain \nderp none\n") == 0);
    for (i = 0; i < n; i++) {
        const nm_vec_step* s = &nm_vec_steps[i];
        int want = s->go_ok && !s->c_refuses, got;
        const char* d;

        if (s->restart) ts_netmap_session_start(&vbox.nm);
        got = apply_n(&vbox.nm, s->json, s->len, vec_now());
        if (got != want)
            fprintf(stderr, "    %s: applied %d, want %d (%s / %s)\n", s->name, got, want,
                    got < 0 ? ts_json_err_text(doc.err) : "json ok", ts_netmap_err_text(res.err));
        CHECK(got == want);
        d = dump(&vbox.nm);
        if (strcmp(d, s->dump) != 0) show_diff(s->name, s->dump, d);
        CHECK(strcmp(d, s->dump) == 0);
        CHECK_INV(&vbox.nm);
    }
}

TEST(vectors_key_and_register)
{
    size_t i;

    for (i = 0; i < sizeof(nm_vec_keys) / sizeof(nm_vec_keys[0]); i++) {
        const nm_vec_answer* a = &nm_vec_keys[i];
        ts_server_keys k;
        ts_netmap_err err;
        char got[200];
        dbuf b;

        b.p = got;
        b.cap = sizeof(got);
        b.len = 0;
        got[0] = '\0';
        REQUIRE(ts_json_parse(&doc, a->json, a->len, tok, NTOK));
        if (ts_server_keys_parse(&doc, &k, &err)) {
            put(&b, "public=");
            put_hex(&b, k.public_key.b, 32);
            put(&b, " legacy=");
            put_hex(&b, k.legacy_public_key.b, 32);
        } else {
            put(&b, "refused");
        }
        if (strcmp(got, a->want) != 0) fprintf(stderr, "    %s: %s\n", a->name, got);
        CHECK(strcmp(got, a->want) == 0);
    }
    for (i = 0; i < sizeof(nm_vec_register) / sizeof(nm_vec_register[0]); i++) {
        const nm_vec_answer* a = &nm_vec_register[i];
        static ts_register r;
        ts_netmap_err err;
        char got[1500];
        dbuf b;

        b.p = got;
        b.cap = sizeof(got);
        b.len = 0;
        REQUIRE(ts_json_parse(&doc, a->json, a->len, tok, NTOK));
        REQUIRE(ts_register_parse(&doc, &r, &err));
        put(&b, "error=");
        put_esc(&b, r.error, strlen(r.error));
        put(&b, " expired=%d authorized=%d url=", r.node_key_expired, r.machine_authorized);
        put_esc(&b, r.auth_url, strlen(r.auth_url));
        put(&b, " nks=%d user=%lld login=", r.node_key_signature, (long long)r.user_id);
        put_esc(&b, r.login_name, strlen(r.login_name));
        put(&b, " display=");
        put_esc(&b, r.display_name, strlen(r.display_name));
        if (strcmp(got, a->want) != 0) fprintf(stderr, "    %s:\n      want %s\n      got  %s\n", a->name, a->want, got);
        CHECK(strcmp(got, a->want) == 0);
        CHECK(!r.truncated);
    }
}

TEST(register_edges)
{
    static ts_register r;
    static char json[4096];
    ts_netmap_err err;
    int n;

    /* an error longer than kept: cut on a character */
    n = sprintf(json, "{\"Error\":\"");
    memset(json + n, 'e', TS_REG_ERROR_MAX - 1);
    n += TS_REG_ERROR_MAX - 1;
    n += sprintf(json + n, "\\u00e9\"}");
    REQUIRE(parse(json));
    CHECK(ts_register_parse(&doc, &r, &err) && r.truncated && strlen(r.error) == TS_REG_ERROR_MAX - 1);
    /* an AuthURL longer than kept is refused, not cut */
    n = sprintf(json, "{\"AuthURL\":\"https://x/");
    memset(json + n, 'a', TS_REG_URL_MAX);
    n += TS_REG_URL_MAX;
    sprintf(json + n, "\"}");
    REQUIRE(parse(json));
    CHECK(!ts_register_parse(&doc, &r, &err) && err == TS_NM_ERR_TOO_LONG);
    REQUIRE(parse("{\"MachineAuthorized\":\"yes\"}"));
    CHECK(!ts_register_parse(&doc, &r, &err) && err == TS_NM_ERR_TYPE);
    REQUIRE(parse("{\"Error\":\"a\",\"error\":\"b\"}"));
    CHECK(!ts_register_parse(&doc, &r, &err) && err == TS_NM_ERR_DUPLICATE);
    REQUIRE(parse("{\"User\":{\"ID\":1.5}}"));
    CHECK(!ts_register_parse(&doc, &r, &err) && err == TS_NM_ERR_VALUE);
    REQUIRE(parse("[]"));
    CHECK(!ts_register_parse(&doc, &r, &err) && err == TS_NM_ERR_NOT_OBJECT);
    REQUIRE(parse("{\"MachineAuthorized\":true,\"User\":null,\"Login\":{\"LoginName\":\"m@x\",\"Other\":[1]},\"Future\":{}}"));
    CHECK(ts_register_parse(&doc, &r, &err) && r.machine_authorized && strcmp(r.login_name, "m@x") == 0);
}

/* ------------------------------------------------------------------ building messages by hand */

static char msg[1 << 20];
static size_t mlen;

static void m_reset(void)
{
    mlen = 0;
    msg[0] = '\0';
}

static void m_add(const char* fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(msg + mlen, sizeof(msg) - mlen, fmt, ap);
    va_end(ap);
    if (n > 0) mlen += (size_t)n;
}

static void key_text(char* out, const char* prefix, unsigned seed)
{
    int i, n = sprintf(out, "%s", prefix);
    for (i = 0; i < 32; i++) n += sprintf(out + n, "%02x", (unsigned)((seed * 7 + (unsigned)i * 3 + 1) & 0xff));
}

/* A peer as JSON: name n<id>, own addresses 100.64.0.<id> and fd7a:115c:a1e0::<id>, a key and a
 * disco key from the id, home region 1 - each unless `extra` (which goes in as it is) has it. */
static void m_node(int id, const char* extra)
{
    char key[80], disco[80];

    key_text(key, "nodekey:", (unsigned)id);
    key_text(disco, "discokey:", (unsigned)id + 100);
    m_add("{\"ID\":%d", id);
    if (!strstr(extra, "\"Name\"")) m_add(",\"Name\":\"n%d.tail.ts.net.\"", id);
    if (!strstr(extra, "\"Key\"")) m_add(",\"Key\":\"%s\"", key);
    if (!strstr(extra, "\"DiscoKey\"")) m_add(",\"DiscoKey\":\"%s\"", disco);
    if (!strstr(extra, "\"Addresses\"")) m_add(",\"Addresses\":[\"100.64.0.%d/32\",\"fd7a:115c:a1e0::%x/128\"]", id & 0xff, id);
    if (!strstr(extra, "\"HomeDERP\"")) m_add(",\"HomeDERP\":1");
    m_add("%s%s}", extra[0] ? "," : "", extra);
}

static const char* self_json = "{\"ID\":1,\"Name\":\"me.tail.ts.net.\",\"Key\":\"nodekey:0101010101010101010101010101010101010101010101010101010101010101\","
                               "\"Addresses\":[\"100.64.0.1/32\",\"fd7a:115c:a1e0::1/128\"],\"MachineAuthorized\":true}";

/* A first message: our node and peers 2 .. 1 + n. */
static void m_full(int n, const char* extra)
{
    int i;

    m_reset();
    m_add("{\"Node\":%s,\"Domain\":\"t.example\",\"Peers\":[", self_json);
    for (i = 0; i < n; i++) {
        if (i) m_add(",");
        m_node(2 + i, extra);
    }
    m_add("]}");
}

static int apply_msg(ts_netmap* nm)
{
    return apply_n(nm, msg, mlen, vec_now());
}

/* ------------------------------------------------------------------ limits: left out, not refused */

static box lbox;

TEST(limits_table)
{
    box_init(&lbox, 4, sizeof(lbox.arena));
    m_full(6, "");
    CHECK(apply_msg(&lbox.nm) == 1);
    CHECK(res.peers_dropped == 2 && lbox.nm.incomplete && ts_netmap_count(&lbox.nm) == 4);
    CHECK(ts_netmap_find_id(&lbox.nm, 5) && !ts_netmap_find_id(&lbox.nm, 6));   /* the list's first four */
    CHECK_INV(&lbox.nm);

    /* a delta adding one more: left out too */
    m_reset();
    m_add("{\"PeersChanged\":[");
    m_node(9, "");
    m_add("]}");
    CHECK(apply_msg(&lbox.nm) == 1 && res.peers_dropped == 1 && !ts_netmap_find_id(&lbox.nm, 9));
    /* removing one makes room within the same message (removals come first) */
    m_reset();
    m_add("{\"PeersRemoved\":[2],\"PeersChanged\":[");
    m_node(9, "");
    m_add("]}");
    CHECK(apply_msg(&lbox.nm) == 1 && res.peers_dropped == 0 && ts_netmap_find_id(&lbox.nm, 9));
    CHECK_INV(&lbox.nm);
    /* a whole list that fits clears `incomplete` */
    m_full(3, "");
    CHECK(apply_msg(&lbox.nm) == 1 && !lbox.nm.incomplete && ts_netmap_count(&lbox.nm) == 3);
    CHECK_INV(&lbox.nm);
}

TEST(limits_node)
{
    static char name[600];
    int i, n;

    box_init(&lbox, 64, sizeof(lbox.arena));
    /* "name" is Name to Go too: the same field twice */
    m_reset();
    m_add("{\"Node\":%s,\"Peers\":[{\"ID\":2,\"Name\":\"a.\",\"name\":\"b.\"}]}", self_json);
    CHECK(apply_msg(&lbox.nm) == 0 && res.err == TS_NM_ERR_DUPLICATE);

    /* a name of exactly TS_NODE_NAME_MAX bytes is kept, one more is not */
    memset(name, 'a', TS_NODE_NAME_MAX);
    name[TS_NODE_NAME_MAX] = '\0';
    m_reset();
    m_add("{\"Node\":%s,\"Peers\":[{\"ID\":2,\"Name\":\"%s\"},{\"ID\":3,\"Name\":\"%sa\"},{\"ID\":4,\"Name\":\"x\\u0000y\"},", self_json, name, name);
    m_add("{\"ID\":5,\"Addresses\":[");
    for (i = 0; i < TS_NODE_ADDRS_MAX; i++) m_add("%s\"10.0.0.%d/32\"", i ? "," : "", i);
    m_add("]},{\"ID\":6,\"Addresses\":[");
    for (i = 0; i <= TS_NODE_ADDRS_MAX; i++) m_add("%s\"10.0.0.%d/32\"", i ? "," : "", i);
    m_add("]},{\"ID\":7,\"AllowedIPs\":[");
    for (i = 0; i < TS_NODE_ALLOWED_MAX; i++) m_add("%s\"10.%d.%d.0/24\"", i ? "," : "", i / 256, i % 256);
    m_add("]},{\"ID\":8,\"AllowedIPs\":[");
    for (i = 0; i <= TS_NODE_ALLOWED_MAX; i++) m_add("%s\"10.%d.%d.0/24\"", i ? "," : "", i / 256, i % 256);
    m_add("]},{\"ID\":9,\"UnsignedPeerAPIOnly\":true,\"Addresses\":[\"100.64.0.9/32\"],\"AllowedIPs\":[");
    for (i = 0; i <= TS_NODE_ALLOWED_MAX; i++) m_add("%s\"10.%d.%d.0/24\"", i ? "," : "", i / 256, i % 256);
    m_add("]}]}");
    n = apply_msg(&lbox.nm);
    CHECK(n == 1 && res.peers_dropped == 4);                /* 3, 4, 6 and 8 */
    CHECK(ts_netmap_find_id(&lbox.nm, 2) && ts_netmap_find_id(&lbox.nm, 2)->name_len == TS_NODE_NAME_MAX);
    CHECK(!ts_netmap_find_id(&lbox.nm, 3) && !ts_netmap_find_id(&lbox.nm, 4));
    CHECK(ts_netmap_find_id(&lbox.nm, 5) && !ts_netmap_find_id(&lbox.nm, 6));
    CHECK(ts_netmap_find_id(&lbox.nm, 7) && ts_netmap_find_id(&lbox.nm, 7)->n_allowed == TS_NODE_ALLOWED_MAX);
    CHECK(!ts_netmap_find_id(&lbox.nm, 8));
    /* an unsigned node's AllowedIPs are cut back to its Addresses, however many it was sent */
    CHECK(ts_netmap_find_id(&lbox.nm, 9) && ts_netmap_find_id(&lbox.nm, 9)->n_allowed == 1);
    CHECK_INV(&lbox.nm);

    /* our own node beyond the limits: the message is refused */
    ts_netmap_session_start(&lbox.nm);
    m_reset();
    m_add("{\"Node\":{\"ID\":1,\"Name\":\"%sa\"}}", name);
    CHECK(apply_msg(&lbox.nm) == 0 && res.err == TS_NM_ERR_SELF_LIMIT);
    m_reset();
    m_add("{\"Node\":{\"ID\":1,\"AllowedIPs\":[\"10.0.0.0/8\",\"10.0.0.0/9\",\"10.0.0.0/10\",\"10.0.0.0/11\","
          "\"10.0.0.0/12\",\"10.0.0.0/13\",\"10.0.0.0/14\",\"10.0.0.0/15\",\"10.0.0.0/16\"]}}");
    CHECK(apply_msg(&lbox.nm) == 0 && res.err == TS_NM_ERR_SELF_LIMIT);
}

TEST(limits_arena)
{
    int round, i;

    /* an arena for about three peers: the rest left out, and churn through it compacts */
    box_init(&lbox, 64, 3 * (6 + 2 * sizeof(wg_prefix) + 17) + 10);
    m_full(5, "");
    CHECK(apply_msg(&lbox.nm) == 1 && ts_netmap_count(&lbox.nm) == 3 && res.peers_dropped == 2);
    CHECK_INV(&lbox.nm);
    for (round = 0; round < 50; round++) {
        /* rename one (a new blob, the old one garbage), remove one, add one */
        m_reset();
        m_add("{\"PeersRemoved\":[%d],\"PeersChanged\":[", 2 + (round + 2) % 5);
        m_node(2 + round % 5, "\"Name\":\"r.tail.ts.net.\"");
        m_add(",");
        m_node(2 + (round + 1) % 5, "");
        m_add("]}");
        CHECK(apply_msg(&lbox.nm) == 1);
        CHECK_INV(&lbox.nm);
    }
    CHECK(lbox.nm.arena_used <= lbox.nm.arena_size);
    for (i = 0; i < (int)ts_netmap_count(&lbox.nm); i++) CHECK(ts_netmap_at(&lbox.nm, i)->name_len > 0);
}

TEST(limits_derp)
{
    static char host[300];
    int i;

    box_init(&lbox, 16, sizeof(lbox.arena));
    memset(host, 'h', TS_DERPMAP_NAME_MAX + 1);
    host[TS_DERPMAP_NAME_MAX + 1] = '\0';
    m_reset();
    m_add("{\"Node\":%s,\"DERPMap\":{\"Regions\":{", self_json);
    for (i = 1; i <= TS_DERPMAP_REGIONS_MAX + 3; i++) m_add("%s\"%d\":{\"RegionID\":%d,\"Nodes\":[{\"Name\":\"%da\",\"HostName\":\"h%d\"}]}", i > 1 ? "," : "", i, i, i, i);
    m_add(",\"1000\":{\"RegionID\":1000,\"Nodes\":[{\"HostName\":\"%s\"},{\"HostName\":\"ok\"}]}", host);
    m_add("},\"HomeParams\":{\"RegionScore\":{");
    for (i = 1; i <= TS_DERPMAP_SCORES_MAX + 2; i++) m_add("%s\"%d\":%d.5", i > 1 ? "," : "", i, i);
    m_add("}}}}");
    CHECK(apply_msg(&lbox.nm) == 1);
    CHECK(lbox.nm.derp.n_regions == TS_DERPMAP_REGIONS_MAX && lbox.nm.derp.n_scores == TS_DERPMAP_SCORES_MAX);
    CHECK(res.derp_dropped == 3 + 1 + 2);        /* regions past the array, the 1000th whole, scores */
    CHECK(ts_derpmap_find(&lbox.nm, 1) && !ts_derpmap_find(&lbox.nm, TS_DERPMAP_REGIONS_MAX + 1));
    CHECK_INV(&lbox.nm);
}

/* ------------------------------------------------------------------ refusals leave no trace */

static box rbox;

TEST(refusals_are_atomic)
{
    static const char* bad[] = {
        "{\"Peers\":{}}",
        "{\"Node\":[]}",
        "{\"KeepAlive\":1}",
        "{\"Domain\":5}",
        "{\"OnlineChange\":[]}",
        "{\"OnlineChange\":{\"x\":true}}",
        "{\"OnlineChange\":{\"2\":\"yes\"}}",
        "{\"PeerSeenChange\":{\"2\":1}}",
        "{\"PeersRemoved\":[\"2\"]}",
        "{\"PeersRemoved\":[2.5]}",
        "{\"PeersChanged\":[null]}",
        "{\"PeersChanged\":[5]}",
        "{\"PeersChangedPatch\":[null]}",
        "{\"PeersChangedPatch\":[{\"NodeID\":2,\"Key\":\"nodekey:00\"}]}",
        "{\"PeersChangedPatch\":[{\"NodeID\":2,\"LastSeen\":\"yesterday\"}]}",
        "{\"PeersChangedPatch\":[{\"NodeID\":2,\"Online\":\"true\"}]}",
        "{\"PeersChangedPatch\":[{\"NodeID\":2,\"NodeID\":3}]}",
        "{\"ControlTime\":\"now\"}",
        "{\"DERPMap\":[]}",
        "{\"DERPMap\":{\"Regions\":{\"1\":5}}}",
        "{\"DERPMap\":{\"Regions\":{\"1\":{\"Nodes\":{}}}}}",
        "{\"DERPMap\":{\"Regions\":{\"1\":{\"Nodes\":[{\"DERPPort\":\"443\"}]}}}}",
        "{\"DERPMap\":{\"Regions\":{\"1\":{\"RegionCode\":1}}}}",
        "{\"DERPMap\":{\"HomeParams\":{\"RegionScore\":{\"1\":\"x\"}}}}",
        "{\"DERPMap\":{\"HomeParams\":{\"RegionScore\":{\"1\":1e999}}}}",
        "{\"DERPMap\":{\"Regions\":{},\"regions\":{}}}",
        "{\"Domain\":\"a\",\"domain\":\"b\"}",
        "{\"KeepAlive\":true,\"Peers\":[{\"ID\":\"x\"}]}",     /* a KeepAlive is still decoded by Go */
        "[]",
    };
    static char before[1 << 18];
    size_t i;
    int k;

    box_init(&rbox, 64, sizeof(rbox.arena));
    m_full(5, "\"Online\":true,\"LastSeen\":\"2026-09-30T10:00:00Z\"");
    REQUIRE(apply_msg(&rbox.nm) == 1);
    strcpy(before, dump(&rbox.nm));
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        k = apply(&rbox.nm, bad[i]);
        if (k != 0) fprintf(stderr, "    took %s (%d)\n", bad[i], k);
        CHECK(k == 0);
        CHECK(strcmp(dump(&rbox.nm), before) == 0);
    }

    /* refused deep inside, after much that would have applied: nothing did */
    m_reset();
    m_add("{\"Domain\":\"new.example\",\"PeersRemoved\":[2,3],\"OnlineChange\":{\"4\":false},\"DERPMap\":{\"Regions\":{}},\"PeersChanged\":[");
    m_node(9, "");
    m_add(",");
    m_node(10, "\"KeyExpiry\":\"2027-01-01\"");
    m_add("]}");
    CHECK(apply_msg(&rbox.nm) == 0 && res.err == TS_NM_ERR_VALUE && res.err_at > 0);
    CHECK(strcmp(dump(&rbox.nm), before) == 0);

    /* a node we hold, listed twice */
    m_reset();
    m_add("{\"PeersChanged\":[");
    m_node(3, "");
    m_add(",");
    m_node(3, "\"HomeDERP\":2");
    m_add("]}");
    CHECK(apply_msg(&rbox.nm) == 0 && res.err == TS_NM_ERR_DUP_PEER);
    CHECK(strcmp(dump(&rbox.nm), before) == 0);
    m_reset();
    m_add("{\"Peers\":[");
    m_node(3, "");
    m_add(",");
    m_node(3, "");
    m_add("]}");
    CHECK(apply_msg(&rbox.nm) == 0 && res.err == TS_NM_ERR_DUP_PEER);
    CHECK(strcmp(dump(&rbox.nm), before) == 0);
    CHECK_INV(&rbox.nm);

    /* a new session's first message must carry Node; until one does, the old netmap stays */
    ts_netmap_session_start(&rbox.nm);
    CHECK(apply(&rbox.nm, "{\"Domain\":\"x\"}") == 0 && res.err == TS_NM_ERR_NO_SELF);
    CHECK(apply(&rbox.nm, "{\"KeepAlive\":true,\"ControlTime\":\"2026-09-30T12:00:00Z\"}") == 1 && res.keepalive &&
          res.has_control_time && res.control_time.sec == 1790769600);
    CHECK(strcmp(dump(&rbox.nm), before) == 0);
    m_full(1, "");
    CHECK(apply_msg(&rbox.nm) == 1 && (res.changed & TS_NM_CHANGED_RESET) && ts_netmap_count(&rbox.nm) == 1);
    CHECK(rbox.nm.derp.present == 0 && strcmp(ts_netmap_domain(&rbox.nm), "t.example") == 0);
    CHECK(apply(&rbox.nm, "{\"Domain\":\"x\"}") == 1 && (res.changed & TS_NM_CHANGED_DOMAIN));
    CHECK(apply(&rbox.nm, "{\"Domain\":\"x\"}") == 1 && !(res.changed & TS_NM_CHANGED_DOMAIN));
    CHECK(apply(&rbox.nm, "{\"Domain\":\"\"}") == 1 && strcmp(ts_netmap_domain(&rbox.nm), "x") == 0);
}

TEST(generations)
{
    const ts_node* x;
    uint32_t g;

    box_init(&rbox, 64, sizeof(rbox.arena));
    m_full(3, "");
    REQUIRE(apply_msg(&rbox.nm) == 1);
    g = rbox.nm.gen;
    CHECK(ts_netmap_find_id(&rbox.nm, 3)->gen == g);
    CHECK(apply(&rbox.nm, "{\"OnlineChange\":{\"3\":true}}") == 1 && (res.changed & TS_NM_CHANGED_PEERS));
    CHECK(rbox.nm.gen == g + 1);
    x = ts_netmap_find_id(&rbox.nm, 3);
    CHECK(x->gen == g + 1 && ts_netmap_find_id(&rbox.nm, 2)->gen == g && ts_node_online(x) == 1);
    CHECK(apply(&rbox.nm, "{\"KeepAlive\":true}") == 1 && rbox.nm.gen == g + 1);
    CHECK(apply(&rbox.nm, "{\"OnlineChange\":{\"77\":true}}") == 1 && !(res.changed & TS_NM_CHANGED_PEERS));
    CHECK(apply(&rbox.nm, "{\"PeerSeenChange\":{\"3\":true}}") == 1);
    x = ts_netmap_find_id(&rbox.nm, 3);
    CHECK((x->flags & TS_NODE_SEEN) && x->last_seen.sec == NM_VEC_NOW_SEC);
}

/* ------------------------------------------------------------------ queries */

static box qbox;

static int route_id(int fam, const char* addr, unsigned flags, int64_t exit_node, ts_time now)
{
    uint8_t a[16];
    int f;
    const ts_node* n;

    if (!ts_addr_parse(addr, strlen(addr), &f, a) || f != fam) return -2;
    n = ts_netmap_route(&qbox.nm, fam, a, flags, exit_node, now);
    return n ? (int)n->id : -1;
}

TEST(queries_route)
{
    ts_time now = at(1790769600), unset = at(1000);
    wg_prefix out[16];
    size_t n;

    box_init(&qbox, 64, sizeof(qbox.arena));
    m_reset();
    m_add("{\"Node\":%s,\"Peers\":[", self_json);
    m_node(2, "");
    m_add(",");
    m_node(3, "\"AllowedIPs\":[\"100.64.0.3/32\",\"fd7a:115c:a1e0::3/128\",\"192.168.1.0/24\",\"10.0.0.0/8\",\"10.0.0.0/8\"]");
    m_add(",");
    m_node(4, "\"AllowedIPs\":[\"100.64.0.4/32\",\"fd7a:115c:a1e0::4/128\",\"192.168.1.7/24\",\"0.0.0.0/0\",\"::/0\",\"1.2.3.4/0\"]");
    m_add(",");
    m_node(5, "\"Expired\":true");
    m_add(",{\"ID\":6,\"Key\":\"nodekey:0606060606060606060606060606060606060606060606060606060606060606\","
          "\"Addresses\":[\"100.64.0.6/32\"]}");            /* no disco key, no home: unreachable */
    m_add(",");
    m_node(7, "\"KeyExpiry\":\"2026-01-01T00:00:00Z\"");
    m_add(",");
    m_node(8, "\"AllowedIPs\":[\"100.64.0.8/32\",\"10.1.0.0/16\",\"fd7a:115c:a1e0::ab/128\",\"100.115.92.5/32\"]");
    m_add(",{\"ID\":9,\"Key\":\"nodekey:0909090909090909090909090909090909090909090909090909090909090909\","
          "\"IsWireGuardOnly\":true,\"Addresses\":[\"100.64.0.9/32\"]}");
    m_add("]}");
    REQUIRE(apply_msg(&qbox.nm) == 1);
    CHECK_INV(&qbox.nm);

    CHECK(route_id(4, "100.64.0.2", 0, 0, now) == 2);
    CHECK(route_id(6, "fd7a:115c:a1e0::2", 0, 0, now) == 2);
    CHECK(route_id(4, "192.168.1.5", 0, 0, now) == -1);                     /* subnets not taken */
    CHECK(route_id(4, "192.168.1.5", TS_ROUTE_SUBNETS, 0, now) == 3);       /* the lower ID of two */
    CHECK(route_id(4, "10.1.2.3", TS_ROUTE_SUBNETS, 0, now) == 8);          /* /16 beats /8 */
    CHECK(route_id(4, "10.2.2.3", TS_ROUTE_SUBNETS, 0, now) == 3);
    CHECK(route_id(4, "8.8.8.8", 0, 0, now) == -1);
    CHECK(route_id(4, "8.8.8.8", TS_ROUTE_SUBNETS, 4, now) == 4);           /* the exit node */
    CHECK(route_id(4, "8.8.8.8", 0, 4, now) == 4);
    CHECK(route_id(6, "2001:db8::1", 0, 4, now) == 4);
    CHECK(route_id(4, "8.8.8.8", 0, 3, now) == -1);                         /* 3 has no /0 */
    CHECK(route_id(4, "1.2.3.4", 0, 0, now) == -1);                         /* 1.2.3.4/0 is no exit route */
    /* ...but a subnet route, which as Go masks it takes every address: IsExitRoute is equality */
    CHECK(route_id(4, "1.2.3.4", TS_ROUTE_SUBNETS, 0, now) == 4);
    CHECK(route_id(4, "8.8.8.8", TS_ROUTE_SUBNETS, 0, now) == 4);
    CHECK(route_id(6, "2001:db8::1", TS_ROUTE_SUBNETS, 0, now) == -1);
    CHECK(route_id(4, "100.64.0.5", 0, 0, now) == -1);                      /* expired by control */
    CHECK(route_id(4, "100.64.0.6", 0, 0, now) == -1);                      /* nothing to reach it by */
    CHECK(route_id(4, "100.64.0.7", 0, 0, now) == -1);                      /* its key expired */
    CHECK(route_id(4, "100.64.0.7", 0, 0, unset) == 7);                     /* a clock not set: control's word */
    CHECK(route_id(6, "fd7a:115c:a1e0::ab", 0, 0, now) == 8);               /* a single Tailscale IP: its own */
    CHECK(route_id(4, "100.115.92.5", 0, 0, now) == -1);                    /* ChromeOS's range is not */
    CHECK(route_id(4, "100.115.92.5", TS_ROUTE_SUBNETS, 0, now) == 8);
    CHECK(route_id(4, "100.64.0.9", 0, 0, now) == 9);                       /* WireGuard-only */
    CHECK(route_id(4, "100.64.0.99", TS_ROUTE_SUBNETS, 4, now) == 4);

    n = ts_netmap_node_routes(&qbox.nm, ts_netmap_find_id(&qbox.nm, 3), TS_ROUTE_SUBNETS, 0, now, out, 16);
    CHECK(n == 4 && out[2].cidr == 24 && out[3].cidr == 8);                  /* its repeat once */
    n = ts_netmap_node_routes(&qbox.nm, ts_netmap_find_id(&qbox.nm, 4), TS_ROUTE_SUBNETS, 4, now, out, 16);
    /* own two and both /0s; 1.2.3.4/0 is the network of 0.0.0.0/0 again, 192.168.1.0/24 is 3's */
    CHECK(n == 4 && out[2].cidr == 0 && out[3].family == 6);
    n = ts_netmap_node_routes(&qbox.nm, ts_netmap_find_id(&qbox.nm, 4), 0, 0, now, out, 1);
    CHECK(n == 2 && out[0].family == 4);
    CHECK(ts_netmap_node_routes(&qbox.nm, ts_netmap_find_id(&qbox.nm, 5), TS_ROUTE_SUBNETS, 0, now, out, 16) == 0);

    n = ts_netmap_os_routes(&qbox.nm, TS_ROUTE_SUBNETS, 4, now, out, 16);
    /* 192.168.1.0/24 (masked, once for 3 and 4), 10.0.0.0/8, 0.0.0.0/0 (1.2.3.4/0 is its network),
     * ::/0, 10.1.0.0/16, 100.115.92.5/32 - not the single Tailscale IPs, the tailnet's ranges have them */
    CHECK(n == 6);
    CHECK(out[0].family == 4 && out[0].cidr == 24 && out[0].addr[3] == 0);
    CHECK(out[2].cidr == 0 && out[2].addr[0] == 0);
    CHECK(ts_netmap_os_routes(&qbox.nm, 0, 0, now, out, 16) == 0);
    /* no exit node: 1.2.3.4/0 is just a route, and the first of its network that counts */
    CHECK(ts_netmap_os_routes(&qbox.nm, TS_ROUTE_SUBNETS, 0, now, out, 2) == 5);
}

TEST(queries_lookup)
{
    const ts_node* on[8];
    char name[64];
    uint8_t key[32];
    char text[80];
    size_t i;

    box_init(&qbox, 64, sizeof(qbox.arena));
    m_reset();
    m_add("{\"Node\":{\"ID\":1,\"Name\":\"phone.tail1234.ts.net.\"},\"Peers\":[");
    m_node(2, "\"Online\":true,\"Name\":\"nas.tail1234.ts.net.\"");
    m_add(",");
    m_node(3, "\"Online\":false,\"Name\":\"x.other.ts.net.\"");
    m_add(",");
    m_node(4, "\"Name\":\"bare\"");
    m_add(",");
    m_node(5, "\"Online\":true,\"Key\":\"nodekey:0202020202020202020202020202020202020202020202020202020202020202\"");
    m_add(",");
    m_node(6, "\"Key\":\"nodekey:0202020202020202020202020202020202020202020202020202020202020202\"");
    m_add("]}");
    REQUIRE(apply_msg(&qbox.nm) == 1);
    CHECK_INV(&qbox.nm);

    for (i = 2; i <= 4; i++) {
        key_text(text, "", (unsigned)i);
        t_hex(key, 32, text);
        CHECK(ts_netmap_find_key(&qbox.nm, key) == ts_netmap_find_id(&qbox.nm, (int64_t)i));
    }
    memset(key, 2, 32);
    CHECK(ts_netmap_find_key(&qbox.nm, key)->id == 5);                     /* two alike: the lower ID */
    memset(key, 9, 32);
    CHECK(ts_netmap_find_key(&qbox.nm, key) == NULL);
    CHECK(ts_netmap_find_id(&qbox.nm, 99) == NULL);

    CHECK(ts_netmap_online(&qbox.nm, on, 8) == 2 && on[0]->id == 2 && on[1]->id == 5);
    CHECK(ts_netmap_online(&qbox.nm, on, 1) == 2);
    CHECK(ts_node_online(ts_netmap_find_id(&qbox.nm, 3)) == 0 && ts_node_online(ts_netmap_find_id(&qbox.nm, 4)) == -1);

    CHECK(ts_node_display_name(&qbox.nm, ts_netmap_find_id(&qbox.nm, 2), name, sizeof(name)) == 3 && strcmp(name, "nas") == 0);
    CHECK(ts_node_display_name(&qbox.nm, ts_netmap_find_id(&qbox.nm, 3), name, sizeof(name)) && strcmp(name, "x.other.ts.net") == 0);
    CHECK(ts_node_display_name(&qbox.nm, ts_netmap_find_id(&qbox.nm, 4), name, sizeof(name)) && strcmp(name, "bare") == 0);
    CHECK(ts_node_display_name(&qbox.nm, ts_netmap_self(&qbox.nm), name, sizeof(name)) && strcmp(name, "phone") == 0);
    CHECK(ts_node_display_name(&qbox.nm, ts_netmap_find_id(&qbox.nm, 2), name, 3) == 2 && strcmp(name, "na") == 0);
    CHECK(ts_netmap_at(&qbox.nm, 99) == NULL);
}

TEST(queries_expiry)
{
    ts_node n;

    memset(&n, 0, sizeof(n));
    n.key_expiry = ts_time_zero();
    CHECK(!ts_node_expired(&n, at(1790769600)));
    n.key_expiry = at(1790769600);
    CHECK(ts_node_expired(&n, at(1790769600)));                         /* not after now: expired */
    CHECK(!ts_node_expired(&n, at(1790769599)));
    CHECK(!ts_node_expired(&n, at(1673373065)));                         /* a clock before 2023-01-10 */
    /* a clock not set yet is not trusted even when the expiry is before it */
    n.key_expiry = at(1000);
    CHECK(!ts_node_expired(&n, at(2000)));
    CHECK(ts_node_expired(&n, at(1673373066)));
    n.flags = TS_NODE_EXPIRED;
    CHECK(ts_node_expired(&n, at(1000)));
}

TEST(queries_derp_home)
{
    int64_t ids[16];
    uint64_t lat[16];
    size_t n;
    const ts_derpmap_region* r;

    box_init(&qbox, 16, sizeof(qbox.arena));
    REQUIRE(apply(&qbox.nm, "{\"Node\":{\"ID\":1},\"DERPMap\":{\"HomeParams\":{\"RegionScore\":{\"2\":2,\"3\":0,\"4\":-1}},"
                            "\"Regions\":{\"1\":{\"RegionID\":1,\"Nodes\":[{\"HostName\":\"a\"}]},"
                            "\"2\":{\"RegionID\":2,\"Nodes\":[{\"HostName\":\"b\",\"DERPPort\":8443}]},"
                            "\"3\":{\"RegionID\":3,\"NoMeasureNoHome\":true,\"Nodes\":[{\"HostName\":\"c\"}]},"
                            "\"4\":{\"RegionID\":4,\"Avoid\":true,\"Nodes\":[{\"HostName\":\"d\",\"DERPPort\":70000}]},"
                            "\"5\":{\"RegionID\":5,\"Nodes\":[{\"HostName\":\"e\",\"STUNOnly\":true}]},"
                            "\"6\":{\"RegionID\":6,\"Nodes\":[{\"HostName\":\"f\",\"STUNOnly\":true},{\"HostName\":\"g\"}]}}}}") == 1);
    CHECK_INV(&qbox.nm);
    n = ts_derpmap_home_candidates(&qbox.nm, 0, ids, 16);
    CHECK(n == 3 && ids[0] == 1 && ids[1] == 2 && ids[2] == 6);
    CHECK(ts_derpmap_home_candidates(&qbox.nm, 4, ids, 16) == 4);        /* Avoid, but our home now */
    CHECK(ts_derpmap_home_candidates(&qbox.nm, 0, ids, 1) == 3 && ids[0] == 1);
    r = ts_derpmap_find(&qbox.nm, 2);
    CHECK(r && ts_derpmap_port(&ts_derpmap_nodes(&qbox.nm, r)[0]) == 8443);
    CHECK(ts_derpmap_port(&ts_derpmap_nodes(&qbox.nm, ts_derpmap_find(&qbox.nm, 1))[0]) == 443);
    CHECK(ts_derpmap_port(&ts_derpmap_nodes(&qbox.nm, ts_derpmap_find(&qbox.nm, 4))[0]) == 0);
    CHECK(ts_derpmap_find(&qbox.nm, 7) == NULL);

#define MS 1000000ULL
#define LAT(a, b, c, d, e) (lat[0] = (a) * MS, lat[1] = (b) * MS, lat[2] = (c) * MS, lat[3] = (d) * MS, lat[4] = (e) * MS)
    ids[0] = 1, ids[1] = 2, ids[2] = 3, ids[3] = 6, ids[4] = 99;
    /* 2 is scaled by its score 2: 15 ms counts as 30; 3 never wins (NoMeasureNoHome), nor 99 (not in
     * the map); the scores 0 and -1 of 3 and 4 are ignored */
    LAT(20, 15, 1, 40, 1);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 0, ~0ULL) == 1);
    LAT(0, 15, 1, 40, 1);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 0, ~0ULL) == 2);
    LAT(31, 15, 0, 0, 0);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 0, ~0ULL) == 2);
    LAT(30, 15, 0, 0, 0);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 0, ~0ULL) == 1);   /* a tie: the lower id */
    /* stickiness with home 6 */
    LAT(20, 0, 0, 40, 0);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 6, ~0ULL) == 1);   /* 20 ms better, 20 < 40 / 3 * 2 */
    LAT(35, 0, 0, 40, 0);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 6, ~0ULL) == 6);   /* less than 10 ms better */
    LAT(31, 0, 0, 45, 0);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 6, ~0ULL) == 6);   /* 14 ms, but not a third better */
    LAT(29, 0, 0, 45, 0);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 6, ~0ULL) == 1);
    /* home did not answer: kept while heard from in the last 8 s, else given up */
    LAT(29, 0, 0, 0, 0);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 6, 2000 * MS) == 6);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 6, 20000 * MS) == 1);
    /* nothing answered: home kept when heard from in the last 120 s */
    LAT(0, 0, 0, 0, 0);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 6, 60000 * MS) == 6);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 6, 200000 * MS) == 0);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 3, 1000 * MS) == 0);   /* NoMeasureNoHome: never */
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 99, 1000 * MS) == 0);  /* not in the map */
    LAT(29, 0, 40, 0, 0);
    CHECK(ts_derpmap_pick_home(&qbox.nm, ids, lat, 5, 3, 0) == 1);           /* nor kept as home */
#undef LAT
#undef MS
}

/* ------------------------------------------------------------------ DNSConfig (MagicDNS) */

static box dbox;

static int bt_addr_is(const bt_addr* a, const char* text)
{
    int family = 0;
    uint8_t want[16] = { 0 };
    return ts_addr_parse(text, strlen(text), &family, want) && a->family == family && memcmp(a->addr, want, 16) == 0;
}

/* A first message with our node and one peer, `dns` as its DNSConfig ("" - none). */
static int dns_first(const char* dns)
{
    m_reset();
    m_add("{\"Node\":%s,\"Domain\":\"t.example\",\"Peers\":[", self_json);
    m_node(2, "");
    m_add("]%s%s}", dns[0] ? ",\"DNSConfig\":" : "", dns);
    return apply_msg(&dbox.nm);
}

TEST(dnsconfig)
{
    const ts_dnsconf* c;
    char sfx[64];
    char big[2048];
    int i, n;

    box_init(&dbox, 16, sizeof(dbox.arena));
    c = ts_netmap_dns(&dbox.nm);

    /* none in the message: none */
    CHECK(dns_first("") == 1 && !c->present && !c->proxied);
    CHECK(res.changed & TS_NM_CHANGED_DNS);                 /* a session's first message resets it */
    CHECK(ts_netmap_magic_suffix(&dbox.nm, sfx, sizeof(sfx)) == 11 && strcmp(sfx, "tail.ts.net") == 0);
    CHECK(ts_netmap_magic_suffix(&dbox.nm, sfx, 5) == 0 && sfx[0] == '\0');   /* does not fit: none */

    /* plain resolvers kept, DoH / other ports / null left out; domains without their dot; A and
     * AAAA records kept, a CNAME or a mismatched kind left out */
    CHECK(dns_first("{\"Proxied\":true,"
                    "\"Resolvers\":[{\"Addr\":\"1.1.1.1\"},{\"Addr\":\"[2606:4700:4700::1111]:53\"},"
                    "{\"Addr\":\"https://dns.nextdns.io/abc\"},{\"Addr\":\"9.9.9.9:853\"},null,{\"Addr\":\"8.8.8.8:53\"}],"
                    "\"Domains\":[\"tail.ts.net\",\"corp.example.\",null,\"\"],"
                    "\"ExtraRecords\":[{\"Name\":\"x.tail.ts.net.\",\"Value\":\"100.64.0.9\"},"
                    "{\"Name\":\"y.tail.ts.net\",\"Type\":\"AAAA\",\"Value\":\"fd7a:115c:a1e0::9\"},"
                    "{\"Name\":\"z.tail.ts.net\",\"Type\":\"CNAME\",\"Value\":\"x.tail.ts.net\"},"
                    "{\"Name\":\"w.tail.ts.net\",\"Type\":\"A\",\"Value\":\"fd7a::1\"},null],"
                    "\"Routes\":{\"corp.example\":[{\"Addr\":\"10.0.0.53\"}]},\"CertDomains\":[\"me.tail.ts.net\"]}") == 1);
    CHECK(c->present && c->proxied);
    CHECK(c->n_resolvers == 3 && bt_addr_is(&c->resolvers[0], "1.1.1.1") &&
          bt_addr_is(&c->resolvers[1], "2606:4700:4700::1111") && bt_addr_is(&c->resolvers[2], "8.8.8.8"));
    CHECK(c->n_domains == 2 && strcmp(c->domains[0], "tail.ts.net") == 0 && strcmp(c->domains[1], "corp.example") == 0);
    CHECK(c->n_extra == 2 && strcmp(c->extra[0].name, "x.tail.ts.net") == 0 && c->extra[0].family == 4 &&
          strcmp(c->extra[1].name, "y.tail.ts.net") == 0 && c->extra[1].family == 6);
    CHECK(c->left_out == 4);                                /* https, :853, CNAME, A with an IPv6 value */
    CHECK_INV(&dbox.nm);

    /* a delta without it, or with null, keeps it */
    m_reset();
    m_add("{\"PeersChanged\":[");
    m_node(3, "");
    m_add("]}");
    CHECK(apply_msg(&dbox.nm) == 1 && !(res.changed & TS_NM_CHANGED_DNS) && c->proxied && c->n_resolvers == 3);
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":null}") == 1 && !(res.changed & TS_NM_CHANGED_DNS) && c->proxied);
    /* {} replaces it whole */
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{}}") == 1 && (res.changed & TS_NM_CHANGED_DNS));
    CHECK(c->present && !c->proxied && c->n_resolvers == 0 && c->n_domains == 0 && c->n_extra == 0);

    /* refused as Go's Unmarshal refuses it - and nothing changes */
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{\"Proxied\":true}}") == 1 && c->proxied);
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":[]}") == 0 && res.err == TS_NM_ERR_TYPE && c->proxied);
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{\"Proxied\":\"yes\"}}") == 0 && res.err == TS_NM_ERR_TYPE && c->proxied);
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{\"Resolvers\":{}}}") == 0 && res.err == TS_NM_ERR_TYPE);
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{\"Resolvers\":[\"1.1.1.1\"]}}") == 0 && res.err == TS_NM_ERR_TYPE);
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{\"Resolvers\":[{\"Addr\":1}]}}") == 0 && res.err == TS_NM_ERR_TYPE);
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{\"Domains\":[1]}}") == 0 && res.err == TS_NM_ERR_TYPE);
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{\"ExtraRecords\":[{\"Name\":[]}]}}") == 0 && res.err == TS_NM_ERR_TYPE);
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{\"Proxied\":false,\"proxied\":false}}") == 0 && res.err == TS_NM_ERR_DUPLICATE);
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{},\"DNSConfig\":{}}") == 0 && res.err == TS_NM_ERR_DUPLICATE);
    CHECK(c->proxied && c->n_resolvers == 0);
    /* a name or value over our limit, or too many items: left out, not refused */
    n = snprintf(big, sizeof(big), "{\"DNSConfig\":{\"Domains\":[\"");
    for (i = 0; i < 300; i++) big[n++] = 'a';
    n += snprintf(big + n, sizeof(big) - (size_t)n, "\"],\"Resolvers\":[");
    for (i = 0; i < 10; i++) n += snprintf(big + n, sizeof(big) - (size_t)n, "%s{\"Addr\":\"10.0.0.%d\"}", i ? "," : "", i + 1);
    n += snprintf(big + n, sizeof(big) - (size_t)n, "]}}");
    CHECK(apply_n(&dbox.nm, big, (size_t)n, vec_now()) == 1);
    CHECK(c->n_domains == 0 && c->n_resolvers == TS_DNS_RESOLVERS_MAX && c->left_out == 3);
    CHECK(bt_addr_is(&c->resolvers[7], "10.0.0.8"));
    CHECK_INV(&dbox.nm);

    /* a new session starts with none until it brings its own */
    ts_netmap_session_start(&dbox.nm);
    CHECK(c->n_resolvers == TS_DNS_RESOLVERS_MAX);          /* the old one readable until then */
    CHECK(dns_first("") == 1 && !c->present && c->n_resolvers == 0);
}

/* Split DNS: DNSConfig.Routes, kept as the resolver will follow them. */
TEST(dnsconfig_routes)
{
    const ts_dnsconf* c;
    static char big[16384];
    int i, n;

    box_init(&dbox, 16, sizeof(dbox.arena));
    c = ts_netmap_dns(&dbox.nm);
    CHECK(dns_first("{\"Proxied\":true,\"Routes\":{"
                    "\"Corp.Example.\":[{\"Addr\":\"10.0.0.53\"},{\"Addr\":\"https://doh.example/q\"},{\"Addr\":\"[fd00::53]:53\"}],"
                    "\"local.example\":null,"
                    "\"empty.example\":[],"
                    "\"doh.example\":[{\"Addr\":\"https://doh.example/q\"},null],"
                    "\"twice.example\":[{\"Addr\":\"1.1.1.1\"}],"
                    "\"twice.example\":[{\"Addr\":\"2.2.2.2\"}],"
                    "\"\":[{\"Addr\":\"3.3.3.3\"}]}}") == 1);
    CHECK(c->n_routes == 5);
    CHECK(strcmp(c->routes[0].suffix, "corp.example") == 0 && c->routes[0].n_servers == 2 && !c->routes[0].unusable &&
          bt_addr_is(&c->routes[0].servers[0], "10.0.0.53") && bt_addr_is(&c->routes[0].servers[1], "fd00::53"));
    CHECK(strcmp(c->routes[1].suffix, "local.example") == 0 && c->routes[1].n_servers == 0 && !c->routes[1].unusable);
    CHECK(strcmp(c->routes[2].suffix, "empty.example") == 0 && c->routes[2].n_servers == 0 && !c->routes[2].unusable);
    CHECK(strcmp(c->routes[3].suffix, "doh.example") == 0 && c->routes[3].n_servers == 0 && c->routes[3].unusable);
    CHECK(strcmp(c->routes[4].suffix, "twice.example") == 0 && c->routes[4].n_servers == 1 &&
          bt_addr_is(&c->routes[4].servers[0], "2.2.2.2"));                 /* the last one, as a Go map */
    CHECK(c->left_out == 3);                                /* two DoH, the empty suffix */
    CHECK_INV(&dbox.nm);

    /* refused as Go's Unmarshal refuses it */
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{\"Routes\":[]}}") == 0 && res.err == TS_NM_ERR_TYPE);
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{\"Routes\":{\"a.example\":{}}}}") == 0 && res.err == TS_NM_ERR_TYPE);
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{\"Routes\":{\"a.example\":[\"1.1.1.1\"]}}}") == 0 && res.err == TS_NM_ERR_TYPE);
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{\"Routes\":{\"a.example\":[{\"Addr\":5}]}}}") == 0 && res.err == TS_NM_ERR_TYPE);
    CHECK(c->n_routes == 5);                                /* nothing changed */
    CHECK(apply(&dbox.nm, "{\"DNSConfig\":{\"Routes\":null}}") == 1 && c->n_routes == 0);

    /* more routes, more servers than we keep: left out, counted */
    n = snprintf(big, sizeof(big), "{\"DNSConfig\":{\"Routes\":{");
    for (i = 0; i < 140; i++) n += snprintf(big + n, sizeof(big) - (size_t)n, "%s\"r%d.example\":[{\"Addr\":\"10.0.0.1\"}]", i ? "," : "", i);
    n += snprintf(big + n, sizeof(big) - (size_t)n, ",\"many.example\":[");
    for (i = 0; i < 6; i++) n += snprintf(big + n, sizeof(big) - (size_t)n, "%s{\"Addr\":\"10.0.1.%d\"}", i ? "," : "", i + 1);
    n += snprintf(big + n, sizeof(big) - (size_t)n, "]}}}");
    REQUIRE((size_t)n < sizeof(big));
    CHECK(apply_n(&dbox.nm, big, (size_t)n, vec_now()) == 1);
    CHECK(c->n_routes == TS_DNS_ROUTES_MAX && c->left_out == 140 - TS_DNS_ROUTES_MAX + 1 + 2);
    CHECK_INV(&dbox.nm);

    /* what control sends of its own: the reverse zones of the tailnet's ranges, MagicDNS's - with room
     * beside them for the tailnet's own routes */
    n = snprintf(big, sizeof(big), "{\"DNSConfig\":{\"Proxied\":true,\"Routes\":{\"0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.\":null");
    for (i = 64; i < 128; i++) n += snprintf(big + n, sizeof(big) - (size_t)n, ",\"%d.100.in-addr.arpa.\":null", i);
    n += snprintf(big + n, sizeof(big) - (size_t)n, ",\"corp.split\":[{\"Addr\":\"10.20.0.5\"}]}}}");
    CHECK(apply_n(&dbox.nm, big, (size_t)n, vec_now()) == 1);
    CHECK(c->n_routes == 66 && c->left_out == 0);
    CHECK(strcmp(c->routes[65].suffix, "corp.split") == 0 && c->routes[65].n_servers == 1);
    CHECK(strcmp(c->routes[1].suffix, "64.100.in-addr.arpa") == 0 && c->routes[1].n_servers == 0);
}

/* ------------------------------------------------------------------ fuzz */

static uint64_t xs = 0x3c6ef372fe94f82bULL;

static uint64_t rnd(void)
{
    xs ^= xs >> 12;
    xs ^= xs << 25;
    xs ^= xs >> 27;
    return xs * 0x2545f4914f6cdd1dULL;
}

static void mutate(uint8_t* buf, size_t* len, size_t cap)
{
    static const uint8_t special[] = { '"', '\\', '{', '}', '[', ']', ':', ',', '0', '-', 'e', '.', 'n', 't',
                                       ' ', 0, 0x1f, 0x80, 0xc3, 0xed, 0xff, 'u', '/' };
    size_t n = *len, i, at;
    int k = (int)(rnd() % 7), times = 1 + (int)(rnd() % 3);

    switch (k) {
    case 0: while (n && times--) buf[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8)); break;
    case 1: while (n && times--) buf[rnd() % n] = special[rnd() % sizeof(special)]; break;
    case 2: if (n) *len = rnd() % n; break;
    case 3:
        if (n > 1) {                                    /* drop a slice */
            size_t from = rnd() % n, cnt = 1 + rnd() % (n - from);
            memmove(buf + from, buf + from + cnt, n - from - cnt);
            *len = n - cnt;
        }
        break;
    case 4:
        at = rnd() % (n + 1);                           /* insert a few bytes */
        for (i = 0; i < (size_t)times && n + 1 <= cap; i++, n++) {
            memmove(buf + at + 1, buf + at, n - at);
            buf[at] = special[rnd() % sizeof(special)];
        }
        *len = n;
        break;
    case 5:
        if (n > 2) {                                    /* duplicate a slice */
            size_t from = rnd() % n, cnt = 1 + rnd() % (n - from);
            if (n + cnt <= cap) {
                memmove(buf + from + cnt, buf + from, n - from);
                *len = n + cnt;
            }
        }
        break;
    default:
        if (n > 4) {                                    /* swap two digits or quotes for others */
            size_t p = rnd() % n;
            if (buf[p] >= '0' && buf[p] <= '9') buf[p] = (uint8_t)('0' + rnd() % 10);
            else if (buf[p] == '"') buf[p] = (uint8_t)(rnd() & 1 ? '\'' : '"');
        }
        break;
    }
}

/* Every token reached once by walking down from the root; each value readable. */
static int walk_ok(const ts_json* d)
{
    static int stack[TS_JSON_MAX_DEPTH + 2];
    static char sbuf[1 << 16];
    int sp = 0, visited = 1, t;

    if (ts_json_skip(d, 0) != d->n) return 0;
    stack[sp++] = 0;
    while (sp) {
        int c = stack[--sp], k;
        for (k = ts_json_first(d, c); k >= 0; k = ts_json_next(d, k)) {
            int v = k;
            size_t len;
            visited++;
            if (ts_json_type_of(d, c) == TS_JSON_OBJECT) {
                char f[32];
                int64_t iv;
                if (ts_json_type_of(d, k) != TS_JSON_STRING) return 0;
                ts_json_key_fold(d, k, f, sizeof(f));
                ts_json_key_i64(d, k, &iv);
                v = k + 1;
                visited++;
            }
            switch (ts_json_type_of(d, v)) {
            case TS_JSON_OBJECT:
            case TS_JSON_ARRAY:
                if (sp >= TS_JSON_MAX_DEPTH + 2) return 0;
                stack[sp++] = v;
                break;
            case TS_JSON_STRING:
                if (!ts_json_str(d, v, sbuf, sizeof(sbuf), &len)) return 0;
                break;
            case TS_JSON_NUMBER: {
                double x;
                int64_t iv;
                ts_json_i64(d, v, &iv);
                ts_json_f64(d, v, &x);
                break;
            }
            case TS_JSON_NONE:
                return 0;
            default:
                break;
            }
        }
    }
    for (t = 0; t < d->n; t++)
        if (ts_json_skip(d, t) <= t || ts_json_skip(d, t) > d->n) return 0;
    return visited == d->n;
}

static const char* const json_seeds[] = {
    "{\"a\":[1,-2.5e3,true,false,null],\"b\":{\"c\":\"\\u00e9\\ud83d\\ude00\\n\"},\"d\":[]}",
    "[{},[],\"\",0,-0,1E+2,{\"x\":{\"y\":{\"z\":[[[\"deep\"]]]}}}]",
    "{\"Peers\":[{\"ID\":2,\"Name\":\"n.\",\"Addresses\":[\"100.64.0.2/32\"]}],\"Domain\":\"d\"}",
};

TEST(fuzz_json)
{
    static uint8_t buf[1 << 15];
    int iter, ok = 0;

    for (iter = 0; iter < 30000; iter++) {
        size_t len, cap = sizeof(buf);
        uint8_t* exact;
        int m, parsed;
        long count;

        if (iter % 3 == 0) {
            const char* s = json_seeds[rnd() % (sizeof(json_seeds) / sizeof(json_seeds[0]))];
            len = strlen(s);
            memcpy(buf, s, len);
        } else {
            const nm_vec_step* v = &nm_vec_steps[rnd() % (sizeof(nm_vec_steps) / sizeof(nm_vec_steps[0]))];
            len = v->len < cap ? v->len : cap;
            memcpy(buf, v->json, len);
        }
        for (m = (int)(rnd() % 4); m >= 0; m--) mutate(buf, &len, cap);
        exact = (uint8_t*)malloc(len ? len : 1);
        memcpy(exact, buf, len);
        count = ts_json_count((const char*)exact, len);
        parsed = ts_json_parse(&doc, (const char*)exact, len, tok, NTOK);
        if (parsed) {
            ok++;
            CHECK(walk_ok(&doc));
            CHECK(count == doc.n);
            /* the exact count is enough, one fewer is not */
            CHECK(ts_json_parse(&doc, (const char*)exact, len, tok, (size_t)count));
            CHECK(!ts_json_parse(&doc, (const char*)exact, len, tok, (size_t)count - 1) && doc.err == TS_JSON_ERR_TOKENS);
        } else {
            CHECK(doc.err != TS_JSON_OK && doc.n == 0);
        }
        free(exact);
    }
    CHECK(ok > 1000);                       /* the mutations leave enough valid JSON to walk */
}

/* Random JSON with strings of every kind of escape; what ts_json reads back must be what was put. */
typedef struct {
    char   text[1 << 16];
    size_t len;
    char   want[512][96];               /* the unescaped strings, in text order */
    size_t want_len[512];
    int    nwant;
    int64_t ints[512];
    int    nints;
} gen;

static void g_put(gen* g, const char* s, size_t n)
{
    if (g->len + n < sizeof(g->text)) {
        memcpy(g->text + g->len, s, n);
        g->len += n;
    }
}

static void g_str(gen* g)
{
    char* w = g->want[g->nwant < 512 ? g->nwant : 511];
    size_t wl = 0;
    int i, n = (int)(rnd() % 12);

    g_put(g, "\"", 1);
    for (i = 0; i < n && wl + 4 < 96; i++) {
        unsigned k = (unsigned)(rnd() % 8);
        char e[16];
        if (k == 0) {                                   /* plain */
            char c = (char)('a' + rnd() % 26);
            g_put(g, &c, 1);
            w[wl++] = c;
        } else if (k == 1) {                            /* a short escape */
            static const char from[] = "\"\\/bfnrt", to[] = "\"\\/\b\f\n\r\t";
            int j = (int)(rnd() % 8);
            e[0] = '\\';
            e[1] = from[j];
            g_put(g, e, 2);
            w[wl++] = to[j];
        } else if (k == 2) {                            /* \u, a BMP character not a surrogate */
            unsigned r = 0x20 + (unsigned)(rnd() % 0xd7e0);
            sprintf(e, "\\u%04x", r);
            g_put(g, e, 6);
            if (r < 0x80) w[wl++] = (char)r;
            else if (r < 0x800) {
                w[wl++] = (char)(0xc0 | (r >> 6));
                w[wl++] = (char)(0x80 | (r & 0x3f));
            } else {
                w[wl++] = (char)(0xe0 | (r >> 12));
                w[wl++] = (char)(0x80 | ((r >> 6) & 0x3f));
                w[wl++] = (char)(0x80 | (r & 0x3f));
            }
        } else if (k == 3) {                            /* a pair */
            unsigned r = 0x10000 + (unsigned)(rnd() % 0x100000);
            sprintf(e, "\\u%04X\\u%04x", 0xd800 + ((r - 0x10000) >> 10), 0xdc00 + ((r - 0x10000) & 0x3ff));
            g_put(g, e, 12);
            w[wl++] = (char)(0xf0 | (r >> 18));
            w[wl++] = (char)(0x80 | ((r >> 12) & 0x3f));
            w[wl++] = (char)(0x80 | ((r >> 6) & 0x3f));
            w[wl++] = (char)(0x80 | (r & 0x3f));
        } else if (k == 4) {                            /* a lone half: a low one, or a high one and 'x' */
            if (rnd() % 2) {
                sprintf(e, "\\u%04x", 0xdc00 + (unsigned)(rnd() % 0x400));
                g_put(g, e, 6);
            } else {
                sprintf(e, "\\u%04Xx", 0xd800 + (unsigned)(rnd() % 0x400));
                g_put(g, e, 7);
            }
            memcpy(w + wl, "\xef\xbf\xbd", 3);
            wl += 3;
            if (e[6] == 'x') w[wl++] = 'x';
        } else if (k == 5) {                            /* raw UTF-8 */
            g_put(g, "\xd0\xb6", 2);
            memcpy(w + wl, "\xd0\xb6", 2);
            wl += 2;
        } else if (k == 6) {                            /* a raw byte that is no UTF-8 */
            g_put(g, "\xfe", 1);
            memcpy(w + wl, "\xef\xbf\xbd", 3);
            wl += 3;
        } else {
            g_put(g, "\\u0000", 6);
            w[wl++] = '\0';
        }
    }
    g_put(g, "\"", 1);
    if (g->nwant < 512) g->want_len[g->nwant++] = wl;
}

static void g_value(gen* g, int depth)
{
    unsigned k = (unsigned)(rnd() % (depth > 5 ? 4 : 6));
    int i, n;

    if (k == 0) {
        g_str(g);
    } else if (k == 1) {
        char s[32];
        int64_t v = (int64_t)rnd();
        if (rnd() % 2) v %= 1000;
        sprintf(s, "%lld", (long long)v);
        g_put(g, s, strlen(s));
        if (g->nints < 512) g->ints[g->nints++] = v;
    } else if (k == 2) {
        static const char* lit[] = { "true", "false", "null" };
        const char* s = lit[rnd() % 3];
        g_put(g, s, strlen(s));
    } else if (k == 3) {
        g_put(g, " ", 1);
        g_str(g);
    } else if (k == 4) {
        n = (int)(rnd() % 4);
        g_put(g, "[", 1);
        for (i = 0; i < n; i++) {
            if (i) g_put(g, ",", 1);
            g_value(g, depth + 1);
        }
        g_put(g, "]", 1);
    } else {
        n = (int)(rnd() % 4);
        g_put(g, "{", 1);
        for (i = 0; i < n; i++) {
            if (i) g_put(g, ", ", 2);
            g_str(g);
            g_put(g, ":", 1);
            g_value(g, depth + 1);
        }
        g_put(g, "}", 1);
    }
}

TEST(fuzz_json_roundtrip)
{
    static gen g;
    static char out[256];
    int iter;

    for (iter = 0; iter < 3000; iter++) {
        int t, si = 0, ii = 0, ok = 1;

        g.len = 0;
        g.nwant = 0;
        g.nints = 0;
        g_put(&g, "[", 1);
        g_value(&g, 0);
        g_put(&g, "]", 1);
        g.text[g.len] = '\0';                           /* for the messages only: parsed by length */
        if (!ts_json_parse(&doc, g.text, g.len, tok, NTOK)) {
            fprintf(stderr, "    refused: %.200s (%s)\n", g.text, ts_json_err_text(doc.err));
            CHECK(0);
            continue;
        }
        for (t = 0; t < doc.n && ok; t++) {
            size_t len;
            if (ts_json_type_of(&doc, t) == TS_JSON_STRING && si < g.nwant) {
                ok = ts_json_str(&doc, t, out, sizeof(out), &len) && len == g.want_len[si] &&
                     memcmp(out, g.want[si], len) == 0;
                si++;
            } else if (ts_json_type_of(&doc, t) == TS_JSON_NUMBER && ii < g.nints) {
                int64_t v;
                ok = ts_json_i64(&doc, t, &v) && v == g.ints[ii];
                ii++;
            }
        }
        if (!ok) fprintf(stderr, "    differs: %.200s\n", g.text);
        CHECK(ok && si == g.nwant && ii == g.nints);
    }
}

static box fbox;

/* The vectors carry no DNSConfig: these go in among them (MagicDNS, docs/TAILSCALE.md section 8a). */
static const char* const dns_seeds[] = {
    "{\"DNSConfig\":{\"Proxied\":true,\"Resolvers\":[{\"Addr\":\"1.1.1.1\"},{\"Addr\":\"[2606:4700:4700::1111]:53\"},"
    "{\"Addr\":\"https://dns.example/q\"}],\"Domains\":[\"tail.ts.net\",\"corp.example.\"],"
    "\"ExtraRecords\":[{\"Name\":\"x.tail.ts.net.\",\"Value\":\"100.64.0.9\"},{\"Name\":\"y\",\"Type\":\"AAAA\",\"Value\":\"fd7a::9\"}],"
    "\"Routes\":{\"corp.example\":[{\"Addr\":\"10.0.0.53\"}]}}}",
    "{\"DNSConfig\":{\"Proxied\":false,\"Domains\":null,\"Resolvers\":null,\"ExtraRecords\":[null]}}",
    "{\"DNSConfig\":null,\"PeerSeenChange\":{\"2\":true}}",
};

TEST(fuzz_netmap)
{
    static uint8_t buf[1 << 15];
    static char before[1 << 18];
    static ts_dnsconf dns_before;
    size_t nsteps = sizeof(nm_vec_steps) / sizeof(nm_vec_steps[0]);
    int iter, applied = 0, refused = 0;

    /* a small table and arena, so the limits are met as well */
    box_init(&fbox, 12, 6000);
    for (iter = 0; iter < 6000; iter++) {
        const nm_vec_step* v = &nm_vec_steps[rnd() % nsteps];
        size_t len = v->len < sizeof(buf) ? v->len : sizeof(buf);
        uint8_t* exact;
        int m, r;

        if (rnd() % 50 == 0) ts_netmap_session_start(&fbox.nm);
        if (rnd() % 5 == 0) {
            const char* s = dns_seeds[rnd() % (sizeof(dns_seeds) / sizeof(dns_seeds[0]))];
            len = strlen(s);
            memcpy(buf, s, len);
        } else {
            memcpy(buf, v->json, len);
        }
        if (rnd() % 4) {
            for (m = (int)(rnd() % 3); m >= 0; m--) mutate(buf, &len, sizeof(buf));
        }
        exact = (uint8_t*)malloc(len ? len : 1);
        memcpy(exact, buf, len);
        strcpy(before, dump(&fbox.nm));
        memcpy(&dns_before, ts_netmap_dns(&fbox.nm), sizeof(dns_before));   /* padding too: memcmp below */
        r = apply_n(&fbox.nm, (const char*)exact, len, at(NM_VEC_NOW_SEC + (int64_t)(rnd() % 1000)));
        if (r == 1) {
            applied++;
        } else {
            refused++;
            if (strcmp(dump(&fbox.nm), before) != 0) show_diff("refusal changed the netmap", before, dump(&fbox.nm));
            CHECK(strcmp(dump(&fbox.nm), before) == 0);
            CHECK(memcmp(&dns_before, ts_netmap_dns(&fbox.nm), sizeof(dns_before)) == 0);
        }
        {
            /* whatever came in: within its arrays, names terminated */
            const ts_dnsconf* c = ts_netmap_dns(&fbox.nm);
            size_t k;
            CHECK(c->n_resolvers <= TS_DNS_RESOLVERS_MAX && c->n_domains <= TS_DNS_DOMAINS_MAX &&
                  c->n_extra <= TS_DNS_EXTRA_MAX);
            for (k = 0; k < c->n_domains; k++) CHECK(memchr(c->domains[k], '\0', sizeof(c->domains[k])) != NULL);
            for (k = 0; k < c->n_extra; k++) CHECK(memchr(c->extra[k].name, '\0', sizeof(c->extra[k].name)) != NULL);
        }
        CHECK_INV(&fbox.nm);
        /* the queries on whatever came out */
        {
            uint8_t a[16];
            wg_prefix out[8];
            int64_t ids[8];
            uint64_t lat[8];
            const ts_node* on[4];
            size_t i;
            memset(a, 0, sizeof(a));
            a[0] = 100;
            a[1] = 64;
            a[3] = (uint8_t)rnd();
            ts_netmap_route(&fbox.nm, 4, a, (unsigned)(rnd() & 1), (int64_t)(rnd() % 8), vec_now());
            ts_netmap_os_routes(&fbox.nm, TS_ROUTE_SUBNETS, 5, vec_now(), out, 8);
            ts_netmap_online(&fbox.nm, on, 4);
            for (i = 0; i < ts_netmap_count(&fbox.nm); i++) {
                char name[64];
                ts_netmap_node_routes(&fbox.nm, ts_netmap_at(&fbox.nm, i), TS_ROUTE_SUBNETS, 5, vec_now(), out, 8);
                ts_node_display_name(&fbox.nm, ts_netmap_at(&fbox.nm, i), name, sizeof(name));
            }
            i = ts_derpmap_home_candidates(&fbox.nm, 4, ids, 8);
            for (m = 0; m < 8; m++) lat[m] = rnd() % 100000000ULL;
            ts_derpmap_pick_home(&fbox.nm, ids, lat, i < 8 ? i : 8, 4, rnd() % 200000000000ULL);
        }
        free(exact);
    }
    CHECK(applied > 500 && refused > 500);
}

int main(void)
{
    const char* seed = getenv("BT_FUZZ_SEED");

    if (seed) xs = strtoull(seed, NULL, 16) | 1;
    printf("test_ts_netmap (fuzz seed %llx)\n", (unsigned long long)xs);
    RUN(json_tokens_and_walk);
    RUN(json_rejects);
    RUN(json_depth_and_tokens);
    RUN(json_strings);
    RUN(json_names);
    RUN(json_numbers);
    RUN(time_forms);
    RUN(address_forms);
    RUN(prefix_and_key_forms);
    RUN(vectors_map_sessions);
    RUN(vectors_key_and_register);
    RUN(register_edges);
    RUN(limits_table);
    RUN(limits_node);
    RUN(limits_arena);
    RUN(limits_derp);
    RUN(refusals_are_atomic);
    RUN(generations);
    RUN(queries_route);
    RUN(queries_lookup);
    RUN(queries_expiry);
    RUN(queries_derp_home);
    RUN(dnsconfig);
    RUN(dnsconfig_routes);
    RUN(fuzz_json);
    RUN(fuzz_json_roundtrip);
    RUN(fuzz_netmap);
    return t_summary("test_ts_netmap");
}
