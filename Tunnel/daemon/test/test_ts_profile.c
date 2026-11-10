/*
 * ts_profile: control URLs taken apart (and the ones refused), auth keys, a profile through its
 * text form and back, logging in again, and every way a stored profile can be broken. The mutation
 * check of this test: build/ts-mut/mutate.py.
 */

#include "test_util.h"
#include "../src/ts_profile.h"

static int all_zero(const void* p, size_t n)
{
    const uint8_t* b = (const uint8_t*)p;
    size_t i;
    for (i = 0; i < n; i++)
        if (b[i]) return 0;
    return 1;
}

TEST(test_url)
{
    static const struct {
        const char* url;
        int         ok, tls, port, literal;
        const char* host;
    } cases[] = {
        { "https://controlplane.tailscale.com", 1, 1, 443, 0, "controlplane.tailscale.com" },
        { "https://controlplane.tailscale.com/", 1, 1, 443, 0, "controlplane.tailscale.com" },
        { "HTTPS://Example.com:8443", 1, 1, 8443, 0, "Example.com" },
        { "http://10.20.0.1:8080", 1, 0, 8080, 1, "10.20.0.1" },
        { "http://10.20.0.1", 1, 0, 80, 1, "10.20.0.1" },
        { "http://[fd00::1]:8080/", 1, 0, 8080, 1, "fd00::1" },
        { "https://[2001:db8::2]", 1, 1, 443, 1, "2001:db8::2" },
        { "https://hs.example.com:65535", 1, 1, 65535, 0, "hs.example.com" },
        { "ftp://example.com", 0, 0, 0, 0, NULL },
        { "https://", 0, 0, 0, 0, NULL },
        { "https:///", 0, 0, 0, 0, NULL },
        { "https://example.com/path", 0, 0, 0, 0, NULL },
        { "https://example.com//", 0, 0, 0, 0, NULL },
        { "https://example.com:", 0, 0, 0, 0, NULL },
        { "https://example.com:0", 0, 0, 0, 0, NULL },
        { "https://example.com:65536", 0, 0, 0, 0, NULL },
        { "https://example.com:44x", 0, 0, 0, 0, NULL },
        { "https://exa mple.com", 0, 0, 0, 0, NULL },
        { "https://fd00::1", 0, 0, 0, 0, NULL },
        { "https://[10.0.0.1]", 0, 0, 0, 0, NULL },
        { "https://[fd00::1", 0, 0, 0, 0, NULL },
        { "https://[fd00::1]8443", 0, 0, 0, 0, NULL },
        { "https://example.com?x=1", 0, 0, 0, 0, NULL },
        { "controlplane.tailscale.com", 0, 0, 0, 0, NULL },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        ts_url u;
        int ok = ts_url_parse(cases[i].url, strlen(cases[i].url), &u);
        CHECK(ok == cases[i].ok);
        if (ok != cases[i].ok) fprintf(stderr, "    url %s\n", cases[i].url);
        if (!ok || !cases[i].ok) continue;
        CHECK(u.tls == cases[i].tls);
        CHECK(u.port == cases[i].port);
        CHECK(u.literal == cases[i].literal);
        CHECK(strcmp(u.host, cases[i].host) == 0);
    }
    /* A NUL inside is not a shorter URL. */
    {
        ts_url u;
        CHECK(!ts_url_parse("https://a.com\0.evil", 19, &u));
    }

    /* The longest name, 253 characters, is a host; a longer one is refused before it is copied
     * into host[] (a 290-character one would not fit the struct). */
    {
        static char url[TS_URL_MAX + 2];
        ts_url u;
        for (i = 0; i < 290; i++) url[8 + i] = i % 64 == 63 ? '.' : 'a';
        memcpy(url, "https://", 8);
        CHECK(ts_url_parse(url, 8 + 253, &u) && strlen(u.host) == 253 && u.port == 443);
        CHECK(!ts_url_parse(url, 8 + 290, &u));

        /* More than 300 characters is refused even when the rest is fine (a port may be written
         * with leading zeros), so a profile never keeps a control URL cut short. */
        memcpy(url, "https://a.com:", 14);
        memset(url + 14, '0', TS_URL_MAX + 1 - 14 - 3);
        memcpy(url + TS_URL_MAX + 1 - 3, "443", 4);
        CHECK(strlen(url) == TS_URL_MAX + 1);
        CHECK(!ts_url_parse(url, strlen(url), &u));
    }
}

TEST(test_authkey)
{
    char big[TS_AUTHKEY_MAX + 2];

    CHECK(ts_authkey_valid("tskey-auth-kAbCdEf1CNTRL-0123456789abcdef", 41));
    CHECK(ts_authkey_valid("0123456789abcdef0123456789abcdef0123456789abcdef", 48));
    CHECK(!ts_authkey_valid("", 0));
    CHECK(!ts_authkey_valid("tskey auth", 10));
    CHECK(!ts_authkey_valid("tskey\nauth", 10));
    CHECK(!ts_authkey_valid("tskey\xd0\xb0", 7));
    CHECK(!ts_authkey_valid("tskey\x7f", 6));
    memset(big, 'k', sizeof(big));
    CHECK(ts_authkey_valid(big, TS_AUTHKEY_MAX));
    CHECK(!ts_authkey_valid(big, TS_AUTHKEY_MAX + 1));

    CHECK(ts_hostname_valid("passport", 8));
    CHECK(ts_hostname_valid("Q10-1", 5));
    CHECK(!ts_hostname_valid("", 0));
    CHECK(!ts_hostname_valid("-a", 2));
    CHECK(!ts_hostname_valid("a-", 2));
    CHECK(!ts_hostname_valid("a.b", 3));
    CHECK(!ts_hostname_valid("a_b", 3));
    CHECK(!ts_hostname_valid("1234567890123456789012345678901234567890123456789012345678901234", 64));
    CHECK(ts_hostname_valid("1234567890123456789012345678901234567890123456789012345678901234", 63));
}

static int fixed_rng(void* ctx, void* buf, size_t len)
{
    uint8_t* p = (uint8_t*)buf;
    uint8_t* n = (uint8_t*)ctx;
    size_t i;
    for (i = 0; i < len; i++) p[i] = (*n)++;
    return 1;
}

static uint8_t rng_state;
static const wg_rng RNG = { fixed_rng, &rng_state };

static char text[8192];

TEST(test_round_trip)
{
    ts_profile p, q;
    size_t n;

    rng_state = 1;
    REQUIRE(ts_profile_new(&p, NULL, "tskey-auth-abc", &RNG));
    CHECK(strcmp(p.control, TS_CONTROL_DEFAULT) == 0);
    CHECK(strcmp(p.auth_key, "tskey-auth-abc") == 0);
    CHECK(!p.registered && !p.has_old_node && !p.has_server);
    CHECK(memcmp(&p.machine, &p.node, sizeof(wg_key)) != 0);

    /* The bare profile. */
    n = ts_profile_format(&p, text, sizeof(text));
    REQUIRE(n > 0);
    CHECK(ts_profile_is(text, n));
    REQUIRE(ts_profile_parse(&q, text, n));
    CHECK(strcmp(q.control, p.control) == 0);
    CHECK_MEM(&q.machine, &p.machine, sizeof(wg_key));
    CHECK_MEM(&q.node, &p.node, sizeof(wg_key));
    CHECK(strcmp(q.auth_key, p.auth_key) == 0);
    CHECK(!q.registered && !q.has_old_node && !q.has_server);

    /* Wiped: not a byte of it left, the auth key included. */
    ts_profile_wipe(&q);
    CHECK(all_zero(&q, sizeof(q)));

    /* Everything filled in. */
    p.registered = 1;
    p.auth_key[0] = '\0';
    memset(p.old_node.b, 0xcd, 32);
    p.has_old_node = 1;
    memset(p.server.b, 0xab, 32);
    p.has_server = 1;
    snprintf(p.control_addr, sizeof(p.control_addr), "192.200.0.101");
    snprintf(p.hostname, sizeof(p.hostname), "passport-2");
    snprintf(p.tailnet, sizeof(p.tailnet), "example.org.github");
    snprintf(p.node_name, sizeof(p.node_name), "passport.tail1234.ts.net.");
    snprintf(p.address[0], sizeof(p.address[0]), "100.64.0.7/32");
    snprintf(p.address[1], sizeof(p.address[1]), "fd7a:115c:a1e0::7/128");
    p.n_address = 2;
    n = ts_profile_format(&p, text, sizeof(text));
    REQUIRE(n > 0);
    REQUIRE(ts_profile_parse(&q, text, n));
    CHECK(q.registered && !q.auth_key[0]);
    CHECK(q.has_old_node);
    CHECK_MEM(&q.old_node, &p.old_node, sizeof(wg_key));
    CHECK(q.has_server);
    CHECK_MEM(&q.server, &p.server, sizeof(wg_key));
    CHECK(strcmp(q.control_addr, "192.200.0.101") == 0);
    CHECK(strcmp(q.hostname, "passport-2") == 0);
    CHECK(strcmp(q.tailnet, "example.org.github") == 0);
    CHECK(strcmp(q.node_name, "passport.tail1234.ts.net.") == 0);
    CHECK(q.n_address == 2);
    CHECK(strcmp(q.address[1], "fd7a:115c:a1e0::7/128") == 0);

    /* The stand: another control server. */
    REQUIRE(ts_profile_new(&p, "http://10.20.0.1:8080/", "k", &RNG));
    CHECK(strcmp(p.control, "http://10.20.0.1:8080") == 0);
    CHECK(!ts_profile_new(&p, "http://10.20.0.1:8080/x", "k", &RNG));
    CHECK(!ts_profile_new(&p, NULL, "bad key", &RNG));

    /* No key: a login by a link (section 11b) - nothing kept to log in with, and it reads back so. */
    {
        static char text[4096];
        ts_profile q;
        size_t n;
        REQUIRE(ts_profile_new(&p, NULL, NULL, &RNG));
        CHECK(p.auth_key[0] == '\0');
        CHECK(!p.registered);
        REQUIRE(ts_profile_new(&p, NULL, "", &RNG));
        CHECK(p.auth_key[0] == '\0');
        n = ts_profile_format(&p, text, sizeof(text));
        REQUIRE(n > 0);
        CHECK(strstr(text, "auth_key=") == NULL);
        REQUIRE(ts_profile_parse(&q, text, n));
        CHECK(q.auth_key[0] == '\0');
        CHECK(!q.registered);
    }

    /* A control URL longer than the profile keeps is refused, not cut short (to a port of 44). */
    {
        static char url[TS_URL_MAX + 2];
        memcpy(url, "https://a.com:", 14);
        memset(url + 14, '0', TS_URL_MAX + 1 - 14 - 3);
        memcpy(url + TS_URL_MAX + 1 - 3, "443", 4);
        CHECK(!ts_profile_new(&p, url, "k", &RNG));
    }
}

TEST(test_relogin)
{
    ts_profile p;
    wg_key machine, node;

    rng_state = 7;
    REQUIRE(ts_profile_new(&p, NULL, "first", &RNG));
    machine = p.machine;
    node = p.node;

    /* Never registered: a new node key, no old one to name. */
    REQUIRE(ts_profile_relogin(&p, "second", &RNG));
    CHECK(!p.has_old_node);
    CHECK(memcmp(&p.node, &node, sizeof(node)) != 0);
    CHECK_MEM(&p.machine, &machine, sizeof(machine));
    CHECK(strcmp(p.auth_key, "second") == 0);

    /* Registered: the current key becomes the old one; the old node's addresses are not kept. */
    p.registered = 1;
    snprintf(p.address[0], sizeof(p.address[0]), "100.117.117.116/32");
    p.n_address = 1;
    node = p.node;
    REQUIRE(ts_profile_relogin(&p, "third", &RNG));
    CHECK(p.has_old_node);
    CHECK_MEM(&p.old_node, &node, sizeof(node));
    CHECK(!p.registered);
    CHECK(memcmp(&p.node, &node, sizeof(node)) != 0);
    CHECK_MEM(&p.machine, &machine, sizeof(machine));
    CHECK(p.n_address == 0);
    CHECK(p.address[0][0] == '\0');

    /* A bad key changes nothing. */
    node = p.node;
    CHECK(!ts_profile_relogin(&p, "two words", &RNG));
    CHECK_MEM(&p.node, &node, sizeof(node));
    CHECK(strcmp(p.auth_key, "third") == 0);

    /* By a link: a new node key, the registered one named, and no key - the earlier one wiped whole. */
    p.registered = 1;
    node = p.node;
    REQUIRE(ts_profile_relogin(&p, NULL, &RNG));
    CHECK(p.has_old_node);
    CHECK_MEM(&p.old_node, &node, sizeof(node));
    CHECK(memcmp(&p.node, &node, sizeof(node)) != 0);
    CHECK(!p.registered);
    CHECK(p.auth_key[0] == '\0' && p.auth_key[1] == '\0' && p.auth_key[4] == '\0');
    node = p.node;
    REQUIRE(ts_profile_relogin(&p, "", &RNG));
    CHECK(memcmp(&p.node, &node, sizeof(node)) != 0);
    CHECK(p.auth_key[0] == '\0');
}

/* Each line of a good profile swapped for a bad one: the whole profile is refused. */
TEST(test_broken)
{
    static const char* good =
        "tailscale=1\n"
        "control=https://controlplane.tailscale.com\n"
        "machine_key=0101010101010101010101010101010101010101010101010101010101010101\n"
        "node_key=0202020202020202020202020202020202020202020202020202020202020202\n"
        "registered=1\n";
    static const struct {
        const char* from;
        const char* to;
    } breaks[] = {
        { "tailscale=1", "tailscale=2" },
        { "tailscale=1", "profile=1" },
        { "control=https://controlplane.tailscale.com", "control=ftp://x" },
        { "control=https://controlplane.tailscale.com", "controlx=https://controlplane.tailscale.com" },
        { "machine_key=01010101", "machine_key=0101010g" },
        { "machine_key=01010101", "machine_key=010101" },
        { "machine_key=0101010101010101010101010101010101010101010101010101010101010101",
          "machine_key=010101010101010101010101010101010101010101010101010101010101010101" },
        { "machine_key=0101010101010101010101010101010101010101010101010101010101010101\n", "" },
        { "node_key=0202", "nodekey=0202" },
        { "registered=1", "registered=yes" },
        { "registered=1", "registered_=1" },
        { "registered=1", "registered=1\nauth_key=two words" },
        { "registered=1", "registered=1\nold_node_key=zz" },
        { "registered=1", "registered=1\nserver_key=0303" },
        { "registered=1", "registered=1\ncontrol_addr=not.an.address" },
        { "registered=1", "registered=1\nhostname=-bad" },
        { "registered=1", "registered=1\nhostname=two words" },
        { "registered=1", "registered=1\ntailnet=a\\nb" },
        { "registered=1", "registered=1\ntailnet=a\x7f" "b" },
        { "registered=1", "registered=1\naddress=100.64.0.1/33" },
        { "registered=1", "registered=1\naddress=100.64.0.1/32\naddress=fd7a::1/128\naddress=100.64.0.2/32" },
        /* a prefix the parser takes (leading zeros in the length), 50 characters: no room for its NUL */
        { "registered=1", "registered=1\naddress=fd7a:115c:a1e0:0000:0000:0000:0000:0007/0000000128" },
    };
    ts_profile p;
    size_t i, n;
    int ok;

    n = strlen(good);
    memcpy(text, good, n + 1);
    REQUIRE(ts_profile_parse(&p, text, n));
    CHECK(p.registered);
    CHECK(p.machine.b[0] == 1 && p.node.b[31] == 2);

    for (i = 0; i < sizeof(breaks) / sizeof(breaks[0]); i++) {
        const char* at = strstr(good, breaks[i].from);
        size_t pre, fl = strlen(breaks[i].from), tl = strlen(breaks[i].to);
        REQUIRE(at != NULL);
        pre = (size_t)(at - good);
        memcpy(text, good, pre);
        memcpy(text + pre, breaks[i].to, tl);
        memcpy(text + pre + tl, at + fl, strlen(at + fl) + 1);
        n = strlen(text);
        /* Parsed once: the parse works in place, a second one would read the remains of the
         * first - and its memset would hide what the first one left in the struct. */
        ok = ts_profile_parse(&p, text, n);
        CHECK(!ok);
        if (ok) fprintf(stderr, "    accepted: %s -> %s\n", breaks[i].from, breaks[i].to);
        /* refused means wiped: nothing of it survives in the struct, keys or the rest */
        CHECK(all_zero(&p, sizeof(p)));
    }

    /* The texts for the screens: 128 characters fit, 129 do not. */
    {
        char t[TS_TEXT_MAX + 2];
        memset(t, 't', sizeof(t));
        t[TS_TEXT_MAX] = '\0';
        n = (size_t)snprintf(text, sizeof(text), "%stailnet=%s\n", good, t);
        REQUIRE(ts_profile_parse(&p, text, n));
        CHECK(strlen(p.tailnet) == TS_TEXT_MAX);
        t[TS_TEXT_MAX] = 't';
        t[TS_TEXT_MAX + 1] = '\0';
        n = (size_t)snprintf(text, sizeof(text), "%snode_name=%s\n", good, t);
        CHECK(!ts_profile_parse(&p, text, n));
        CHECK(all_zero(&p, sizeof(p)));
    }

    /* Not a Tailscale profile at all: a WireGuard .conf. */
    snprintf(text, sizeof(text), "[Interface]\nPrivateKey = x\n");
    CHECK(!ts_profile_is(text, strlen(text)));
    CHECK(!ts_profile_parse(&p, text, strlen(text)));
    CHECK(!ts_profile_is("tailscale=1", 11));
    CHECK(ts_profile_is("tailscale=1\r\n", 13));
}

TEST(test_hex)
{
    uint8_t k[32], back[32];
    char hex[65];
    size_t i;

    for (i = 0; i < 32; i++) k[i] = (uint8_t)(i * 9 + 1);
    ts_hex32(hex, k);
    CHECK(strlen(hex) == 64);
    CHECK(strncmp(hex, "010a131c", 8) == 0);
    REQUIRE(ts_unhex32(back, hex, 64));
    CHECK_MEM(back, k, 32);
    hex[0] = 'A';
    CHECK(ts_unhex32(back, hex, 64));
    CHECK(back[0] == 0xa1);
    CHECK(!ts_unhex32(back, hex, 63));
    hex[5] = 'x';
    CHECK(!ts_unhex32(back, hex, 64));
}

int main(void)
{
    if (!wg_crypto_init()) return 2;
    printf("ts_profile\n");
    RUN(test_url);
    RUN(test_authkey);
    RUN(test_round_trip);
    RUN(test_relogin);
    RUN(test_broken);
    RUN(test_hex);
    return t_summary("ts_profile");
}
