/*
 * wg_conf: keys, addresses and endpoints in their text forms, whole files as servers hand them out,
 * the errors a user would be shown (with their lines), and applying a file to a device.
 */

#include "test_util.h"
#include "../src/wg_conf.h"
#include "../src/wg_device.h"

static wg_conf C;
static wg_conf_peer PEERS[4];
static wg_prefix ALLOWED[32];

static int parse(const char* text)
{
    wg_conf_init(&C, PEERS, 4, ALLOWED, 32);
    return wg_conf_parse(&C, text, strlen(text));
}

/* A valid key and its text, for building files. */
#define KEY_0_31 "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

static int addr_is(const char* text, int family, const char* hex)
{
    uint8_t got[16], want[16];
    int fam;

    memset(want, 0, sizeof(want));
    t_hex(want, sizeof(want), hex);
    return wg_addr_parse(text, strlen(text), &fam, got) && fam == family
        && memcmp(got, want, family == 4 ? 4 : 16) == 0;
}

static int addr_bad(const char* text)
{
    uint8_t a[16];
    int fam;
    return !wg_addr_parse(text, strlen(text), &fam, a);
}

/* ------------------------------------------------------------------------------ text forms */

TEST(base64_keys)
{
    wg_key k, back, want;
    char text[45];
    int i, round = 1;

    for (i = 0; i < 32; i++) want.b[i] = (uint8_t)i;
    CHECK(wg_key_from_base64(&k, KEY_0_31, 44));
    CHECK_MEM(k.b, want.b, 32);
    wg_key_to_base64(text, &want);
    CHECK(strcmp(text, KEY_0_31) == 0);

    for (i = 0; i < 200; i++) {
        if (!wg_random(k.b, 32)) round = 0;
        wg_key_to_base64(text, &k);
        if (strlen(text) != 44 || !wg_key_from_base64(&back, text, 44) || memcmp(back.b, k.b, 32) != 0) round = 0;
    }
    CHECK(round);

    CHECK(!wg_key_from_base64(&k, KEY_0_31, 43));                               /* short */
    CHECK(!wg_key_from_base64(&k, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8A", 44)); /* no '=' */
    CHECK(!wg_key_from_base64(&k, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9=", 44)); /* bits left over */
    CHECK(!wg_key_from_base64(&k, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd*h8=", 44)); /* not base64 */
}

TEST(ipv4_addresses)
{
    CHECK(addr_is("10.0.0.1", 4, "0a000001"));
    CHECK(addr_is("255.255.255.255", 4, "ffffffff"));
    CHECK(addr_is("0.0.0.0", 4, "00000000"));
    CHECK(addr_bad("10.0.0"));
    CHECK(addr_bad("10.0.0.1.2"));
    CHECK(addr_bad("10.0.0.256"));
    CHECK(addr_bad("10.00.0.1"));                       /* leading zero: octal to some parsers */
    CHECK(addr_bad("10..0.1"));
    CHECK(addr_bad("10.0.0.1."));
    CHECK(addr_bad(" 10.0.0.1"));
    CHECK(addr_bad(""));
}

TEST(ipv6_addresses)
{
    CHECK(addr_is("::", 6, "00000000000000000000000000000000"));
    CHECK(addr_is("::1", 6, "00000000000000000000000000000001"));
    CHECK(addr_is("1::", 6, "00010000000000000000000000000000"));
    CHECK(addr_is("2001:db8::1", 6, "20010db8000000000000000000000001"));
    CHECK(addr_is("1:2:3:4:5:6:7:8", 6, "00010002000300040005000600070008"));
    CHECK(addr_is("1:2:3:4:5:6:7::", 6, "00010002000300040005000600070000"));
    CHECK(addr_is("FE80::ABCD", 6, "fe80000000000000000000000000abcd"));
    CHECK(addr_is("::ffff:192.0.2.1", 6, "00000000000000000000ffffc0000201"));
    CHECK(addr_is("1:2:3:4:5:6:1.2.3.4", 6, "00010002000300040005000601020304"));

    CHECK(addr_bad(":::"));
    CHECK(addr_bad("1::2::3"));
    CHECK(addr_bad("1:2:3:4:5:6:7:8:9"));
    CHECK(addr_bad("1:2:3:4:5:6:7"));                   /* seven groups and no "::" */
    CHECK(addr_bad("::1:2:3:4:5:6:7:8"));               /* "::" standing for nothing */
    CHECK(addr_bad("12345::"));
    CHECK(addr_bad("g::1"));
    CHECK(addr_bad("1:"));
    CHECK(addr_bad(":1"));
    CHECK(addr_bad("fe80::1%eth0"));                    /* zones mean nothing in a config */
    CHECK(addr_bad("1:2:3:4:5:6:7:1.2.3.4"));
}

TEST(prefixes)
{
    wg_prefix p;

    CHECK(wg_prefix_parse("10.0.0.0/8", 10, &p) && p.family == 4 && p.cidr == 8);
    CHECK(wg_prefix_parse("10.1.2.3", 8, &p) && p.cidr == 32);
    CHECK(wg_prefix_parse("10.1.2.3/24", 11, &p) && p.cidr == 24 && p.addr[3] == 3);   /* kept */
    CHECK(wg_prefix_parse("::/0", 4, &p) && p.family == 6 && p.cidr == 0);
    CHECK(wg_prefix_parse("fd00::2", 7, &p) && p.cidr == 128);
    CHECK(!wg_prefix_parse("10.0.0.0/33", 11, &p));
    CHECK(!wg_prefix_parse("2001:db8::/129", 14, &p));
    CHECK(!wg_prefix_parse("10.0.0.0/", 9, &p));
    CHECK(!wg_prefix_parse("/8", 2, &p));
    CHECK(!wg_prefix_parse("10.0.0.0/8x", 11, &p));
}

/* ------------------------------------------------------------------------------ whole files */

TEST(a_client_file)
{
    static const char text[] =
        "# exported by a server\r\n"
        "[Interface]\r\n"
        "PrivateKey = " KEY_0_31 "\r\n"
        "address = 10.8.0.2/32, fd08::2/128\r\n"
        "DNS = 10.8.0.1, 2606:4700:4700::1111, home.lan\r\n"
        "MTU=1380\r\n"
        "\r\n"
        "  [ peer ]  \r\n"
        "PublicKey = " KEY_0_31 "   # the server\r\n"
        "PresharedKey = " KEY_0_31 "\r\n"
        "AllowedIPs = 0.0.0.0/0,\r\n"
        "AllowedIPs = ::/0\r\n"
        "Endpoint = [2001:db8::1]:51820\r\n"
        "PersistentKeepalive = 25";                     /* no newline at the end */
    const wg_conf_peer* p;

    REQUIRE(parse(text));
    CHECK(C.has_private_key && C.private_key.b[31] == 31);
    CHECK(C.n_address == 2 && C.address[0].family == 4 && C.address[0].cidr == 32);
    CHECK(C.address[1].family == 6 && C.address[1].cidr == 128);
    CHECK(C.n_dns == 2 && C.dns[0].family == 4 && C.dns[1].family == 6);
    CHECK(strcmp(C.dns_search, "home.lan") == 0);
    CHECK(C.mtu == 1380 && C.listen_port == 0 && !C.awg && C.warnings == 0);

    REQUIRE(C.n_peers == 1);
    p = &C.peers[0];
    CHECK(p->has_public_key && p->has_psk);
    CHECK(p->allowed_count == 2 && ALLOWED[p->allowed_first].cidr == 0);
    CHECK(ALLOWED[p->allowed_first + 1].family == 6);
    CHECK(strcmp(p->endpoint_host, "2001:db8::1") == 0 && p->endpoint_port == 51820);
    CHECK(p->endpoint.family == 6 && p->endpoint.port == 51820 && p->endpoint.addr[1] == 0x01);
    CHECK(p->persistent_keepalive.lo == 25 && p->persistent_keepalive.hi == 25 && p->line == 8);
}

TEST(a_server_with_peers)
{
    static const char text[] =
        "[Interface]\n"
        "PrivateKey = " KEY_0_31 "\n"
        "ListenPort = 51820\n"
        "Address = 10.8.0.1/24\n"
        "[Peer]\n"
        "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\n"
        "AllowedIPs = 10.8.0.2/32\n"
        "[Peer]\n"
        "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\n"
        "AllowedIPs = 10.8.0.3/32, 192.168.50.0/24\n"
        "Endpoint = vpn.example.com:443\n"
        "PersistentKeepalive = off\n"
        "[Peer]\n"
        "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM=\n";

    REQUIRE(parse(text));
    CHECK(C.listen_port == 51820 && C.n_peers == 3);
    CHECK(C.peers[0].allowed_first == 0 && C.peers[0].allowed_count == 1);
    CHECK(C.peers[1].allowed_first == 1 && C.peers[1].allowed_count == 2);
    CHECK(C.peers[2].allowed_count == 0 && !C.peers[2].has_psk);
    CHECK(C.peers[1].public_key.b[31] == 2 && C.peers[2].public_key.b[31] == 3);
    /* a name stays a name: the daemon resolves it */
    CHECK(strcmp(C.peers[1].endpoint_host, "vpn.example.com") == 0 && C.peers[1].endpoint_port == 443);
    CHECK(C.peers[1].endpoint.family == 0 && C.peers[1].persistent_keepalive.hi == 0);
}

static void expect_error(const char* text, int line)
{
    CHECK(!parse(text));
    CHECK(C.error_line == line);
    CHECK(C.error[0] != 0);
    if (C.error_line != line) fprintf(stderr, "    (line %d: %s)\n", C.error_line, C.error);
}

TEST(errors_point_at_their_line)
{
    expect_error("[Interface]\nPrivateKey = nope\n", 2);
    expect_error("PrivateKey = " KEY_0_31 "\n[Interface]\n", 1);
    expect_error("[Interface]\nPrivateKey = " KEY_0_31 "\n[Peer]\nPublicKey = " KEY_0_31 "\n"
                 "AllowedIPs = 10.0.0.0/33\n", 5);
    expect_error("[Interfaces]\n", 1);
    expect_error("[Interface\n", 1);
    expect_error("[Interface]\nPrivateKey\n", 2);                           /* no '=' at all */
    expect_error("[Interface]\nPrivateKey = " KEY_0_31 "\n\n[Peer]\nAllowedIPs = 10.0.0.1\n", 4);
    expect_error("[Peer]\nPublicKey = " KEY_0_31 "\n", 0);                /* no [Interface] */
    expect_error("[Interface]\nMTU = 1420\n", 0);                           /* no PrivateKey */
    expect_error("[Interface]\nPrivateKey = " KEY_0_31 "\n[Interface]\n", 3);
    expect_error("[Interface]\nPrivateKey = " KEY_0_31 "\n[Peer]\nPublicKey = " KEY_0_31 "\n"
                 "Endpoint = 2001:db8::1:51820\n", 5);                    /* IPv6 needs [] */
    expect_error("[Interface]\nPrivateKey = " KEY_0_31 "\n[Peer]\nPublicKey = " KEY_0_31 "\n"
                 "Endpoint = 1.2.3.4:0\n", 5);
    expect_error("[Interface]\nPrivateKey = " KEY_0_31 "\n[Peer]\nPublicKey = " KEY_0_31 "\n"
                 "Endpoint = 1.2.3.4:70000\n", 5);
    expect_error("[Interface]\nPrivateKey = " KEY_0_31 "\nMTU = 100\n", 3);
    expect_error("[Interface]\nPrivateKey = " KEY_0_31 "\n"
                 "[Peer]\nPublicKey = " KEY_0_31 "\n[Peer]\nPublicKey = " KEY_0_31 "\n"
                 "[Peer]\nPublicKey = " KEY_0_31 "\n[Peer]\nPublicKey = " KEY_0_31 "\n"
                 "[Peer]\n", 11);                                           /* a fifth: no room */
}

TEST(wg_quick_extras_are_skipped)
{
    static const char text[] =
        "[Interface]\n"
        "PrivateKey = " KEY_0_31 "\n"
        "PostUp = iptables -A FORWARD -i %i -j ACCEPT\n"
        "Table = off\n"
        "SaveConfig = true\n"
        "[Peer]\n"
        "PublicKey = " KEY_0_31 "\n"
        "FooBar = 1\n";

    CHECK(parse(text));
    CHECK(C.warnings == 4 && C.warning_line == 3);
    CHECK(strstr(C.warning, "PostUp") != NULL);
}

TEST(amneziawg_keys)
{
    static const char text[] =
        "[Interface]\n"
        "PrivateKey = " KEY_0_31 "\n"
        "Jc = 4\n"
        "Jmin = 40\n"
        "Jmax = 70\n"
        "S1 = 15\n"
        "S2 = 68\n"
        "S4 = 12\n"
        "H1 = 1233645711\n"
        "H2 = 100000-100800\n"
        "H3 = 4000000000 - 4100000000\n"
        "H4 = 7\n"
        "I1 = <b 0xc6000000010843290a47ba8ba2ed000044d0><r 16>\n";

    REQUIRE(parse(text));
    CHECK(C.awg && C.jc == 4 && C.jmin == 40 && C.jmax == 70);
    CHECK(C.s[1] == 15 && C.s[2] == 68 && C.s[3] == 0 && C.s[4] == 12);
    CHECK(C.h[1].lo == 1233645711u && C.h[1].hi == 1233645711u);
    CHECK(C.h[2].lo == 100000 && C.h[2].hi == 100800);
    CHECK(C.h[3].lo == 4000000000u && C.h[3].hi == 4100000000u);
    CHECK(C.h[4].lo == 7 && C.h[4].hi == 7);
    CHECK(C.i[1] && C.i_len[1] == strlen("<b 0xc6000000010843290a47ba8ba2ed000044d0><r 16>"));
    CHECK(C.warnings == 0);
}

#define IFACE "[Interface]\nPrivateKey = " KEY_0_31 "\n"

TEST(amneziawg_3_keys)
{
    static const char text[] =
        IFACE
        "S1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\n"
        "HeaderProtectionKey = " KEY_0_31 "\n"
        "ContentPaddingAddition = 0-64\n"
        "RandomTrailers = on\n"
        "DisableCookies = 1\n"
        "RekeyAfterTime = 100-140\n"
        "RekeyTimeout = 4-6\n"
        "RejectAfterTime = 170\n"
        "KeepaliveTimeout = off\n"
        "MaxHandshakeAttempts = 10-30\n"
        "[Peer]\n"
        "PublicKey = " KEY_0_31 "\n"
        "PersistentKeepalive = 20-30\n"
        "AdvancedSecurity = on\n";

    REQUIRE(parse(text));
    CHECK(C.awg && C.hp_key[0] == 0 && C.hp_key[31] == 31);
    CHECK(C.random_trailers && C.disable_cookies);
    CHECK(C.content_padding.lo == 0 && C.content_padding.hi == 64);
    CHECK(C.timing.rekey_after_time.lo == 100 && C.timing.rekey_after_time.hi == 140);
    CHECK(C.timing.rekey_timeout.lo == 4 && C.timing.rekey_timeout.hi == 6);
    CHECK(C.timing.reject_after_time.lo == 170 && C.timing.reject_after_time.hi == 170);
    CHECK(C.timing.keepalive_timeout.lo == 0 && C.timing.keepalive_timeout.hi == 0);
    CHECK(C.timing.max_handshake_attempts.lo == 10 && C.timing.max_handshake_attempts.hi == 30);
    CHECK(C.peers[0].persistent_keepalive.lo == 20 && C.peers[0].persistent_keepalive.hi == 30);
    CHECK(C.h[1].lo == 1 && C.h[1].hi == 1 && C.h[4].lo == 4);     /* not set: awg's 1-4 */
    CHECK(C.warnings == 0);

    /* awg's booleans */
    REQUIRE(parse(IFACE "RandomTrailers = OFF\nDisableCookies = 0\n"));
    CHECK(!C.random_trailers && !C.disable_cookies && C.awg);
    REQUIRE(parse(IFACE "RandomTrailers = 7\nDisableCookies = true\n"));
    CHECK(C.random_trailers && C.disable_cookies);
    /* I-packets without a tag are simply not sent */
    CHECK(parse(IFACE "I1 = \nI2 = just text\n"));
}

TEST(amneziawg_errors)
{
    /* on their lines */
    expect_error(IFACE "H1 = 9-3\n", 3);
    expect_error(IFACE "H1 = off\n", 3);
    expect_error(IFACE "Jc = 200\n", 3);
    expect_error(IFACE "Jmin = 70000\n", 3);
    expect_error(IFACE "S1 = 2000\n", 3);
    expect_error(IFACE "I2 = <b 0xabc>\n", 3);                    /* odd hex */
    expect_error(IFACE "I2 = <b 0x>\n", 3);                       /* no bytes */
    expect_error(IFACE "I2 = <b 0xzz>\n", 3);
    expect_error(IFACE "I1 = <r 10><q 5>\n", 3);                  /* no such tag */
    expect_error(IFACE "I1 = <r 10\n", 3);                        /* missing > */
    expect_error(IFACE "I1 = <>\n", 3);
    expect_error(IFACE "I1 = <r -5>\n", 3);                       /* the reference crashes on it */
    expect_error(IFACE "I1 = <rc>\n", 3);                         /* a count is needed */
    expect_error(IFACE "HeaderProtectionKey = 00112233\n", 3);
    expect_error(IFACE "RandomTrailers = maybe\n", 3);
    expect_error(IFACE "RekeyTimeout = 70000\n", 3);
    expect_error(IFACE "ContentPaddingAddition = 9-3\n", 3);
    expect_error(IFACE "[Peer]\nPublicKey = " KEY_0_31 "\nPersistentKeepalive = 30-20\n", 5);
    expect_error(IFACE "[Peer]\nPublicKey = " KEY_0_31 "\nAdvancedSecurity = yes please\n", 5);

    /* the rules that span keys concern the whole file (line 0) */
    expect_error(IFACE "Jmin = 90\nJmax = 30\n", 0);
    expect_error(IFACE "Jc = 3\nJmin = 20\n", 0);                /* Jmax not set: 0 */
    expect_error(IFACE "H1 = 3\n", 0);                            /* H3 not set: 3 */
    expect_error(IFACE "H1 = 5-10\nH2 = 10-20\n", 0);            /* both hold 10 */
    expect_error(IFACE "HeaderProtectionKey = " KEY_0_31 "\nS1 = 12\nS2 = 12\nS3 = 11\nS4 = 12\n", 0);
    expect_error(IFACE "HeaderProtectionKey = " KEY_0_31 "\n", 0);   /* S1-S4 not set: 0 */
    CHECK(parse(IFACE "H1 = 5-10\nH2 = 11-20\nH3 = 0\nH4 = 4294967295\n"));
}

/* ------------------------------------------------------------------------------ onto a device */

static wg_device D;
static wg_awg AWG;
static wg_peer DP[4];
static uint8_t STAGE[4 * 1024];
static wg_allowedips_node NODES[64];

static void fresh_device(void)
{
    wg_device_init(&D);
    CHECK(wg_device_set_allowedips_storage(&D, NODES, 64));
}

TEST(apply_to_a_device)
{
    static const char text[] =
        "[Interface]\n"
        "PrivateKey = " KEY_0_31 "\n"
        "MTU = 1280\n"
        "[Peer]\n"
        "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\n"
        "PresharedKey = " KEY_0_31 "\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "Endpoint = 192.0.2.1:51820\n"
        "PersistentKeepalive = 25\n"
        "[Peer]\n"
        "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\n"
        "AllowedIPs = 10.20.0.0/16\n"
        "Endpoint = relay.example.net:51820\n";
    static const uint8_t in20[4] = { 10, 20, 1, 1 }, elsewhere[4] = { 1, 1, 1, 1 };
    wg_key own, pub;
    char err[128];
    int i;

    REQUIRE(parse(text));
    fresh_device();
    REQUIRE(wg_conf_apply(&C, &D, NULL, DP, STAGE, 1024, 0, err, sizeof(err)));

    for (i = 0; i < 32; i++) own.b[i] = (uint8_t)i;
    wg_key_clamp(&own);
    CHECK(wg_key_public(&own, &pub));
    CHECK_MEM(D.local.public_key.b, pub.b, 32);
    CHECK(D.mtu == 1280);
    CHECK(wg_allowedips_lookup(&D.allowedips, 4, in20) == &DP[1]);
    CHECK(wg_allowedips_lookup(&D.allowedips, 4, elsewhere) == &DP[0]);
    CHECK(DP[0].endpoint.family == 4 && DP[0].endpoint.port == 51820 && DP[0].endpoint.addr[0] == 192);
    CHECK(DP[1].endpoint.family == 0);                  /* a name: left to the daemon */
    CHECK(DP[0].persistent_keepalive.lo == 25 && DP[0].persistent_keepalive.hi == 25);
    CHECK(DP[0].noise.psk[31] == 31);
    CHECK(wg_device_find_peer(&D, &C.peers[1].public_key) == &DP[1]);

    /* AmneziaWG settings that are plain WireGuard anyway need no codec; any other do. */
    REQUIRE(parse(IFACE "Jc = 0\nS1 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n"));
    fresh_device();
    CHECK(wg_conf_apply(&C, &D, &AWG, DP, STAGE, 1024, 0, err, sizeof(err)));
    CHECK(D.codec.ops == &wg_codec_wireguard);
    REQUIRE(parse(IFACE "Jc = 4\nJmin = 10\nJmax = 50\nI3 = <b 0x0102><t>\n"));
    fresh_device();
    CHECK(!wg_conf_apply(&C, &D, NULL, DP, STAGE, 1024, 0, err, sizeof(err)));
    CHECK(strstr(err, "AmneziaWG") != NULL);
    fresh_device();
    CHECK(wg_conf_apply(&C, &D, &AWG, DP, STAGE, 1024, 0, err, sizeof(err)));
    CHECK(D.codec.ops == &wg_codec_awg && D.codec.st == &AWG && AWG.dev == &D);
    CHECK(AWG.p.jc == 4 && AWG.p.jmin == 10 && AWG.p.jmax == 50 && !AWG.hp);
    CHECK(AWG.p.i[3].nops == 2 && AWG.p.i[3].len == 6 && AWG.p.i[1].nops == 0);

    /* Timings and DisableCookies are the device's, with or without a codec; a timing the file
     * leaves out stays WireGuard's. */
    REQUIRE(parse(IFACE "RekeyTimeout = 4-6\nRejectAfterTime = 150-170\nDisableCookies = on\n"
                  "[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\n"
                  "PersistentKeepalive = 20-30\n"));
    fresh_device();
    CHECK(wg_conf_apply(&C, &D, NULL, DP, STAGE, 1024, 0, err, sizeof(err)));
    CHECK(D.codec.ops == &wg_codec_wireguard && D.disable_cookies);
    CHECK(D.timing.rekey_timeout.lo == 4 && D.timing.rekey_timeout.hi == 6);
    CHECK(D.timing.keepalive_timeout.lo == 10 && D.timing.keepalive_timeout.hi == 10);
    CHECK(D.timing.max_handshake_attempts.lo == 18 && D.timing.rekey_after_time.hi == 120);
    CHECK(DP[0].persistent_keepalive.lo == 20 && DP[0].persistent_keepalive.hi == 30);
    CHECK(DP[0].session.reject_after_ns == 170 * WG_NSEC_PER_SEC);   /* keys live to the top */

    /* A range from 0 is set all the same; only 0..0 (or off) is not. */
    REQUIRE(parse(IFACE "RekeyTimeout = 0-3\nKeepaliveTimeout = 0\n"
                  "[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\n"
                  "PersistentKeepalive = 0-30\n"));
    fresh_device();
    CHECK(wg_conf_apply(&C, &D, NULL, DP, STAGE, 1024, 0, err, sizeof(err)));
    CHECK(D.timing.rekey_timeout.lo == 0 && D.timing.rekey_timeout.hi == 3);
    CHECK(D.timing.keepalive_timeout.lo == 10);
    CHECK(DP[0].persistent_keepalive.lo == 0 && DP[0].persistent_keepalive.hi == 30);

    /* A table too small for the file's AllowedIPs */
    REQUIRE(parse(text));
    wg_device_init(&D);
    CHECK(!wg_conf_apply(&C, &D, NULL, DP, STAGE, 1024, 0, err, sizeof(err)));
    CHECK(strstr(err, "AllowedIPs") != NULL);
}

int main(void)
{
    if (!wg_crypto_init()) {
        fprintf(stderr, "wg_crypto_init failed\n");
        return 2;
    }
    RUN(base64_keys);
    RUN(ipv4_addresses);
    RUN(ipv6_addresses);
    RUN(prefixes);
    RUN(a_client_file);
    RUN(a_server_with_peers);
    RUN(errors_point_at_their_line);
    RUN(wg_quick_extras_are_skipped);
    RUN(amneziawg_keys);
    RUN(amneziawg_3_keys);
    RUN(amneziawg_errors);
    RUN(apply_to_a_device);
    wg_crypto_cleanup();
    return t_summary("test_conf");
}
