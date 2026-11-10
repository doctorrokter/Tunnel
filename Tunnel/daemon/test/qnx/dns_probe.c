/*
 * Host probe of bt_plat_qnx.c's DNS section (status_public + _CS_RESOLVE), extracted as it is:
 * confstr in memory, status_public a temp file (what we append to it), the network manager's object
 * fed to pps_parse by hand. Run: daemon/test/qnx/run.sh (it extracts the section and builds this).
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bt_plat.h"
#include "bt_resolve.h"

#define BT_I(...) (printf("     [I] "), printf(__VA_ARGS__), printf("\n"))
#define BT_W(...) (printf("     [W] "), printf(__VA_ARGS__), printf("\n"))
#define BT_D(...) ((void)0)

static char PPS_FILE[256];
#define PPS_STATUS      PPS_FILE
#define PPS_NS_MAX      8
#define PPS_SEARCH_MAX  256
#define PPS_FIGHT_MAX   10
#define PPS_FIGHT_NS    (60 * 1000000000ULL)
#define DNS_CHECK_NS    (5 * 1000000000ULL)

/* confstr(_CS_RESOLVE) in memory: no blanks, as the phone */
#define _CS_RESOLVE 1
#define _CS_SET     0x100
static char cs_value[BT_DNS_TEXT_MAX] = "nameserver_192.168.1.1";
static size_t fake_confstr(int name, char* buf, size_t len)
{
    if (name & _CS_SET) {
        if (strchr(buf, ' ')) { errno = EINVAL; return 0; }
        snprintf(cs_value, sizeof(cs_value), "%s", buf);
        return 1;
    }
    if (len) snprintf(buf, len, "%s", cs_value);
    return strlen(cs_value) + 1;
}
#define confstr fake_confstr

static uint64_t fake_now = 1000000000ULL;
static uint64_t mono_ns(void) { return fake_now; }
static int family_af(int f) { return f == 6 ? AF_INET6 : AF_INET; }

int bt_addr_equal(const bt_addr* a, const bt_addr* b)
{
    return a->family == b->family && memcmp(a->addr, b->addr, a->family == 6 ? 16 : 4) == 0;
}

static struct {
    int      pps;
    bt_addr  pps_ns[PPS_NS_MAX];
    size_t   pps_n;
    char     pps_search[PPS_SEARCH_MAX];
    char     pps_if[BT_IFNAME_MAX];
    int      pps_ours_in;
    bt_addr  pps_ours[PPS_NS_MAX];
    size_t   pps_ours_n;
    char     pps_ours_search[PPS_SEARCH_MAX];
    int      pps_given_up;
    unsigned pps_fights;
    uint64_t pps_fight_since;
    char     sys_text[BT_DNS_TEXT_MAX];
    char     our_text[BT_DNS_TEXT_MAX];
    uint64_t check_due;
} P;

#include "qnx_dns_body.c"

/* ------------------------------------------------------------------------------------------- */

static int failed;
static void check(const char* what, int ok)
{
    printf("   %s  %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failed = 1;
}

static size_t file_size(void)
{
    struct stat st;
    return stat(PPS_FILE, &st) == 0 ? (size_t)st.st_size : 0;
}

static void file_text(char* out, size_t cap)
{
    FILE* f = fopen(PPS_FILE, "r");
    size_t n = f ? fread(out, 1, cap - 1, f) : 0;
    out[n] = '\0';
    if (f) fclose(f);
}

static void file_reset(void)
{
    FILE* f = fopen(PPS_FILE, "w");
    if (f) fclose(f);
}

/* the whole object as net_pps keeps it, with these nameservers / searchdomains */
static int feed(const char* ns_json, const char* sd)
{
    char obj[2048];
    snprintf(obj, sizeof(obj),
             "@status_public\ndefault_gateway:json:[\"192.168.1.1\"]\ndefault_interface::bcm0\nip4_ok::yes\n"
             "nameservers:json:%s\npriority:json:[\"ipsec0\",\"bcm0\"]\nsearchdomains::%s\n", ns_json, sd);
    return pps_parse(obj);
}

static bt_addr ip(const char* s)
{
    bt_addr a;
    memset(&a, 0, sizeof(a));
    if (inet_pton(AF_INET, s, a.addr) == 1) a.family = 4;
    else if (inet_pton(AF_INET6, s, a.addr) == 1) a.family = 6;
    return a;
}

int main(void)
{
    bt_addr magic[2], warp[2], got[8];
    char text[4096], snap[BT_DNS_TEXT_MAX];
    size_t n, size;
    int i;

    snprintf(PPS_FILE, sizeof(PPS_FILE), "/tmp/qnx_dns_probe.%d", (int)getpid());
    file_reset();
    memset(&P, 0, sizeof(P));
    P.pps = 3;                                  /* "open" */
    P.check_due = BT_NEVER;
    magic[0] = ip("100.100.100.100");
    magic[1] = ip("192.168.1.1");
    warp[0] = ip("1.1.1.1");
    warp[1] = ip("2606:4700:4700::1111");

    printf("== start: the network manager's object\n");
    feed("[\"192.168.1.1\"]", "");
    snprintf(P.sys_text, sizeof(P.sys_text), "nameserver_192.168.1.1");
    n = bt_dns_system(got, 8);
    check("the network's servers: 192.168.1.1", n == 1 && bt_addr_equal(&got[0], &magic[1]));

    printf("== MagicDNS in\n");
    check("apply", bt_dns_apply(magic, 2, "tailb78ad.ts.net"));
    file_text(text, sizeof(text));
    printf("     status_public got: %s", text);
    check("... the two attributes, one write, no blank in _CS_RESOLVE",
          strcmp(text, "nameservers:json:[\"100.100.100.100\",\"192.168.1.1\"]\nsearchdomains::tailb78ad.ts.net\n") == 0 &&
          strcmp(cs_value, "nameserver_100.100.100.100_nameserver_192.168.1.1_search_tailb78ad.ts.net") == 0);
    check("... ours are in", P.pps_ours_in);
    check("the echo of our write: no change", feed("[\"100.100.100.100\",\"192.168.1.1\"]", "tailb78ad.ts.net") == 0);
    n = bt_dns_system(got, 8);
    check("... the network's servers stay 192.168.1.1 (never ours)", n == 1 && bt_addr_equal(&got[0], &magic[1]));
    size = file_size();
    check("apply again, the same: no write", bt_dns_apply(magic, 2, "tailb78ad.ts.net") && file_size() == size);
    {
        bt_addr swapped[2] = { magic[1], magic[0] };
        file_reset();
        check("the same servers in another order: written", bt_dns_apply(swapped, 2, "tailb78ad.ts.net") && file_size() > 0);
        file_reset();
        bt_dns_apply(magic, 2, "tailb78ad.ts.net");
        feed("[\"100.100.100.100\",\"192.168.1.1\"]", "tailb78ad.ts.net");
    }

    printf("== the crash journal while ours are in\n");
    bt_dns_snapshot(snap, sizeof(snap));
    printf("     snapshot: %s\n", snap);
    check("snapshot: _CS_RESOLVE, the network's, its domains, ours",
          strcmp(snap, "nameserver_192.168.1.1|net:192.168.1.1|search:|ours:100.100.100.100,192.168.1.1") == 0);

    printf("== the network manager writes over ours\n");
    check("its write: a change", feed("[\"192.168.1.1\"]", "") == 1);
    check("... ours no longer in", !P.pps_ours_in);
    file_reset();
    check("... ours again (the tunnel's reconcile)", bt_dns_apply(magic, 2, "tailb78ad.ts.net") && file_size() > 0);
    feed("[\"100.100.100.100\",\"192.168.1.1\"]", "tailb78ad.ts.net");

    printf("== a new network while ours are in (net_pps writes 10.0.0.1)\n");
    check("its write: a change", feed("[\"10.0.0.1\"]", "home.lan") == 1);
    n = bt_dns_system(got, 8);
    {
        bt_addr home = ip("10.0.0.1");
        check("... the network's servers: 10.0.0.1, domains home.lan",
              n == 1 && bt_addr_equal(&got[0], &home) && strcmp(P.pps_search, "home.lan") == 0);
    }

    printf("== down: the network manager's back\n");
    bt_dns_apply(magic, 2, "tailb78ad.ts.net");
    feed("[\"100.100.100.100\",\"192.168.1.1\"]", "tailb78ad.ts.net");
    file_reset();
    check("restore", bt_dns_restore());
    file_text(text, sizeof(text));
    printf("     status_public got: %s", text);
    check("... its servers and domains written back",
          strcmp(text, "nameservers:json:[\"10.0.0.1\"]\nsearchdomains::home.lan\n") == 0 && !P.pps_ours_in);
    check("... the echo: no change", feed("[\"10.0.0.1\"]", "home.lan") == 0);
    size = file_size();
    check("restore again: no write", bt_dns_restore() && file_size() == size);

    printf("== after a crash: ours still in the object\n");
    memset(&P, 0, sizeof(P));
    P.pps = 3;
    P.check_due = BT_NEVER;
    snprintf(cs_value, sizeof(cs_value), "nameserver_100.100.100.100_nameserver_192.168.1.1_search_tailb78ad.ts.net");
    feed("[\"100.100.100.100\",\"192.168.1.1\"]", "tailb78ad.ts.net");    /* the start reads the dead run's */
    file_reset();
    check("restore from the journal", bt_dns_restore_text("nameserver_192.168.1.1|net:192.168.1.1|search:|ours:100.100.100.100,192.168.1.1"));
    file_text(text, sizeof(text));
    printf("     status_public got: %s", text);
    check("... the network's written back", strcmp(text, "nameservers:json:[\"192.168.1.1\"]\nsearchdomains::\n") == 0);
    n = bt_dns_system(got, 8);
    check("... and the network's for us again", n == 1 && bt_addr_equal(&got[0], &magic[1]));
    check("... _CS_RESOLVE the network's", strcmp(cs_value, "nameserver_192.168.1.1") == 0);

    printf("== after a crash: the network manager moved on already\n");
    memset(&P, 0, sizeof(P));
    P.pps = 3;
    P.check_due = BT_NEVER;
    feed("[\"10.0.0.1\"]", "");
    file_reset();
    bt_dns_restore_text("nameserver_192.168.1.1|net:192.168.1.1|search:|ours:100.100.100.100,192.168.1.1");
    check("... status_public left alone", file_size() == 0);

    printf("== a journal of 0.1.5 (no PPS part)\n");
    file_reset();
    check("restore", bt_dns_restore_text("nameserver_192.168.1.1"));
    check("... status_public left alone", file_size() == 0);

    printf("== WARP's DNS (IPv6 in it), domains with a control character\n");
    feed("[\"192.168.1.1\"]", "");
    file_reset();
    check("apply", bt_dns_apply(warp, 2, "a.lan\tb.lan"));
    file_text(text, sizeof(text));
    printf("     status_public got: %s", text);
    check("... IPv6 in the list, the tab a blank",
          strcmp(text, "nameservers:json:[\"1.1.1.1\",\"2606:4700:4700::1111\"]\nsearchdomains::a.lan b.lan\n") == 0);
    bt_dns_restore();

    printf("== the network manager will not have ours\n");
    feed("[\"192.168.1.1\"]", "");
    for (i = 0; i < 12; i++) {
        bt_dns_apply(magic, 2, "tailb78ad.ts.net");
        feed("[\"192.168.1.1\"]", "");
        fake_now += 1000000000ULL;
    }
    check("given up after 10 in a minute", P.pps_given_up);
    file_reset();
    bt_dns_apply(magic, 2, "tailb78ad.ts.net");
    check("... no more writes", file_size() == 0);
    bt_dns_restore();
    check("down: it may try again next time", !P.pps_given_up);

    unlink(PPS_FILE);
    printf("%s\n", failed ? "qnx dns: FAILURES" : "qnx dns: all passed");
    return failed;
}
