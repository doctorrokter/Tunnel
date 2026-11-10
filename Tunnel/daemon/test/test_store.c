/*
 * bt_store in a temporary directory: profiles saved, listed, loaded, replaced and deleted; what a
 * crash leaves behind swept; every id and name rule; file modes.
 */

#include "test_util.h"
#include "../src/bt_store.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static char root[256];
static char dir[300];

static void put_file(const char* name, const char* text)
{
    char path[400];
    FILE* f;
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    f = fopen(path, "w");
    if (f) {
        fputs(text, f);
        fclose(f);
    }
}

static int file_exists(const char* name)
{
    char path[400];
    struct stat st;
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    return lstat(path, &st) == 0;
}

static unsigned file_mode(const char* path)
{
    struct stat st;
    return lstat(path, &st) == 0 ? (unsigned)(st.st_mode & 0777) : 0xffffffffu;
}

/* a counter as the random source: ids come out predictable */
static int counter_fn(void* ctx, void* buf, size_t len)
{
    uint8_t* p = (uint8_t*)buf;
    unsigned* c = (unsigned*)ctx;
    size_t i;
    for (i = 0; i < len; i++) p[i] = (uint8_t)(*c)++;
    return 1;
}

static void fresh_dir(bt_store* s)
{
    char cmd[400];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) fprintf(stderr, "rm failed\n");
    if (!bt_store_open(s, dir)) fprintf(stderr, "open failed\n");
}

static bt_meta mk(const char* id, const char* name, uint32_t order, uint64_t created)
{
    bt_meta m;
    memset(&m, 0, sizeof(m));
    snprintf(m.id, sizeof(m.id), "%s", id);
    snprintf(m.name, sizeof(m.name), "%s", name);
    snprintf(m.type, sizeof(m.type), "%s", BT_TYPE_WIREGUARD);
    m.order = order;
    m.created = created;
    return m;
}

TEST(open_rules)
{
    bt_store s;
    char path[400];

    CHECK(bt_store_open(&s, dir));
    CHECK(file_mode(dir) == 0700);
    chmod(dir, 0755);
    CHECK(bt_store_open(&s, dir));              /* opening again puts the mode right */
    CHECK(file_mode(dir) == 0700);

    snprintf(path, sizeof(path), "%s/plainfile", root);
    put_file("../plainfile", "x");
    CHECK(!bt_store_open(&s, path));
    snprintf(path, sizeof(path), "%s/link", root);
    CHECK(symlink(dir, path) == 0);
    CHECK(!bt_store_open(&s, path));
    snprintf(path, sizeof(path), "%s/no/such/parent", root);
    CHECK(!bt_store_open(&s, path));
}

TEST(save_load_delete)
{
    static const char conf[] = "[Interface]\nPrivateKey = x\n\n[Peer]\nPublicKey = y\n";
    bt_store s;
    bt_meta m, back;
    char* text;
    size_t len;
    char path[400];
    unsigned c = 0xa0;
    wg_rng rng = { counter_fn, &c };

    fresh_dir(&s);
    REQUIRE(bt_store_new_id(&s, &rng, m.id));
    CHECK(strcmp(m.id, "a0a1a2a3") == 0);
    m = mk(m.id, "Дом - 🏠", 3, 1759200000);
    snprintf(m.type, sizeof(m.type), "%s", BT_TYPE_AMNEZIAWG);
    m.ts_ceiling = 1759203600;
    m.n_resolved = 2;
    strcpy(m.resolved[0].host, "vpn.example.com");
    strcpy(m.resolved[0].addr, "203.0.113.7");
    strcpy(m.resolved[1].host, "vpn.example.com");
    strcpy(m.resolved[1].addr, "2001:db8::7");
    REQUIRE(bt_store_save(&s, &m, conf, strlen(conf)));

    snprintf(path, sizeof(path), "%s/a0a1a2a3.conf", dir);
    CHECK(file_mode(path) == 0600);
    snprintf(path, sizeof(path), "%s/a0a1a2a3.meta", dir);
    CHECK(file_mode(path) == 0600);

    REQUIRE(bt_store_load_meta(&s, "a0a1a2a3", &back));
    CHECK(strcmp(back.name, m.name) == 0);
    CHECK(strcmp(back.type, BT_TYPE_AMNEZIAWG) == 0);
    CHECK(back.order == 3 && back.created == 1759200000 && back.ts_ceiling == 1759203600);
    CHECK(back.n_resolved == 2);
    CHECK(strcmp(back.resolved[1].addr, "2001:db8::7") == 0);

    text = bt_store_load_conf(&s, "a0a1a2a3", &len);
    REQUIRE(text);
    CHECK(len == strlen(conf) && strcmp(text, conf) == 0);
    bt_store_free_conf(text, len);

    /* meta only: the conf stays */
    back.order = 9;
    REQUIRE(bt_store_save(&s, &back, NULL, 0));
    text = bt_store_load_conf(&s, "a0a1a2a3", &len);
    REQUIRE(text);
    CHECK(strcmp(text, conf) == 0);
    bt_store_free_conf(text, len);
    REQUIRE(bt_store_load_meta(&s, "a0a1a2a3", &back));
    CHECK(back.order == 9);

    /* the next id skips the one taken: the counter goes on, but a clash is retried */
    c = 0xa0;
    REQUIRE(bt_store_new_id(&s, &rng, m.id));
    CHECK(strcmp(m.id, "a4a5a6a7") == 0);

    CHECK(bt_store_delete(&s, "a0a1a2a3"));
    CHECK(!file_exists("a0a1a2a3.meta") && !file_exists("a0a1a2a3.conf"));
    CHECK(!bt_store_delete(&s, "a0a1a2a3"));
    CHECK(!bt_store_load_meta(&s, "a0a1a2a3", &back));
    CHECK(bt_store_load_conf(&s, "a0a1a2a3", &len) == NULL);
    CHECK(!file_exists("a0a1a2a3.meta.tmp") && !file_exists("a0a1a2a3.conf.tmp"));
}

TEST(ids_are_checked)
{
    static const char* bad[] = { "../../etc", "ABCDEF12", "1234567", "123456789", "1234567g",
                                 "12345/78", "", "1234\0" "5678" };
    bt_store s;
    bt_meta m;
    size_t i, len;

    fresh_dir(&s);
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(!bt_id_valid(bad[i]));
        CHECK(!bt_store_load_meta(&s, bad[i], &m));
        CHECK(bt_store_load_conf(&s, bad[i], &len) == NULL);
        CHECK(!bt_store_delete(&s, bad[i]));
    }
    CHECK(bt_id_valid("0123abcd"));
    m = mk("../x", "n", 0, 0);
    CHECK(!bt_store_save(&s, &m, "c", 1));
}

TEST(names)
{
    char n64[65], n65[66];

    CHECK(bt_name_valid("Home", 4));
    CHECK(bt_name_valid("Работа", strlen("Работа")));
    CHECK(bt_name_valid("\xf0\x9f\x8f\xa0", 4));               /* U+1F3E0 */
    CHECK(!bt_name_valid("", 0));
    CHECK(!bt_name_valid("a\nb", 3));
    CHECK(!bt_name_valid("a\tb", 3));
    CHECK(!bt_name_valid("\x7f", 1));
    CHECK(!bt_name_valid("\xc0\x80", 2));                       /* overlong NUL */
    CHECK(!bt_name_valid("\xe0\x80\xaf", 3));                   /* overlong '/' */
    CHECK(!bt_name_valid("\xe0\x9f\xbf", 3));                   /* overlong U+07FF */
    CHECK(bt_name_valid("\xe0\xa0\x80", 3));                    /* U+0800, the first 3-byte one */
    CHECK(!bt_name_valid("\xf0\x8f\xbf\xbf", 4));               /* overlong U+FFFF */
    CHECK(bt_name_valid("\xf0\x90\x80\x80", 4));                /* U+10000 */
    CHECK(!bt_name_valid("\xed\xa0\x80", 3));                   /* a surrogate */
    CHECK(!bt_name_valid("\xc2\x85", 2));                       /* C1 NEL */
    CHECK(!bt_name_valid("\xd0", 1));                           /* cut short */
    CHECK(!bt_name_valid("\xf5\x80\x80\x80", 4));               /* past U+10FFFF */
    CHECK(!bt_name_valid("\xf4\x90\x80\x80", 4));
    CHECK(!bt_name_valid("\x80", 1));
    memset(n64, 'x', 64);
    n64[64] = 0;
    memset(n65, 'x', 65);
    n65[65] = 0;
    CHECK(bt_name_valid(n64, 64));
    CHECK(!bt_name_valid(n65, 65));
}

TEST(list_order)
{
    bt_store s;
    bt_meta out[8];
    bt_meta m;
    size_t n = 0, bad = 0;

    fresh_dir(&s);
    m = mk("00000003", "c", 1, 100); bt_store_save(&s, &m, "x", 1);
    m = mk("00000001", "a", 0, 300); bt_store_save(&s, &m, "x", 1);
    m = mk("00000002", "b", 0, 200); bt_store_save(&s, &m, "x", 1);
    m = mk("00000004", "d", 1, 100); bt_store_save(&s, &m, "x", 1);
    put_file("0000000f.meta", "profile=1\nid=0000000f\nname=\n");             /* broken */
    put_file("00000010.meta", "profile=1\nid=00000011\nname=x\ntype=wireguard\ncreated=1\norder=0\nts_ceiling=0\n");
    put_file("notes.txt", "hello");

    REQUIRE(bt_store_list(&s, out, 8, &n, &bad));
    CHECK(n == 4 && bad == 2);          /* the second one names another id than its file */
    CHECK(strcmp(out[0].id, "00000002") == 0);
    CHECK(strcmp(out[1].id, "00000001") == 0);
    CHECK(strcmp(out[2].id, "00000003") == 0);
    CHECK(strcmp(out[3].id, "00000004") == 0);

    REQUIRE(bt_store_list(&s, out, 2, &n, NULL));
    CHECK(n == 4);
}

TEST(sweep)
{
    bt_store s;
    bt_meta m;

    fresh_dir(&s);
    m = mk("0000000a", "kept", 0, 0);
    REQUIRE(bt_store_save(&s, &m, "conf", 4));
    put_file("0000000b.conf", "orphan");
    put_file("0000000a.meta.tmp", "half");
    put_file("settings.tmp", "half");
    put_file("zzz.conf", "not ours");
    CHECK(bt_store_sweep(&s) == 3);
    CHECK(file_exists("0000000a.conf") && file_exists("0000000a.meta"));
    CHECK(!file_exists("0000000b.conf"));
    CHECK(file_exists("zzz.conf"));
}

TEST(conf_limits)
{
    bt_store s;
    bt_meta m;
    char* big = (char*)malloc(BT_CONF_MAX + 1);
    char* text;
    size_t len;

    REQUIRE(big);
    fresh_dir(&s);
    memset(big, '#', BT_CONF_MAX + 1);
    m = mk("0000000c", "big", 0, 0);
    CHECK(bt_store_save(&s, &m, big, BT_CONF_MAX));
    text = bt_store_load_conf(&s, "0000000c", &len);
    CHECK(text && len == BT_CONF_MAX);
    bt_store_free_conf(text, len);
    CHECK(!bt_store_save(&s, &m, big, BT_CONF_MAX + 1));
    CHECK(!bt_store_save(&s, &m, "a\0b", 3));
    m = mk("0000000d", "", 0, 0);
    CHECK(!bt_store_save(&s, &m, "x", 1));
    free(big);
}

TEST(meta_text)
{
    bt_meta m, back;
    char buf[8192];
    size_t len, i;

    m = mk("12345678", "x", 5, 6);
    m.n_resolved = BT_META_RESOLVED;
    for (i = 0; i < BT_META_RESOLVED; i++) {
        snprintf(m.resolved[i].host, sizeof(m.resolved[i].host), "h%u.example", (unsigned)i);
        snprintf(m.resolved[i].addr, sizeof(m.resolved[i].addr), "10.0.0.%u", (unsigned)i);
    }
    len = bt_meta_format(&m, buf, sizeof(buf));
    REQUIRE(len > 0);
    CHECK(bt_meta_parse(&back, buf, len));
    CHECK(back.n_resolved == BT_META_RESOLVED);
    CHECK(strcmp(back.resolved[7].host, "h7.example") == 0);

    /* one resolved line too many, a bad address, a bad type, a missing field */
    len = bt_meta_format(&m, buf, sizeof(buf));
    len += (size_t)sprintf(buf + len, "resolved=h8 10.0.0.8\n");
    CHECK(!bt_meta_parse(&back, buf, len));
    strcpy(buf, "profile=1\nid=12345678\nname=x\ntype=wireguard\ncreated=1\norder=0\nts_ceiling=0\nresolved=h 10.0.0.300\n");
    CHECK(!bt_meta_parse(&back, buf, strlen(buf)));
    strcpy(buf, "profile=1\nid=12345678\nname=x\ntype=ipsec\ncreated=1\norder=0\nts_ceiling=0\n");
    CHECK(!bt_meta_parse(&back, buf, strlen(buf)));
    strcpy(buf, "profile=1\nid=12345678\nname=x\ntype=wireguard\ncreated=1\nts_ceiling=0\n");
    CHECK(!bt_meta_parse(&back, buf, strlen(buf)));
    strcpy(buf, "profile=2\nid=12345678\nname=x\ntype=wireguard\ncreated=1\norder=0\nts_ceiling=0\n");
    CHECK(!bt_meta_parse(&back, buf, strlen(buf)));
    strcpy(buf, "profile=1\nid=12345678\nname=x\ntype=wireguard\ncreated=1\norder=4294967296\nts_ceiling=0\n");
    CHECK(!bt_meta_parse(&back, buf, strlen(buf)));
    /* unknown keys from a newer daemon are fine */
    strcpy(buf, "profile=1\nid=12345678\nname=x\ntype=wireguard\ncreated=1\norder=0\nts_ceiling=0\nfuture=1\n");
    CHECK(bt_meta_parse(&back, buf, strlen(buf)));
    /* the three types there are */
    strcpy(buf, "profile=1\nid=12345678\nname=x\ntype=tailscale\ncreated=1\norder=0\nts_ceiling=0\n");
    CHECK(bt_meta_parse(&back, buf, strlen(buf)));
    CHECK(strcmp(back.type, BT_TYPE_TAILSCALE) == 0);
    strcpy(buf, "profile=1\nid=12345678\nname=x\ntype=tailscale2\ncreated=1\norder=0\nts_ceiling=0\n");
    CHECK(!bt_meta_parse(&back, buf, strlen(buf)));
}

TEST(settings)
{
    bt_store s;
    bt_settings st;

    fresh_dir(&s);
    CHECK(bt_store_load_settings(&s, &st) == 1);
    CHECK(st.always_on[0] == 0 && st.always_on_tailscale[0] == 0 && st.kill_switch == 0 && st.ts_floor == 0);
    strcpy(st.always_on, "0badc0de");
    strcpy(st.always_on_tailscale, "1badc0de");
    st.kill_switch = 1;
    st.ts_floor = 1790000123ULL;
    REQUIRE(bt_store_save_settings(&s, &st));
    memset(&st, 0x55, sizeof(st));
    CHECK(bt_store_load_settings(&s, &st) == 1);
    CHECK(strcmp(st.always_on, "0badc0de") == 0 && strcmp(st.always_on_tailscale, "1badc0de") == 0);
    CHECK(st.kill_switch == 1 && st.ts_floor == 1790000123ULL);
    /* A file from before Tailscale's own place: none there, and nothing wrong with it. */
    put_file("settings", "settings=1\nalways_on=0badc0de\nkill_switch=0\n");
    CHECK(bt_store_load_settings(&s, &st) == 1 && strcmp(st.always_on, "0badc0de") == 0 && st.always_on_tailscale[0] == 0);
    /* A file from before the floor: none, and nothing wrong with it. */
    put_file("settings", "settings=1\nalways_on=\nkill_switch=0\n");
    CHECK(bt_store_load_settings(&s, &st) == 1 && st.ts_floor == 0);
    put_file("settings", "settings=1\nts_floor=soon\n");
    CHECK(bt_store_load_settings(&s, &st) == 0);
    strcpy(st.always_on, "");
    REQUIRE(bt_store_save_settings(&s, &st));
    CHECK(bt_store_load_settings(&s, &st) == 1 && st.always_on[0] == 0);

    put_file("settings", "settings=1\nalways_on=../x\n");
    CHECK(bt_store_load_settings(&s, &st) == 0);
    CHECK(st.always_on[0] == 0);
    put_file("settings", "settings=1\nalways_on_tailscale=../x\n");
    CHECK(bt_store_load_settings(&s, &st) == 0);
    CHECK(st.always_on_tailscale[0] == 0);
    put_file("settings", "settings=1\nkill_switch=2\n");
    CHECK(bt_store_load_settings(&s, &st) == 0);
    put_file("settings", "junk");
    CHECK(bt_store_load_settings(&s, &st) == 0);
    strcpy(st.always_on, "nothex!!");
    CHECK(!bt_store_save_settings(&s, &st));
    strcpy(st.always_on, "");
    strcpy(st.always_on_tailscale, "nothex!!");
    CHECK(!bt_store_save_settings(&s, &st));
}

int main(void)
{
    char cmd[400];

    snprintf(root, sizeof(root), "/tmp/bt_store_test.XXXXXX");
    if (!mkdtemp(root)) {
        perror("mkdtemp");
        return 2;
    }
    snprintf(dir, sizeof(dir), "%s/daemon", root);
    printf("test_store\n");
    RUN(open_rules);
    RUN(save_load_delete);
    RUN(ids_are_checked);
    RUN(names);
    RUN(list_order);
    RUN(sweep);
    RUN(conf_limits);
    RUN(meta_text);
    RUN(settings);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", root);
    if (system(cmd) != 0) fprintf(stderr, "cleanup failed\n");
    return t_summary("test_store");
}
