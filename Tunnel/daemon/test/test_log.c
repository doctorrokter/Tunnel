/*
 * bt_log: the line format, levels, the memory ring and its tail, the two rotating files.
 */

#include "test_util.h"
#include "../src/bt_log.h"

#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static uint64_t fake_ms = 1790776992345ULL;     /* 2026-09-30 14:03:12.345 UTC */

static uint64_t fake_clock(void)
{
    return fake_ms;
}

static char out[64 * 1024];
static char root[256];

static size_t file_size(const char* path)
{
    struct stat st;
    return stat(path, &st) == 0 ? (size_t)st.st_size : (size_t)-1;
}

TEST(format_and_levels)
{
    size_t n;

    bt_log_close();
    bt_log_set_level(BT_LOG_INFO);
    bt_log(BT_LOG_INFO, "tunnel %s: up", "3fa81c02");
    n = bt_log_tail(out, sizeof(out), 1);
    CHECK(strcmp(out, "2026-09-30 14:03:12.345 I tunnel 3fa81c02: up\n") == 0);
    CHECK(n == strlen(out));

    BT_D("not shown");
    bt_log_tail(out, sizeof(out), 1);
    CHECK(strstr(out, "not shown") == NULL);
    bt_log_set_level(BT_LOG_DEBUG);
    BT_D("shown");
    BT_E("err");
    BT_W("warn");
    bt_log_tail(out, sizeof(out), 3);
    CHECK(strcmp(out, "2026-09-30 14:03:12.345 D shown\n"
                      "2026-09-30 14:03:12.345 E err\n"
                      "2026-09-30 14:03:12.345 W warn\n") == 0);
    bt_log_set_level(BT_LOG_INFO);

    /* A message with line ends stays one line. */
    BT_I("two\nlines\r");
    bt_log_tail(out, sizeof(out), 1);
    CHECK(strcmp(out, "2026-09-30 14:03:12.345 I two lines \n") == 0);
}

TEST(long_line_cut)
{
    char big[2000];

    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = 0;
    BT_I("%s", big);
    bt_log_tail(out, sizeof(out), 1);
    CHECK(strlen(out) == BT_LOG_LINE_MAX);
    CHECK(memcmp(out + BT_LOG_LINE_MAX - 4, "...\n", 4) == 0);
}

TEST(tail_limits)
{
    int i;
    size_t n;

    for (i = 0; i < 10; i++) BT_I("line %d", i);
    bt_log_tail(out, sizeof(out), 2);
    CHECK(strstr(out, "line 8\n") != NULL && strstr(out, "line 9\n") != NULL && strstr(out, "line 7") == NULL);

    /* not enough room for two lines: only the newest one */
    n = bt_log_tail(out, 50, 2);
    CHECK(n == strlen("2026-09-30 14:03:12.345 I line 9\n"));
    CHECK(strstr(out, "line 9") != NULL);
    /* the exact edge: a line of L bytes needs L + 1 with its NUL (heap buffers: ASan sees past them) */
    {
        size_t L = strlen("2026-09-30 14:03:12.345 I line 9\n");
        char* exact = (char*)malloc(L);
        char* room = (char*)malloc(L + 1);
        CHECK(bt_log_tail(exact, L, 1) == 0 && exact[0] == 0);
        CHECK(bt_log_tail(room, L + 1, 1) == L && strstr(room, "line 9\n") != NULL);
        free(exact);
        free(room);
    }
    n = bt_log_tail(out, 10, 5);
    CHECK(n == 0 && out[0] == 0);
    CHECK(bt_log_tail(out, 0, 5) == 0);
}

TEST(ring_wraps_on_line_boundaries)
{
    int i;
    size_t n;

    for (i = 0; i < 3000; i++) BT_I("ring filler number %05d", i);
    n = bt_log_tail(out, sizeof(out), 100000);
    CHECK(n <= BT_LOG_RING);
    CHECK(n > BT_LOG_RING / 2);
    CHECK(memcmp(out, "2026-", 5) == 0);                /* starts with a whole line */
    CHECK(strstr(out, "number 02999\n") != NULL);
    CHECK(out[n - 1] == '\n');
}

TEST(files_rotate)
{
    char path[400], old[400], line[64];
    FILE* f;
    int i;

    snprintf(path, sizeof(path), "%s/daemon.txt", root);
    snprintf(old, sizeof(old), "%s/daemon.1.txt", root);
    REQUIRE(bt_log_open(path, old, 4096, -1, -1));
    BT_I("first");
    CHECK(file_size(path) == strlen("2026-09-30 14:03:12.345 I first\n"));
    for (i = 0; i < 300; i++) BT_I("rotation filler %03d", i);
    CHECK(file_size(path) <= 4096);
    CHECK(file_size(old) <= 4096 && file_size(old) > 3000);

    /* the newest line is at the end of the current file */
    f = fopen(path, "r");
    REQUIRE(f);
    while (fgets(line, sizeof(line), f)) {}
    fclose(f);
    CHECK(strcmp(line, "2026-09-30 14:03:12.345 I rotation filler 299\n") == 0);

    /* reopening appends and knows the size */
    bt_log_close();
    REQUIRE(bt_log_open(path, old, 4096, -1, -1));
    BT_I("after reopen");
    CHECK(file_size(path) <= 4096);
    bt_log_close();
    CHECK(!bt_log_open(NULL, NULL, 0, -1, -1));
    BT_I("memory only still works");
    bt_log_tail(out, sizeof(out), 1);
    CHECK(strstr(out, "memory only") != NULL);
}

int main(void)
{
    char cmd[300];

    setenv("TZ", "UTC", 1);
    tzset();
    bt_log_set_clock(fake_clock);
    snprintf(root, sizeof(root), "/tmp/bt_log_test.XXXXXX");
    if (!mkdtemp(root)) return 2;
    printf("test_log\n");
    RUN(format_and_levels);
    RUN(long_line_cut);
    RUN(tail_limits);
    RUN(ring_wraps_on_line_boundaries);
    RUN(files_rotate);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", root);
    if (system(cmd) != 0) fprintf(stderr, "cleanup failed\n");
    return t_summary("test_log");
}
