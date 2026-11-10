/*
 * A minimal test harness: no framework to port to QNX, so the same test binaries run on the
 * workstation and, cross-built, on the phone.
 */

#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int t_failures;
static int t_checks;

#define CHECK(cond)                                                              \
    do {                                                                         \
        t_checks++;                                                              \
        if (!(cond)) {                                                           \
            t_failures++;                                                        \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
        }                                                                        \
    } while (0)

/* A CHECK that ends the test when it fails: for preconditions (a pointer the next lines use)
 * whose failure would otherwise crash the whole binary instead of failing one test. `cond` is
 * evaluated ONCE - it may be a call with side effects (an earlier version evaluated it twice, and
 * the second, repeated call quietly ended a test that had passed). */
#define REQUIRE(cond)                                                            \
    do {                                                                         \
        int require_ok_ = (cond) ? 1 : 0;                                        \
        t_checks++;                                                              \
        if (!require_ok_) {                                                      \
            t_failures++;                                                        \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
            return;                                                              \
        }                                                                        \
    } while (0)

#define CHECK_MEM(a, b, n)                                                       \
    do {                                                                         \
        t_checks++;                                                              \
        if (memcmp((a), (b), (n)) != 0) {                                        \
            t_failures++;                                                        \
            fprintf(stderr, "  FAIL %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b); \
            t_dump("    got ", (const uint8_t*)(a), (n));                        \
            t_dump("    want", (const uint8_t*)(b), (n));                        \
        }                                                                        \
    } while (0)

static void t_dump(const char* label, const uint8_t* p, size_t n)
{
    size_t i;
    fprintf(stderr, "%s ", label);
    for (i = 0; i < n; i++) fprintf(stderr, "%02x", p[i]);
    fprintf(stderr, "\n");
}

/* Parses a hex string into buf; returns the byte count. Aborts on malformed input - a typo in a
 * test vector must not silently shorten it. */
static size_t t_hex(uint8_t* buf, size_t cap, const char* hex)
{
    size_t n = 0;
    while (*hex) {
        unsigned v;
        if (*hex == ' ' || *hex == ':') { hex++; continue; }
        if (n >= cap || sscanf(hex, "%2x", &v) != 1) {
            fprintf(stderr, "bad test vector near \"%s\"\n", hex);
            exit(2);
        }
        buf[n++] = (uint8_t)v;
        hex += 2;
    }
    return n;
}

#define TEST(name) static void name(void)
#define RUN(name)                                                                \
    do {                                                                         \
        int before = t_failures;                                                 \
        name();                                                                  \
        printf("  %-40s %s\n", #name, t_failures == before ? "ok" : "FAILED");   \
    } while (0)

static int t_summary(const char* suite)
{
    printf("%s: %d checks, %d failed\n", suite, t_checks, t_failures);
    return t_failures ? 1 : 0;
}

#endif /* TEST_UTIL_H */
