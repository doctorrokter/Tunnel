/*
 * bt_proto - the text protocol between the app and the daemon (docs/DAEMON.md, section 3), without
 * any I/O: framing a byte stream into blocks, parsing a block, building one.
 *
 * A block is lines of key=value ended by an empty line, as in WireGuard's UAPI:
 *
 *   cmd=profile.import
 *   id=7
 *   name=Home
 *   conf=[Interface]\nPrivateKey = ...\n
 *
 * The first key says what the block is (cmd / reply / event); the rest is up to the command. A key
 * may repeat (lists). Values are escaped so a block stays lines: backslash, LF and CR become \\, \n
 * and \r; no other escape exists, and a NUL byte cannot be carried at all. CRLF line ends are
 * accepted and a stray empty line between blocks is skipped.
 *
 * The daemon runs as root and parses what a client sends, so everything here is bounded and
 * refuses rather than guesses: a key is 1-32 of [a-z0-9_.], a block is at most BT_BLOCK_MAX bytes
 * and BT_BLOCK_MAX_LINES lines. A client that breaks the rules is dropped by the caller.
 */

#ifndef BT_PROTO_H
#define BT_PROTO_H

#include <stddef.h>
#include <stdint.h>

#define BT_PROTO_VERSION    1
#define BT_BLOCK_MAX        (256 * 1024)    /* a long split-tunnel .conf fits */
#define BT_BLOCK_MAX_LINES  256
#define BT_KEY_MAX          32

/* One line of a parsed block. Both strings are NUL-terminated and point into the parsed text;
 * `val_len` is the unescaped length. */
typedef struct {
    const char* key;
    const char* val;
    size_t      val_len;
} bt_kv;

typedef struct {
    bt_kv  kv[BT_BLOCK_MAX_LINES];
    size_t n;
} bt_block;

/*
 * Parses one block - its lines without the ending empty line - IN PLACE: '=' and line ends become
 * NULs, values are unescaped where they lie. `text` must stay as long as the block is used. 1 on
 * success; 0 with a reason in `err` (may be NULL).
 */
int bt_block_parse(bt_block* b, char* text, size_t len, char* err, size_t errlen);

/* The first key: "cmd", "reply" or "event" in a well-formed block; NULL for an empty one. */
const char* bt_block_kind(const bt_block* b);

/* The value of the first line with `key`, NULL when absent. */
const char* bt_get(const bt_block* b, const char* key);

/* The same with its length (values may be long .conf text). */
const char* bt_get_len(const bt_block* b, const char* key, size_t* len);

/* The index of the next line with `key` at or after `from`; b->n when there is none. For lists. */
size_t bt_find(const bt_block* b, const char* key, size_t from);

/* A decimal number no larger than `max`: 1 and *out when present and well-formed, 0 when absent,
 * -1 when present but not such a number. */
int bt_get_u64(const bt_block* b, const char* key, uint64_t max, uint64_t* out);

/* 0 or 1, the same way. */
int bt_get_bool(const bt_block* b, const char* key, int* out);

/* A key the protocol allows: 1-32 of [a-z0-9_.]. */
int bt_key_valid(const char* key, size_t len);

/* --- a byte stream into blocks -------------------------------------------------------------- */

/*
 * Collects what a connection reads and hands out whole blocks. The buffer is the caller's and
 * must hold a whole block and its ending: BT_BLOCK_MAX + 4 bytes for any block the protocol allows.
 */
typedef struct {
    char*  buf;
    size_t cap;
    size_t len;         /* bytes held */
    size_t scanned;     /* bytes already searched for the end of the block, not yet complete */
    size_t consumed;    /* bytes of the block handed out last; dropped on the next call */
} bt_reader;

void bt_reader_init(bt_reader* r, char* buf, size_t cap);

/* Where to read into and how much room there is (0 once full: the caller then calls next). */
char* bt_reader_space(bt_reader* r, size_t* room);

/* `n` bytes were read into the space. */
void bt_reader_commit(bt_reader* r, size_t n);

/*
 * The next whole block, parsed in place into `b` and valid until the next call of either function
 * (call it until it returns 0 before reading more: one read may bring several blocks): 1. 0 when more
 * bytes are needed. -1 when the stream breaks the rules (a block too long or malformed); the
 * connection is then beyond repair, the reason in `err`.
 */
int bt_reader_next(bt_reader* r, bt_block* b, char* err, size_t errlen);

/* --- building a block ------------------------------------------------------------------------ */

/*
 * Appends lines to the caller's buffer. A line that does not fit, a bad key or a NUL in a value
 * sets `failed` and the writer stops taking lines: check it once at the end.
 */
typedef struct {
    char*  buf;
    size_t cap;
    size_t len;
    int    failed;
} bt_writer;

void bt_writer_init(bt_writer* w, char* buf, size_t cap);

void bt_put(bt_writer* w, const char* key, const char* val);
void bt_put_n(bt_writer* w, const char* key, const char* val, size_t len);
void bt_put_u64(bt_writer* w, const char* key, uint64_t v);
void bt_put_i64(bt_writer* w, const char* key, int64_t v);

/* The empty line that ends the block. 1 when the whole block is in the buffer. */
int bt_end(bt_writer* w);

#endif /* BT_PROTO_H */
