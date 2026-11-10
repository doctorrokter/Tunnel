/*
 * ts_json - JSON as Tailscale's control server sends it (docs/TAILSCALE.md, section 5.6): jsmn
 * tokens over the text, strict checks on top, and typed getters that read our fields the way Go's
 * encoding/json reads them. Sans-IO and allocation-free, like the engine.
 *
 * Why tokens and not a tree (cJSON): a netmap is tens to hundreds of KB, a tree of it several
 * times that. jsmn only records where each value lies (20 bytes a token); the text is the storage
 * and must outlive the parsed document. Getters copy out what is kept.
 *
 * jsmn's configuration, set here for every file that sees the token type:
 *   JSMN_STRICT        keys must be strings, a primitive must start like a JSON literal;
 *   JSMN_PARENT_LINKS  without them a closing bracket or a comma looks for the open container by
 *                      walking BACK over every token so far, and [[],[],[],...] makes the whole
 *                      parse quadratic - a few hundred KB of hostile text costs seconds;
 *   JSMN_STATIC        in ts_json.c only: the parser is compiled there, static - no jsmn_* symbol
 *                      leaves the object, so a copy in some library cannot clash with it. Other
 *                      files get the types (JSMN_HEADER) and must not call jsmn themselves.
 *
 * jsmn alone is lenient - a missing comma or colon, a trailing comma, garbage after the value,
 * several top-level values, any run of printable bytes as a "primitive", raw control characters
 * in strings - and its walk up to the open container costs the nesting depth at every closing
 * bracket. So ts_json_parse does three passes:
 *   1. a scan of the bytes: no NUL, nesting at most TS_JSON_MAX_DEPTH. Before jsmn runs, so a
 *      bracket bomb costs one linear pass, and jsmn's walk is bounded by the depth limit;
 *   2. jsmn into the caller's token array (ts_json_count says how many tokens a text needs);
 *   3. a check of the tokens: one value, an object or an array; object members are a string key
 *      and exactly one value; every byte between tokens is whitespace or the one separator the
 *      grammar wants there; numbers and literals exactly as RFC 8259 spells them; no raw control
 *      character and only the eight escapes in strings.
 * What passes is what Go's scanner accepts (bytes >= 0x80 are not checked for valid UTF-8 by Go
 * either), save a scalar at the top level, which no Tailscale message is.
 *
 * The getters follow Go's encoding/json where it matters for the fields we read:
 *   - a member name matches a struct field exactly or under Go's case folding (ts_json_key_is):
 *     "peers" and "PEERS" both are Peers, and so are the only two letters beyond ASCII whose fold
 *     set holds an ASCII one - U+017F long s (S) and U+212A Kelvin sign (K): "Peer" and U+017F
 *     is Peers to Go. U+0130 and U+0131 fold onto nothing else: U+0130 and "D" is not ID;
 *   - strings: escapes and surrogate pairs become UTF-8; a lone surrogate and every byte of
 *     invalid UTF-8 become U+FFFD - Go does not fail on them; \u0000 stays a NUL byte (the length
 *     says where the value ends). A value longer than the caller's buffer is refused, not cut;
 *   - integers: a number without fraction or exponent and in range. "1.0", "1e2" and values out
 *     of range are refused, as Go refuses them for an integer field;
 *   - null: the callers take it as absent - what it means to Go for every field we read.
 */

#ifndef TS_JSON_H
#define TS_JSON_H

#include <stddef.h>
#include <stdint.h>

#define JSMN_STRICT
#define JSMN_PARENT_LINKS
#ifndef TS_JSON_IMPL
#define JSMN_HEADER                     /* the types only; the parser is ts_json.c's */
#endif
#include "jsmn.h"

#define TS_JSON_MAX_DEPTH   64          /* nesting; Tailscale's deepest is about 8 */
#define TS_JSON_MAX_TEXT    (16u << 20) /* jsmn keeps offsets in int; callers set lower limits */

typedef enum {
    TS_JSON_OK = 0,
    TS_JSON_ERR_SIZE,                   /* longer than TS_JSON_MAX_TEXT */
    TS_JSON_ERR_DEPTH,                  /* nested deeper than TS_JSON_MAX_DEPTH */
    TS_JSON_ERR_TOKENS,                 /* more tokens than the caller's array has */
    TS_JSON_ERR_TRUNCATED,              /* the text ends before the value does (or is empty) */
    TS_JSON_ERR_SYNTAX                  /* not JSON, or a scalar at the top level */
} ts_json_err;

typedef enum {
    TS_JSON_NONE = 0,                   /* no such token */
    TS_JSON_OBJECT,
    TS_JSON_ARRAY,
    TS_JSON_STRING,
    TS_JSON_NUMBER,
    TS_JSON_TRUE,
    TS_JSON_FALSE,
    TS_JSON_NULL
} ts_json_type;

/*
 * A parsed document. Tokens are numbered in the order their values start in the text; token 0 is
 * the top-level value. An object's tokens are its keys, each followed by its value (and whatever
 * that value holds); an array's are its elements.
 */
typedef struct {
    const char*      text;
    size_t           len;
    const jsmntok_t* tok;
    int              n;                 /* tokens used */
    ts_json_err      err;               /* why ts_json_parse refused the text */
    size_t           err_at;            /* about where, as a byte offset */
} ts_json;

/* The number of tokens `text` needs - the size of the array for ts_json_parse - or -1 when the
 * byte scan already refuses it. Exact for JSON; malformed text may get any count and is refused by
 * the parse itself. */
long ts_json_count(const char* text, size_t len);

/* Parses and checks `text` (kept by reference) into the caller's `cap` tokens. 1 on success; 0
 * with d->err and d->err_at set. */
int ts_json_parse(ts_json* d, const char* text, size_t len, jsmntok_t* tok, size_t cap);

const char* ts_json_err_text(ts_json_err e);

/* --- walking ------------------------------------------------------------------------------- */

ts_json_type ts_json_type_of(const ts_json* d, int t);

/* The token after t and everything inside it (a key: after its value). O(log n). */
int ts_json_skip(const ts_json* d, int t);

/* An object's first key or an array's first element; -1 when empty or not a container. */
int ts_json_first(const ts_json* d, int t);

/* The key or element after `t` in the same container; -1 at the end. A key's value is key + 1. */
int ts_json_next(const ts_json* d, int t);

/* Members of an object or elements of an array; 0 for anything else. */
int ts_json_size(const ts_json* d, int t);

/* The byte offset where token t starts (for messages). */
size_t ts_json_offset(const ts_json* d, int t);

/* --- keys ---------------------------------------------------------------------------------- */

/* Whether key `t` names the field `name` (ASCII) the way Go matches JSON names to struct fields:
 * equal under its case folding, escapes decoded. */
int ts_json_key_is(const ts_json* d, int t, const char* name);

/*
 * Key `t` folded as Go folds it, into `out` (cap bytes, NUL-terminated): ASCII letters upper case,
 * the two letters above onto theirs. 0 when the name holds anything else beyond ASCII (then it
 * can name no field of ours) or does not fit - for matching against many names at once.
 */
int ts_json_key_fold(const ts_json* d, int t, char* out, size_t cap);

/* The value of member `name` (Go's matching) among the direct members of object `obj` - never
 * inside their values: its token, -1 when absent, -2 when more than one member matches. */
int ts_json_find(const ts_json* d, int obj, const char* name);

/* Key `t` as Go reads a map key of an integer type (strconv.ParseInt): an optional sign, decimal
 * digits, leading zeros allowed, in range. 1 and *v when it is one. */
int ts_json_key_i64(const ts_json* d, int t, int64_t* v);

/* --- values -------------------------------------------------------------------------------- */

/* A string's value, unescaped as Go does it, into out (cap bytes; a NUL is written after it).
 * 1 and *len; 0 when t is not a string or the value does not fit in cap - 1 bytes. */
int ts_json_str(const ts_json* d, int t, char* out, size_t cap, size_t* len);

/* The same for text only shown to a person: a value that does not fit is cut after the last
 * whole character that does. 1 when it fit whole, 2 when cut, 0 when t is not a string. */
int ts_json_str_cut(const ts_json* d, int t, char* out, size_t cap, size_t* len);

int ts_json_i64(const ts_json* d, int t, int64_t* v);
int ts_json_u64(const ts_json* d, int t, uint64_t* v);

/* Any number, to the nearest double for ordinary values (multipliers like 0.8 and 1.5 exactly as
 * Go's ParseFloat; long mantissas and extreme exponents may differ in the last bits). 0 when not a
 * number or out of double range - Go refuses that for a float64 field. */
int ts_json_f64(const ts_json* d, int t, double* v);

int ts_json_bool(const ts_json* d, int t, int* v);
int ts_json_is_null(const ts_json* d, int t);

/* The token's text as it stands: a string without its quotes, its escapes as written. */
const char* ts_json_raw(const ts_json* d, int t, size_t* len);

#endif /* TS_JSON_H */
