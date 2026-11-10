/*
 * ts_json - see ts_json.h. Go's behaviour is from encoding/json (decode.go unquote, fold.go) and
 * unicode/utf8 of Go 1.27; the grammar is RFC 8259.
 */

#define TS_JSON_IMPL
#define JSMN_STATIC
#include "ts_json.h"

#include <float.h>
#include <string.h>

#define INT64_LOW   (-9223372036854775807LL - 1)    /* QNX's stdint.h has no INT64_MIN in gnu99 */

static int is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static int is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int fail(ts_json* d, ts_json_err e, size_t at)
{
    d->err = e;
    d->err_at = at;
    return 0;
}

/* --------------------------------------------------------------------- the byte scan */

/* No NUL anywhere (jsmn stops at one and would ignore the rest); brackets outside strings nested
 * at most TS_JSON_MAX_DEPTH. A string here runs to the next unescaped quote, as in jsmn. */
static ts_json_err prescan(const char* s, size_t len, size_t* at)
{
    size_t i;
    int depth = 0, in_str = 0, esc = 0;

    for (i = 0; i < len; i++) {
        char c = s[i];

        if (c == '\0') {
            *at = i;
            return TS_JSON_ERR_SYNTAX;
        }
        if (esc) {
            esc = 0;
        } else if (in_str) {
            if (c == '\\') esc = 1;
            else if (c == '"') in_str = 0;
        } else if (c == '"') {
            in_str = 1;
        } else if (c == '{' || c == '[') {
            if (++depth > TS_JSON_MAX_DEPTH) {
                *at = i;
                return TS_JSON_ERR_DEPTH;
            }
        } else if (c == '}' || c == ']') {
            if (--depth < 0) {
                *at = i;
                return TS_JSON_ERR_SYNTAX;
            }
        }
    }
    return TS_JSON_OK;
}

long ts_json_count(const char* text, size_t len)
{
    jsmn_parser p;
    size_t at;
    int r;

    if (len == 0 || len > TS_JSON_MAX_TEXT || prescan(text, len, &at) != TS_JSON_OK) return -1;
    jsmn_init(&p);
    r = jsmn_parse(&p, text, len, NULL, 0);
    return r < 0 ? -1 : (long)r;
}

/* --------------------------------------------------------------------- the token check */

/* Where a token's text begins and ends, quotes included: jsmn's string tokens exclude them. */
static size_t outer_start(const jsmntok_t* t)
{
    return (size_t)(t->type == JSMN_STRING ? t->start - 1 : t->start);
}

static size_t outer_end(const jsmntok_t* t)
{
    return (size_t)(t->type == JSMN_STRING ? t->end + 1 : t->end);
}

/* text[from, to) is whitespace with exactly one `sep` in it - or none, for sep 0. */
static int gap_ok(const char* s, size_t from, size_t to, char sep)
{
    size_t i;
    int seen = 0;

    if (from > to) return 0;
    for (i = from; i < to; i++) {
        if (is_ws(s[i])) continue;
        if (sep && s[i] == sep && !seen) {
            seen = 1;
            continue;
        }
        return 0;
    }
    return sep ? seen : 1;
}

/* Inside a string: no raw control character, only the escapes JSON has. */
static int string_ok(const char* s, size_t from, size_t to)
{
    size_t i;

    for (i = from; i < to; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20) return 0;
        if (c != '\\') continue;
        if (++i >= to) return 0;
        switch (s[i]) {
        case '"': case '\\': case '/': case 'b': case 'f': case 'n': case 'r': case 't':
            break;
        case 'u':
            if (to - i < 5) return 0;
            if (hex_val(s[i + 1]) < 0 || hex_val(s[i + 2]) < 0 || hex_val(s[i + 3]) < 0 ||
                hex_val(s[i + 4]) < 0)
                return 0;
            i += 4;
            break;
        default:
            return 0;
        }
    }
    return 1;
}

/* -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)? and nothing more. */
static int number_ok(const char* s, size_t n)
{
    size_t i = 0;

    if (i < n && s[i] == '-') i++;
    if (i >= n) return 0;
    if (s[i] == '0') {
        i++;
    } else if (s[i] >= '1' && s[i] <= '9') {
        while (i < n && is_digit(s[i])) i++;
    } else {
        return 0;
    }
    if (i < n && s[i] == '.') {
        i++;
        if (i >= n || !is_digit(s[i])) return 0;
        while (i < n && is_digit(s[i])) i++;
    }
    if (i < n && (s[i] == 'e' || s[i] == 'E')) {
        i++;
        if (i < n && (s[i] == '+' || s[i] == '-')) i++;
        if (i >= n || !is_digit(s[i])) return 0;
        while (i < n && is_digit(s[i])) i++;
    }
    return i == n;
}

static int primitive_ok(const char* s, size_t n)
{
    if (n == 4 && memcmp(s, "true", 4) == 0) return 1;
    if (n == 5 && memcmp(s, "false", 5) == 0) return 1;
    if (n == 4 && memcmp(s, "null", 4) == 0) return 1;
    return number_ok(s, n);
}

typedef struct {
    int tok;                            /* the container */
    int left;                           /* members or elements still to come */
    int first;                          /* none seen yet */
    int key;                            /* an object: the key whose value comes next, or -1 */
} frame;

/* A value token at i: a container opens a frame; a string or primitive is checked. */
static int value_ok(ts_json* d, int i, frame* st, int* sp, size_t* pos)
{
    const jsmntok_t* t = &d->tok[i];

    switch (t->type) {
    case JSMN_OBJECT:
    case JSMN_ARRAY:
        if (*sp >= TS_JSON_MAX_DEPTH) return fail(d, TS_JSON_ERR_DEPTH, (size_t)t->start);
        st[*sp].tok = i;
        st[*sp].left = t->size;
        st[*sp].first = 1;
        st[*sp].key = -1;
        (*sp)++;
        *pos = (size_t)t->start + 1;
        return 1;
    case JSMN_STRING:
        if (t->size != 0 || !string_ok(d->text, (size_t)t->start, (size_t)t->end))
            return fail(d, TS_JSON_ERR_SYNTAX, (size_t)t->start);
        *pos = outer_end(t);
        return 1;
    case JSMN_PRIMITIVE:
        if (t->size != 0 || !primitive_ok(d->text + t->start, (size_t)(t->end - t->start)))
            return fail(d, TS_JSON_ERR_SYNTAX, (size_t)t->start);
        *pos = (size_t)t->end;
        return 1;
    default:
        return fail(d, TS_JSON_ERR_SYNTAX, (size_t)t->start);
    }
}

/* The container on top is complete: only whitespace before its closing bracket. */
static int close_ok(ts_json* d, const frame* f, size_t* pos)
{
    const jsmntok_t* t = &d->tok[f->tok];
    char want = t->type == JSMN_OBJECT ? '}' : ']';

    if (f->left != 0 || f->key >= 0 || t->end < 1 || !gap_ok(d->text, *pos, (size_t)t->end - 1, 0) ||
        d->text[t->end - 1] != want)
        return fail(d, TS_JSON_ERR_SYNTAX, *pos);
    *pos = (size_t)t->end;
    return 1;
}

/*
 * Every token in document order against the grammar. Tokens are checked against the frame of the
 * container they must belong to - by jsmn's parent link and by the separator before them - so a
 * missing or extra comma or colon, a key that is no string or has no value, or a second top-level
 * value cannot pass.
 */
static int tokens_ok(ts_json* d)
{
    frame st[TS_JSON_MAX_DEPTH];
    int sp = 0, i;
    size_t pos = 0;
    const jsmntok_t* t0 = &d->tok[0];

    if (t0->type != JSMN_OBJECT && t0->type != JSMN_ARRAY) return fail(d, TS_JSON_ERR_SYNTAX, 0);
    if (!gap_ok(d->text, 0, outer_start(t0), 0)) return fail(d, TS_JSON_ERR_SYNTAX, 0);
    if (!value_ok(d, 0, st, &sp, &pos)) return 0;

    for (i = 1; i < d->n; i++) {
        const jsmntok_t* t = &d->tok[i];
        frame* f;

        while (sp > 0 && st[sp - 1].left == 0 && st[sp - 1].key < 0) {
            if (!close_ok(d, &st[sp - 1], &pos)) return 0;
            sp--;
        }
        if (sp == 0) return fail(d, TS_JSON_ERR_SYNTAX, (size_t)t->start);   /* a second value */
        f = &st[sp - 1];

        if (d->tok[f->tok].type == JSMN_OBJECT) {
            if (f->key < 0) {
                /* a key: a string with exactly one value */
                if (f->left <= 0 || t->type != JSMN_STRING || t->size != 1 || t->parent != f->tok ||
                    !gap_ok(d->text, pos, outer_start(t), f->first ? 0 : ',') ||
                    !string_ok(d->text, (size_t)t->start, (size_t)t->end))
                    return fail(d, TS_JSON_ERR_SYNTAX, (size_t)t->start);
                f->first = 0;
                f->key = i;
                pos = outer_end(t);
                continue;
            }
            if (t->parent != f->key || !gap_ok(d->text, pos, outer_start(t), ':'))
                return fail(d, TS_JSON_ERR_SYNTAX, (size_t)t->start);
            f->key = -1;
        } else {
            if (f->left <= 0 || t->parent != f->tok ||
                !gap_ok(d->text, pos, outer_start(t), f->first ? 0 : ','))
                return fail(d, TS_JSON_ERR_SYNTAX, (size_t)t->start);
            f->first = 0;
        }
        f->left--;
        if (!value_ok(d, i, st, &sp, &pos)) return 0;
    }
    while (sp > 0) {
        if (!close_ok(d, &st[sp - 1], &pos)) return 0;
        sp--;
    }
    if (!gap_ok(d->text, pos, d->len, 0)) return fail(d, TS_JSON_ERR_SYNTAX, pos);
    return 1;
}

int ts_json_parse(ts_json* d, const char* text, size_t len, jsmntok_t* tok, size_t cap)
{
    jsmn_parser p;
    ts_json_err e;
    size_t at = 0;
    int r;

    memset(d, 0, sizeof(*d));
    d->text = text;
    d->len = len;
    d->tok = tok;
    if (len > TS_JSON_MAX_TEXT) return fail(d, TS_JSON_ERR_SIZE, 0);
    if (len == 0) return fail(d, TS_JSON_ERR_TRUNCATED, 0);
    e = prescan(text, len, &at);
    if (e != TS_JSON_OK) return fail(d, e, at);

    jsmn_init(&p);
    r = jsmn_parse(&p, text, len, tok, cap > 0x7fffffffu ? 0x7fffffffu : (unsigned)cap);
    if (r == JSMN_ERROR_NOMEM) return fail(d, TS_JSON_ERR_TOKENS, p.pos);
    if (r == JSMN_ERROR_PART) return fail(d, TS_JSON_ERR_TRUNCATED, len);
    if (r < 0) return fail(d, TS_JSON_ERR_SYNTAX, p.pos);
    if (r == 0) return fail(d, TS_JSON_ERR_TRUNCATED, len);
    d->n = r;
    if (!tokens_ok(d)) {
        d->n = 0;
        return 0;
    }
    return 1;
}

const char* ts_json_err_text(ts_json_err e)
{
    switch (e) {
    case TS_JSON_OK:            return "ok";
    case TS_JSON_ERR_SIZE:      return "too long";
    case TS_JSON_ERR_DEPTH:     return "nested too deep";
    case TS_JSON_ERR_TOKENS:    return "too many values";
    case TS_JSON_ERR_TRUNCATED: return "cut short";
    case TS_JSON_ERR_SYNTAX:    return "not JSON";
    }
    return "?";
}

/* --------------------------------------------------------------------- walking */

ts_json_type ts_json_type_of(const ts_json* d, int t)
{
    const jsmntok_t* k;

    if (t < 0 || t >= d->n) return TS_JSON_NONE;
    k = &d->tok[t];
    switch (k->type) {
    case JSMN_OBJECT:   return TS_JSON_OBJECT;
    case JSMN_ARRAY:    return TS_JSON_ARRAY;
    case JSMN_STRING:   return TS_JSON_STRING;
    case JSMN_PRIMITIVE:
        switch (d->text[k->start]) {
        case 't':       return TS_JSON_TRUE;
        case 'f':       return TS_JSON_FALSE;
        case 'n':       return TS_JSON_NULL;
        default:        return TS_JSON_NUMBER;
        }
    default:
        return TS_JSON_NONE;
    }
}

int ts_json_skip(const ts_json* d, int t)
{
    const jsmntok_t* k;
    int lo, hi;

    if (t < 0 || t >= d->n) return d->n;
    k = &d->tok[t];
    if (k->type == JSMN_STRING && k->size == 1) {
        /* a key: its value follows it, and is never a key itself */
        t++;
        if (t >= d->n) return d->n;
        k = &d->tok[t];
    }
    if (k->type != JSMN_OBJECT && k->type != JSMN_ARRAY) return t + 1;
    /* Tokens are in the order their text starts: what lies inside the container starts before its
     * end, what follows it at or after. */
    lo = t + 1;
    hi = d->n;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (d->tok[mid].start < k->end) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

int ts_json_first(const ts_json* d, int t)
{
    ts_json_type ty = ts_json_type_of(d, t);

    if ((ty != TS_JSON_OBJECT && ty != TS_JSON_ARRAY) || d->tok[t].size == 0) return -1;
    return t + 1;
}

int ts_json_next(const ts_json* d, int t)
{
    int j;

    if (t <= 0 || t >= d->n) return -1;
    j = ts_json_skip(d, t);
    if (j >= d->n || d->tok[j].parent != d->tok[t].parent) return -1;
    return j;
}

int ts_json_size(const ts_json* d, int t)
{
    ts_json_type ty = ts_json_type_of(d, t);

    return ty == TS_JSON_OBJECT || ty == TS_JSON_ARRAY ? d->tok[t].size : 0;
}

size_t ts_json_offset(const ts_json* d, int t)
{
    if (t < 0 || t >= d->n) return d->len;
    return outer_start(&d->tok[t]);
}

const char* ts_json_raw(const ts_json* d, int t, size_t* len)
{
    if (t < 0 || t >= d->n) {
        *len = 0;
        return "";
    }
    *len = (size_t)(d->tok[t].end - d->tok[t].start);
    return d->text + d->tok[t].start;
}

/* --------------------------------------------------------------------- strings, as Go reads them */

#define RUNE_ERROR  0xfffdu

static int cont(unsigned char c)
{
    return (c & 0xc0) == 0x80;
}

/* utf8.DecodeRune: the rune at s (n bytes left) and its length; U+FFFD and 1 for anything that
 * is not shortest-form UTF-8 of a scalar value (surrogates and overlong forms included). */
static uint32_t utf8_decode(const unsigned char* s, size_t n, size_t* used)
{
    unsigned char c = s[0];

    *used = 1;
    if (c < 0x80) return c;
    if (c >= 0xc2 && c <= 0xdf) {
        if (n >= 2 && cont(s[1])) {
            *used = 2;
            return ((uint32_t)(c & 0x1f) << 6) | (s[1] & 0x3f);
        }
    } else if (c >= 0xe0 && c <= 0xef) {
        unsigned char lo = c == 0xe0 ? 0xa0 : 0x80, hi = c == 0xed ? 0x9f : 0xbf;
        if (n >= 3 && s[1] >= lo && s[1] <= hi && cont(s[2])) {
            *used = 3;
            return ((uint32_t)(c & 0x0f) << 12) | ((uint32_t)(s[1] & 0x3f) << 6) | (s[2] & 0x3f);
        }
    } else if (c >= 0xf0 && c <= 0xf4) {
        unsigned char lo = c == 0xf0 ? 0x90 : 0x80, hi = c == 0xf4 ? 0x8f : 0xbf;
        if (n >= 4 && s[1] >= lo && s[1] <= hi && cont(s[2]) && cont(s[3])) {
            *used = 4;
            return ((uint32_t)(c & 0x07) << 18) | ((uint32_t)(s[1] & 0x3f) << 12) |
                   ((uint32_t)(s[2] & 0x3f) << 6) | (s[3] & 0x3f);
        }
    }
    return RUNE_ERROR;
}

static size_t utf8_encode(uint32_t r, unsigned char* out)
{
    if (r < 0x80) {
        out[0] = (unsigned char)r;
        return 1;
    }
    if (r < 0x800) {
        out[0] = (unsigned char)(0xc0 | (r >> 6));
        out[1] = (unsigned char)(0x80 | (r & 0x3f));
        return 2;
    }
    if (r < 0x10000) {
        out[0] = (unsigned char)(0xe0 | (r >> 12));
        out[1] = (unsigned char)(0x80 | ((r >> 6) & 0x3f));
        out[2] = (unsigned char)(0x80 | (r & 0x3f));
        return 3;
    }
    out[0] = (unsigned char)(0xf0 | (r >> 18));
    out[1] = (unsigned char)(0x80 | ((r >> 12) & 0x3f));
    out[2] = (unsigned char)(0x80 | ((r >> 6) & 0x3f));
    out[3] = (unsigned char)(0x80 | (r & 0x3f));
    return 4;
}

static int32_t hex4(const char* s)
{
    int a = hex_val(s[0]), b = hex_val(s[1]), c = hex_val(s[2]), e = hex_val(s[3]);

    if (a < 0 || b < 0 || c < 0 || e < 0) return -1;
    return (int32_t)((a << 12) | (b << 8) | (c << 4) | e);
}

/*
 * The next rune of a string's text s[*i, end) as Go's unquote yields it: escapes decoded, a
 * surrogate pair joined, a lone surrogate or an invalid UTF-8 byte as U+FFFD. The text passed
 * the token check, so every escape is complete.
 */
static uint32_t next_rune(const char* s, size_t* i, size_t end)
{
    unsigned char c = (unsigned char)s[*i];

    if (c == '\\') {
        char e = s[*i + 1];
        *i += 2;
        switch (e) {
        case 'b': return 0x08;
        case 'f': return 0x0c;
        case 'n': return 0x0a;
        case 'r': return 0x0d;
        case 't': return 0x09;
        case 'u': {
            int32_t r = hex4(s + *i);
            *i += 4;
            if (r < 0) return RUNE_ERROR;
            if (r >= 0xd800 && r < 0xe000) {
                /* utf16.DecodeRune(r, the next \u escape): a high and a low half, or U+FFFD - and
                 * then the next escape is read on its own */
                if (r < 0xdc00 && end - *i >= 6 && s[*i] == '\\' && s[*i + 1] == 'u') {
                    int32_t r2 = hex4(s + *i + 2);
                    if (r2 >= 0xdc00 && r2 < 0xe000) {
                        *i += 6;
                        return 0x10000u + (((uint32_t)r - 0xd800u) << 10) + ((uint32_t)r2 - 0xdc00u);
                    }
                }
                return RUNE_ERROR;
            }
            return (uint32_t)r;
        }
        default:
            return (unsigned char)e;    /* " \ / */
        }
    }
    if (c < 0x80) {
        (*i)++;
        return c;
    }
    {
        size_t used;
        uint32_t r = utf8_decode((const unsigned char*)s + *i, end - *i, &used);
        *i += used;
        return r;
    }
}

/* Unescapes into out: 1 whole, 2 cut (when `cut` allows it), 0 not a string or not fitting. */
static int str_copy(const ts_json* d, int t, char* out, size_t cap, size_t* len, int cut)
{
    const jsmntok_t* k;
    size_t i, end, w = 0;
    int whole = 1;

    if (ts_json_type_of(d, t) != TS_JSON_STRING || cap == 0) return 0;
    k = &d->tok[t];
    i = (size_t)k->start;
    end = (size_t)k->end;
    while (i < end) {
        unsigned char buf[4];
        size_t n;
        char c = d->text[i];

        if (c != '\\' && (unsigned char)c < 0x80) {
            /* plain ASCII: the common case */
            buf[0] = (unsigned char)c;
            n = 1;
            i++;
        } else {
            n = utf8_encode(next_rune(d->text, &i, end), buf);
        }
        if (w + n + 1 > cap) {
            if (!cut) return 0;
            whole = 0;
            break;
        }
        memcpy(out + w, buf, n);
        w += n;
    }
    out[w] = '\0';
    if (len) *len = w;
    return whole ? 1 : 2;
}

int ts_json_str(const ts_json* d, int t, char* out, size_t cap, size_t* len)
{
    return str_copy(d, t, out, cap, len, 0);
}

int ts_json_str_cut(const ts_json* d, int t, char* out, size_t cap, size_t* len)
{
    return str_copy(d, t, out, cap, len, 1);
}

/* --------------------------------------------------------------------- keys */

/* The ASCII byte rune r folds to under Go's foldName - ASCII letters to upper case, any other rune
 * to the least rune of its unicode.SimpleFold orbit - or -1 when that is beyond ASCII. Only two
 * runes beyond ASCII have an ASCII letter in their orbit (the vectors check it against Go); I with
 * a dot and the dotless i fold only onto themselves. */
static int fold_rune(uint32_t r)
{
    if (r >= 'a' && r <= 'z') return (int)(r - 'a' + 'A');
    if (r < 0x80) return (int)r;
    if (r == 0x17f) return 'S';                 /* LATIN SMALL LETTER LONG S: {S, s, U+017F} */
    if (r == 0x212a) return 'K';                /* KELVIN SIGN: {K, k, U+212A} */
    return -1;
}

int ts_json_key_fold(const ts_json* d, int t, char* out, size_t cap)
{
    size_t i, end, w = 0;

    if (ts_json_type_of(d, t) != TS_JSON_STRING || cap == 0) return 0;
    i = (size_t)d->tok[t].start;
    end = (size_t)d->tok[t].end;
    while (i < end) {
        int f = fold_rune(next_rune(d->text, &i, end));
        /* a NUL (\u0000) would end the folded name early: "ID\u0000x" must not read as ID */
        if (f <= 0 || w + 1 >= cap) return 0;
        out[w++] = (char)f;
    }
    out[w] = '\0';
    return 1;
}

int ts_json_key_is(const ts_json* d, int t, const char* name)
{
    size_t i, end;

    if (ts_json_type_of(d, t) != TS_JSON_STRING) return 0;
    i = (size_t)d->tok[t].start;
    end = (size_t)d->tok[t].end;
    while (i < end) {
        int f = fold_rune(next_rune(d->text, &i, end));
        char c = *name;
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        if (f < 0 || c == '\0' || f != c) return 0;
        name++;
    }
    return *name == '\0';
}

int ts_json_find(const ts_json* d, int obj, const char* name)
{
    int k, found = -1;

    if (ts_json_type_of(d, obj) != TS_JSON_OBJECT) return -1;
    for (k = ts_json_first(d, obj); k >= 0; k = ts_json_next(d, k)) {
        if (!ts_json_key_is(d, k, name)) continue;
        if (found >= 0) return -2;
        found = k + 1;
    }
    return found;
}

int ts_json_key_i64(const ts_json* d, int t, int64_t* v)
{
    size_t i, end, digits = 0;
    uint64_t u = 0, limit;
    int neg = 0;

    if (ts_json_type_of(d, t) != TS_JSON_STRING) return 0;
    i = (size_t)d->tok[t].start;
    end = (size_t)d->tok[t].end;
    if (i < end) {
        size_t j = i;
        uint32_t r = next_rune(d->text, &j, end);
        if (r == '+' || r == '-') {
            neg = r == '-';
            i = j;
        }
    }
    limit = neg ? 9223372036854775808ULL : 9223372036854775807ULL;
    while (i < end) {
        uint32_t r = next_rune(d->text, &i, end);
        unsigned dig;
        if (r < '0' || r > '9') return 0;
        dig = r - '0';
        if (u > (limit - dig) / 10) return 0;
        u = u * 10 + dig;
        digits++;
    }
    if (!digits) return 0;
    *v = neg ? (u == 9223372036854775808ULL ? INT64_LOW : -(int64_t)u) : (int64_t)u;
    return 1;
}

/* --------------------------------------------------------------------- numbers and literals */

int ts_json_u64(const ts_json* d, int t, uint64_t* v)
{
    const char* s;
    size_t n, i;
    uint64_t u = 0;

    if (ts_json_type_of(d, t) != TS_JSON_NUMBER) return 0;
    s = ts_json_raw(d, t, &n);
    for (i = 0; i < n; i++) {
        unsigned dig;
        if (!is_digit(s[i])) return 0;      /* a sign, a fraction or an exponent */
        dig = (unsigned)(s[i] - '0');
        if (u > (~0ULL - dig) / 10) return 0;
        u = u * 10 + dig;
    }
    *v = u;
    return 1;
}

int ts_json_i64(const ts_json* d, int t, int64_t* v)
{
    const char* s;
    size_t n, i = 0;
    uint64_t u = 0, limit;
    int neg;

    if (ts_json_type_of(d, t) != TS_JSON_NUMBER) return 0;
    s = ts_json_raw(d, t, &n);
    neg = n > 0 && s[0] == '-';
    if (neg) i = 1;
    limit = neg ? 9223372036854775808ULL : 9223372036854775807ULL;
    for (; i < n; i++) {
        unsigned dig;
        if (!is_digit(s[i])) return 0;
        dig = (unsigned)(s[i] - '0');
        if (u > (limit - dig) / 10) return 0;
        u = u * 10 + dig;
    }
    *v = neg ? (u == 9223372036854775808ULL ? INT64_LOW : -(int64_t)u) : (int64_t)u;
    return 1;
}

int ts_json_f64(const ts_json* d, int t, double* v)
{
    static const double pow10[] = {
        1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11,
        1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22
    };
    const char* s;
    size_t n, i = 0;
    uint64_t m = 0;
    int neg = 0, kept = 0;
    long e10 = 0, ex = 0;
    double x;

    if (ts_json_type_of(d, t) != TS_JSON_NUMBER) return 0;
    s = ts_json_raw(d, t, &n);
    if (s[0] == '-') {
        neg = 1;
        i = 1;
    }
    /* Up to 19 significant digits go into m; the rest only move the exponent. */
    for (; i < n && is_digit(s[i]); i++) {
        if (m == 0 && s[i] == '0') continue;
        if (kept < 19) {
            m = m * 10 + (uint64_t)(s[i] - '0');
            kept++;
        } else {
            e10++;
        }
    }
    if (i < n && s[i] == '.') {
        for (i++; i < n && is_digit(s[i]); i++) {
            if (m == 0 && s[i] == '0') {
                e10--;
                continue;
            }
            if (kept < 19) {
                m = m * 10 + (uint64_t)(s[i] - '0');
                kept++;
                e10--;
            }
        }
    }
    if (i < n && (s[i] == 'e' || s[i] == 'E')) {
        int eneg = 0;
        i++;
        if (s[i] == '+' || s[i] == '-') eneg = s[i++] == '-';
        for (; i < n; i++)
            if (ex < 100000) ex = ex * 10 + (s[i] - '0');
        e10 += eneg ? -ex : ex;
    }
    x = (double)m;
    if (m != 0) {
        /* One multiplication or division by an exact power of ten for ordinary values - correctly
         * rounded when m is exact (below 2^53); steps of 1e22 beyond, stopping at infinity
         * (refused) or zero. */
        while (e10 > 22) {
            x *= 1e22;
            e10 -= 22;
            if (x > DBL_MAX) return 0;
        }
        while (e10 < -22 && x != 0) {
            x /= 1e22;
            e10 += 22;
        }
        if (x != 0) {
            if (e10 >= 0) x *= pow10[e10];
            else if (e10 >= -22) x /= pow10[-e10];
            else x = 0;
        }
        if (x > DBL_MAX) return 0;
    }
    *v = neg ? -x : x;
    return 1;
}

int ts_json_bool(const ts_json* d, int t, int* v)
{
    ts_json_type ty = ts_json_type_of(d, t);

    if (ty != TS_JSON_TRUE && ty != TS_JSON_FALSE) return 0;
    *v = ty == TS_JSON_TRUE;
    return 1;
}

int ts_json_is_null(const ts_json* d, int t)
{
    return ts_json_type_of(d, t) == TS_JSON_NULL;
}
