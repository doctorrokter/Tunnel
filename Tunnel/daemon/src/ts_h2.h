/*
 * ts_h2 - the HTTP/2 client of the control channel (docs/TAILSCALE.md, section 5), sans-IO: the
 * plaintext byte stream of ts2021 goes in, the bytes for the server come out, and what happened
 * comes back as events the caller pulls one by one. No TLS and no ALPN: Noise is the encryption,
 * and tailscaled's transport speaks prior-knowledge HTTP/2 over it (SetUnencryptedHTTP2). The
 * server is Go's HTTP/2 server - the control plane's and Headscale's - so golang.org/x/net/http2 is
 * the reference for both sides; where this client differs from Go's, it says so next to the code.
 *
 * A connection:
 *   - the preface and our SETTINGS go out at once (no push, the stream window the caller chose,
 *     our header list limit), and a WINDOW_UPDATE that makes the connection window cover all
 *     streams, so no stream can starve another;
 *   - optionally the EarlyNoise payload first (control/ts2021/conn.go): the first 9 bytes are either
 *     "\xff\xff\xffTS" + a big-endian length + JSON, or already the server's SETTINGS frame;
 *   - requests (HEADERS, then DATA as the server's windows allow) on up to TS_H2_MAX_STREAMS
 *     streams at once - register and map run side by side;
 *   - the server's SETTINGS acknowledged, its PINGs answered - none of our own: the server's
 *     keep-alives hold the connection, a timer of ours would only cost battery - its WINDOW_UPDATE,
 *     RST_STREAM and GOAWAY obeyed;
 *   - response header blocks (HEADERS + CONTINUATION) through a full HPACK decoder (RFC 7541:
 *     static and dynamic tables, Huffman), DATA handed to the caller as it arrives, our windows
 *     refilled as the caller says it has taken the data (ts_h2_consume) - a long map response is
 *     paced by the caller, not by the server.
 *
 * Everything from the wire is hostile: frames are at most TS_H2_FRAME_MAX, a header block at most
 * TS_H2_HEADER_BLOCK_MAX encoded and TS_H2_HEADER_LIST_MAX decoded, the dynamic table 4096 bytes;
 * nothing is allocated. A violation of the protocol ends the connection with GOAWAY (RFC 9113 5.4.1
 * allows any stream error to be treated so); a malformed response only resets its own stream.
 *
 * The struct is large (140 KB on the phone: the buffers live inside) - allocate it, never on the
 * stack.
 */

#ifndef TS_H2_H
#define TS_H2_H

#include <stddef.h>
#include <stdint.h>

#define TS_H2_MAX_STREAMS       8           /* open at once; register and map need two */
#define TS_H2_FRAME_MAX         16384       /* SETTINGS_MAX_FRAME_SIZE both ways: never raised */
#define TS_H2_HEADER_BLOCK_MAX  16384       /* a response's header block as it comes, encoded */
#define TS_H2_HEADER_LIST_MAX   16384       /* ... decoded, sized as RFC 9113 says (name + value + 32 a
                                               field); advertised as SETTINGS_MAX_HEADER_LIST_SIZE */
#define TS_H2_FIELDS_MAX        64          /* fields of one header block kept */
#define TS_H2_REQ_BLOCK_MAX     8192        /* our request's header block: always one HEADERS frame */
#define TS_H2_SEND_MAX          65536       /* request bodies not yet sent, all streams together */
#define TS_H2_OUT_MAX           32768       /* bytes framed for the server, not yet taken by the caller */
#define TS_H2_EARLY_MAX         16384       /* the EarlyNoise JSON: Go allows 10 MiB, but its one field
                                               (NodeKeyChallenge) is under 100 bytes */
#define TS_H2_DEFAULT_WINDOW    65535       /* RFC 9113 6.9.2 */
#define TS_H2_MAX_WINDOW        (1u << 24)  /* the largest stream window a caller may ask for */
#define TS_H2_EVQ               (2 * TS_H2_MAX_STREAMS + 4)

/* Error codes (RFC 9113 section 7), as RST_STREAM and GOAWAY carry them. */
#define TS_H2_NO_ERROR              0x0
#define TS_H2_PROTOCOL_ERROR        0x1
#define TS_H2_INTERNAL_ERROR        0x2
#define TS_H2_FLOW_CONTROL_ERROR    0x3
#define TS_H2_SETTINGS_TIMEOUT      0x4
#define TS_H2_STREAM_CLOSED         0x5
#define TS_H2_FRAME_SIZE_ERROR      0x6
#define TS_H2_REFUSED_STREAM        0x7
#define TS_H2_CANCEL                0x8
#define TS_H2_COMPRESSION_ERROR     0x9
#define TS_H2_CONNECT_ERROR         0xa
#define TS_H2_ENHANCE_YOUR_CALM     0xb
#define TS_H2_INADEQUATE_SECURITY   0xc
#define TS_H2_HTTP_1_1_REQUIRED     0xd
#define TS_H2_ERR_EOF               0x100   /* not on the wire: the transport closed (ts_h2_eof) */

/* --- HPACK (RFC 7541) ----------------------------------------------------------------------- */

#define TS_HPACK_TABLE_MAX      4096        /* SETTINGS_HEADER_TABLE_SIZE: the default, never raised */
#define TS_HPACK_ENTRIES_MAX    (TS_HPACK_TABLE_MAX / 32)   /* an entry costs at least 32 */

/* A decoded field. The strings are NUL-terminated, but HPACK carries any byte - a NUL included -
 * so the lengths are the truth; HTTP/2 rules (lowercase names, no control bytes in values) are
 * checked above HPACK, on responses. */
typedef struct {
    const char* name;
    size_t      name_len;
    const char* value;
    size_t      value_len;
} ts_h2_field;

/* The decoded fields of one header block. The buffer leaves room for one field the size of the
 * whole dynamic table beyond the list limit: a field that must enter the table can always be
 * decoded whole, even after the list itself overflowed. */
typedef struct {
    ts_h2_field fields[TS_H2_FIELDS_MAX];
    size_t      n;
    uint64_t    size;           /* the RFC 9113 size of every field decoded, kept or not */
    int         overflow;       /* fields past TS_H2_FIELDS_MAX / TS_H2_HEADER_LIST_MAX were dropped */
    size_t      used;
    char        buf[TS_H2_HEADER_LIST_MAX + TS_HPACK_TABLE_MAX];
} ts_hpack_list;

/* The decoder's dynamic table: entries oldest first in a ring, their bytes oldest first in one run
 * of bytes[] (compacted when the end is reached - the run is never longer than the table). */
typedef struct {
    uint32_t limit;             /* SETTINGS_HEADER_TABLE_SIZE we advertised: no size update above it */
    uint32_t max_size;          /* the size the encoder chose (dynamic table size updates) */
    uint32_t size;              /* RFC 7541 4.1: name + value + 32 over the entries */
    size_t   oldest;            /* ring index of the oldest entry */
    size_t   count;
    struct { uint16_t off, nlen, vlen; } ent[TS_HPACK_ENTRIES_MAX];
    size_t   start, end;        /* the entries' bytes */
    uint8_t  bytes[TS_HPACK_TABLE_MAX];
} ts_hpack;

/* A fresh decoder; `limit` is the SETTINGS_HEADER_TABLE_SIZE the peer was told (at most
 * TS_HPACK_TABLE_MAX; 4096 when nothing was said). */
void ts_hpack_init(ts_hpack* h, uint32_t limit);

/*
 * Decodes one whole header block into `out` (emptied first), updating the dynamic table. 1 on
 * success - out->overflow tells whether fields were dropped; 0 on a decoding error
 * (COMPRESSION_ERROR): the table is then out of step with the encoder's and the connection must go.
 */
int ts_hpack_decode(ts_hpack* h, const uint8_t* block, size_t len, ts_hpack_list* out);

/* Entry i of the dynamic table, 0 the newest; 0 when there is none. For tests and logs. */
int ts_hpack_entry(const ts_hpack* h, size_t i, const uint8_t** name, size_t* nlen,
                   const uint8_t** value, size_t* vlen);

/*
 * The Huffman code of RFC 7541 Appendix B: in[0, len) decoded into out[0, cap). Returns the
 * decoded length - also when it is more than cap (then out holds its first cap bytes) - or
 * (size_t)-1 when the input is malformed: EOS inside, padding longer than 7 bits or not all ones.
 */
size_t ts_hpack_huffman_decode(const uint8_t* in, size_t len, uint8_t* out, size_t cap);

/* RFC 7541 5.1 integers with an n-bit prefix (1-8). Reading takes up to 9 continuation bytes, as
 * Go's readVarInt, and advances *pos; 0 when the input ends first. Writing ORs `first` into the
 * first byte (the representation's pattern bits) and returns the length, 0 when cap is short. */
int    ts_hpack_get_int(const uint8_t* b, size_t len, size_t* pos, unsigned n, uint64_t* out);
size_t ts_hpack_put_int(uint8_t* out, size_t cap, uint8_t first, unsigned n, uint64_t v);

/* --- the connection -------------------------------------------------------------------------- */

typedef enum {
    TS_H2_EV_NONE = 0,          /* the input is used up and nothing else happened */
    TS_H2_EV_EARLY,             /* the EarlyNoise JSON: data, len */
    TS_H2_EV_HEADERS,           /* the response's head: status, fields (":status" not among them) */
    TS_H2_EV_DATA,              /* body bytes: data, len - give them back with ts_h2_consume */
    TS_H2_EV_END,               /* the whole response arrived; the stream is over */
    TS_H2_EV_RESET,             /* the stream is over without its whole response: error, refused, local */
    TS_H2_EV_GOAWAY,            /* the server takes no new streams: last_stream, error, data (debug) */
    TS_H2_EV_CLOSED             /* the connection is over: error (TS_H2_ERR_EOF - the transport closed) */
} ts_h2_event_type;

typedef struct {
    ts_h2_event_type   type;
    uint32_t           stream;
    int                status;          /* HEADERS: :status, 200-599 */
    const ts_h2_field* fields;          /* HEADERS */
    size_t             n_fields;
    const uint8_t*     data;            /* EARLY, DATA; GOAWAY: its debug data, the first 64 bytes */
    size_t             len;
    uint32_t           error;           /* RESET, GOAWAY, CLOSED */
    int                refused;         /* RESET: the server never processed it (GOAWAY above it, or
                                           REFUSED_STREAM) - safe to send again on a new connection */
    int                local;           /* RESET: we reset it - a malformed response or one over our
                                           limits; CLOSED: we ended the connection (error = why) */
    uint32_t           last_stream;     /* GOAWAY */
} ts_h2_event;

/* A field of a request: C strings. */
typedef struct {
    const char* name;
    const char* value;
} ts_h2_pair;

/* A request. Pseudo-fields and fields go out as HPACK literals without indexing - the server's
 * table is never touched, so nothing has to be tracked about it; `fields` are the regular ones
 * (lowercase names: "content-type", "ts-lb"...), content-length is added from the body. */
typedef struct {
    const char*        method;      /* "POST" */
    const char*        scheme;      /* "https" - tailscaled's URL is https:// even inside Noise */
    const char*        authority;   /* the control host without a port, as tailscaled's URL has it */
    const char*        path;        /* "/machine/map" */
    const ts_h2_pair*  fields;
    size_t             n_fields;
    const uint8_t*     body;        /* copied: free to reuse once ts_h2_request returns */
    size_t             body_len;
} ts_h2_req;

/* A stream as the connection keeps it. */
typedef struct {
    uint32_t id;                    /* 0: a free slot */
    unsigned flags;
    int64_t  send_window;           /* the server's window for our DATA (SETTINGS may push it below 0) */
    int64_t  recv_window;           /* what the server may still send us */
    uint32_t recv_unsent;           /* taken by the caller, not yet given back in a WINDOW_UPDATE */
    uint32_t recv_held;             /* handed to the caller, not yet taken */
    size_t   body_off, body_len, body_sent;     /* the request body, in send[] */
    int      status;
    unsigned interim;               /* 1xx heads seen */
    int64_t  content_length;        /* declared by the response, -1 when not */
    uint64_t data_got;
} ts_h2_stream;

typedef struct {
    /* the connection */
    uint32_t     stream_window;     /* ours, SETTINGS_INITIAL_WINDOW_SIZE */
    int          early;             /* EarlyNoise may come first */
    int          dead;              /* CLOSED is out or queued: input is ignored, requests refused */
    int          goaway;            /* the server sent GOAWAY */
    uint32_t     goaway_last;
    uint32_t     next_id;
    int          got_settings;      /* the server's first SETTINGS came (it must come first) */
    uint32_t     peer_max_frame;
    uint32_t     peer_initial_window;
    uint32_t     peer_max_streams;
    uint32_t     enc_table_size;    /* the server's decoder table as our encoder must assume it */
    int          enc_update;        /* a size update is owed at the start of our next header block */
    int64_t      conn_send_window;
    int64_t      conn_recv_window;
    uint32_t     conn_recv_unsent;
    ts_h2_stream st[TS_H2_MAX_STREAMS];

    /* the frame being read */
    int          phase;
    uint8_t      hdr[9];
    size_t       hdr_got;
    uint32_t     f_len, f_stream;
    uint8_t      f_type, f_flags;
    int          f_slot;            /* the stream's slot, -1 when its data goes nowhere */
    uint32_t     f_prefix;          /* fixed bytes first: pad length, priority, a control payload */
    uint8_t      fixed[16];
    size_t       fixed_got;
    int          prefix_done;
    uint32_t     f_body_left;       /* content: DATA, a header block fragment, GOAWAY's debug data */
    uint32_t     f_pad_left;
    uint32_t     early_len;
    uint8_t      setting[6];        /* a SETTINGS entry being collected */
    size_t       setting_got;
    size_t       debug_got;         /* GOAWAY debug data kept so far */

    /* the header block being collected, and the decoder */
    uint8_t      block[TS_H2_HEADER_BLOCK_MAX];
    size_t       block_len;
    uint32_t     block_stream;
    int          block_end_stream;
    int          in_block;          /* HEADERS came without END_HEADERS: only its CONTINUATION may follow */
    ts_hpack     hpack;
    ts_hpack_list list;

    /* events not yet handed out: at most a reset per stream twice over (GOAWAY, then the end of
     * the transport before the caller pulled them) and a few more - the queue never fills */
    ts_h2_event  evq[TS_H2_EVQ];
    size_t       ev_head, ev_n;
    ts_h2_event  ev_spare;          /* where an event would go if it ever did */
    uint8_t      goaway_data[64];

    /* for the server */
    uint8_t      out[TS_H2_OUT_MAX];
    size_t       out_len;
    uint8_t      send[TS_H2_SEND_MAX];
    size_t       send_used;
} ts_h2;

/*
 * Starts a connection: the preface, our SETTINGS and the connection's WINDOW_UPDATE are in the
 * output at once (prior knowledge: the server sends its SETTINGS without waiting). `stream_window`
 * is what each stream may receive ahead of the caller taking it - the caller must be able to hold
 * that much per stream; 0 is the default 65535, other values are kept within 1024..TS_H2_MAX_WINDOW.
 * `early`: EarlyNoise may come first (tailscaled always looks for it; Headscale sends it).
 */
void ts_h2_init(ts_h2* c, uint32_t stream_window, int early);

/*
 * Bytes from the server. Takes some of them, puts the next event into *ev and returns how many
 * bytes it took: call again with the rest - and also with none - until the event is
 * TS_H2_EV_NONE, which comes only once all of in[0, len) is taken and no event waits. The pointers
 * in an event (fields, data) stay valid until the next call of ts_h2_input. Output may be waiting
 * after any call (ts_h2_output). After CLOSED, bytes are taken and ignored.
 */
size_t ts_h2_input(ts_h2* c, const uint8_t* in, size_t len, ts_h2_event* ev);

/* The transport is gone (end of stream or an error): every open stream is reset, then CLOSED -
 * pull them with ts_h2_input(c, NULL, 0, &ev). */
void ts_h2_eof(ts_h2* c);

/* Bytes for the server: *len of them at the returned pointer (0: nothing now). Owed window updates
 * and request bodies are framed here, as the windows and the room allow. Then tell how many went. */
const uint8_t* ts_h2_output(ts_h2* c, size_t* len);
void ts_h2_output_done(ts_h2* c, size_t n);

/*
 * Opens a stream: its HEADERS into the output now, the body as DATA later in ts_h2_output. Returns
 * the stream id (odd), or 0 when it cannot go now: the connection is dead or going away (see
 * ts_h2_usable), TS_H2_MAX_STREAMS (or the server's own limit) are open, the body does not fit
 * TS_H2_SEND_MAX next to the bodies still unsent, the output is full, or an argument is bad (a
 * field name not lowercase or connection-specific, a control byte in a value, a head over
 * TS_H2_REQ_BLOCK_MAX).
 */
uint32_t ts_h2_request(ts_h2* c, const ts_h2_req* req);

/* The caller has taken n bytes of `stream`'s DATA: the server may send that much more. A stream
 * already over needs nothing - its share went back to the connection when it ended. */
void ts_h2_consume(ts_h2* c, uint32_t stream, size_t n);

/* Drops a stream: RST_STREAM(CANCEL) if the server may still send on it; no events for it after. */
void ts_h2_cancel(ts_h2* c, uint32_t stream);

/* 1 while new requests may go: the connection is not dead and the server sent no GOAWAY. */
int ts_h2_usable(const ts_h2* c);

/* The value of field `name` (lowercase, as HTTP/2 has it) in a HEADERS event; NULL when absent. */
const char* ts_h2_field_value(const ts_h2_event* ev, const char* name, size_t* len);

const char* ts_h2_error_text(uint32_t code);

#endif /* TS_H2_H */
