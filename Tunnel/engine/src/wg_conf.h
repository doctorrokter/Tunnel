/*
 * wg_conf - WireGuard configuration files: the .conf a server hands out, as wg-quick reads it.
 *
 *   [Interface]                           [Peer]                      (any number)
 *   PrivateKey = <base64>                 PublicKey = <base64>
 *   Address = 10.0.0.2/32, fd00::2/128    PresharedKey = <base64>
 *   DNS = 1.1.1.1, home.lan               AllowedIPs = 0.0.0.0/0, ::/0
 *   MTU = 1420                            Endpoint = vpn.example.com:51820 | [2001:db8::1]:51820
 *   ListenPort = 51820                    PersistentKeepalive = 25
 *
 * plus AmneziaWG's interface keys, as awg(8) of amneziawg-tools reads them (wg_awg.h says what they
 * do on the wire):
 *
 *   Jc = 4   Jmin = 40   Jmax = 70         junk ahead of each initiation (Jc at most 128 here)
 *   S1 = 15  S2 = 68  S3 = 20  S4 = 16     random prefixes (at most 1024 here)
 *   H1 = 1233645711   H2 = 100000-100800   type field values, a value or a range (H3, H4 too)
 *   I1 = <b 0xc600...><r 16><t>            packets ahead of each initiation (I2..I5 too)
 *   HeaderProtectionKey = <base64>         AmneziaWG 3.x, like the keys below
 *   ContentPaddingAddition = 0-64          ranges: "a" or "a-b", 0 to 65535, or "off"
 *   RandomTrailers = on   DisableCookies = on        booleans: on/off, true/false, 0/1
 *   RekeyAfterTime  RekeyTimeout  RejectAfterTime  KeepaliveTimeout  MaxHandshakeAttempts
 *                                          timings (wg_timing), ranges of seconds
 *   and in [Peer]: PersistentKeepalive as a range, AdvancedSecurity (the kernel module's per-peer
 *   switch - amneziawg-go refuses it - accepted and ignored: here the codec is the device's)
 *
 * wg-quick's scripts and routing knobs (PostUp, Table, FwMark, SaveConfig...) mean nothing on the
 * phone and are skipped with a warning - as is any key this parser does not know, so a newer file
 * still loads.
 *
 * As in wg(8): keys and sections are case-insensitive, `#` starts a comment, AllowedIPs, Address
 * and DNS may repeat and add up, any other key repeated simply wins. CRLF is fine.
 *
 * Sans-IO and allocation-free: the caller provides the arrays for the peers and for all their
 * AllowedIPs (shared; each peer owns a slice), and the I-packet strings point into the text, which
 * must outlive the result. Endpoint names stay text - resolving them is the daemon's job; a literal
 * address is parsed on the spot.
 */

#ifndef WG_CONF_H
#define WG_CONF_H

#include <stddef.h>
#include <stdint.h>

#include "wg_awg.h"
#include "wg_crypto.h"
#include "wg_peer.h"

#define WG_CONF_MAX_ADDRESS 8
#define WG_CONF_MAX_DNS     8
#define WG_CONF_TEXT_MAX    256

typedef struct {
    uint8_t family;                     /* 4 or 6 */
    uint8_t cidr;
    uint8_t addr[16];                   /* as written: Address keeps its host bits */
} wg_prefix;

typedef struct {
    wg_key      public_key;
    int         has_public_key;
    uint8_t     psk[WG_KEY_LEN];
    int         has_psk;
    size_t      allowed_first;          /* its AllowedIPs: allowed[first .. first + count) */
    size_t      allowed_count;
    char        endpoint_host[WG_CONF_TEXT_MAX];    /* as written, a name or an address; "" = none */
    uint16_t    endpoint_port;
    wg_endpoint endpoint;               /* family != 0 when the host was a literal address */
    wg_range    persistent_keepalive;   /* seconds; 0..0 = off */
    int         line;                   /* where its [Peer] header is */
} wg_conf_peer;

typedef struct {
    /* [Interface] */
    wg_key        private_key;
    int           has_private_key;
    wg_prefix     address[WG_CONF_MAX_ADDRESS];
    size_t        n_address;
    wg_prefix     dns[WG_CONF_MAX_DNS];     /* resolver addresses */
    size_t        n_dns;
    char          dns_search[WG_CONF_TEXT_MAX];     /* the names in DNS=, comma-separated */
    uint16_t      mtu;                  /* 0 = not set */
    uint16_t      listen_port;          /* 0 = not set */

    /* AmneziaWG. `awg` says any of it was present. */
    int           awg;
    uint16_t      jc, jmin, jmax;
    uint16_t      s[5];                 /* S1..S4 in s[1..4] */
    wg_range      h[5];                 /* H1..H4 in h[1..4]; 1, 2, 3, 4 when not set */
    const char*   i[6];                 /* I1..I5 in i[1..5]: into the text, not terminated */
    size_t        i_len[6];
    uint8_t       hp_key[WG_KEY_LEN];   /* zeroes: none */
    wg_range      content_padding;      /* 0..0: off */
    int           random_trailers;
    int           disable_cookies;
    wg_timing     timing;               /* each range 0..0 when not set: WireGuard's */

    /* [Peer] sections, in the caller's arrays */
    wg_conf_peer* peers;
    size_t        n_peers, cap_peers;
    wg_prefix*    allowed;
    size_t        n_allowed, cap_allowed;

    /* The first problem, for the UI. error_line 0 is about the file as a whole. */
    int           error_line;
    char          error[128];
    int           warnings;             /* keys skipped */
    int           warning_line;         /* the first of them */
    char          warning[128];
} wg_conf;

void wg_conf_init(wg_conf* c, wg_conf_peer* peers, size_t cap_peers, wg_prefix* allowed,
                  size_t cap_allowed);

/* 1 when the text is a usable configuration; 0 with error_line / error set. */
int wg_conf_parse(wg_conf* c, const char* text, size_t len);

struct wg_device;

/* The file's AmneziaWG wire settings as codec parameters: I1-I5 parsed, the whole set checked the
 * way the reference checks it (wg_awg_check). 1 on success; 0 with a reason in `err`. */
int wg_conf_awg_params(const wg_conf* c, wg_awg_params* p, char* err, size_t errlen);

/*
 * Sets up a fresh device from a parsed configuration: identity, MTU, timings, DisableCookies, and
 * each peer - in `peers`, with `stage_each` bytes of `stage` for the packets waiting for its keys -
 * with its PSK, AllowedIPs (the device needs its table storage first), literal endpoint and
 * persistent keepalive. When the file's wire settings differ from plain WireGuard, `awg` (storage
 * the caller owns, for as long as the device lives) becomes the device's codec; without it such a
 * file is refused. Endpoint names are left to the caller to resolve and set; so are Address, DNS
 * and ListenPort, which belong to the daemon. 1 on success; 0 with a reason in `err`.
 */
int wg_conf_apply(const wg_conf* c, struct wg_device* d, wg_awg* awg, wg_peer* peers, uint8_t* stage,
                  size_t stage_each, uint64_t now_ns, char* err, size_t errlen);

/* --- the text forms, also for the UI and UAPI ---------------------------------------------- */

/* A 32-byte key as wg writes it: 44 characters of base64. 0 for anything else. */
int  wg_key_from_base64(wg_key* k, const char* s, size_t len);
void wg_key_to_base64(char out[45], const wg_key* k);

/* An IPv4 (dotted quad) or IPv6 address. 0 for anything else. */
int wg_addr_parse(const char* s, size_t len, int* family, uint8_t addr[16]);

/* addr or addr/cidr; without /cidr, the full length. */
int wg_prefix_parse(const char* s, size_t len, wg_prefix* p);

#endif /* WG_CONF_H */
