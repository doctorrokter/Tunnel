/*
 * ts_profile - what a Tailscale profile keeps on disk (docs/TAILSCALE.md, sections 3 and 10): the
 * daemon's own key=value text in bt_proto's block form, stored as the profile's .conf. It holds
 * the private keys, so it lives where a WireGuard .conf does - 0600 in the profile store - and never
 * goes to a client.
 *
 *   tailscale=1
 *   control=https://controlplane.tailscale.com    the control server; another only on the stand
 *   machine_key=<64 hex>                           ours toward control (Noise), for good
 *   node_key=<64 hex>                              this node's WireGuard key
 *   old_node_key=<64 hex>                          the one before, while a new one registers
 *   auth_key=<text>                                until a registration went through, then gone;
 *                                                  none while not registered - the login is by a link
 *   registered=0|1                                 the node key is in the tailnet
 *   server_key=<64 hex>                            control's Noise key from /key (a cache)
 *   control_addr=<ip>                              where control's name led last (a cache)
 *   hostname=<label>                               the name the node asks for in the tailnet
 *   tailnet=, node_name=, address=                 the last netmap's, for the screens (a cache)
 *
 * The caches may go stale or be dropped at any time: nothing breaks without them.
 */

#ifndef TS_PROFILE_H
#define TS_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#include "wg_crypto.h"

#define TS_CONTROL_DEFAULT  "https://controlplane.tailscale.com"
#define TS_URL_MAX          300
#define TS_HOST_MAX         253
#define TS_AUTHKEY_MAX      256
#define TS_TEXT_MAX         128         /* a tailnet or node name kept for the screens */
#define TS_ADDR_TEXT_MAX    50          /* an address with its /length */
#define TS_PROFILE_ADDRS    2           /* our own: one IPv4, one IPv6 */
#define TS_HOSTNAME_MAX     63          /* one DNS label */
#define TS_HOSTNAME_DEFAULT "blackberry"

/* A control URL taken apart: scheme, host (a name or an address, IPv6 without brackets), port. */
typedef struct {
    int      tls;                       /* https */
    char     host[TS_HOST_MAX + 1];
    uint16_t port;
    int      literal;                   /* the host is an address: no DNS, no SNI */
} ts_url;

/*
 * "https://host[:port]" or "http://host[:port]", one trailing slash allowed, nothing after it -
 * the ts2021 path and /key are ours to add. A name of DNS labels, an IPv4 address, or an IPv6 one
 * in brackets. 1 when it is one.
 */
int ts_url_parse(const char* url, size_t len, ts_url* out);

/* An auth key as the admin console (or `headscale preauthkeys create`) prints it: 1-256 printable
 * ASCII characters, no spaces. */
int ts_authkey_valid(const char* key, size_t len);

/* A host name for the tailnet: one DNS label, 1-63 of [A-Za-z0-9-], no hyphen at either end. */
int ts_hostname_valid(const char* name, size_t len);

typedef struct {
    char    control[TS_URL_MAX + 1];
    wg_key  machine;
    wg_key  node;
    wg_key  old_node;
    int     has_old_node;
    char    auth_key[TS_AUTHKEY_MAX + 1];
    int     registered;
    wg_key  server;
    int     has_server;
    char    hostname[TS_HOSTNAME_MAX + 1];     /* "" = TS_HOSTNAME_DEFAULT */
    char    control_addr[TS_ADDR_TEXT_MAX];
    char    tailnet[TS_TEXT_MAX + 1];
    char    node_name[TS_TEXT_MAX + 1];
    char    address[TS_PROFILE_ADDRS][TS_ADDR_TEXT_MAX];
    size_t  n_address;
} ts_profile;

/* A new profile: fresh machine and node keys (from `rng`, NULL = the CSPRNG), the auth key to
 * register with - NULL or "": none, the login is by a link (TAILSCALE.md section 11b) - and
 * `control` (NULL or "" = the official server). 1 on success. */
int ts_profile_new(ts_profile* p, const char* control, const char* auth_key, const wg_rng* rng);

/*
 * Logging in again (after the old node key expired or was refused): a new node key, the current one
 * kept as old_node_key so control ties the new one to this node, and the auth key to register it with
 * - NULL or "": by a link. The machine key stays - it is the same device. The cached addresses go:
 * a new node may have others.
 */
int ts_profile_relogin(ts_profile* p, const char* auth_key, const wg_rng* rng);

/* The text form into `buf`: its length, 0 when it does not fit. */
size_t ts_profile_format(const ts_profile* p, char* buf, size_t cap);

/* Parses the text form IN PLACE (text[len] must be writable). 1 on success; a text that is not a
 * complete, well-formed profile gives 0 and a wiped `p`. */
int ts_profile_parse(ts_profile* p, char* text, size_t len);

/* 1 when `text` starts like a Tailscale profile ("tailscale=1"), before any parsing. */
int ts_profile_is(const char* text, size_t len);

void ts_profile_wipe(ts_profile* p);

/* 32 bytes as 64 lowercase hex characters and a NUL; and back (exactly 64 hex, either case). */
void ts_hex32(char out[65], const uint8_t in[32]);
int  ts_unhex32(uint8_t out[32], const char* hex, size_t len);

#endif /* TS_PROFILE_H */
