# Code by others

These parts are not covered by the MIT license in `LICENSE` and keep their own terms. The notices are in the files.

| What | Where | License |
|---|---|---|
| jsmn, by Serge Zaitsev | `Tunnel/daemon/src/jsmn.h` | MIT |
| Let's Encrypt root certificates as baked into Tailscale | `Tunnel/daemon/src/bt_roots.h` | BSD-3-Clause (Tailscale Inc & contributors) |
| QR Code generator library, by Project Nayuki | `bb-shared/ui/qr/qrcodegen.h`, `qrcodegen.c` | MIT |
| BlackBerry sample code and project templates | the files with a BlackBerry Limited notice, in `Tunnel/BBTunnel/src`, `Tunnel/BBTunnelService/src` and `bb-shared/ui` | Apache-2.0 |
| Stock BlackBerry 10 icons | among the images in `Tunnel/BBTunnel/assets/images` | BlackBerry's |

Linked in the phone build, not included here: OpenSSL 3.5 (Apache-2.0).

The HPACK tables in `Tunnel/daemon/src/ts_h2.c` are the ones of RFC 7541, checked against Go's. The test vectors under
`Tunnel/daemon/test/vectors` were generated with Tailscale's and Go's code (BSD-3-Clause).

Read for the design, no code taken: wireguard-lwip (BSD-3-Clause), OpenBSD's wg (ISC), microlink (MIT),
amneziawg-go (MIT), amnezia-client (GPL).
