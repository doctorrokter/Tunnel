# Tunnel

A VPN client for BlackBerry 10: WireGuard, AmneziaWG and Tailscale, with its own engine written for the
phone. Profiles come from a `.conf` file, a QR code, pasted text, an AmneziaVPN key (`vpn://`), or a
Tailscale login (by a link with its QR code, or with an auth key).

The tunnels are run by a service, `bbtunneld`, that works as **root** and starts when the phone boots;
the app and its background service only talk to it. **A phone with root v4 is required**: without root the
service cannot run, and the app says so.

The app's own guide - *How to start*, on the first start and in the app menu - walks through the steps
below on the phone.

## Install

1. **Install the `.bar`** as you sideload any app, and open Tunnel once.
   The app's background service sets up the boot start by itself, in `/var/addons/tunnel/`.
2. **Reboot.** The tunnel service comes up when root does, up to about 15 minutes after the boot;
   *How to start* (and Settings > Diagnostics) show that it answers, with its version.
3. **Add a profile** - the + action.

## Good to know

- **Off switch, no root needed:** a file or a folder named `tunnel-off` in `misc` keeps the service from
  starting (then Diagnostics > Restart the tunnel service, or reboot). Remove it to start it again.
- **Boot-loop breaker:** if the phone goes down within a minute of starting the service, the next boot
  does not start it (once).
- **Logs:** the start script's - `misc/bbtunneld-boot.txt`; the service's and the app's - Settings >
  Diagnostics > Share the log. They never grow past a few hundred KB.
- **Updates** of the app take effect after a restart of the phone - the app says when one is needed.
- **Uninstalling** the app stops its service: the tunnels, routes and DNS go down, and the service's copies
  are removed, and the boot start removes itself.
- Nothing the service does survives a reboot except its profiles: routes, DNS and the tunnel device live in
  memory, so a reboot always gives the phone's network back as it was.
