# Tunnel

A VPN client for rooted BlackBerry 10 phones: WireGuard, AmneziaWG and Tailscale, on an engine of its own.

**Published as is. There is no support: issues and pull requests are closed on purpose. Take it, fork it, do
whatever you want with it.**

## What is here

- `Tunnel/` - the Cascades app, its background service, the root service `bbtunneld`, the C engine and the tests.
  `Tunnel/README.md` says how the app is installed and used. `Tunnel/docs/` holds the design notes and the working
  log, in Russian.
- `bb-shared/` - only the part of the author's shared BlackBerry 10 library that Tunnel builds with.

The two folders have to stay side by side: the projects find `bb-shared` by a relative path.

## Building

On Linux or WSL, the service and the engine with their unit tests (gcc and OpenSSL 3.x):

    Tunnel/daemon/build.sh host

For the phone:

    Tunnel/daemon/build.sh cross
    cd Tunnel/BBTunnel
    bash ../../bb-shared/tools/build-bar.sh

That needs the BlackBerry 10 Native SDK 10.3.1, a gcc 9.3 cross compiler for BB10 and a static OpenSSL 3.5, none of
which are here. The default paths in the scripts are the author's: set `QNX_HOST` and `QNX_TARGET` for `build-bar.sh`,
`TOOLCHAIN_ENV`, `BB10_OPENSSL` and `BB10_NDK_TARGET` for `build.sh`.

Running it needs a phone with root v4.

## License

MIT, see `LICENSE`. Code by others keeps its own license: see `THIRD-PARTY.md`.

WireGuard is a registered trademark of Jason A. Donenfeld, Tailscale is a trademark of Tailscale Inc. This project is
not made by them.
