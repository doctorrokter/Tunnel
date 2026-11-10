// The ts2021 vectors and interop server for daemon/src/ts_noise.c. Tailscale itself comes from the
// read-only clone in refs/ (v1.102.5), not from the module proxy.
module bbtunnel/tsnoise

go 1.26.6

require (
	golang.org/x/crypto v0.54.0
	tailscale.com v1.102.5
)

require (
	github.com/coder/websocket v1.8.14 // indirect
	github.com/dblohm7/wingoes v0.0.0-20240119213807-a09d6be7affa // indirect
	github.com/go-json-experiment/json v0.0.0-20260214004413-d219187c3433 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/jsimonetti/rtnetlink v1.4.1 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.3 // indirect
)

replace tailscale.com => /mnt/e/dev/momentics-projects/refs/tailscale
