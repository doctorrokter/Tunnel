// The Go side of daemon/src/ts_http1.c and ts_h2.c: Go's own net/http and x/net/http2 are the
// reference the C code is checked against.
//
//	go run . gen > kat_h2.h     the vectors test_ts_http1.c and test_ts_h2.c compile in: the exact
//	                            bytes Go's HTTP/1.1 client writes for tailscaled's three requests,
//	                            the HPACK Huffman code and static table, header blocks from Go's
//	                            HPACK encoder with what they decode to
//	go run . serve PORTFILE     the interop server on loopback (HTTP/1.1 and h2c on one port, a
//	                            second h2c port whose idle connections get GOAWAY, a third that
//	                            shuts down gracefully mid-request); the ports go to PORTFILE
//
// Built with -tags http2legacy, x/net's own HTTP/2 server is used instead of the one net/http has
// wrapped since Go 1.27 - run the interop against both (daemon/build/ts-http/run.sh does). The
// graceful-shutdown server differs between the two (shutdown_*.go): the wrapped h2c handler serves
// each connection through a one-off http.Server that Shutdown never reaches.
package main

import (
	"fmt"
	"os"
	"runtime"
)

func goVersion() string { return runtime.Version() }

func main() {
	switch {
	case len(os.Args) == 2 && os.Args[1] == "gen":
		genMain()
	case len(os.Args) == 3 && os.Args[1] == "serve":
		serveMain(os.Args[2])
	default:
		fmt.Fprintln(os.Stderr, "usage: h2 gen | h2 serve PORTFILE")
		os.Exit(2)
	}
}
