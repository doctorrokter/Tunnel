//go:build !(go1.27 && !http2legacy)

package main

import (
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// shutdownServer is the server whose Shutdown sends GOAWAY to an open HTTP/2 connection: x/net's
// own HTTP/2 server through h2c, registered with ConfigureServer so that Shutdown reaches the
// connections ServeConn serves.
func shutdownServer(h http.Handler) *http.Server {
	s := &http.Server{}
	h2s := &http2.Server{}
	must(http2.ConfigureServer(s, h2s))
	s.Handler = h2c.NewHandler(h, h2s)
	return s
}
