//go:build go1.27 && !http2legacy

package main

import "net/http"

// shutdownServer is the server whose Shutdown sends GOAWAY to an open HTTP/2 connection. Since Go
// 1.27 x/net/http2 is net/http's own HTTP/2, and its h2c handler serves each connection through a
// one-off http.Server that Shutdown never reaches - the connection is just dropped. net/http's own
// unencrypted HTTP/2 keeps the connection on this server, so Shutdown says GOAWAY to it.
func shutdownServer(h http.Handler) *http.Server {
	s := &http.Server{Handler: h, Protocols: new(http.Protocols)}
	s.Protocols.SetHTTP1(true)
	s.Protocols.SetUnencryptedHTTP2(true)
	return s
}
