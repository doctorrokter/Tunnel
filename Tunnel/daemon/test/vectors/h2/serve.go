package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// pat is byte i of a generated body with this seed; the C tests compute the same.
func pat(seed, i int) byte { return byte((i*7 + seed) % 251) }

// The key /key answers, in the shape of tailcfg.OverTLSPublicKeyResponse.
const keyJSON = `{"legacyPublicKey":"mkey:1111111111111111111111111111111111111111111111111111111111111111",` +
	`"publicKey":"mkey:2222222222222222222222222222222222222222222222222222222222222222"}`

func hasToken(values []string, token string) bool {
	for _, v := range values {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// checkHead holds a request to what the C builders promise: tailscaled's User-Agent and the Host
// the test connected to.
func checkHead(w http.ResponseWriter, r *http.Request, host string) bool {
	if r.UserAgent() != "Go-http-client/1.1" || r.Host != host {
		http.Error(w, fmt.Sprintf("bad head: User-Agent %q, Host %q", r.UserAgent(), r.Host), 400)
		return false
	}
	return true
}

func handleKey(host string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkHead(w, r, host) {
			return
		}
		if r.Method != "GET" || r.URL.RawQuery != "v=130" {
			http.Error(w, "bad key request", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, keyJSON) // small and not flushed: Go sends Content-Length
	}
}

// handleChunked flushes as it goes, so Go's server frames the body with chunked encoding.
func handleChunked(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	f := w.(http.Flusher)
	buf := make([]byte, 3000)
	const n = 100000
	for off := 0; off < n; {
		k := min(len(buf), n-off)
		for j := 0; j < k; j++ {
			buf[j] = pat(5, off+j)
		}
		w.Write(buf[:k])
		f.Flush()
		off += k
	}
}

// handleEOF answers with a body that only the end of the connection ends: no Content-Length, not
// chunked. Go's server never does that on its own, so the response is written by hand.
func handleEOF(w http.ResponseWriter, r *http.Request) {
	conn, brw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	brw.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n")
	for i := 0; i < 5000; i++ {
		brw.WriteByte(pat(9, i))
	}
	brw.Flush()
}

// handleTS2021 answers the upgrade as control/controlhttp/controlhttpserver does, then plays the
// Noise server's first 51 bytes and echoes one read back: the connection is a plain byte stream
// from here on.
func handleTS2021(host string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkHead(w, r, host) {
			return
		}
		if strings.ToLower(r.Header.Get("Upgrade")) != "tailscale-control-protocol" ||
			!hasToken(r.Header["Connection"], "upgrade") || r.ContentLength != 0 {
			http.Error(w, "unknown next protocol", 400)
			return
		}
		init, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Tailscale-Handshake"))
		if err != nil || !bytes.Equal(init, handshake()) {
			http.Error(w, "invalid tailscale handshake header", 400)
			return
		}
		w.Header().Set("Upgrade", "tailscale-control-protocol")
		w.Header().Set("Connection", "upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)
		conn, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		resp := make([]byte, 51)
		for i := range resp {
			resp[i] = pat(3, i)
		}
		brw.Write(resp) // one flush: the head and the first bytes of the new protocol together
		brw.Flush()
		echo(conn, brw.Reader)
	}
}

// handleDERP answers the upgrade as derp/derpserver/handler.go does and sends a ServerKey frame in
// the same flush, as the DERP server's Accept does right behind it.
func handleDERP(host string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkHead(w, r, host) {
			return
		}
		up := strings.ToLower(r.Header.Get("Upgrade"))
		if up != "derp" || r.Header.Get("Connection") != "Upgrade" {
			http.Error(w, "DERP requires connection upgrade", http.StatusUpgradeRequired)
			return
		}
		conn, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: DERP\r\n"+
			"Connection: Upgrade\r\n"+
			"Derp-Version: %v\r\n"+
			"Derp-Public-Key: %s\r\n\r\n",
			2, strings.Repeat("ab", 32))
		frame := []byte{0x01, 0, 0, 0, 40}
		frame = append(frame, "DERP\xf0\x9f\x94\x91"...)
		for i := 0; i < 32; i++ {
			frame = append(frame, pat(4, i))
		}
		brw.Write(frame)
		brw.Flush()
		echo(conn, brw.Reader)
	}
}

func echo(conn net.Conn, br *bufio.Reader) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := br.Read(buf)
	conn.Write(buf[:n])
}

// handleEcho sends a POST's body back, with what the server saw of the request.
func handleEcho(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 2 {
		http.Error(w, "HTTP/2 only", 400)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Got-Method", r.Method)
	h.Set("X-Got-Host", r.Host)
	h.Set("X-Got-Path", r.URL.Path)
	h.Set("X-Got-Content-Type", r.Header.Get("Content-Type"))
	h.Set("X-Got-Content-Length", strconv.FormatInt(r.ContentLength, 10))
	h.Set("X-Got-Lb", r.Header.Get("Ts-Lb"))
	w.Write(body)
}

// handleStream sends ?n= bytes of pat(?seed=) in 8 KiB writes, each flushed: a long response the
// client's flow-control window has to be refilled for, as a map response is.
func handleStream(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	n, _ := strconv.Atoi(q.Get("n"))
	seed, _ := strconv.Atoi(q.Get("seed"))
	w.Header().Set("Content-Type", "application/octet-stream")
	f := w.(http.Flusher)
	buf := make([]byte, 8192)
	for off := 0; off < n; {
		k := min(len(buf), n-off)
		for j := 0; j < k; j++ {
			buf[j] = pat(seed, off+j)
		}
		if _, err := w.Write(buf[:k]); err != nil {
			return
		}
		f.Flush()
		off += k
	}
}

// handleHeaders answers with ?n= extra header fields, the same on every call with the same ?seed=:
// the second response on a connection comes out of Go's HPACK dynamic table.
func handleHeaders(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	n, _ := strconv.Atoi(q.Get("n"))
	seed, _ := strconv.Atoi(q.Get("seed"))
	for i := 0; i < n; i++ {
		w.Header().Set(fmt.Sprintf("x-h-%02d", i), fmt.Sprintf("v%d-%d-%s", seed, i, strings.Repeat("abc", i)))
	}
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, "headers")
}

func handleRateLimit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "7")
	http.Error(w, "rate limited", http.StatusTooManyRequests)
}

func listen() net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	return ln
}

func serveMain(portfile string) {
	ln1, ln2, ln3 := listen(), listen(), listen()
	port := func(ln net.Listener) int { return ln.Addr().(*net.TCPAddr).Port }
	host1 := fmt.Sprintf("127.0.0.1:%d", port(ln1))

	// 1. HTTP/1.1 and h2c with prior knowledge on one port, as Headscale's http2.Server{}.
	mux := http.NewServeMux()
	mux.HandleFunc("/key", handleKey(host1))
	mux.HandleFunc("/chunked", handleChunked)
	mux.HandleFunc("/eof", handleEOF)
	mux.HandleFunc("/ts2021", handleTS2021(host1))
	mux.HandleFunc("/derp", handleDERP(host1))
	mux.HandleFunc("/echo", handleEcho)
	mux.HandleFunc("/stream", handleStream)
	mux.HandleFunc("/headers", handleHeaders)
	mux.HandleFunc("/ratelimit", handleRateLimit)
	s1 := &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{}), ReadHeaderTimeout: 10 * time.Second}

	// 2. An idle connection is sent GOAWAY (NO_ERROR) after 300 ms, then closed.
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/quick", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "quick") })
	idle := 300 * time.Millisecond
	s2 := &http.Server{Handler: h2c.NewHandler(mux2, &http2.Server{IdleTimeout: idle}), IdleTimeout: idle}

	// 3. /hold?ms=N answers after N ms and shuts the server down gracefully 100 ms into it: the
	// GOAWAY comes while the stream is still open, and the stream still completes.
	var s3 *http.Server
	mux3 := http.NewServeMux()
	mux3.HandleFunc("/hold", func(w http.ResponseWriter, r *http.Request) {
		ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
		go func() {
			time.Sleep(100 * time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s3.Shutdown(ctx)
		}()
		time.Sleep(time.Duration(ms) * time.Millisecond)
		io.WriteString(w, "held")
	})
	s3 = shutdownServer(mux3)

	must(os.WriteFile(portfile, []byte(fmt.Sprintf("%d %d %d\n", port(ln1), port(ln2), port(ln3))), 0o644))
	go s2.Serve(ln2)
	go s3.Serve(ln3)
	log.Fatal(s1.Serve(ln1))
}
