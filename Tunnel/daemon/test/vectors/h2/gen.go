package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2/hpack"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// handshake is what the C tests put into X-Tailscale-Handshake: 101 bytes 0, 1, ..., 100 - the
// size of a real Noise initiation.
func handshake() []byte {
	b := make([]byte, 101)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// cBytes is b as a C string literal: printable ASCII as is, the rest as 3-digit octal escapes (a
// hex escape would swallow the hex digits after it; '?' is escaped against trigraphs).
func cBytes(b []byte) string {
	var s strings.Builder
	s.WriteByte('"')
	for _, c := range b {
		if c >= 0x20 && c < 0x7f && c != '"' && c != '\\' && c != '?' {
			s.WriteByte(c)
		} else {
			fmt.Fprintf(&s, "\\%03o", c)
		}
	}
	s.WriteByte('"')
	return s.String()
}

// cText is an HTTP head as C string literals, one line per literal.
func cText(b []byte) string {
	var s strings.Builder
	for _, line := range bytes.SplitAfter(b, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		s.WriteString("\n    ")
		lit := cBytes(line)
		lit = strings.ReplaceAll(lit, `\015`, `\r`)
		lit = strings.ReplaceAll(lit, `\012`, `\n`)
		s.WriteString(lit)
	}
	return s.String()
}

// capture runs one request through `do` against a listener on loopback and returns the request
// head exactly as it arrived; the listener answers `reply`.
func capture(reply string, do func(dial func(context.Context, string, string) (net.Conn, error))) []byte {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		var head bytes.Buffer
		for {
			line, err := br.ReadString('\n')
			head.WriteString(line)
			if err != nil || line == "\r\n" {
				break
			}
		}
		got <- head.Bytes()
		io.WriteString(c, reply)
	}()
	do(func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	})
	select {
	case b := <-got:
		return b
	case <-time.After(5 * time.Second):
		panic("capture: no request arrived")
	}
}

// keyRequest is GET /key as control/controlclient/direct.go's loadServerPubKeys sends it, with the
// transport NewDirect builds (compression off). The scheme is http here because the listener has
// no TLS; the request head does not depend on it.
func keyRequest(serverURL string) []byte {
	return capture("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", func(dial func(context.Context, string, string) (net.Conn, error)) {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = nil
		tr.DialContext = dial
		tr.ForceAttemptHTTP2 = true
		tr.DisableCompression = true
		httpc := &http.Client{Transport: tr}
		req, err := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("%v/key?v=%d", serverURL, 130), nil)
		must(err)
		res, err := httpc.Do(req)
		must(err)
		io.ReadAll(res.Body)
		res.Body.Close()
	})
}

// ts2021Request is the upgrade control/controlhttp/client.go's tryURLUpgrade sends: its request,
// its transport settings, the host joined with the port as dialHostOpt does.
func ts2021Request(hostPort string) []byte {
	reply := "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n"
	return capture(reply, func(dial func(context.Context, string, string) (net.Conn, error)) {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = nil
		tr.DialContext = dial
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.NextProtos = []string{}
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		tr.DisableCompression = true
		req := &http.Request{
			Method: "POST",
			URL:    &url.URL{Scheme: "http", Host: hostPort, Path: "/ts2021"},
			Header: http.Header{
				"Upgrade":               []string{"tailscale-control-protocol"},
				"Connection":            []string{"upgrade"},
				"X-Tailscale-Handshake": []string{base64.StdEncoding.EncodeToString(handshake())},
			},
		}
		resp, err := tr.RoundTrip(req)
		must(err)
		resp.Body.Close()
	})
}

// derpRequest is the upgrade derp/derphttp/derphttp_client.go's connect writes with req.Write.
func derpRequest(u, idealNode string) []byte {
	req, err := http.NewRequest("GET", u, nil)
	must(err)
	req.Header.Set("Upgrade", "DERP")
	req.Header.Set("Connection", "Upgrade")
	if idealNode != "" {
		req.Header.Set("Ideal-Node", idealNode)
	}
	var buf bytes.Buffer
	must(req.Write(&buf))
	return buf.Bytes()
}

func genRequests(w io.Writer) {
	reqs := []struct{ name, comment string; b []byte }{
		{"kat_req_key", "GET /key of https://controlplane.tailscale.com", keyRequest("http://controlplane.tailscale.com")},
		{"kat_req_key_stand", "GET /key of http://10.1.2.3:8080 (a Headscale stand)", keyRequest("http://10.1.2.3:8080")},
		{"kat_req_ts2021", "POST /ts2021 to controlplane.tailscale.com over TLS (port 443)", ts2021Request(net.JoinHostPort("controlplane.tailscale.com", "443"))},
		{"kat_req_ts2021_v6", "POST /ts2021 to http://[fd7a:115c:a1e0::1]:8080", ts2021Request(net.JoinHostPort("fd7a:115c:a1e0::1", "8080"))},
		{"kat_req_derp", "GET /derp of derp1.tailscale.com (DERPPort 0 = 443)", derpRequest("https://derp1.tailscale.com/derp", "")},
		{"kat_req_derp_ideal", "GET /derp of derp.example.com:8443, not the region's first node", derpRequest("https://derp.example.com:8443/derp", "900a")},
		{"kat_req_derp_stand", "GET /derp over plain HTTP (TS_DEBUG_USE_DERP_HTTP), port 3340", derpRequest("http://10.1.2.3:3340/derp", "")},
	}
	fmt.Fprintf(w, "/* The handshake in the ts2021 requests: bytes 0, 1, ..., 100. */\n\n")
	for _, r := range reqs {
		fmt.Fprintf(w, "/* %s */\nstatic const char %s[] =%s;\n\n", r.comment, r.name, cText(r.b))
	}
}

// huffCode is the code of symbol b: 8 copies of it take exactly `bits` bytes, and the first
// `bits` bits of the encoding of one copy are the code.
func huffCode(b byte) (uint32, int) {
	s := string([]byte{b})
	bits := int(hpack.HuffmanEncodeLength(strings.Repeat(s, 8)))
	enc := hpack.AppendHuffmanString(nil, s)
	var v uint64
	for _, x := range enc {
		v = v<<8 | uint64(x)
	}
	return uint32(v >> uint(len(enc)*8-bits)), bits
}

func genHuffman(w io.Writer, r *rand.Rand) {
	fmt.Fprintf(w, "/* RFC 7541 Appendix B as Go's hpack encodes it: {code, bits} of bytes 0-255. */\n")
	fmt.Fprintf(w, "static const struct { uint32_t code; unsigned bits; } kat_huff[256] = {")
	for b := 0; b < 256; b++ {
		if b%4 == 0 {
			fmt.Fprintf(w, "\n   ")
		}
		code, bits := huffCode(byte(b))
		fmt.Fprintf(w, " { 0x%08x, %2d },", code, bits)
	}
	fmt.Fprintf(w, "\n};\n\n")

	// Strings and their Huffman encodings: every byte value, the ASCII headers carry, and the
	// padding in all its lengths.
	type hs struct{ in, enc []byte }
	var list []hs
	add := func(s []byte) { list = append(list, hs{s, hpack.AppendHuffmanString(nil, string(s))}) }
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	add(all)
	add([]byte{})
	add([]byte("application/json"))
	add([]byte("Mon, 21 Oct 2013 20:13:21 GMT"))
	for i := 0; i < 40; i++ {
		n := r.IntN(48)
		s := make([]byte, n)
		for j := range s {
			if i%2 == 0 {
				s[j] = byte(r.IntN(256))
			} else {
				s[j] = byte(0x20 + r.IntN(0x5f))
			}
		}
		add(s)
	}
	fmt.Fprintf(w, "/* Strings and their Huffman encodings, from Go's hpack. */\n")
	fmt.Fprintf(w, "static const struct { const char* in; size_t inlen; const char* enc; size_t enclen; } kat_huff_str[] = {\n")
	for _, x := range list {
		fmt.Fprintf(w, "    { %s, %d,\n      %s, %d },\n", cBytes(x.in), len(x.in), cBytes(x.enc), len(x.enc))
	}
	fmt.Fprintf(w, "};\n\n")
}

func genStatic(w io.Writer) {
	dec := hpack.NewDecoder(4096, nil)
	fmt.Fprintf(w, "/* The static table (RFC 7541 Appendix A) as Go's hpack decodes indexes 1-61. */\n")
	fmt.Fprintf(w, "static const char* const kat_static[62][2] = {\n    { 0, 0 },\n")
	for i := 1; i <= 61; i++ {
		hfs, err := dec.DecodeFull([]byte{byte(0x80 | i)})
		must(err)
		if len(hfs) != 1 {
			panic("static entry")
		}
		fmt.Fprintf(w, "    { %s, %s },\n", cBytes([]byte(hfs[0].Name)), cBytes([]byte(hfs[0].Value)))
	}
	fmt.Fprintf(w, "};\n\n")
}

var namePool = []string{
	":status", "content-type", "date", "server", "cache-control", "set-cookie", "location",
	"retry-after", "content-length", "vary", "www-authenticate", "etag", "ts-lb", "x-request-id",
	"x-tailscale-thing", "grpc-status",
}

var valuePool = []string{
	"200", "404", "429", "application/json", "text/plain; charset=utf-8", "7", "0",
	"Mon, 21 Oct 2013 20:13:21 GMT", "private", "gzip", "nodekey:0123456789abcdef", "",
}

func randName(r *rand.Rand) string {
	if r.IntN(3) > 0 {
		return namePool[r.IntN(len(namePool))]
	}
	n := 1 + r.IntN(20)
	b := make([]byte, n)
	for i := range b {
		b[i] = "abcdefghijklmnopqrstuvwxyz-0123456789"[r.IntN(37)]
	}
	return string(b)
}

func randValue(r *rand.Rand) string {
	k := r.IntN(100)
	var n int
	switch {
	case k < 40:
		return valuePool[r.IntN(len(valuePool))]
	case k < 70:
		n = r.IntN(31)
	case k < 88:
		n = 1 + r.IntN(24)
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(r.IntN(256)) // any byte: HPACK itself is byte-transparent
		}
		return string(b)
	default:
		n = 100 + r.IntN(600) // lengths of two and three integer bytes
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(0x20 + r.IntN(0x5f))
	}
	return string(b)
}

// genHpack writes sequences of header blocks from one Go encoder each - the dynamic table carries
// over between the blocks of a sequence - and the lists they decode to. The decoder on the C side
// has the default limit, 4096.
func genHpack(w io.Writer, r *rand.Rand) {
	sizes := []uint32{0, 1, 31, 32, 64, 100, 256, 1000, 4096}
	const nseq, nblk = 12, 6
	for seq := 0; seq < nseq; seq++ {
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		type blk struct {
			b      []byte
			fields []hpack.HeaderField
		}
		var blocks []blk
		for i := 0; i < nblk; i++ {
			for r.IntN(4) == 0 {
				enc.SetMaxDynamicTableSize(sizes[r.IntN(len(sizes))])
			}
			buf.Reset()
			n := 1 + r.IntN(8)
			var fields []hpack.HeaderField
			for j := 0; j < n; j++ {
				hf := hpack.HeaderField{Name: randName(r), Value: randValue(r), Sensitive: r.IntN(10) == 0}
				must(enc.WriteField(hf))
				fields = append(fields, hf)
			}
			if seq == 0 && i == 1 {
				// One field longer than the dynamic table: Go's encoder sends it unindexed
				// (shouldIndex), raw - these bytes cost more as Huffman.
				hf := hpack.HeaderField{Name: "x-long", Value: strings.Repeat("{}|~<>`^", 520)}
				must(enc.WriteField(hf))
				fields = append(fields, hf)
			}
			blocks = append(blocks, blk{append([]byte(nil), buf.Bytes()...), fields})
		}
		for i, b := range blocks {
			fmt.Fprintf(w, "static const kat_field kat_hp_f_%d_%d[] = {\n", seq, i)
			for _, f := range b.fields {
				fmt.Fprintf(w, "    { %s, %d, %s, %d },\n", cBytes([]byte(f.Name)), len(f.Name), cBytes([]byte(f.Value)), len(f.Value))
			}
			fmt.Fprintf(w, "};\n")
		}
		fmt.Fprintf(w, "static const kat_block kat_hp_b_%d[] = {\n", seq)
		for i, b := range blocks {
			fmt.Fprintf(w, "    { %s, %d, kat_hp_f_%d_%d, %d },\n", cBytes(b.b), len(b.b), seq, i, len(b.fields))
		}
		fmt.Fprintf(w, "};\n\n")
	}
	fmt.Fprintf(w, "static const kat_seq kat_hpack[%d] = {\n", nseq)
	for seq := 0; seq < nseq; seq++ {
		fmt.Fprintf(w, "    { kat_hp_b_%d, %d },\n", seq, nblk)
	}
	fmt.Fprintf(w, "};\n")
}

func genMain() {
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	r := rand.New(rand.NewPCG(2026, 930))
	fmt.Fprintf(w, `/*
 * Generated by daemon/test/vectors/h2 ("go run . gen > kat_h2.h", %s) - do not edit. Go's net/http
 * and golang.org/x/net/http2/hpack are the reference: the request heads are what tailscaled's code
 * paths write, the HPACK blocks come from Go's encoder. Deterministic: the same Go gives the same file.
 */

#ifndef KAT_H2_H
#define KAT_H2_H

#include <stddef.h>
#include <stdint.h>

typedef struct { const char* name; size_t nlen; const char* value; size_t vlen; } kat_field;
typedef struct { const char* blk; size_t len; const kat_field* want; size_t n; } kat_block;
typedef struct { const kat_block* blocks; size_t n; } kat_seq;

`, goVersion())
	genRequests(w)
	genHuffman(w, r)
	genStatic(w)
	genHpack(w, r)
	fmt.Fprintf(w, "\n#endif /* KAT_H2_H */\n")
}
