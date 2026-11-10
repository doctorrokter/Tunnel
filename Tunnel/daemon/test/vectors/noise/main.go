// The ts2021 interop server for test_ts_noise --interop: the Noise side is Tailscale's own
// controlbase (v1.102.5, from refs/tailscale) on loopback TCP.
//
//	go build -buildvcs=false -o tsnoise_server . && ./tsnoise_server -mode raw -ok 1 -refused 2
//
// It prints "LISTEN <addr> <control public key, hex>" and serves connections one at a time:
//
//	raw   controlbase.Server reads the initiation off the stream itself, no HTTP. After the
//	      handshake the stream starts with an HTTP/2 SETTINGS frame header - no EarlyNoise.
//	http  POST /ts2021 through controlhttpserver.AcceptHTTP - the initiation in the
//	      X-Tailscale-Handshake header, EarlyNoise written by earlyWrite in three writes as
//	      ts2021's test server does, and all of it corked into one TCP write with the response,
//	      as the real server sends it.
//
// Then the session: a hello (the peer's machine key, the protocol version, the handshake hash),
// 100000 bytes of pattern (i*131 + 7) in one write; it reads a 4-byte big-endian length and that
// many bytes of pattern (i*29 + 3), echoes them back in one write, writes "BYE" and closes. A
// handshake controlbase fails counts as refused. The exit status is 0 when the counts match -ok
// and -refused and no session failed.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	helloBlobLen = 100000
	maxEcho      = 1 << 20
)

var settingsFrame = []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}

type result struct {
	refused bool
	err     error
}

func session(c *controlbase.Conn, mode string) error {
	if mode == "raw" {
		if _, err := c.Write(settingsFrame); err != nil {
			return err
		}
	}
	hh := c.HandshakeHash()
	hello := append([]byte{}, c.Peer().UntypedBytes()...)
	hello = binary.BigEndian.AppendUint16(hello, uint16(c.ProtocolVersion()))
	hello = append(hello, hh[:]...)
	if _, err := c.Write(hello); err != nil {
		return err
	}
	if _, err := c.Write(pattern(helloBlobLen, 131, 7)); err != nil {
		return err
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return fmt.Errorf("reading the length: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxEcho {
		return fmt.Errorf("length %d too big", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(c, data); err != nil {
		return fmt.Errorf("reading %d bytes: %w", n, err)
	}
	if !bytes.Equal(data, pattern(int(n), 29, 3)) {
		return errors.New("the client's bytes are not the pattern")
	}
	if _, err := c.Write(data); err != nil {
		return err
	}
	_, err := c.Write([]byte("BYE"))
	return err
}

// earlyWrite is ts2021's test server's EarlyNoise, write for write.
func earlyWrite(challenge key.ChallengePublic) func(int, io.Writer) error {
	return func(_ int, w io.Writer) error {
		js, err := json.Marshal(&tailcfg.EarlyNoise{NodeKeyChallenge: challenge})
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte("\xff\xff\xffTS")); err != nil {
			return err
		}
		if _, err := w.Write(binary.BigEndian.AppendUint32(nil, uint32(len(js)))); err != nil {
			return err
		}
		_, err = w.Write(js)
		return err
	}
}

// drainClose ends a refused raw connection gently: FIN first, then read what the client still
// sends. Closing with its initiation unread would send an RST, and an RST can overtake the error
// message controlbase has just written.
func drainClose(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	io.Copy(io.Discard, conn)
	conn.Close()
}

func serveRaw(ln net.Listener, controlKey key.MachinePrivate, total int, results chan<- result) {
	for i := 0; i < total; i++ {
		conn, err := ln.Accept()
		if err != nil {
			results <- result{err: err}
			return
		}
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		c, err := controlbase.Server(context.Background(), conn, controlKey, nil)
		if err != nil {
			log.Printf("raw: handshake refused: %v", err)
			drainClose(conn)
			results <- result{refused: true, err: err}
			continue
		}
		err = session(c, "raw")
		c.Close()
		results <- result{err: err}
	}
}

func serveHTTP(ln net.Listener, controlKey key.MachinePrivate, results chan<- result) {
	challenge := key.NewChallenge().Public()
	mux := http.NewServeMux()
	mux.HandleFunc("/ts2021", func(w http.ResponseWriter, r *http.Request) {
		c, err := controlhttpserver.AcceptHTTP(r.Context(), w, r, controlKey, earlyWrite(challenge))
		if err != nil {
			log.Printf("http: handshake refused: %v", err)
			results <- result{refused: true, err: err}
			return
		}
		c.SetDeadline(time.Now().Add(20 * time.Second))
		err = session(c, "http")
		c.Close()
		results <- result{err: err}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	srv.Serve(ln)
}

// pattern is a blob both ends compute instead of carrying it: b[i] = i*mul + add. The C test and
// kat_test.go use the same.
func pattern(n int, mul, add int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*mul + add)
	}
	return b
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "address to listen on")
	mode := flag.String("mode", "raw", "raw or http")
	wantOK := flag.Int("ok", 1, "sessions that must complete")
	wantRefused := flag.Int("refused", 0, "handshakes that must be refused")
	timeout := flag.Duration("timeout", 60*time.Second, "give up after this long")
	flag.Parse()
	log.SetPrefix("tsnoise_server: ")
	log.SetFlags(0)

	controlKey := key.NewMachine()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	pub := controlKey.Public()
	fmt.Printf("LISTEN %s %s\n", ln.Addr(), hex.EncodeToString(pub.UntypedBytes()))

	total := *wantOK + *wantRefused
	results := make(chan result, total+4)
	switch *mode {
	case "raw":
		go serveRaw(ln, controlKey, total, results)
	case "http":
		go serveHTTP(ln, controlKey, results)
	default:
		log.Fatalf("unknown mode %q", *mode)
	}

	ok, refused, failed := 0, 0, 0
	deadline := time.After(*timeout)
	for ok+refused+failed < total {
		select {
		case r := <-results:
			switch {
			case r.refused:
				refused++
			case r.err != nil:
				log.Printf("session failed: %v", r.err)
				failed++
			default:
				ok++
			}
		case <-deadline:
			log.Printf("timed out: ok=%d refused=%d failed=%d", ok, refused, failed)
			os.Exit(1)
		}
	}
	log.Printf("%s: ok=%d refused=%d failed=%d", *mode, ok, refused, failed)
	if ok != *wantOK || refused != *wantRefused || failed != 0 {
		os.Exit(1)
	}
}
