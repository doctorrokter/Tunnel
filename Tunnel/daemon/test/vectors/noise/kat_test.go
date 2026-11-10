// The vectors for daemon/test/test_ts_noise.c, taken from Tailscale's own controlbase (v1.102.5).
//
//	go test -buildvcs=false -run TestKAT .                    checks ../kat_ts_noise.h is current
//	TS_KAT_WRITE=1 go test -buildvcs=false -run TestKAT .     rewrites it
//
// controlbase draws its ephemeral keys from crypto/rand, and testing/cryptotest.SetGlobalRandom
// (Go 1.26+) makes that a ChaCha8 stream from a seed - so the client and the server run
// deterministically, one after the other in one goroutine over memnet, and the ephemeral seeds
// the C test scripts into wg_rng are the first 64 bytes of the same stream. ref.go, written from
// the Noise specification, must reproduce every byte of every transcript before anything is
// written; the far-counter records at the end come from it alone.

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/cryptotest"

	"golang.org/x/crypto/blake2s"
	"tailscale.com/control/controlbase"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const katPath = "../kat_ts_noise.h"

// fixedKey is a long-term key the vectors can print: clamp(BLAKE2s(label)).
func fixedKey(label string) key32 {
	return refClamp(blake2s.Sum256([]byte(label)))
}

func machinePrivate(k key32) key.MachinePrivate {
	var m key.MachinePrivate
	if err := m.UnmarshalText([]byte("privkey:" + hex.EncodeToString(k[:]))); err != nil {
		panic(err)
	}
	return m
}

// tapConn keeps a copy of every byte written through it: what went on the wire.
type tapConn struct {
	net.Conn
	mu   sync.Mutex
	wire bytes.Buffer
}

func (c *tapConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.wire.Write(b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

// globalRandom is the stream cryptotest.SetGlobalRandom(seed) serves: ChaCha8 keyed with the seed
// little-endian in its first 8 bytes.
func globalRandom(seed uint64, n int) []byte {
	var s [32]byte
	binary.LittleEndian.PutUint64(s[:8], seed)
	out := make([]byte, n)
	mathrand.NewChaCha8(s).Read(out)
	return out
}

type transcript struct {
	name    string
	version uint16
	seed    uint64
	s2c     [][]byte // the server's writes after the handshake, one Write each
	c2s     [][]byte // the client's

	clientEph, serverEph key32
	init                 [refInitLen]byte
	resp                 [refRespLen]byte
	hash                 key32
	tx, rx               key32 // the client's
	s2cWire, c2sWire     []byte
}

// runControlbase runs the transcript through controlbase and keeps what went over the wire.
func runControlbase(t *testing.T, tr *transcript, machine, control key32) {
	t.Helper()
	stream := globalRandom(tr.seed, 64)
	copy(tr.clientEph[:], stream[:32])
	copy(tr.serverEph[:], stream[32:])
	cryptotest.SetGlobalRandom(t, tr.seed)

	ctx := context.Background()
	cRaw, sRaw := memnet.NewConn("kat", 1<<20)
	cConn, sConn := &tapConn{Conn: cRaw}, &tapConn{Conn: sRaw}

	// The client's ephemeral is drawn here, the server's inside Server: in that order.
	init, cont, err := controlbase.ClientDeferred(machinePrivate(machine), machinePrivate(control).Public(), tr.version)
	if err != nil || len(init) != refInitLen {
		t.Fatalf("%s: ClientDeferred: %v (%d bytes)", tr.name, err, len(init))
	}
	server, err := controlbase.Server(ctx, sConn, machinePrivate(control), init)
	if err != nil {
		t.Fatalf("%s: Server: %v", tr.name, err)
	}
	for _, w := range tr.s2c {
		if _, err := server.Write(w); err != nil {
			t.Fatalf("%s: server write: %v", tr.name, err)
		}
	}
	client, err := cont(ctx, cConn)
	if err != nil {
		t.Fatalf("%s: client handshake: %v", tr.name, err)
	}

	want := bytes.Join(tr.s2c, nil)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s: client read: %v", tr.name, err)
	}
	for _, w := range tr.c2s {
		if _, err := client.Write(w); err != nil {
			t.Fatalf("%s: client write: %v", tr.name, err)
		}
	}
	want = bytes.Join(tr.c2s, nil)
	got = make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s: server read: %v", tr.name, err)
	}

	if client.HandshakeHash() != server.HandshakeHash() || client.ProtocolVersion() != int(tr.version) ||
		server.ProtocolVersion() != int(tr.version) {
		t.Fatalf("%s: client and server disagree", tr.name)
	}
	copy(tr.init[:], init)
	wire := sConn.wire.Bytes()
	copy(tr.resp[:], wire[:refRespLen])
	tr.s2cWire = bytes.Clone(wire[refRespLen:])
	tr.c2sWire = bytes.Clone(cConn.wire.Bytes())
	tr.hash = client.HandshakeHash()
	client.Close()
	server.Close()
}

// checkRef makes ref.go replay the transcript from the same inputs; every byte must match.
func checkRef(t *testing.T, tr *transcript, machine, control key32) {
	t.Helper()
	init, c, err := refInitiation(machine, refPublic(control), tr.clientEph, tr.version)
	if err != nil || init != tr.init {
		t.Fatalf("%s: ref initiation differs from controlbase (%v)", tr.name, err)
	}
	r, err := refRespond(control, init, tr.serverEph)
	if err != nil || r.msg != tr.resp || r.machinePub != refPublic(machine) || r.version != tr.version {
		t.Fatalf("%s: ref response differs from controlbase (%v)", tr.name, err)
	}
	tx, rx, h, err := c.consume(r.msg)
	if err != nil || h != tr.hash || r.hash != tr.hash || tx != r.c2s || rx != r.s2c {
		t.Fatalf("%s: ref keys or handshake hash differ (%v)", tr.name, err)
	}
	var n uint64
	var s2c, c2s []byte
	for _, w := range tr.s2c {
		s2c = append(s2c, refSealWrite(rx, &n, w)...)
	}
	n = 0
	for _, w := range tr.c2s {
		c2s = append(c2s, refSealWrite(tx, &n, w)...)
	}
	if !bytes.Equal(s2c, tr.s2cWire) || !bytes.Equal(c2s, tr.c2sWire) {
		t.Fatalf("%s: ref records differ from controlbase", tr.name)
	}
	tr.tx, tr.rx = tx, rx
}

// --------------------------------------------------------------------------- the header

type farRecord struct {
	counter  uint64
	toServer bool
	pt       string
	wire     []byte
}

func cString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "\\%03o", c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// hexLiteral: one C string of hex, 32 bytes to a line.
func hexLiteral(b []byte, indent string) string {
	if len(b) == 0 {
		return indent + `""`
	}
	var lines []string
	for len(b) > 0 {
		n := min(len(b), 32)
		lines = append(lines, indent+`"`+hex.EncodeToString(b[:n])+`"`)
		b = b[n:]
	}
	return strings.Join(lines, "\n")
}

func constHex(w io.Writer, name string, b []byte) {
	fmt.Fprintf(w, "static const char %s[] =\n%s;\n", name, hexLiteral(b, "    "))
}

func render(machine, control key32, main *transcript, versions []*transcript, early []byte, far []farRecord,
	s2cBlob, c2sBlob [3]int) []byte {
	var w bytes.Buffer
	mp, cp := refPublic(machine), refPublic(control)

	fmt.Fprint(&w, `/*
 * Generated by daemon/test/vectors/noise (kat_test.go) - do not edit; regenerate with
 *     cd daemon/test/vectors/noise && TS_KAT_WRITE=1 go test -buildvcs=false -run TestKAT .
 * A plain "go test" there checks that this file is current.
 *
 * The transcripts are Tailscale's own controlbase (v1.102.5) talking to itself over memnet, its
 * ephemeral keys fixed by testing/cryptotest.SetGlobalRandom; ref.go, a second implementation
 * written from the Noise specification, reproduced every byte of them before this was written.
 * The far-counter records at the end come from ref.go alone: controlbase never sends an empty
 * record and cannot be wound forward.
 *
 * Long-term keys are stored clamped; the ephemeral seeds are the raw 32 bytes the RNG returns
 * (the client clamps them). TX/RX are the client's keys. A WIRE string is every byte one side
 * wrote, in order - the server's starts with the response. Blobs are not spelled out: they are
 * b[i] = (uint8_t)(i * MUL + ADD).
 */

#ifndef KAT_TS_NOISE_H
#define KAT_TS_NOISE_H

`)
	constHex(&w, "KAT_TS_MACHINE_PRIVATE", machine[:])
	constHex(&w, "KAT_TS_MACHINE_PUBLIC", mp[:])
	constHex(&w, "KAT_TS_CONTROL_PRIVATE", control[:])
	constHex(&w, "KAT_TS_CONTROL_PUBLIC", cp[:])

	fmt.Fprintf(&w, "\n/* --- main: our capver as the version; the server writes EarlyNoise as ts2021's test server\n"+
		" * does (magic, length, JSON: three writes), an empty SETTINGS frame header, then a blob; the\n"+
		" * client writes the HTTP/2 preface, then a blob. Each blob is one write, cut at 4077 bytes. --- */\n")
	fmt.Fprintf(&w, "#define KAT_TS_MAIN_VERSION %d\n", main.version)
	constHex(&w, "KAT_TS_MAIN_CLIENT_EPH", main.clientEph[:])
	constHex(&w, "KAT_TS_MAIN_SERVER_EPH", main.serverEph[:])
	constHex(&w, "KAT_TS_MAIN_INIT", main.init[:])
	constHex(&w, "KAT_TS_MAIN_RESP", main.resp[:])
	constHex(&w, "KAT_TS_MAIN_HASH", main.hash[:])
	constHex(&w, "KAT_TS_MAIN_TX_KEY", main.tx[:])
	constHex(&w, "KAT_TS_MAIN_RX_KEY", main.rx[:])
	fmt.Fprintf(&w, "static const char KAT_TS_MAIN_EARLY_JSON[] =\n    %s;\n", cString(string(early)))
	fmt.Fprintf(&w, "#define KAT_TS_MAIN_S2C_WRITES %d\n", len(main.s2c))
	fmt.Fprintf(&w, "#define KAT_TS_S2C_BLOB_LEN %d\n#define KAT_TS_S2C_BLOB_MUL %d\n#define KAT_TS_S2C_BLOB_ADD %d\n",
		s2cBlob[0], s2cBlob[1], s2cBlob[2])
	constHex(&w, "KAT_TS_MAIN_S2C_WIRE", append(main.resp[:], main.s2cWire...))
	fmt.Fprintf(&w, "static const char KAT_TS_MAIN_C2S_PREFACE[] =\n    %s;\n", cString(string(main.c2s[0])))
	fmt.Fprintf(&w, "#define KAT_TS_C2S_BLOB_LEN %d\n#define KAT_TS_C2S_BLOB_MUL %d\n#define KAT_TS_C2S_BLOB_ADD %d\n",
		c2sBlob[0], c2sBlob[1], c2sBlob[2])
	constHex(&w, "KAT_TS_MAIN_C2S_WIRE", main.c2sWire)

	fmt.Fprintf(&w, "\n/* --- other versions: how the prologue spells them (1 is controlbase's own test version) --- */\n")
	for _, tr := range versions {
		up := strings.ToUpper(tr.name)
		fmt.Fprintf(&w, "#define KAT_TS_%s_VERSION %d\n", up, tr.version)
		constHex(&w, "KAT_TS_"+up+"_CLIENT_EPH", tr.clientEph[:])
		constHex(&w, "KAT_TS_"+up+"_SERVER_EPH", tr.serverEph[:])
		constHex(&w, "KAT_TS_"+up+"_INIT", tr.init[:])
		constHex(&w, "KAT_TS_"+up+"_RESP", tr.resp[:])
		constHex(&w, "KAT_TS_"+up+"_HASH", tr.hash[:])
	}

	fmt.Fprintf(&w, "\n/* --- records at far counters under main's keys (ref.go): to the server with TX, to the\n"+
		" * client with RX. 0xfffffffffffffffe is the last counter controlbase allows. --- */\n")
	fmt.Fprintf(&w, "typedef struct {\n    unsigned long long counter;\n    int to_server;\n    const char* pt;\n    const char* wire;\n} kat_ts_record;\n\n")
	fmt.Fprintf(&w, "static const kat_ts_record KAT_TS_RECORDS[] = {\n")
	for _, r := range far {
		to := 0
		if r.toServer {
			to = 1
		}
		fmt.Fprintf(&w, "    { 0x%016xull, %d, %s,\n%s },\n", r.counter, to, cString(r.pt), hexLiteral(r.wire, "      "))
	}
	fmt.Fprintf(&w, "};\n\n#endif /* KAT_TS_NOISE_H */\n")
	return w.Bytes()
}

// --------------------------------------------------------------------------- the test

func TestKAT(t *testing.T) {
	machine := fixedKey("ts_noise kat: machine key")
	control := fixedKey("ts_noise kat: control key")

	var chal key.ChallengePublic
	chalPub := refPublic(fixedKey("ts_noise kat: node key challenge"))
	if err := chal.UnmarshalText([]byte("chalpub:" + hex.EncodeToString(chalPub[:]))); err != nil {
		t.Fatal(err)
	}
	early, err := json.Marshal(&tailcfg.EarlyNoise{NodeKeyChallenge: chal})
	if err != nil {
		t.Fatal(err)
	}

	s2cBlob := [3]int{4200, 131, 7}
	c2sBlob := [3]int{4100, 29, 3}
	main := &transcript{
		name:    "main",
		version: 130,
		seed:    0x7473326e6f697365, // "ts2noise"
		s2c: [][]byte{
			[]byte("\xff\xff\xffTS"),
			binary.BigEndian.AppendUint32(nil, uint32(len(early))),
			early,
			{0, 0, 0, 4, 0, 0, 0, 0, 0}, // an HTTP/2 frame header: length 0, SETTINGS, no flags, stream 0
			pattern(s2cBlob[0], s2cBlob[1], s2cBlob[2]),
		},
		c2s: [][]byte{
			[]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
			pattern(c2sBlob[0], c2sBlob[1], c2sBlob[2]),
		},
	}
	versions := []*transcript{
		{name: "v1", version: 1, seed: 1, s2c: [][]byte{[]byte("s")}, c2s: [][]byte{[]byte("c")}},
		{name: "v65535", version: 65535, seed: 65535, s2c: [][]byte{[]byte("s")}, c2s: [][]byte{[]byte("c")}},
	}
	for _, tr := range append([]*transcript{main}, versions...) {
		runControlbase(t, tr, machine, control)
		checkRef(t, tr, machine, control)
	}

	// The seal splits exactly like controlbase: one full record, then the rest.
	if len(main.c2sWire) != (24+19)+(4096)+(c2sBlob[0]-4077+19) {
		t.Fatalf("unexpected c2s wire length %d", len(main.c2sWire))
	}

	far := []farRecord{
		{counter: 1, toServer: true, pt: "ts2021"},
		{counter: 2, toServer: true, pt: ""},
		{counter: 255, toServer: false, pt: "x"},
		{counter: 256, toServer: false, pt: "xy"},
		{counter: 0x0102030405060708, toServer: true, pt: "big-endian"},
		{counter: 0x0102030405060708, toServer: false, pt: "big-endian"},
		{counter: 0xfffffffffffffffe, toServer: true, pt: "last"},
		{counter: 0xfffffffffffffffe, toServer: false, pt: "last"},
	}
	for i := range far {
		k := main.rx
		if far[i].toServer {
			k = main.tx
		}
		far[i].wire = refSealRecord(k, far[i].counter, []byte(far[i].pt))
	}

	text := render(machine, control, main, versions, early, far, s2cBlob, c2sBlob)
	if os.Getenv("TS_KAT_WRITE") == "1" {
		if err := os.WriteFile(katPath, text, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", katPath, len(text))
		return
	}
	old, err := os.ReadFile(katPath)
	if err != nil {
		t.Fatalf("%v - generate it with TS_KAT_WRITE=1", err)
	}
	if !bytes.Equal(old, text) {
		t.Fatalf("%s is stale - regenerate it with TS_KAT_WRITE=1", katPath)
	}
}

// TestRefRefuses: ref.go must fail where controlbase fails, or its agreement above proves little.
func TestRefRefuses(t *testing.T) {
	machine := fixedKey("ts_noise kat: machine key")
	control := fixedKey("ts_noise kat: control key")
	var eph key32
	eph[0] = 1
	init, c, err := refInitiation(machine, refPublic(control), eph, 130)
	if err != nil {
		t.Fatal(err)
	}
	r, err := refRespond(control, init, eph)
	if err != nil {
		t.Fatal(err)
	}
	for i := 5; i < refInitLen; i++ {
		bad := init
		bad[i] ^= 1
		if _, err := refRespond(control, bad, eph); err == nil {
			t.Fatalf("tampered initiation byte %d accepted", i)
		}
	}
	for i := 3; i < refRespLen; i++ {
		bad := r.msg
		bad[i] ^= 1
		c2 := *c
		sym := *c.sym
		c2.sym = &sym
		if _, _, _, err := c2.consume(bad); err == nil {
			t.Fatalf("tampered response byte %d accepted", i)
		}
	}
	if _, _, _, err := c.consume(r.msg); err != nil {
		t.Fatal(err)
	}
}
