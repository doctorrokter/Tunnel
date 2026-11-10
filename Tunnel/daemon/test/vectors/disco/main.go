// Command tsdisco writes the vectors for daemon/src/ts_disco.c (kat_disco.h): disco frames as
// Tailscale's magicsock sends them (sendDiscoMessage: disco.Magic, the sender's disco key, then
// key.DiscoShared.Seal of the message's AppendMarshal - nonce || box) with the nonce fixed here
// instead of random, and each frame's message as disco.Parse reads it back. Hand-made frames too:
// what an old client, a future one or a broken one sends.
//
//	MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/build/ts-disco/run.sh gen
//
// Tailscale comes from the read-only clone in refs/ (v1.102.5), not from the module proxy.
package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"go4.org/mem"
	"golang.org/x/crypto/nacl/box"
	"tailscale.com/disco"
	"tailscale.com/types/key"
)

// A frame and what it carries.
type vec struct {
	name   string
	frame  []byte
	opens  bool   // the box opens with the shared key
	parsed string // disco.Parse's view, in the C test's format; "" when it refuses the message
}

func seq(start, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(start + i*3)
	}
	return b
}

var (
	aRaw  = seq(1, 32)  // the sender's private key, raw
	bRaw  = seq(77, 32) // the receiver's
	aPriv = key.DiscoPrivateFromRaw32(mem.B(aRaw))
	bPriv = key.DiscoPrivateFromRaw32(mem.B(bRaw))
	aPub  = aPriv.Public()
	bPub  = bPriv.Public()
)

func raw(k key.DiscoPublic) []byte { return k.AppendTo(nil) }

// The shared key as box.Precompute has it - key.DiscoPrivate.Shared does the same, inside.
func shared() *[32]byte {
	var k, pub, priv [32]byte
	copy(pub[:], raw(bPub))
	copy(priv[:], aRaw)
	box.Precompute(&k, &pub, &priv)
	return &k
}

// A frame of `inner` (a marshaled message) from a to b under `nonce`.
func frame(inner []byte, nonce byte) []byte {
	var n [24]byte
	for i := range n {
		n[i] = nonce + byte(i)
	}
	out := []byte(disco.Magic)
	out = append(out, raw(aPub)...)
	out = append(out, n[:]...)
	return box.SealAfterPrecomputation(out, inner, &n, shared())
}

// The endpoints of a CallMeMaybe the C side keeps (TS_DISCO_EPS_MAX): the first ones.
const cEpsMax = 16

// disco.Parse's message in the C test's words.
func describe(m disco.Message) string {
	switch m := m.(type) {
	case *disco.Ping:
		nk := "-"
		if !m.NodeKey.IsZero() {
			nk = fmt.Sprintf("%x", m.NodeKey.AppendTo(nil))
		}
		return fmt.Sprintf("ping tx=%x key=%s pad=%d", m.TxID[:], nk, m.Padding)
	case *disco.Pong:
		return fmt.Sprintf("pong tx=%x src=%s", m.TxID[:], m.Src.String())
	case *disco.CallMeMaybe:
		eps := make([]string, 0, len(m.MyNumber))
		for i, e := range m.MyNumber {
			if i == cEpsMax {
				break
			}
			eps = append(eps, e.String())
		}
		return strings.TrimSpace(fmt.Sprintf("cmm n=%d %s", len(eps), strings.Join(eps, " ")))
	default:
		return "other"
	}
}

func add(vs *[]vec, name string, inner []byte, nonce byte) {
	f := frame(inner, nonce)
	v := vec{name: name, frame: f, opens: true}
	if m, err := disco.Parse(inner); err == nil {
		v.parsed = describe(m)
	}
	*vs = append(*vs, v)
}

func main() {
	out := "."
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	var vs []vec
	var tx [12]byte
	copy(tx[:], seq(200, 12))
	nodeKey := key.NodePublicFromRaw32(mem.B(seq(9, 32)))

	// What magicsock sends.
	add(&vs, "ping", (&disco.Ping{TxID: tx, NodeKey: nodeKey}).AppendMarshal(nil), 1)
	add(&vs, "ping_padded", (&disco.Ping{TxID: tx, NodeKey: nodeKey, Padding: 40}).AppendMarshal(nil), 2)
	add(&vs, "pong_v4", (&disco.Pong{TxID: tx, Src: netip.MustParseAddrPort("192.168.1.93:41641")}).AppendMarshal(nil), 3)
	add(&vs, "pong_v6", (&disco.Pong{TxID: tx, Src: netip.MustParseAddrPort("[2001:db8::1]:41641")}).AppendMarshal(nil), 4)
	add(&vs, "cmm", (&disco.CallMeMaybe{MyNumber: []netip.AddrPort{
		netip.MustParseAddrPort("192.168.1.15:41641"),
		netip.MustParseAddrPort("203.0.113.7:61234"),
		netip.MustParseAddrPort("[2001:db8::7]:41641"),
	}}).AppendMarshal(nil), 5)
	add(&vs, "cmm_empty", (&disco.CallMeMaybe{}).AppendMarshal(nil), 6)

	// What an old client (no node key, before 1.16), a newer one (another version, more bytes) or
	// a broken one sends - by hand.
	add(&vs, "ping_old", append([]byte{0x01, 0x00}, tx[:]...), 7)
	add(&vs, "ping_short", append([]byte{0x01, 0x00}, tx[:11]...), 8)
	add(&vs, "ping_v1_longer", append(append([]byte{0x01, 0x01}, (&disco.Ping{TxID: tx, NodeKey: nodeKey}).AppendMarshal(nil)[2:]...), 0xee, 0xee), 9)
	pong := (&disco.Pong{TxID: tx, Src: netip.MustParseAddrPort("10.0.0.2:1")}).AppendMarshal(nil)
	add(&vs, "pong_short", pong[:len(pong)-1], 10)
	add(&vs, "pong_longer", append(append([]byte{}, pong...), 1, 2, 3), 11)
	cmm := (&disco.CallMeMaybe{MyNumber: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.9:9")}}).AppendMarshal(nil)
	add(&vs, "cmm_ragged", append(append([]byte{}, cmm...), 0), 12)
	add(&vs, "cmm_v1", append([]byte{0x03, 0x01}, cmm[2:]...), 13)
	add(&vs, "type_unknown", []byte{0x7f, 0x00, 1, 2, 3}, 14)
	add(&vs, "type_relay_bind", (&disco.BindUDPRelayEndpoint{}).AppendMarshal(nil), 15)
	add(&vs, "empty", []byte{}, 16)
	add(&vs, "type_only", []byte{0x01}, 17)
	many := make([]netip.AddrPort, 20)
	for i := range many {
		many[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), uint16(1000+i))
	}
	add(&vs, "cmm_twenty", (&disco.CallMeMaybe{MyNumber: many}).AppendMarshal(nil), 18)

	// A box that does not open: one bit off in the tag.
	bad := frame((&disco.Ping{TxID: tx, NodeKey: nodeKey}).AppendMarshal(nil), 19)
	bad[len(disco.Magic)+32+24] ^= 1
	vs = append(vs, vec{name: "tampered", frame: bad})

	var b bytes.Buffer
	fmt.Fprintf(&b, "/*\n * Generated by daemon/test/vectors/disco (tsdisco, Go) from Tailscale v1.102.5: disco frames from\n")
	fmt.Fprintf(&b, " * key A to key B as magicsock seals them (nonce fixed), and disco.Parse's view of each. Do not edit.\n */\n\n")
	fmt.Fprintf(&b, "static const uint8_t disco_vec_a_priv[32] = { %s };\n", cbytes(aRaw))
	fmt.Fprintf(&b, "static const uint8_t disco_vec_a_pub[32] = { %s };\n", cbytes(raw(aPub)))
	fmt.Fprintf(&b, "static const uint8_t disco_vec_b_priv[32] = { %s };\n", cbytes(bRaw))
	fmt.Fprintf(&b, "static const uint8_t disco_vec_b_pub[32] = { %s };\n", cbytes(raw(bPub)))
	fmt.Fprintf(&b, "static const uint8_t disco_vec_shared[32] = { %s };\n\n", cbytes(shared()[:]))
	fmt.Fprintf(&b, "typedef struct {\n    const char*    name;\n    const uint8_t* frame;\n    size_t         len;\n")
	fmt.Fprintf(&b, "    int            opens;      /* the box opens */\n")
	fmt.Fprintf(&b, "    const char*    parsed;     /* disco.Parse's message; \"\" when it refuses it */\n} disco_vec;\n\n")
	for i, v := range vs {
		fmt.Fprintf(&b, "static const uint8_t disco_vec_frame_%d[] = { %s };\n", i, cbytes(v.frame))
	}
	fmt.Fprintf(&b, "\nstatic const disco_vec disco_vecs[] = {\n")
	for i, v := range vs {
		opens := 0
		if v.opens {
			opens = 1
		}
		fmt.Fprintf(&b, "    { %q, disco_vec_frame_%d, sizeof(disco_vec_frame_%d), %d, %q },\n", v.name, i, i, opens, v.parsed)
	}
	fmt.Fprintf(&b, "};\n")
	if err := os.WriteFile(filepath.Join(out, "kat_disco.h"), b.Bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%d vectors\n", len(vs))
}

func cbytes(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("0x%02x", c)
	}
	return strings.Join(parts, ", ")
}
