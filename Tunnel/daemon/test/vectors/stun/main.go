// Command tsstun writes the vectors for daemon/src/ts_stun.c (kat_stun.h): binding requests as
// Tailscale's stun.Request builds them, and stun.ParseResponse's verdict on answers - the answers of
// Tailscale's own stun_test.go (real servers: Google, sipgate, powervoip, stuntman, pion), answers
// stun.Response builds, hand-made ones, and every one of them cut short at each length and with each
// byte flipped. The C test makes the same cuts and flips and must come to the same verdict.
//
//	MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/build/ts-stun/run.sh gen
//
// Tailscale comes from the read-only clone in refs/ (v1.102.5), not from the module proxy.
package main

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"tailscale.com/net/stun"
)

type fixture struct {
	name string
	data []byte
}

func txN(n byte) (x stun.TxID) {
	for i := range x {
		x[i] = n
	}
	return
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// An answer put together by hand: the header, then the attributes as given (each type, value; padded).
func answer(msgType uint16, tx stun.TxID, attrs ...[]byte) []byte {
	var body []byte
	for _, a := range attrs {
		body = append(body, a...)
	}
	b := []byte{byte(msgType >> 8), byte(msgType), byte(len(body) >> 8), byte(len(body)), 0x21, 0x12, 0xa4, 0x42}
	b = append(b, tx[:]...)
	return append(b, body...)
}

func attr(t uint16, v []byte) []byte {
	b := []byte{byte(t >> 8), byte(t), byte(len(v) >> 8), byte(len(v))}
	b = append(b, v...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// A MAPPED-ADDRESS value in clear: 0, family, port, address.
func plainAddr(fam byte, port uint16, ip []byte) []byte {
	return append([]byte{0, fam, byte(port >> 8), byte(port)}, ip...)
}

func fixtures() []fixture {
	f := []fixture{
		// net/stun/stun_test.go's responseTests, as they are there.
		{"google-1", []byte{
			0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42,
			0x23, 0x60, 0xb1, 0x1e, 0x3e, 0xc6, 0x8f, 0xfa,
			0x93, 0xe0, 0x80, 0x07, 0x00, 0x20, 0x00, 0x08,
			0x00, 0x01, 0xc7, 0x86, 0x69, 0x57, 0x85, 0x6f,
		}},
		{"google-2", []byte{
			0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42,
			0xf9, 0xf1, 0x21, 0xcb, 0xde, 0x7d, 0x7c, 0x75,
			0x92, 0x3c, 0xe2, 0x71, 0x00, 0x20, 0x00, 0x08,
			0x00, 0x01, 0xc7, 0x87, 0x69, 0x57, 0x85, 0x6f,
		}},
		{"stun-sipgate-net-10000", []byte{
			0x01, 0x01, 0x00, 0x44, 0x21, 0x12, 0xa4, 0x42,
			0x48, 0x2e, 0xb6, 0x47, 0x15, 0xe8, 0xb2, 0x8e,
			0xae, 0xad, 0x64, 0x44, 0x00, 0x01, 0x00, 0x08,
			0x00, 0x01, 0xe4, 0xab, 0x48, 0x45, 0x21, 0x2d,
			0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x27, 0x10,
			0xd9, 0x0a, 0x44, 0x98, 0x00, 0x05, 0x00, 0x08,
			0x00, 0x01, 0x27, 0x11, 0xd9, 0x74, 0x7a, 0x8a,
			0x80, 0x20, 0x00, 0x08, 0x00, 0x01, 0xc5, 0xb9,
			0x69, 0x57, 0x85, 0x6f, 0x80, 0x22, 0x00, 0x10,
			0x56, 0x6f, 0x76, 0x69, 0x64, 0x61, 0x2e, 0x6f,
			0x72, 0x67, 0x20, 0x30, 0x2e, 0x39, 0x36, 0x00,
		}},
		{"stun-powervoip-com-3478", []byte{
			0x01, 0x01, 0x00, 0x24, 0x21, 0x12, 0xa4, 0x42,
			0x7e, 0x57, 0x96, 0x68, 0x29, 0xf4, 0x44, 0x60,
			0x9d, 0x1d, 0xea, 0xa6, 0x00, 0x01, 0x00, 0x08,
			0x00, 0x01, 0xe9, 0xd3, 0x48, 0x45, 0x21, 0x2d,
			0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x0d, 0x96,
			0x4d, 0x48, 0xa9, 0xd4, 0x00, 0x05, 0x00, 0x08,
			0x00, 0x01, 0x0d, 0x97, 0x4d, 0x48, 0xa9, 0xd5,
		}},
		{"in-process-pion-server", []byte{
			0x01, 0x01, 0x00, 0x24, 0x21, 0x12, 0xa4, 0x42,
			0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c,
			0x4f, 0x3e, 0x30, 0x8e, 0x80, 0x22, 0x00, 0x0a,
			0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74,
			0x65, 0x72, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08,
			0x00, 0x01, 0xce, 0x66, 0x5e, 0x12, 0xa4, 0x43,
			0x80, 0x28, 0x00, 0x04, 0xb6, 0x99, 0xbb, 0x02,
			0x01, 0x01, 0x00, 0x24, 0x21, 0x12, 0xa4, 0x42,
		}},
		{"stuntman-server-ipv6", []byte{
			0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42,
			0x06, 0xf5, 0x66, 0x85, 0xd2, 0x8a, 0xf3, 0xe6,
			0x9c, 0xe3, 0x41, 0xe2, 0x00, 0x01, 0x00, 0x14,
			0x00, 0x02, 0x90, 0xce, 0x26, 0x02, 0x00, 0xd1,
			0xb4, 0xcf, 0xc1, 0x00, 0x38, 0xb2, 0x31, 0xff,
			0xfe, 0xef, 0x96, 0xf6, 0x80, 0x2b, 0x00, 0x14,
			0x00, 0x02, 0x0d, 0x96, 0x26, 0x04, 0xa8, 0x80,
			0x00, 0x02, 0x00, 0xd1, 0x00, 0x00, 0x00, 0x00,
			0x00, 0xc5, 0x70, 0x01, 0x00, 0x20, 0x00, 0x14,
			0x00, 0x02, 0xb1, 0xdc, 0x07, 0x10, 0xa4, 0x93,
			0xb2, 0x3a, 0xa7, 0x85, 0xea, 0x38, 0xc2, 0x19,
			0x62, 0x0c, 0xd7, 0x14,
		}},
		{"software-a", []byte{
			0x01, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42,
			0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c,
			0x4f, 0x3e, 0x30, 0x8e, 0x80, 0x22, 0x00, 0x01,
			0x61, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08,
			0x00, 0x01, 0xce, 0x66, 0x5e, 0x12, 0xa4, 0x43,
		}},
		{"software-abc", []byte{
			0x01, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42,
			0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c,
			0x4f, 0x3e, 0x30, 0x8e, 0x80, 0x22, 0x00, 0x03,
			0x61, 0x62, 0x63, 0x00, 0x00, 0x20, 0x00, 0x08,
			0x00, 0x01, 0xce, 0x66, 0x5e, 0x12, 0xa4, 0x43,
		}},
		{"no-4in6", mustHex("010100182112a4424fd5d202dcb37d31fc773306002000140002cd3d2112a4424fd5d202dcb382ce2dc3fcc7")},
	}
	// stun.Response, as derper and Headscale answer (TestResponse's cases and two more).
	resp := []struct {
		tx   stun.TxID
		addr string
	}{
		{txN(1), "1.2.3.4:254"},
		{txN(2), "1.2.3.4:257"},
		{txN(3), "[1::4]:254"},
		{txN(4), "[1::4]:257"},
		{txN(5), "0.0.0.0:0"},
		{txN(6), "203.0.113.77:41642"},
	}
	for i, r := range resp {
		f = append(f, fixture{fmt.Sprintf("response-%d", i+1), stun.Response(r.tx, netip.MustParseAddrPort(r.addr))})
	}
	tx := txN(7)
	xor4 := stun.Response(tx, netip.MustParseAddrPort("10.20.77.2:41641"))[20:] // its one attribute
	f = append(f,
		fixture{"mapped-only", answer(0x0101, tx, attr(0x0001, plainAddr(1, 3478, []byte{10, 20, 88, 2})))},
		fixture{"mapped-and-xor", answer(0x0101, tx, attr(0x0001, plainAddr(1, 1, []byte{9, 9, 9, 9})), xor4)},
		fixture{"xor-alt-0x8020", answer(0x0101, tx, attr(0x8020, xor4[4:]))},
		fixture{"two-xor-last-wins", answer(0x0101, tx, xor4, attr(0x0020, stun.Response(tx, netip.MustParseAddrPort("5.6.7.8:9"))[24:]))},
		fixture{"mapped-v4-in-v6", answer(0x0101, tx, attr(0x0001, plainAddr(2, 80, netip.MustParseAddr("::ffff:1.2.3.4").AsSlice())))},
		fixture{"broken-xor-then-mapped", answer(0x0101, tx, attr(0x0020, []byte{0, 1, 0}), attr(0x0001, plainAddr(1, 1, []byte{1, 1, 1, 1})))},
		fixture{"mapped-family-3", answer(0x0101, tx, attr(0x0001, plainAddr(3, 1, []byte{1, 1, 1, 1})))},
		fixture{"xor-ipv6-short", answer(0x0101, tx, attr(0x0020, []byte{0, 2, 0, 1, 1, 2, 3, 4}))},
		fixture{"unknown-attrs-only", answer(0x0101, tx, attr(0x8022, []byte("tailnode")), attr(0x8028, []byte{1, 2, 3, 4}))},
		fixture{"no-attrs", answer(0x0101, tx)},
		fixture{"error-response", answer(0x0111, tx, xor4)},
		fixture{"binding-request", stun.Request(tx)},
		fixture{"trailing-bytes", append(append([]byte{}, stun.Response(tx, netip.MustParseAddrPort("8.8.4.4:53"))...), 0xde, 0xad, 0xbe, 0xef, 0x01)},
	)
	// The length field longer than the datagram, and one that ends inside an attribute.
	long := append([]byte{}, stun.Response(tx, netip.MustParseAddrPort("8.8.8.8:1"))...)
	long[3] += 4
	f = append(f, fixture{"length-past-the-end", long})
	inside := append([]byte{}, stun.Response(tx, netip.MustParseAddrPort("8.8.8.8:1"))...)
	inside[3] -= 2
	f = append(f, fixture{"length-inside-an-attr", inside})
	return f
}

// stun.ParseResponse's and stun.Is's view of one datagram, as the C test reads it.
func verdict(b []byte) string {
	is := 0
	if stun.Is(b) {
		is = 1
	}
	_, ap, err := stun.ParseResponse(b)
	if err != nil {
		return fmt.Sprintf("{ 0, %d, 0, 0, \"\" }", is)
	}
	a := ap.Addr()
	fam := 6
	raw := a.AsSlice()
	if a.Is4() {
		fam = 4
	}
	return fmt.Sprintf("{ 1, %d, %d, %d, \"%s\" }", is, fam, ap.Port(), hex.EncodeToString(raw))
}

var masks = []byte{0x01, 0xff}

func cArray(b []byte) string {
	var s strings.Builder
	for i, c := range b {
		if i > 0 {
			s.WriteString(", ")
		}
		fmt.Fprintf(&s, "0x%02x", c)
	}
	return s.String()
}

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	var out strings.Builder
	out.WriteString(`/*
 * Generated by daemon/test/vectors/stun (tsstun, Go) from Tailscale v1.102.5: binding requests as
 * stun.Request builds them, and stun.ParseResponse's verdict on answers - stun_test.go's, built
 * ones, hand-made ones - each whole, cut short at every length and with every byte flipped (by
 * each of stun_masks). Do not edit.
 */

typedef struct {
    uint8_t     ok;         /* stun.ParseResponse took it */
    uint8_t     is;         /* stun.Is */
    uint8_t     family;     /* 4 or 6 when ok */
    uint16_t    port;
    const char* addr;       /* hex, 4 or 16 bytes */
} stun_verdict;

typedef struct {
    const char*         name;
    const uint8_t*      data;
    size_t              len;
    stun_verdict        whole;
    const stun_verdict* cut;    /* len + 1: data[0 .. n) for n = 0 .. len */
    const stun_verdict* flip;   /* len * STUN_MASKS: byte i ^ stun_masks[m] at [i * STUN_MASKS + m] */
} stun_fixture;

`)
	fmt.Fprintf(&out, "#define STUN_MASKS %d\nstatic const uint8_t stun_masks[STUN_MASKS] = { %s };\n\n", len(masks), cArray(masks))

	// Requests.
	reqTx := []stun.TxID{txN(0), txN(1), txN(0xff), {0x23, 0x60, 0xb1, 0x1e, 0x3e, 0xc6, 0x8f, 0xfa, 0x93, 0xe0, 0x80, 0x07}}
	out.WriteString("typedef struct { uint8_t txid[12]; uint8_t req[40]; } stun_request_vec;\n")
	out.WriteString("static const stun_request_vec stun_requests[] = {\n")
	for _, tx := range reqTx {
		req := stun.Request(tx)
		if len(req) != 40 {
			panic("request length")
		}
		fmt.Fprintf(&out, "    { { %s },\n      { %s } },\n", cArray(tx[:]), cArray(req))
	}
	out.WriteString("};\n\n")

	fx := fixtures()
	for i, f := range fx {
		fmt.Fprintf(&out, "/* %s */\nstatic const uint8_t stun_d%d[] = { %s };\n", f.name, i, cArray(f.data))
		fmt.Fprintf(&out, "static const stun_verdict stun_c%d[] = {\n", i)
		for n := 0; n <= len(f.data); n++ {
			fmt.Fprintf(&out, "    %s,\n", verdict(f.data[:n]))
		}
		out.WriteString("};\n")
		fmt.Fprintf(&out, "static const stun_verdict stun_f%d[] = {\n", i)
		for p := range f.data {
			for _, m := range masks {
				b := append([]byte{}, f.data...)
				b[p] ^= m
				fmt.Fprintf(&out, "    %s,\n", verdict(b))
			}
		}
		if len(f.data) == 0 {
			out.WriteString("    { 0, 0, 0, 0, \"\" },\n")
		}
		out.WriteString("};\n\n")
	}
	out.WriteString("static const stun_fixture stun_fixtures[] = {\n")
	for i, f := range fx {
		fmt.Fprintf(&out, "    { \"%s\", stun_d%d, sizeof(stun_d%d), %s, stun_c%d, stun_f%d },\n", f.name, i, i, verdict(f.data), i, i)
	}
	out.WriteString("};\n")

	path := filepath.Join(dir, "kat_stun.h")
	if err := os.WriteFile(path, []byte(out.String()), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("%s: %d requests, %d answers\n", path, len(reqTx), len(fx))
}
