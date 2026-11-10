// Command tsnetmap writes the vectors for daemon/src/ts_netmap.c (kat_netmap.h) and the wire
// examples next to it (example_*.json).
//
// The messages are tailcfg values marshaled by Go's encoding/json - exactly what a control server
// written in Go (Tailscale's, Headscale) puts on the wire, omitempty and all - plus hand-written
// JSON for what only a broken or hostile server sends. Each sequence is applied by Tailscale's own
// mapSession (control/controlclient/map.go, reached with go:linkname: it is unexported), with
// direct.go's rules around it (a KeepAlive is not applied; a session's first message must carry
// Node), and the netmap after every message is written as a canonical text that the C test
// produces from its model the same way.
//
//	MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/build/ts-netmap/run.sh gen
//
// go build needs -ldflags=-checklinkname=0 (linkname into another package) and -buildvcs=false.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"go4.org/mem"
	"tailscale.com/control/controlclient"
	"tailscale.com/control/controlknobs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
)

//go:linkname newMapSession tailscale.com/control/controlclient.newMapSession
func newMapSession(privateNodeKey key.NodePrivate, nu controlclient.NetmapUpdater, controlKnobs *controlknobs.Knobs) unsafe.Pointer

//go:linkname handleNonKeepAlive tailscale.com/control/controlclient.(*mapSession).HandleNonKeepAliveMapResponse
func handleNonKeepAlive(ms unsafe.Pointer, ctx context.Context, resp *tailcfg.MapResponse) error

//go:linkname closeSession tailscale.com/control/controlclient.(*mapSession).Close
func closeSession(ms unsafe.Pointer)

// The clock PeerSeenChange stamps LastSeen with (direct.go): made fixed, so the vectors are.
//
//go:linkname ccClock tailscale.com/control/controlclient.clock
var ccClock tstime.Clock

var (
	t0  = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	now = t0.Add(time.Hour) // what the C test passes as `now`
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// --------------------------------------------------------------------- the canonical dump

// esc keeps printable ASCII but space and backslash, the rest as \xHH: a token never has a space.
func esc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c > 0x20 && c < 0x7f && c != '\\' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "\\x%02x", c)
		}
	}
	return b.String()
}

func tm(t time.Time) string {
	if t.IsZero() {
		return "zero"
	}
	return fmt.Sprintf("%d.%09d", t.Unix(), t.Nanosecond())
}

func pfx(p netip.Prefix) string {
	if !p.IsValid() {
		return "-"
	}
	a := p.Addr()
	if a.Is4() {
		r := a.As4()
		return fmt.Sprintf("%x/%d", r[:], p.Bits())
	}
	r := a.As16()
	return fmt.Sprintf("%x/%d", r[:], p.Bits())
}

func pfxs(v views.Slice[netip.Prefix]) string {
	var parts []string
	for _, p := range v.All() {
		parts = append(parts, pfx(p))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func b01(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nodeLine(kind string, n tailcfg.NodeView) string {
	online := "-"
	if v, ok := n.Online().GetOk(); ok {
		online = fmt.Sprint(b01(v))
	}
	seen := "-"
	if v, ok := n.LastSeen().GetOk(); ok {
		seen = tm(v)
	}
	k := n.Key().Raw32()
	d := n.DiscoKey().Raw32()
	return fmt.Sprintf("%s id=%d user=%d key=%x disco=%x name=%s addrs=%s allowed=%s derp=%d online=%s seen=%s expiry=%s expired=%d auth=%d unsigned=%d wgonly=%d\n",
		kind, n.ID(), n.User(), k[:], d[:], esc(n.Name()), pfxs(n.Addresses()), pfxs(n.AllowedIPs()),
		n.HomeDERP(), online, seen, tm(n.KeyExpiry()), b01(n.Expired()), b01(n.MachineAuthorized()),
		b01(n.UnsignedPeerAPIOnly()), b01(n.IsWireGuardOnly()))
}

// ipMode is how ts_netmap keeps a DERP node's IPv4 / IPv6 field (derphttp's shouldDialProto; a zone,
// which Go would dial, is "off" there - see ts_netmap.h).
func ipMode(s string, want4 bool) string {
	if s == "" {
		return "dns"
	}
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" {
		return "off"
	}
	if want4 && ip.Is4() {
		r := ip.As4()
		return fmt.Sprintf("%x", r[:])
	}
	if !want4 && ip.Is6() {
		r := ip.As16()
		return fmt.Sprintf("%x", r[:])
	}
	return "off"
}

func derpDump(b *strings.Builder, dm *tailcfg.DERPMap) {
	if dm == nil {
		b.WriteString("derp none\n")
		return
	}
	fmt.Fprintf(b, "derp omit=%d\n", b01(dm.OmitDefaultRegions))
	switch {
	case dm.HomeParams == nil:
		b.WriteString("home none\n")
	case dm.HomeParams.RegionScore == nil:
		b.WriteString("home scores=none\n")
	default:
		ids := make([]int, 0, len(dm.HomeParams.RegionScore))
		for id := range dm.HomeParams.RegionScore {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		fmt.Fprintf(b, "home scores=%d\n", len(ids))
		for _, id := range ids {
			fmt.Fprintf(b, "score %d %016x\n", id, math.Float64bits(dm.HomeParams.RegionScore[id]))
		}
	}
	for _, id := range dm.RegionIDs() {
		r := dm.Regions[id]
		fmt.Fprintf(b, "region %d id=%d code=%s name=%s avoid=%d nomeasure=%d nodes=%d\n", id, r.RegionID,
			esc(r.RegionCode), esc(r.RegionName), b01(r.Avoid), b01(r.NoMeasureNoHome), len(r.Nodes))
		for _, n := range r.Nodes {
			fmt.Fprintf(b, "node name=%s region=%d host=%s cert=%s v4=%s v6=%s stun=%d stunonly=%d port=%d insecure=%d port80=%d\n",
				esc(n.Name), n.RegionID, esc(n.HostName), esc(n.CertName), ipMode(n.IPv4, true), ipMode(n.IPv6, false),
				n.STUNPort, b01(n.STUNOnly), n.DERPPort, b01(n.InsecureForTests), b01(n.CanPort80))
		}
	}
}

func dump(nm *netmap.NetworkMap) string {
	var b strings.Builder
	if nm.SelfNode.Valid() {
		b.WriteString(nodeLine("self", nm.SelfNode))
	} else {
		b.WriteString("self none\n")
	}
	for _, p := range nm.Peers {
		b.WriteString(nodeLine("peer", p))
	}
	fmt.Fprintf(&b, "domain %s\n", esc(nm.Domain))
	derpDump(&b, nm.DERPMap)
	return b.String()
}

const emptyDump = "self none\ndomain \nderp none\n"

// --------------------------------------------------------------------- running sequences

type step struct {
	name     string
	restart  bool   // a new map session begins with this message
	json     []byte // the message as on the wire
	goOK     bool   // Go applies it (a KeepAlive counts as applied)
	cRefuses bool   // ts_netmap refuses it on purpose although Go takes it (see ts_netmap.h)
	dump     string // the netmap after it, as ts_netmap must have it
}

type updater struct{ ch chan *netmap.NetworkMap }

func (u *updater) UpdateFullNetmap(nm *netmap.NetworkMap) { u.ch <- nm }

type runner struct {
	sess        unsafe.Pointer
	u           *updater
	gotFirst    bool
	state       string
	restartNext bool
	mustRestart bool
	steps       []step
}

func newRunner() *runner {
	return &runner{u: &updater{ch: make(chan *netmap.NetworkMap, 1)}, state: emptyDump}
}

func (r *runner) restart() {
	if r.sess != nil {
		closeSession(r.sess)
	}
	r.sess = newMapSession(key.NewNode(), r.u, nil)
	r.gotFirst = false
	r.restartNext = true
	r.mustRestart = false
}

// send applies msg the way Direct.sendMapRequest does and records what the C side must see.
// After a refusal (by Go or, on purpose, by us) the session is over: the next send must restart.
func (r *runner) send(name string, msg []byte, cRefuses bool) {
	if r.mustRestart {
		panic(name + ": the session ended with the message before; restart first")
	}
	st := step{name: name, restart: r.restartNext, json: msg, cRefuses: cRefuses}
	r.restartNext = false
	var resp tailcfg.MapResponse
	err := json.Unmarshal(msg, &resp)
	switch {
	case err != nil:
		st.goOK = false
	case resp.KeepAlive:
		st.goOK = true
	case !r.gotFirst && resp.Node == nil:
		st.goOK = false // "initial MapResponse lacked node"
	default:
		st.goOK = true
		if cRefuses {
			break // Go's state moves on, ours does not: the sequence must restart now
		}
		must(handleNonKeepAlive(r.sess, context.Background(), &resp))
		select {
		case nm := <-r.u.ch:
			r.state = dump(nm)
		case <-time.After(5 * time.Second):
			panic(name + ": no netmap from mapSession")
		}
		r.gotFirst = true
	}
	if cRefuses && !st.goOK {
		panic(name + ": marked as refused by us only, but Go refuses it too")
	}
	if !st.goOK || cRefuses {
		r.mustRestart = true
	}
	st.dump = r.state
	r.steps = append(r.steps, st)
}

// --------------------------------------------------------------------- building messages

func raw32(seed byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed*7 + byte(i)*3 + 1
	}
	return b
}

func nk(seed byte) key.NodePublic    { return key.NodePublicFromRaw32(mem.B(raw32(seed))) }
func dk(seed byte) key.DiscoPublic   { return key.DiscoPublicFromRaw32(mem.B(raw32(seed + 100))) }
func mk(seed byte) key.MachinePublic { return key.MachinePublicFromRaw32(mem.B(raw32(seed + 200))) }
func ptr[T any](v T) *T              { return &v }
func at(d time.Duration) time.Time   { return t0.Add(d) }
func ats(d time.Duration) *time.Time { return ptr(t0.Add(d)) }
func hours(h float64) time.Duration  { return time.Duration(h * float64(time.Hour)) }
func mr(resp *tailcfg.MapResponse) []byte {
	b, err := json.Marshal(resp)
	must(err)
	return b
}

func pp(s ...string) []netip.Prefix {
	out := []netip.Prefix{}
	for _, x := range s {
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}

func own(n int) []netip.Prefix {
	return pp(fmt.Sprintf("100.64.0.%d/32", n), fmt.Sprintf("fd7a:115c:a1e0::%x/128", n))
}

func hostinfo(name, os string) tailcfg.HostinfoView {
	return (&tailcfg.Hostinfo{
		Hostname: name,
		OS:       os,
		Services: []tailcfg.Service{{Proto: tailcfg.PeerAPI4, Port: 41641}},
	}).View()
}

func fqdn(host string) string { return host + ".tail1234.ts.net." }

// node is a peer with every field a real one has; the tests then change what they need.
func node(id int, host string) *tailcfg.Node {
	return &tailcfg.Node{
		ID:                tailcfg.NodeID(id),
		StableID:          tailcfg.StableNodeID(fmt.Sprintf("n%dCNTRL", id)),
		Name:              fqdn(host),
		User:              10,
		Key:               nk(byte(id)),
		KeyExpiry:         at(hours(24 * 120)),
		Machine:           mk(byte(id)),
		DiscoKey:          dk(byte(id)),
		Addresses:         own(id),
		Endpoints:         []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:41641")},
		HomeDERP:          1,
		Hostinfo:          hostinfo(host, "linux"),
		Created:           at(-hours(24 * 30)),
		Cap:               130,
		Online:            ptr(true),
		MachineAuthorized: true,
		CapMap:            tailcfg.NodeCapMap{"https://tailscale.com/cap/file-sharing-target": nil},
	}
}

func selfNode() *tailcfg.Node {
	n := node(1, "phone")
	n.Hostinfo = hostinfo("phone", "blackberry")
	n.AllowedIPs = own(1) // the server sends ours explicitly
	n.HomeDERP = 2
	n.Online = nil
	n.CapMap = tailcfg.NodeCapMap{"https://tailscale.com/cap/is-admin": nil}
	return n
}

func derpMap1() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{
		HomeParams: &tailcfg.DERPHomeParams{RegionScore: map[int]float64{1: 1.5, 4: 0.8}},
		Regions: map[int]*tailcfg.DERPRegion{
			1: {RegionID: 1, RegionCode: "nyc", RegionName: "New York City", Latitude: 40.7, Longitude: -74,
				Nodes: []*tailcfg.DERPNode{
					{Name: "1a", RegionID: 1, HostName: "derp1.tailscale.com", IPv4: "199.38.181.104", IPv6: "2607:f740:f::bc"},
					{Name: "1b", RegionID: 1, HostName: "derp1b.tailscale.com", IPv4: "none", IPv6: "2607:f740:f::bd", CanPort80: true},
				}},
			2: {RegionID: 2, RegionCode: "sfo", RegionName: "San Francisco",
				Nodes: []*tailcfg.DERPNode{{Name: "2a", RegionID: 2, HostName: "derp2.tailscale.com", IPv4: "192.73.252.65", IPv6: "2607:f740:0:3f::287"}}},
			3: {RegionID: 3, RegionCode: "sin", RegionName: "Singapore", NoMeasureNoHome: true,
				Nodes: []*tailcfg.DERPNode{{Name: "3a", RegionID: 3, HostName: "derp3.tailscale.com"}}},
			4: {RegionID: 4, RegionCode: "fra", RegionName: "Frankfurt",
				Nodes: []*tailcfg.DERPNode{
					{Name: "4s", RegionID: 4, HostName: "derp4s.tailscale.com", STUNOnly: true, STUNPort: 3478},
					{Name: "4a", RegionID: 4, HostName: "derp4.tailscale.com", IPv4: "185.40.234.219", IPv6: "none",
						DERPPort: 8443, CertName: "sha256-raw:" + strings.Repeat("0f", 32), InsecureForTests: true},
				}},
			900: {RegionID: 900, RegionCode: "home", RegionName: "Home stand <&> Zürich", Avoid: true,
				Nodes: []*tailcfg.DERPNode{{Name: "900a", RegionID: 900, HostName: "192.168.1.5", IPv4: "192.168.1.5",
					STUNPort: -1, DERPPort: 3340}}},
			5: nil, // Headscale has been seen sending these
		},
	}
}

// full1 is a first netmap with every kind of node the model has to tell apart.
func full1() *tailcfg.MapResponse {
	nas := node(2, "nas")
	nas.KeyExpiry = time.Time{} // tagged: never expires
	nas.Tags = []string{"tag:nas"}
	nas.HomeDERP = 4

	laptop := node(3, "laptop")
	laptop.HomeDERP = 0
	laptop.LegacyDERPString = "127.3.3.40:2" // an old server
	laptop.Online = ptr(false)
	laptop.LastSeen = ats(-hours(1))

	router := node(5, "router")
	router.AllowedIPs = append(own(5), pp("192.168.1.0/24", "0.0.0.0/0", "::/0")...)
	router.PrimaryRoutes = pp("192.168.1.0/24")
	router.HomeDERP = 900

	old := node(7, "old")
	old.Expired = true
	old.KeyExpiry = at(-hours(24 * 10))
	old.Online = ptr(false)

	empty := node(9, "empty")
	empty.AllowedIPs = []netip.Prefix{} // explicitly none: not the same as absent

	unsigned := node(11, "unsigned")
	unsigned.UnsignedPeerAPIOnly = true
	unsigned.AllowedIPs = append(own(11), pp("10.0.0.0/8")...)

	wg := node(12, "wg")
	wg.IsWireGuardOnly = true
	wg.DiscoKey = key.DiscoPublic{}
	wg.HomeDERP = 0
	wg.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.9:51820")}

	both := node(13, "both")
	both.HomeDERP = 3
	both.LegacyDERPString = "127.3.3.40:9" // HomeDERP wins
	both.Online = ptr(false)
	both.LastSeen = ats(-hours(1))

	bracket := node(14, "bracket")
	bracket.HomeDERP = 0
	bracket.LegacyDERPString = "[127.3.3.40]:5"

	plus := node(15, "plus")
	plus.HomeDERP = 0
	plus.LegacyDERPString = "127.3.3.40:+7"

	badLegacy := node(16, "badlegacy")
	badLegacy.HomeDERP = 0
	badLegacy.LegacyDERPString = "127.3.3.41:5"

	negLegacy := node(17, "neglegacy")
	negLegacy.HomeDERP = 0
	negLegacy.LegacyDERPString = "127.3.3.40:-3"

	odd := node(18, "x<y>&z")
	odd.Name = "кот-x<y>&z.tail1234.ts.net." // UTF-8, and < > & - which Go's encoder writes as escapes

	seenOnly := node(20, "seenonly")
	seenOnly.Online = nil
	seenOnly.LastSeen = ats(-hours(2))

	return &tailcfg.MapResponse{
		Node:    selfNode(),
		DERPMap: derpMap1(),
		Peers:   []*tailcfg.Node{nas, laptop, router, old, empty, unsigned, wg, both, bracket, plus, badLegacy, negLegacy, odd, seenOnly},
		Domain:  "misha@example.com",
		// below: what this client does not read, in the message as a real server sends it
		DNSConfig:       &tailcfg.DNSConfig{Domains: []string{"tail1234.ts.net"}, Proxied: true},
		PacketFilter:    []tailcfg.FilterRule{{SrcIPs: []string{"*"}, DstPorts: []tailcfg.NetPortRange{{IP: "*", Ports: tailcfg.PortRangeAny}}}},
		UserProfiles:    []tailcfg.UserProfile{{ID: 10, LoginName: "misha@example.com", DisplayName: "Misha"}},
		ControlTime:     ptr(t0),
		CollectServices: "true",
		Health:          []string{},
		SSHPolicy:       &tailcfg.SSHPolicy{},
		ClientVersion:   &tailcfg.ClientVersion{RunningLatest: true},
	}
}

func delta1() *tailcfg.MapResponse {
	nas := full1().Peers[0]
	nas.Online = ptr(false)         // known before: becomes a patch
	nas.LastSeen = ats(hours(0.04)) // none before: patchifyPeer does not carry it

	router := full1().Peers[2]
	router.AllowedIPs = append(own(5), pp("192.168.1.0/24")...) // not a patch field: replaced whole

	fresh := node(21, "fresh")
	fresh.HomeDERP = 2

	return &tailcfg.MapResponse{
		PeersChanged: []*tailcfg.Node{nas, router, fresh},
		PeersRemoved: []tailcfg.NodeID{3, 99},
	}
}

func delta2() *tailcfg.MapResponse {
	return &tailcfg.MapResponse{
		PeersChangedPatch: []*tailcfg.PeerChange{
			{NodeID: 2, DERPRegion: 1},
			{NodeID: 5, Key: ptr(nk(55))},
			{NodeID: 42, Online: ptr(true)}, // not a node we hold
			// disco key, offline, a LastSeen older than the one held: dropped whole, KeyExpiry too
			{NodeID: 13, DiscoKey: ptr(dk(77)), Online: ptr(false), LastSeen: ats(-hours(5)), KeyExpiry: ats(hours(24 * 99))},
			// the same with a newer LastSeen: taken (judged against the node as the message found it)
			{NodeID: 13, DiscoKey: ptr(dk(78)), Online: ptr(false), LastSeen: ats(-hours(0.5))},
			{NodeID: 20, LastSeen: ats(hours(0.05)), KeyExpiry: ats(hours(24))},
		},
		OnlineChange:   map[tailcfg.NodeID]bool{2: true, 20: true, 77: false},
		PeerSeenChange: map[tailcfg.NodeID]bool{14: true, 20: false},
	}
}

func self2() *tailcfg.Node {
	n := selfNode()
	n.Addresses = pp("100.64.0.101/32", "fd7a:115c:a1e0::65/128")
	n.AllowedIPs = nil // nil: its Addresses
	n.KeyExpiry = at(hours(24 * 200))
	n.LegacyDERPString = "127.3.3.40:4"
	n.HomeDERP = 0
	return n
}

// full2 is a second full list in the same session: unlisted nodes go, node 13 may not move to an
// older disco key, 21 may (it is online).
func full2() *tailcfg.MapResponse {
	nas := full1().Peers[0]
	nas.DiscoKey = dk(92)

	both := full1().Peers[7]
	both.DiscoKey = dk(79)
	both.LastSeen = ats(-hours(2))

	fresh := node(21, "fresh")
	fresh.HomeDERP = 2
	fresh.DiscoKey = dk(93)
	fresh.Online = ptr(true)

	newer := node(30, "newer")
	return &tailcfg.MapResponse{Peers: []*tailcfg.Node{nas, both, fresh, newer}}
}

// base is a small first netmap for the edge cases.
func base() *tailcfg.MapResponse {
	p2 := node(2, "two")
	p3 := node(3, "three")
	p3.Online = nil
	p3.LastSeen = ats(-hours(1))
	p4 := node(4, "four")
	p4.Online = ptr(false)
	p4.LastSeen = ats(-hours(2))
	p4.HomeDERP = 2
	p5 := node(5, "five")
	p5.LastSeen = ats(-hours(1))
	return &tailcfg.MapResponse{
		Node:   selfNode(),
		Peers:  []*tailcfg.Node{p2, p3, p4, p5},
		Domain: "base.example",
		DERPMap: &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
			1: {RegionID: 1, RegionCode: "a", RegionName: "A", Nodes: []*tailcfg.DERPNode{{Name: "1a", RegionID: 1, HostName: "a.example"}}},
			2: {RegionID: 2, RegionCode: "b", RegionName: "B", Nodes: []*tailcfg.DERPNode{{Name: "2a", RegionID: 2, HostName: "b.example"}}},
		}},
	}
}

func basePeer(id int) *tailcfg.Node {
	for _, p := range base().Peers {
		if int(p.ID) == id {
			return p
		}
	}
	panic("no base peer")
}

// rawJSON joins hand-written JSON: for messages tailcfg cannot write (an empty Peers, a key twice,
// values only a broken server sends...).
func rawJSON(parts ...string) []byte { return []byte(strings.Join(parts, "")) }

// ju is the JSON escape of r: backslash, u, four hex digits. The backslash is written \x5c here
// on purpose - an editor (or a tool) that turns escapes in the source into characters would
// otherwise quietly make these vectors test raw UTF-8 instead of escapes.
func ju(r rune) string { return fmt.Sprintf("\x5cu%04x", r) }

func nodeJSON(n *tailcfg.Node) string {
	b, err := json.Marshal(n)
	must(err)
	return string(b)
}

// --------------------------------------------------------------------- the sequences

func sequences(r *runner) {
	// 1. A tailnet over time: the first netmap, a KeepAlive, deltas, DERP map updates, our node,
	// a second full list, an emptied region set.
	r.restart()
	r.send("full", mr(full1()), false)
	r.send("keepalive", mr(&tailcfg.MapResponse{KeepAlive: true, ControlTime: ats(hours(1.0 / 60))}), false)
	r.send("changed", mr(delta1()), false)
	r.send("patches", mr(delta2()), false)
	r.send("derp-home-only", mr(&tailcfg.MapResponse{DERPMap: &tailcfg.DERPMap{
		HomeParams: &tailcfg.DERPHomeParams{RegionScore: map[int]float64{2: 2.5}}}}), false)
	r.send("derp-home-noscore", mr(&tailcfg.MapResponse{DERPMap: &tailcfg.DERPMap{HomeParams: &tailcfg.DERPHomeParams{}}}), false)
	r.send("self", mr(&tailcfg.MapResponse{Node: self2(), Domain: ""}), false)
	r.send("full-again", mr(full2()), false)
	r.send("derp-regions-empty", rawJSON(`{"DERPMap":{"Regions":{},"omitDefaultRegions":true}}`), false)
	r.send("domain", mr(&tailcfg.MapResponse{Domain: "other.example"}), false)

	// 2. A new session: its first message must carry Node, then it replaces everything.
	r.restart()
	r.send("first-without-node", mr(&tailcfg.MapResponse{Peers: []*tailcfg.Node{node(2, "two")}}), false)
	r.restart()
	r.send("first-keepalive", mr(&tailcfg.MapResponse{KeepAlive: true}), false)
	r.send("base", mr(base()), false)

	// 3. patchifyPeer and removeUnwantedDiscoUpdates at their edges.
	{
		p2 := basePeer(2)
		p2.HomeDERP = 0 // a patch does not carry 0: kept
		p2.Online = nil // nor unknown
		r.send("patchify-keeps", mr(&tailcfg.MapResponse{PeersChanged: []*tailcfg.Node{p2}}), false)

		p3 := basePeer(3)
		p3.Online = ptr(true) // unknown before: patchifyPeer leaves it out
		r.send("patchify-online-unknown", mr(&tailcfg.MapResponse{PeersChanged: []*tailcfg.Node{p3}}), false)

		p2 = basePeer(2)
		p2.Name = fqdn("two-renamed")
		p2.HomeDERP = 0
		p2.Online = nil
		r.send("upsert-whole", mr(&tailcfg.MapResponse{PeersChanged: []*tailcfg.Node{p2}}), false)

		p5 := basePeer(5)
		p5.DiscoKey = dk(55)
		p5.Online = ptr(false)
		p5.LastSeen = ats(-hours(2)) // older: the patch made of it is dropped
		r.send("disco-stale", mr(&tailcfg.MapResponse{PeersChanged: []*tailcfg.Node{p5}}), false)

		p4 := basePeer(4)
		p4.Name = fqdn("four-again")
		p5 = basePeer(5)
		p5.Online = ptr(false) // a patch: applied to a node that is gone - stays gone
		r.send("remove-and-change", mr(&tailcfg.MapResponse{
			PeersRemoved: []tailcfg.NodeID{4, 5},
			PeersChanged: []*tailcfg.Node{p4, p5},
		}), false)

		p6 := node(6, "six")
		p6.Online = nil
		r.send("new-and-patch", mr(&tailcfg.MapResponse{
			PeersChanged:      []*tailcfg.Node{p6},
			PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 6, DERPRegion: 2}},
			OnlineChange:      map[tailcfg.NodeID]bool{6: true},
		}), false)

		// removed and added back in one message: a patch is judged against the node as it was
		// before (dropped - its LastSeen is older); a node new in the message has nothing to be
		// judged against (taken)
		p3 = basePeer(3)
		p3.Name = fqdn("three-again")
		r.send("remove-readd-patch", mr(&tailcfg.MapResponse{
			PeersRemoved: []tailcfg.NodeID{3},
			PeersChanged: []*tailcfg.Node{p3, node(9, "nine")},
			PeersChangedPatch: []*tailcfg.PeerChange{
				{NodeID: 3, DiscoKey: ptr(dk(33)), Online: ptr(false), LastSeen: ats(-hours(3))},
				{NodeID: 9, DiscoKey: ptr(dk(99)), Online: ptr(false), LastSeen: ats(-hours(3))},
			},
		}), false)

		v1 := node(10, "ten-first")
		v2 := node(10, "ten-second")
		v2.HomeDERP = 2
		r.send("changed-new-twice", mr(&tailcfg.MapResponse{PeersChanged: []*tailcfg.Node{v1, v2}}), false)

		// PeerSeenChange moves 4's LastSeen to now first; the patch is still judged against the
		// LastSeen it had before the message (older than the patch's): taken
		r.send("patch-after-seen", mr(&tailcfg.MapResponse{
			PeerSeenChange:    map[tailcfg.NodeID]bool{4: true},
			PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 4, DiscoKey: ptr(dk(44)), Online: ptr(false), LastSeen: ats(-hours(1))}},
		}), false)

		p7 := node(7, "seven")
		r.send("peers-empty-array", rawJSON(`{"Peers":[],"PeersChanged":[`, nodeJSON(p7), `]}`), false)
		r.send("keepalive-with-peers", rawJSON(`{"KeepAlive":true,"Peers":[`, nodeJSON(node(8, "eight")), `]}`), false)
		r.send("removed-null", rawJSON(`{"PeersRemoved":[null,7]}`), false)
		r.send("seen-now", mr(&tailcfg.MapResponse{PeerSeenChange: map[tailcfg.NodeID]bool{2: true, 3: true}}), false)
	}

	// 4. How Go reads JSON, where a field we use depends on it.
	baseJSON := string(mr(base()))
	fold := baseJSON
	for _, rp := range [][2]string{
		{`"Node":`, `"nODE":`},
		{`"Peers":`, `"peer` + ju(0x17f) + `":`},  // long s, escaped: its fold set holds S
		{`"KeyExpiry":`, "\"KeyExpiry\":"},        // Kelvin sign as raw UTF-8: K
		{`"Domain":`, `"` + ju(0x44) + `OMAIN":`}, // an escaped D
		{`"DERPMap":`, `"derpmap":`},
		{`"HostName":`, `"hostnam` + ju(0x65) + `":`},
	} {
		fold = strings.ReplaceAll(fold, rp[0], rp[1])
	}
	r.restart()
	r.send("fold", []byte(fold), false)
	// I with a dot folds onto nothing else: no node has an ID, all are node 0, the last one wins
	r.restart()
	r.send("no-fold", []byte(strings.ReplaceAll(baseJSON, `"ID":`, `"`+ju(0x130)+`D":`)), false)

	r.restart()
	r.send("dup-domain", rawJSON(`{"Node":`, nodeJSON(selfNode()), `,"Domain":"a","Domain":"b"}`), true)
	r.restart()
	r.send("dup-field-folded", rawJSON(`{"Node":`, nodeJSON(selfNode()), `,"Peers":[{"ID":2,"Name":"x.","name":"y.","Key":"`,
		keyText(nk(2)), `"}]}`), true)
	r.restart()
	r.send("one-digit-hour", rawJSON(`{"Node":`, strings.Replace(nodeJSON(selfNode()), `"KeyExpiry":"`, `"KeyExpiry":"2027-01-02T3:04:05Z","x":"`, 1), `}`), true)

	for _, c := range []struct {
		name, peer string
	}{
		{"int-fraction", `{"ID":2.0}`},
		{"int-exponent", `{"ID":2e0}`},
		{"int-overflow", `{"ID":9223372036854775808}`},
		{"int-as-string", `{"ID":2,"HomeDERP":"5"}`},
		{"bool-as-number", `{"ID":2,"Online":1}`},
		{"prefix-leading-zero", `{"ID":2,"Addresses":["100.064.0.2/32"]}`},
		{"prefix-bits-zero", `{"ID":2,"Addresses":["100.64.0.2/032"]}`},
		{"prefix-zone", `{"ID":2,"Addresses":["fd7a:115c:a1e0::2%eth0/128"]}`},
		{"prefix-no-bits", `{"ID":2,"Addresses":["100.64.0.2"]}`},
		{"key-short", `{"ID":2,"Key":"nodekey:` + strings.Repeat("a", 63) + `"}`},
		{"key-prefix-case", `{"ID":2,"Key":"NODEKEY:` + strings.Repeat("a", 64) + `"}`},
		{"time-lowercase-z", `{"ID":2,"KeyExpiry":"2027-01-02T03:04:05z"}`},
		{"time-escaped", `{"ID":2,"KeyExpiry":"2027-01-02T03:04:05` + ju(0x5a) + `"}`}, // Go does not undo escapes in times
		{"addresses-not-array", `{"ID":2,"Addresses":"100.64.0.2/32"}`},
	} {
		r.restart()
		r.send(c.name, rawJSON(`{"Node":`, nodeJSON(selfNode()), `,"Peers":[`, c.peer, `]}`), false)
	}

	r.restart()
	r.send("values-go-takes", rawJSON(`{"Node":`, nodeJSON(selfNode()), `,"Peers":[`,
		`{"ID":-0,"Name":"neg-zero.","Key":"nodekey:`, strings.ToUpper(strings.TrimPrefix(keyText(nk(2)), "nodekey:")), `"},`,
		`{"ID":3,"Name":"`, ju(0xd800), `x`, ju(0xd83d), ju(0xde00), ju(0x3c), ju(0x26), ju(0x2028),
		`.","Addresses":["::ffff:100.64.0.9/128","",null],"AllowedIPs":null,`,
		`"KeyExpiry":"0000-01-01T00:00:00Z","LastSeen":"2026-09-30T15:04:05.1234567891+03:00","Online":null,"Key":"`, keyText(nk(3)), `"},`,
		`{"ID":4,"Name":"raw-`, "\xff\xfe", `-bytes.","AllowedIPs":[],"Addresses":["100.64.0.4/32"],"HomeDERP":null,"DERP":"127.3.3.40:007"}`,
		`],"Domain":null,"DERPMap":{"Regions":{"+4":{"RegionID":4,"RegionCode":"x","Nodes":[]},"04":{"RegionID":4,"RegionCode":"y","Nodes":null},`,
		`"7":{"RegionID":7,"Nodes":[{"Name":"7a","HostName":"h","IPv4":"::ffff:1.2.3.4","IPv6":"::ffff:1.2.3.4"}]},"8":{"RegionID":8},"8":null},`,
		`"HomeParams":{"RegionScore":{"4":null,"+7":1e-3,"7":0.125}}}}`), false)
	r.send("map-keys", rawJSON(`{"OnlineChange":{"+3":false,"03":true,"-0":true},"PeerSeenChange":{"4":null}}`), false)

	r.restart()
	r.send("region-key-bad", rawJSON(`{"Node":`, nodeJSON(selfNode()), `,"DERPMap":{"Regions":{"x":{"RegionID":1}}}}`), false)
	r.restart()
	// Go takes it - and its DERP client would crash on the nil node later
	r.send("region-node-null", rawJSON(`{"Node":`, nodeJSON(selfNode()), `,"DERPMap":{"Regions":{"1":{"RegionID":1,"Nodes":[null]}}}}`), true)
	r.restart()
	r.send("first-derp-no-regions", rawJSON(`{"Node":`, nodeJSON(selfNode()), `,"DERPMap":{"HomeParams":{},"omitDefaultRegions":true}}`), false)
}

func keyText(k key.NodePublic) string {
	b, err := k.MarshalText()
	must(err)
	return string(b)
}

// --------------------------------------------------------------------- /key and register

type answer struct {
	name string
	json []byte
	want string // what ts_server_keys_parse / ts_register_parse must give; "refused" for a refusal
}

func keyAnswers() []answer {
	var out []answer
	add := func(name string, b []byte, want string) { out = append(out, answer{name, b, want}) }
	mkText := func(k key.MachinePublic) string { return fmt.Sprintf("%x", k.UntypedBytes()) }

	ok := tailcfg.OverTLSPublicKeyResponse{PublicKey: mk(9)}
	b, err := json.Marshal(ok)
	must(err)
	add("key", b, "public="+mkText(mk(9))+" legacy="+mkText(key.MachinePublic{}))

	both := tailcfg.OverTLSPublicKeyResponse{PublicKey: mk(9), LegacyPublicKey: mk(8)}
	b, err = json.Marshal(both)
	must(err)
	add("key-legacy", b, "public="+mkText(mk(9))+" legacy="+mkText(mk(8)))

	b, err = json.Marshal(tailcfg.OverTLSPublicKeyResponse{})
	must(err)
	add("key-zero", b, "refused") // "control server is too old; no noise key"
	add("key-bad", []byte(`{"publicKey":"mkey:`+strings.Repeat("z", 64)+`"}`), "refused")
	return out
}

func regText(r tailcfg.RegisterResponse) string {
	return fmt.Sprintf("error=%s expired=%d authorized=%d url=%s nks=%d user=%d login=%s display=%s",
		esc(r.Error), b01(r.NodeKeyExpired), b01(r.MachineAuthorized), esc(r.AuthURL), b01(len(r.NodeKeySignature) > 0),
		r.User.ID, esc(r.Login.LoginName), esc(r.Login.DisplayName))
}

func registerAnswers() []answer {
	var out []answer
	add := func(name string, r tailcfg.RegisterResponse) {
		b, err := json.Marshal(r)
		must(err)
		var back tailcfg.RegisterResponse
		must(json.Unmarshal(b, &back))
		out = append(out, answer{name, b, regText(back)})
	}
	add("register-ok", tailcfg.RegisterResponse{
		User:              tailcfg.User{ID: 10, DisplayName: "Misha", ProfilePicURL: "https://example.com/p.png", Created: t0},
		Login:             tailcfg.Login{ID: 20, Provider: "github", LoginName: "misha@example.com", DisplayName: "Миша <&>"},
		MachineAuthorized: true,
	})
	add("register-authurl", tailcfg.RegisterResponse{AuthURL: "https://login.tailscale.com/a/1a2b3c4d5e6f"})
	add("register-approval", tailcfg.RegisterResponse{User: tailcfg.User{ID: 10}})
	add("register-expired", tailcfg.RegisterResponse{NodeKeyExpired: true})
	add("register-error", tailcfg.RegisterResponse{Error: "invalid key: unable to validate API key"})
	add("register-nks", tailcfg.RegisterResponse{NodeKeySignature: []byte{1, 2, 3}, MachineAuthorized: true})
	return out
}

// --------------------------------------------------------------------- output

// cBytes is b as C string literals of at most 96 bytes, one per line: printable ASCII as is, the
// rest as 3-digit octal escapes ('?' too, against trigraphs).
func cBytes(b []byte, indent string) string {
	if len(b) == 0 {
		return `""`
	}
	var lines []string
	for len(b) > 0 {
		n := min(96, len(b))
		var s strings.Builder
		s.WriteByte('"')
		for _, c := range b[:n] {
			if c >= 0x20 && c < 0x7f && c != '"' && c != '\\' && c != '?' {
				s.WriteByte(c)
			} else {
				fmt.Fprintf(&s, "\\%03o", c)
			}
		}
		s.WriteByte('"')
		lines = append(lines, s.String())
		b = b[n:]
	}
	return strings.Join(lines, "\n"+indent)
}

// foldRune is encoding/json's (fold.go): the least rune of r's unicode.SimpleFold orbit.
func foldRune(r rune) rune {
	for {
		r2 := unicode.SimpleFold(r)
		if r2 <= r {
			return r2
		}
		r = r2
	}
}

// foldOntoASCII lists the runes beyond ASCII that Go's folding of JSON names maps onto an ASCII
// letter - ts_json's fold_rune has exactly these.
func foldOntoASCII() []rune {
	var out []rune
	for r := rune(0x80); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		if f := foldRune(r); f < 0x80 {
			out = append(out, r)
		}
	}
	return out
}

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	ccClock = tstest.NewClock(tstest.ClockOpts{Start: now})

	r := newRunner()
	sequences(r)
	closeSession(r.sess)
	keys := keyAnswers()
	regs := registerAnswers()

	var h bytes.Buffer
	h.WriteString("/*\n * Generated by daemon/test/vectors/netmap (tsnetmap, Go) from Tailscale v1.102.5: the messages as\n")
	h.WriteString(" * tailcfg marshals them (or written by hand), the netmap after each as control/controlclient's\n")
	h.WriteString(" * mapSession has it, in test_ts_netmap.c's dump format. Do not edit.\n")
	fmt.Fprintf(&h, " *\n * Runes beyond ASCII that Go's JSON name folding maps onto ASCII:")
	for _, x := range foldOntoASCII() {
		fmt.Fprintf(&h, " U+%04X", x)
	}
	h.WriteString("\n */\n\n")
	fmt.Fprintf(&h, "#define NM_VEC_NOW_SEC  %dLL       /* `now` for every message: PeerSeenChange stamps it */\n\n", now.Unix())
	h.WriteString("typedef struct {\n    const char* name;\n    int         restart;        /* a new map session begins with it */\n")
	h.WriteString("    int         go_ok;          /* Go applies it */\n    int         c_refuses;      /* we refuse it on purpose (ts_netmap.h) */\n")
	h.WriteString("    const char* json;\n    size_t      len;\n    const char* dump;           /* the netmap after it */\n} nm_vec_step;\n\n")
	h.WriteString("static const nm_vec_step nm_vec_steps[] = {\n")
	for _, s := range r.steps {
		fmt.Fprintf(&h, "    { %q, %d, %d, %d,\n      %s,\n      %d,\n      %s },\n", s.name, b01(s.restart), b01(s.goOK), b01(s.cRefuses),
			cBytes(s.json, "      "), len(s.json), cBytes([]byte(s.dump), "      "))
	}
	h.WriteString("};\n\n")
	h.WriteString("typedef struct {\n    const char* name;\n    const char* json;\n    size_t      len;\n    const char* want;\n} nm_vec_answer;\n\n")
	for _, set := range []struct {
		name string
		list []answer
	}{{"nm_vec_keys", keys}, {"nm_vec_register", regs}} {
		fmt.Fprintf(&h, "static const nm_vec_answer %s[] = {\n", set.name)
		for _, a := range set.list {
			fmt.Fprintf(&h, "    { %q,\n      %s,\n      %d,\n      %s },\n", a.name, cBytes(a.json, "      "), len(a.json), cBytes([]byte(a.want), "      "))
		}
		h.WriteString("};\n\n")
	}
	must(os.WriteFile(filepath.Join(dir, "kat_netmap.h"), h.Bytes(), 0o644))

	// The wire, to read: some messages as they are, one line each.
	examples := map[string][]byte{}
	for _, s := range r.steps {
		switch s.name {
		case "full", "keepalive", "changed", "patches", "derp-home-only", "full-again":
			examples["example_map_"+strings.ReplaceAll(s.name, "-", "_")+".json"] = s.json
		}
	}
	for _, a := range append(keys[:1], regs...) {
		examples["example_"+strings.ReplaceAll(a.name, "-", "_")+".json"] = a.json
	}
	for name, b := range examples {
		must(os.WriteFile(filepath.Join(dir, name), append(append([]byte{}, b...), '\n'), 0o644))
	}
	fmt.Printf("%d steps, %d /key answers, %d register answers\n", len(r.steps), len(keys), len(regs))
}
