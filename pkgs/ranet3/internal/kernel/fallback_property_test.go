// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// switchPacket is one packet at postrouting as the chain reads it
type switchPacket struct {
	// oif is the device of the route the packet leaves by, and iif the one it
	// arrived on, empty for the host's own
	oif, iif    string
	mark        uint32
	destination netip.Addr
	// tracked is a packet conntrack holds an entry for, reply one of the
	// entry's reply direction, protocol the entry's transport protocol and
	// port the destination port of its original direction
	tracked, reply bool
	protocol       uint8
	port           uint16
}

func (p switchPacket) String() string {
	ct := "untracked"
	if p.tracked {
		ct = fmt.Sprintf("tracked reply %v protocol %d original port %d", p.reply, p.protocol, p.port)
	}
	return fmt.Sprintf("oif %q iif %q mark %#x to %s %s", p.oif, p.iif, p.mark, p.destination, ct)
}

// switchConfig is one drawn host: its links outside the mesh with their
// connected networks, the links forward expands to and its own prefixes the
// mesh's table throws, inbound's services as the pass hands them to the
// table, and inbound's entries as written
type switchConfig struct {
	view     exitView
	services []Service
	entries  []Service
}

// switchModel is the chain item 4's table writes, as a function of what the
// chain reads, written from the table's lines rather than from the encoder:
// the tun and lo, the underlay's mark, a packet forwarded from a link forward
// leaves out, the LAN, link-local, multicast and the limited broadcast, this
// node's own prefixes, and a reply of a flow the far side opened to a listed
// service pass, and everything else is dropped. The LAN is each connected
// network of a link outside the mesh that overlaps no overlay prefix and does
// not count as capturing the machine.
func switchModel(c switchConfig, p switchPacket) bool {
	switch {
	case p.oif == loopback || p.oif == switchTun:
		return true
	case p.mark == schema.UnderlayMark:
		return true
	case p.iif != "" && !slices.Contains(c.view.forwarded, p.iif):
		return true
	}
	for _, links := range [][]Link{c.view.network.IPv4.Links, c.view.network.IPv6.Links} {
		for _, link := range links {
			for _, prefix := range link.Prefixes {
				network := prefix.Masked()
				overlaps := slices.ContainsFunc(exitPassOverlay, func(o schema.Prefix) bool { return o.Overlaps(network) })
				if !overlaps && !schema.CapturesTheMachine(network, exitPassOverlay) && network.Contains(p.destination) {
					return true
				}
			}
		}
	}
	if slices.ContainsFunc(switchLocal, func(local netip.Prefix) bool { return local.Contains(p.destination) }) {
		return true
	}
	if slices.ContainsFunc(c.view.own, func(prefix netip.Prefix) bool { return prefix.Contains(p.destination) }) {
		return true
	}
	if !p.tracked || !p.reply {
		return false
	}
	return slices.ContainsFunc(c.entries, func(s Service) bool {
		protocol := map[string]uint8{"tcp": unix.IPPROTO_TCP, "udp": unix.IPPROTO_UDP}[s.Protocol]
		return protocol == p.protocol && s.First <= p.port && p.port <= s.Last
	})
}

// switchLocal is link-local, multicast and the limited broadcast, which the
// chain passes by any link
var switchLocal = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

// switchTun is the drawn host's tun
const switchTun = "ranet3"

// switchSets is every set a rule of s reads, by the ID its lookup names it by
func switchSets(t testing.TB, s fallbackSets, rules []fallbackRule) map[uint32]struct {
	set      nftables.Set
	elements []nftables.Interval
} {
	t.Helper()
	out := map[uint32]struct {
		set      nftables.Set
		elements []nftables.Interval
	}{}
	elements := s.elements()
	for _, set := range fallbackNamed {
		out[set.ID] = struct {
			set      nftables.Set
			elements []nftables.Interval
		}{set, elements[set.Name]}
	}
	for _, rule := range rules {
		if rule.anonymous == nil {
			continue
		}
		if _, taken := out[rule.anonymous.ID]; taken {
			t.Fatalf("two sets carry the ID %d", rule.anonymous.ID)
		}
		out[rule.anonymous.ID] = struct {
			set      nftables.Set
			elements []nftables.Interval
		}{*rule.anonymous, rule.members}
	}
	return out
}

// header is the packet's network header as far as the chain reads it, its
// destination at the offset the family puts it
func (p switchPacket) header() []byte {
	if p.destination.Is4() {
		header := make([]byte, 20)
		header[0] = 0x45
		copy(header[16:], p.destination.AsSlice())
		return header
	}
	header := make([]byte, 40)
	header[0] = 0x60
	copy(header[24:], p.destination.AsSlice())
	return header
}

// switchIndex is the index of the device a forwarded packet arrived on, any
// device's alike to a rule comparing it with zero
const switchIndex = 7

// evaluate runs the chain's encoded rules in order over p as nf_tables does:
// the first rule to reach a verdict decides, a load or a comparison that fails
// ends a rule undecided, and a packet no rule decides meets the accept
// policy. It fails the test on any expression or attribute it does not model.
func evaluate(t testing.TB, rules []fallbackRule, sets map[uint32]struct {
	set      nftables.Set
	elements []nftables.Interval
}, p switchPacket) bool {
	t.Helper()
	for _, rule := range rules {
		if code, decided := evaluateRule(t, rule.expressions, sets, p); decided {
			return code == nftables.Accept
		}
	}
	return true
}

func evaluateRule(t testing.TB, expressions [][]byte, sets map[uint32]struct {
	set      nftables.Set
	elements []nftables.Interval
}, p switchPacket) (uint32, bool) {
	t.Helper()
	var register []byte
	for _, expression := range expressions {
		elements := nftables.Nested(expression)
		if len(elements) != 1 || elements[0].Kind != unix.NFTA_LIST_ELEM {
			t.Fatalf("an expression is no list element: %x", expression)
		}
		var name string
		fields := map[uint16][]byte{}
		for _, field := range nftables.Nested(elements[0].Value) {
			switch field.Kind {
			case unix.NFTA_EXPR_NAME:
				name = unix.ByteSliceToString(field.Value)
			case unix.NFTA_EXPR_DATA:
				for _, inner := range nftables.Nested(field.Value) {
					fields[inner.Kind] = inner.Value
				}
			}
		}
		for field := range fields {
			if !slices.Contains(switchModeled[name], field) {
				t.Fatalf("a %q expression carries attribute %d, which the evaluator does not model", name, field)
			}
		}
		switch name {
		case "meta":
			switchRegister(t, name, fields[unix.NFTA_META_DREG])
			switch key := switchBE32(t, fields[unix.NFTA_META_KEY]); key {
			case unix.NFT_META_OIFNAME:
				register = nftables.InterfaceName(p.oif)
			case unix.NFT_META_IIFNAME:
				register = nftables.InterfaceName(p.iif)
			case unix.NFT_META_IIF:
				var index uint32
				if p.iif != "" {
					index = switchIndex
				}
				register = binary.NativeEndian.AppendUint32(nil, index)
			case unix.NFT_META_MARK:
				register = binary.NativeEndian.AppendUint32(nil, p.mark)
			case unix.NFT_META_NFPROTO:
				register = []byte{map[bool]uint8{true: unix.NFPROTO_IPV4, false: unix.NFPROTO_IPV6}[p.destination.Is4()]}
			default:
				t.Fatalf("meta loads key %d, which the evaluator does not model", key)
			}
		case "payload":
			switchRegister(t, name, fields[unix.NFTA_PAYLOAD_DREG])
			if base := switchBE32(t, fields[unix.NFTA_PAYLOAD_BASE]); base != unix.NFT_PAYLOAD_NETWORK_HEADER {
				t.Fatalf("payload loads from base %d, not the network header", base)
			}
			header := p.header()
			offset, length := int(switchBE32(t, fields[unix.NFTA_PAYLOAD_OFFSET])), int(switchBE32(t, fields[unix.NFTA_PAYLOAD_LEN]))
			if offset+length > len(header) {
				return 0, false
			}
			register = slices.Clone(header[offset : offset+length])
		case "ct":
			switchRegister(t, name, fields[unix.NFTA_CT_DREG])
			// a packet with no entry ends the rule at every key the chain reads
			if !p.tracked {
				return 0, false
			}
			direction, directed := fields[unix.NFTA_CT_DIRECTION]
			switch key := switchBE32(t, fields[unix.NFTA_CT_KEY]); {
			case key == unix.NFT_CT_DIRECTION && !directed:
				register = []byte{map[bool]uint8{true: nftables.CTReply, false: nftables.CTOriginal}[p.reply]}
			case key == unix.NFT_CT_PROTOCOL && !directed:
				register = []byte{p.protocol}
			case key == unix.NFT_CT_PROTO_DST && directed && bytes.Equal(direction, []byte{nftables.CTOriginal}):
				register = binary.BigEndian.AppendUint16(nil, p.port)
			default:
				t.Fatalf("ct loads key %d with direction %x, which the evaluator does not model", key, direction)
			}
		case "cmp":
			switchRegister(t, name, fields[unix.NFTA_CMP_SREG])
			want := switchValue(fields[unix.NFTA_CMP_DATA])
			if len(want) == 0 || len(want) > len(register) {
				t.Fatalf("cmp of %d bytes against a %d byte register", len(want), len(register))
			}
			equal := bytes.Equal(register[:len(want)], want)
			switch op := switchBE32(t, fields[unix.NFTA_CMP_OP]); op {
			case unix.NFT_CMP_EQ:
				if !equal {
					return 0, false
				}
			case unix.NFT_CMP_NEQ:
				if equal {
					return 0, false
				}
			default:
				t.Fatalf("cmp with operator %d, which the evaluator does not model", op)
			}
		case "lookup":
			switchRegister(t, name, fields[unix.NFTA_LOOKUP_SREG])
			held, ok := sets[switchBE32(t, fields[unix.NFTA_LOOKUP_SET_ID])]
			if !ok || unix.ByteSliceToString(fields[unix.NFTA_LOOKUP_SET]) != held.set.Name {
				t.Fatalf("lookup names the set %q by ID %d, which no set of the table is", fields[unix.NFTA_LOOKUP_SET], switchBE32(t, fields[unix.NFTA_LOOKUP_SET_ID]))
			}
			length := int(held.set.KeyLen)
			if len(register) < length {
				t.Fatalf("lookup of a %d byte key in a %d byte register", length, len(register))
			}
			key := register[:length]
			found := slices.ContainsFunc(held.elements, func(interval nftables.Interval) bool {
				return bytes.Compare(interval.First, key) <= 0 && bytes.Compare(key, interval.Last) <= 0
			})
			invert := false
			if flags, ok := fields[unix.NFTA_LOOKUP_FLAGS]; ok {
				invert = switchBE32(t, flags)&unix.NFT_LOOKUP_F_INV != 0
			}
			if found == invert {
				return 0, false
			}
		case "counter":
		case "immediate":
			if dreg := switchBE32(t, fields[unix.NFTA_IMMEDIATE_DREG]); dreg != unix.NFT_REG_VERDICT {
				t.Fatalf("immediate loads register %d, not the verdict", dreg)
			}
			for _, data := range nftables.Nested(fields[unix.NFTA_IMMEDIATE_DATA]) {
				for _, field := range nftables.Nested(data.Value) {
					if data.Kind == unix.NFTA_DATA_VERDICT && field.Kind == unix.NFTA_VERDICT_CODE {
						return switchBE32(t, field.Value), true
					}
				}
			}
			t.Fatal("immediate carries no verdict code")
		default:
			t.Fatalf("a rule holds a %q expression, which the evaluator does not model", name)
		}
	}
	return 0, false
}

// switchModeled is the attributes the evaluator reads of each expression
var switchModeled = map[string][]uint16{
	"meta":      {unix.NFTA_META_KEY, unix.NFTA_META_DREG},
	"payload":   {unix.NFTA_PAYLOAD_DREG, unix.NFTA_PAYLOAD_BASE, unix.NFTA_PAYLOAD_OFFSET, unix.NFTA_PAYLOAD_LEN},
	"ct":        {unix.NFTA_CT_KEY, unix.NFTA_CT_DREG, unix.NFTA_CT_DIRECTION},
	"cmp":       {unix.NFTA_CMP_SREG, unix.NFTA_CMP_OP, unix.NFTA_CMP_DATA},
	"lookup":    {unix.NFTA_LOOKUP_SET, unix.NFTA_LOOKUP_SET_ID, unix.NFTA_LOOKUP_SREG, unix.NFTA_LOOKUP_FLAGS},
	"counter":   {},
	"immediate": {unix.NFTA_IMMEDIATE_DREG, unix.NFTA_IMMEDIATE_DATA},
}

func switchRegister(t testing.TB, name string, value []byte) {
	t.Helper()
	if got := switchBE32(t, value); got != unix.NFT_REG_1 {
		t.Fatalf("%s names register %d where every expression of the chain shares register 1", name, got)
	}
}

func switchBE32(t testing.TB, value []byte) uint32 {
	t.Helper()
	if len(value) != 4 {
		t.Fatalf("a 32 bit attribute of %d bytes", len(value))
	}
	return binary.BigEndian.Uint32(value)
}

// switchValue is the bytes of an NFTA_DATA_VALUE nested in an attribute
func switchValue(attribute []byte) []byte {
	for _, inner := range nftables.Nested(attribute) {
		if inner.Kind == unix.NFTA_DATA_VALUE {
			return inner.Value
		}
	}
	return nil
}

// switchNetworks is the connected networks a drawn link may hold: the LAN's,
// one beside it, one inside the overlay, one overlapping it, and one of each
// family that counts as capturing the machine
var switchNetworks = []netip.Prefix{
	netip.MustParsePrefix("198.51.100.10/25"), netip.MustParsePrefix("198.51.100.200/26"), netip.MustParsePrefix("203.0.113.70/31"),
	netip.MustParsePrefix("192.0.2.9/28"), netip.MustParsePrefix("192.0.0.1/22"), netip.MustParsePrefix("198.51.100.10/7"),
	netip.MustParsePrefix("2001:db8:a::10/64"), netip.MustParsePrefix("2001:db8:b::1/127"), netip.MustParsePrefix("3fff::9/64"),
	netip.MustParsePrefix("3ff0::1/12"), netip.MustParsePrefix("2001:db8::1/14"),
}

// switchOwn is the own prefixes a drawn host may throw
var switchOwn = []netip.Prefix{
	netip.MustParsePrefix("203.0.113.0/26"), netip.MustParsePrefix("203.0.113.128/32"),
	netip.MustParsePrefix("2001:db8:5::/48"), netip.MustParsePrefix("2001:db8:6::1/128"),
}

// switchLinks is the links outside the mesh a drawn host may have
var switchLinks = []string{"eth0", "eth1", "docker0"}

// drawSwitch draws a host: each link with up to two networks, in the family
// list each network's family puts it in, a subset of the links forwarded, a
// subset of switchOwn thrown and inbound's entries
func drawSwitch(tc *hegel.T) (switchConfig, bool) {
	var view exitView
	view.on, view.fallback = true, true
	for _, name := range switchLinks {
		var v4, v6 []netip.Prefix
		for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
			network := switchNetworks[hegel.Draw(tc, pbt.Spanning(0, len(switchNetworks)-1))]
			if network.Addr().Is4() {
				v4 = append(v4, network)
			} else {
				v6 = append(v6, network)
			}
		}
		view.network.IPv4.Links = append(view.network.IPv4.Links, Link{Name: name, Prefixes: v4})
		view.network.IPv6.Links = append(view.network.IPv6.Links, Link{Name: name, Prefixes: v6})
	}
	view.forwarded = pbt.Subset(tc, switchLinks, 0, len(switchLinks))
	view.own = pbt.Subset(tc, switchOwn, 0, len(switchOwn))
	mode := ExitMode{Fallback: FallbackNone, Inbound: drawnInbound(tc)}
	if mode.Validate() != nil {
		return switchConfig{}, false
	}
	c := switchConfig{view: view, services: mode.Normalized().Services()}
	for _, entry := range mode.Inbound {
		c.entries = append(c.entries, entryOf(tc, entry))
	}
	return c, true
}

// prefixEdges is each address at a boundary of prefix: its first and last and
// one past each
func prefixEdges(prefix netip.Prefix) []netip.Addr {
	first := prefix.Masked().Addr()
	last := lastOf(prefix.Masked())
	out := []netip.Addr{first, last}
	if before := first.Prev(); before.IsValid() {
		out = append(out, before)
	}
	if after := last.Next(); after.IsValid() {
		out = append(out, after)
	}
	return out
}

// destinations is every address the drawn packets go to: each boundary of a
// drawn network, an own prefix and each link-local, multicast and broadcast
// range, and a host of the internet of each family
func (c switchConfig) destinations() []netip.Addr {
	var out []netip.Addr
	for _, links := range [][]Link{c.view.network.IPv4.Links, c.view.network.IPv6.Links} {
		for _, link := range links {
			for _, network := range link.Prefixes {
				out = append(out, prefixEdges(network)...)
			}
		}
	}
	for _, own := range c.view.own {
		out = append(out, prefixEdges(own)...)
	}
	for _, local := range append(slices.Clone(linkLocal4), linkLocal6...) {
		out = append(out, prefixEdges(local)...)
	}
	return append(out, netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8:f::9"))
}

// ports is every port a drawn reply's flow was opened to: each boundary of a
// listed range and one past each
func (c switchConfig) ports() []uint16 {
	out := []uint16{22}
	for _, s := range c.entries {
		out = append(out, s.First, s.Last, s.First-1, s.Last+1)
	}
	return out
}

// switchMarks is the marks a drawn packet carries: none, the underlay's, its
// neighbors, one sharing its bits, and Tailscale's bypass mark
var switchMarks = []uint32{0, schema.UnderlayMark, schema.UnderlayMark - 1, schema.UnderlayMark + 1, schema.UnderlayMark | 0x100, 0x80000}

// The chain the table writes, run as nf_tables runs its encoded expressions
// over the sets the pass fills, gives every drawn packet the verdict the
// table's lines give it, on drawn hosts: a packet into the tun or lo, carrying
// the underlay's mark or a neighbor of it, forwarded from a link forward
// leaves out or names or sent by the host, to each boundary of the LAN, the
// own prefixes, link-local, multicast and the broadcast and one past it, and
// tracked as each direction of a flow to each boundary of a listed range and
// one past it, of either protocol.
func TestFallbackChainGivesEachPacketTheVerdictOfItsLines(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		c, valid := drawSwitch(ht)
		if !valid {
			return
		}
		s := c.view.fallbackSetsOf(switchTun, exitPassOverlay, c.services, nil)
		rules, err := s.rules()
		if err != nil {
			ht.Fatal(err)
		}
		sets := switchSets(ht, s, rules)
		destinations, ports := c.destinations(), c.ports()
		devices := slices.Concat([]string{loopback, switchTun, switchTun + "0"}, switchLinks)
		incoming := slices.Concat([]string{"", "", "docker1"}, switchLinks)
		for range 40 {
			p := switchPacket{
				oif:         devices[hegel.Draw(ht, pbt.Spanning(0, len(devices)-1))],
				iif:         incoming[hegel.Draw(ht, pbt.Spanning(0, len(incoming)-1))],
				mark:        switchMarks[hegel.Draw(ht, pbt.Spanning(0, len(switchMarks)-1))],
				destination: destinations[hegel.Draw(ht, pbt.Spanning(0, len(destinations)-1))],
				tracked:     hegel.Draw(ht, pbt.Spanning(0, 3)) > 0,
				reply:       hegel.Draw(ht, pbt.Spanning(0, 1)) == 1,
				protocol:    []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP, unix.IPPROTO_ICMP}[hegel.Draw(ht, pbt.Spanning(0, 2))],
				port:        ports[hegel.Draw(ht, pbt.Spanning(0, len(ports)-1))],
			}
			if got, want := evaluate(ht, rules, sets, p), switchModel(c, p); got != want {
				ht.Fatalf("the chain gives %s accept %v, where its lines give %v, on a host of\n%s", p, got, want, c)
			}
		}
	})
}

func (c switchConfig) String() string {
	var lines []string
	for _, links := range [][]Link{c.view.network.IPv4.Links, c.view.network.IPv6.Links} {
		for _, link := range links {
			if len(link.Prefixes) > 0 {
				lines = append(lines, fmt.Sprintf("  link %s %v", link.Name, link.Prefixes))
			}
		}
	}
	lines = append(lines, fmt.Sprintf("  forwarded %v own %v services %v", c.view.forwarded, c.view.own, c.services))
	return strings.Join(lines, "\n")
}

// carvedOut reports p one the switch lets leave by a link outside the mesh:
// carrying the underlay's mark, or to a connected network of a link outside
// the mesh that overlaps no overlay prefix and does not count as capturing the
// machine, to link-local, multicast or the limited broadcast, or to an own
// prefix the mirror throws
func (h interpreted) carvedOut(p fibPacket) bool {
	if p.mark == schema.UnderlayMark || slices.ContainsFunc(switchLocal, func(local netip.Prefix) bool { return local.Contains(p.destination) }) {
		return true
	}
	if slices.ContainsFunc(h.mode.own, func(own netip.Prefix) bool { return own.Contains(p.destination) }) {
		return true
	}
	for _, link := range h.mode.links() {
		for _, prefix := range link.Prefixes {
			network := prefix.Masked()
			overlaps := slices.ContainsFunc(h.rt.Overlay, func(o schema.Prefix) bool { return o.Overlaps(network) })
			if !overlaps && !schema.CapturesTheMachine(network, h.rt.Overlay) && network.Contains(p.destination) {
				return true
			}
		}
	}
	return false
}

// switchState is h's kernel in one state of the switch
type switchState struct {
	name   string
	kernel fib
}

// switchStates is h's kernel with the defaults present, as derived, with them
// retracted, the mirror less each route into the tun that counts as a default,
// and with the tun gone, the mirror less every route into it
func (h interpreted) switchStates() []switchState {
	without := func(drop func(fibRoute) bool) fib {
		tables := maps.Clone(h.kernel.tables)
		tables[DefaultTable] = slices.DeleteFunc(slices.Clone(tables[DefaultTable]), drop)
		return fib{rules: h.kernel.rules, tables: tables}
	}
	return []switchState{
		{"the defaults present", h.kernel},
		{"the defaults retracted", without(func(route fibRoute) bool {
			return route.device == tunDevice && schema.CapturesTheMachine(route.destination, h.rt.Overlay)
		})},
		{"the tun gone", without(func(route fibRoute) bool { return route.device == tunDevice })},
	}
}

// Linux's rule walk over the derived rules under fallback = "none", composed
// with the chain the table writes run as nf_tables runs it, lets out by a link
// outside the mesh only what carvedOut names, of every drawn packet of the
// host's own and forwarded from a link forward names, with the defaults
// present, retracted and with the tun gone, the tun holding an overlay address
// of each family and holding none of either in turn, beside another program's
// rules and tables, to each boundary of the links' networks and the own
// prefixes
func TestFallbackWalkAndChainLetOutOnlyTheCarveOuts(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		build := drawInterpretedIn(t, ht, func(ht *hegel.T, overlay []schema.Prefix) exitView {
			mode := drawExitMode(ht, overlay)
			mode.on, mode.fallback = true, true
			return mode
		})
		h := build(nil)
		s := h.mode.fallbackSetsOf(tunDevice, h.rt.Overlay, nil, nil)
		rules, err := s.rules()
		if err != nil {
			ht.Fatal(err)
		}
		sets := switchSets(ht, s, rules)
		packets := h.packets(ht)
		var boundaries []netip.Addr
		for _, link := range h.mode.links() {
			for _, prefix := range link.Prefixes {
				boundaries = append(boundaries, prefixEdges(prefix)...)
			}
		}
		for _, own := range h.mode.own {
			boundaries = append(boundaries, prefixEdges(own)...)
		}
		for _, destination := range boundaries {
			if p := (fibPacket{source: uplink[destination.Is6()], destination: destination}); h.lookedUp(p) {
				packets = append(packets, p)
			}
		}
		for _, unaddressed := range [][]Family{nil, {FamilyIPv4}, {FamilyIPv6}} {
			h := build(unaddressed)
			for _, state := range h.switchStates() {
				for _, p := range packets {
					if p.iif != "" && !slices.Contains(h.mode.forwarded, p.iif) {
						continue
					}
					device := state.kernel.walk(p)
					if device == tunDevice || device == "unreachable" || device == "none" {
						continue
					}
					out := switchPacket{oif: device, iif: p.iif, mark: p.mark, destination: p.destination}
					if evaluate(ht, rules, sets, out) && !h.carvedOut(p) {
						ht.Fatalf("with %s and the tun holding no overlay address of %v, %s leaves by %s and the chain passes it\nranet3's table:\n%s\nown %v, forwarding %v over %v\nthe rules:\n%s",
							state.name, unaddressed, p, device, strings.Join(h.routes.Debug(), "\n"), h.mode.own, h.mode.forwarded, h.mode.links(), rulesText(state.kernel.rules))
					}
				}
			}
		}
	})
}
