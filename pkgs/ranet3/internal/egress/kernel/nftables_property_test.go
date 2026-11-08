// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// deviceNames draws a device name from one to IFNAMSIZ bytes, one past the
// longest a device carries, over few letters so that two draws often agree or
// share a prefix.
func deviceNames() hegel.Generator[string] {
	return hegel.Composite(func(tc hegel.TestCase) string {
		size := hegel.Draw(tc, pbt.Spanning(1, unix.IFNAMSIZ))
		return hegel.Draw(tc, hegel.Text().Alphabet("ran0e").MinSize(size).MaxSize(size))
	})
}

// ctStates is each state ct state reads: invalid, established, related, new
// and untracked, NF_CT_STATE_INVALID_BIT, NF_CT_STATE_BIT of IP_CT_ESTABLISHED,
// IP_CT_RELATED and IP_CT_NEW, and NF_CT_STATE_UNTRACKED_BIT
var ctStates = []uint32{nftables.CTStateInvalid, 1 << 1, 1 << 2, nftables.CTStateNew, nftables.CTStateUntracked}

// ctReplies is each state a packet going its connection's reply way reads,
// established and related
var ctReplies = []uint32{1 << 1, 1 << 2}

// tracking is a packet's state as ct state reads it and whether it goes its
// connection's reply way
type tracking struct {
	state uint32
	reply bool
}

// Every rule of each direction, translation and timeouts, and every rule taking
// what no flow is tracked for out of the mesh or into it, encodes to
// expressions that, run as nf_tables runs them, take exactly the packets the
// rule is meant for and do to each what the rule says: masquerade, a source
// nat to its address, for none a source nat to the source the packet carries,
// each counted, for a timeout rule its object attached with no count and the
// chain going on past it, and for a packet no flow is tracked for a counted
// drop. An IPv4 drop takes the ICMP types of its message in any state and
// either way with a counted drop, and a refusal its protocol in its flow's
// original direction with a counted reject of code 13 in IPv4 and 1 in IPv6,
// and neither a reply nor a packet no flow is tracked for. A class of none's
// pass out of the mesh takes every packet in any state and either way with no
// count. The packets arrive on
// and leave by the mesh device, two devices whose names start like it, a drawn
// link whose name often shares a prefix with it, another link and this host
// itself, from sources on either side of each edge of the rule's From, or of
// each prefix of the set a screen of a class of none's chain takes in its place,
// and one drawn anywhere in its family, carrying each protocol and first octet carried
// names, in a state ct state reads, each of them and the reply way of an
// established and a related flow for a rule taking what no flow is tracked
// for, a drop or a refusal. A rule is refused exactly when its name is too long
// for a device.
func TestEncodedRuleTakesThePacketsItIsMeantFor(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		rule := Rule{
			Family:    hegel.Draw(ht, hegel.SampledFrom([]uint8{egress.FamilyIPv4, egress.FamilyIPv6})),
			Direction: Direction(hegel.Draw(ht, pbt.Spanning(uint8(Out), uint8(Local)))),
			Interface: hegel.Draw(ht, deviceNames()),
		}
		other := hegel.Draw(ht, deviceNames())
		var addresses hegel.Generator[netip.Addr] = hegel.IPAddresses().IPv4()
		bits, destination := 32, netip.MustParseAddr("203.0.113.9")
		if rule.Family == egress.FamilyIPv6 {
			addresses, bits, destination = unmappedIPv6(), 128, netip.MustParseAddr("2001:db8:ffff::9")
		}
		switch hegel.Draw(ht, pbt.Spanning(0, 7)) {
		case 1:
			rule.Source = hegel.Draw(ht, addresses)
		case 2:
			rule.None = true
		case 3:
			rule.Timeouts = Timeouts(hegel.Draw(ht, pbt.Spanning(uint8(UDPTimeouts), uint8(ICMPv6Timeouts))))
		case 4:
			rule.Direction, rule.Untracked = hegel.Draw(ht, hegel.SampledFrom([]Direction{Out, In})), true
		case 5:
			// the drops are IPv4's alone
			rule.Family, rule.Direction = egress.FamilyIPv4, hegel.Draw(ht, hegel.SampledFrom([]Direction{Out, In}))
			rule.Drops = Message(hegel.Draw(ht, pbt.Spanning(uint8(SourceQuench), uint8(Information))))
		case 6:
			rule.Direction = hegel.Draw(ht, hegel.SampledFrom([]Direction{Out, In}))
			rule.Protocol = hegel.Draw(ht, hegel.SampledFrom(checksummed))
		case 7:
			// only a class of none out of the mesh passes
			rule.Direction, rule.Passes = Out, true
		}
		if rule.Family == egress.FamilyIPv4 {
			addresses, bits, destination = hegel.IPAddresses().IPv4(), 32, netip.MustParseAddr("203.0.113.9")
		}
		states := []tracking{{hegel.Draw(ht, hegel.SampledFrom(ctStates)), false}}
		if rule.Untracked || rule.byProtocol() || rule.kind() == passing {
			states = nil
			for _, state := range ctStates {
				states = append(states, tracking{state, false})
			}
			for _, state := range ctReplies {
				states = append(states, tracking{state, true})
			}
		}
		if hegel.Draw(ht, hegel.WeightedBooleans(3.0/4)) {
			rule.From = netip.PrefixFrom(hegel.Draw(ht, addresses), hegel.Draw(ht, pbt.Spanning(1, bits))).Masked()
		}
		// the screens of a class of none's chain take the classes inside it as one set
		var sets map[string][]nftables.Interval
		if rule.Direction == Out && (rule.Untracked || rule.Protocol.Number != 0) && hegel.Draw(ht, hegel.WeightedBooleans(1.0/3)) {
			var members []netip.Prefix
			for range hegel.Draw(ht, pbt.Spanning(1, 3)) {
				members = append(members, netip.PrefixFrom(hegel.Draw(ht, addresses), hegel.Draw(ht, pbt.Spanning(1, bits))).Masked())
			}
			rule.From, rule.Sources, rule.Under = netip.Prefix{}, prefixSet(members), netip.PrefixFrom(members[0].Addr(), 1).Masked()
			made, err := sourceRequests(rule, 2)
			if err != nil {
				ht.Fatal(err)
			}
			sets = encodedSets(ht, made)
		}

		request, err := newRule(rule, 2)
		refused := len(rule.Interface) >= unix.IFNAMSIZ
		if refused != (err != nil) {
			ht.Fatalf("%s encoded with %v, want refused %v", rule, err, refused)
		}
		if refused {
			return
		}
		sources := []netip.Addr{hegel.Draw(ht, addresses)}
		edges := rule.Sources.Prefixes()
		if rule.From.IsValid() {
			edges = append(edges, rule.From)
		}
		for _, prefix := range edges {
			first, last := prefix.Addr(), lastAddress(prefix)
			sources = append(sources, first, last, first.Prev(), last.Next())
		}
		sources = slices.DeleteFunc(sources, func(a netip.Addr) bool { return !a.IsValid() })
		devices := []string{rule.Interface, rule.Interface + "1", rule.Interface + "e", other, "eth0"}
		for _, arrival := range append([]string{""}, devices...) {
			for _, departure := range devices {
				for _, source := range sources {
					for _, carry := range carried {
						for _, state := range states {
							untracked := state.state == nftables.CTStateInvalid || state.state == nftables.CTStateUntracked
							packet := crossing{arrival, departure, source, carry.protocol, carry.port, carry.first, untracked, state.reply}
							wire := drawnPacket{iif: arrival, source: source, destination: destination}.carrying(carry.protocol, carry.port)
							wire.transport[0] = carry.first
							wire.oif, wire.ctState, wire.reply, wire.sets = departure, state.state, state.reply, sets
							run := runChain(ht, []nftables.Request{request}, wire)
							want := chainRun{rule: -1, accept: true}
							switch {
							case !meant(rule, packet):
							case rule.Timeouts != NoTimeouts:
								want.timeouts = timeoutObject + rule.Timeouts.String() + map[uint8]string{egress.FamilyIPv4: "4", egress.FamilyIPv6: "6"}[rule.Family]
							case rule.kind() == passing:
								want = chainRun{accept: true}
							case rule.Untracked:
								want = chainRun{counted: true}
							case rule.Drops != NoMessage:
								want = chainRun{counted: true}
							case rule.Protocol.Number != 0:
								// administratively prohibited, RFC 1812's code 13 and RFC 4443's code 1
								want = chainRun{counted: true, rejected: 1}
								if rule.Family == egress.FamilyIPv4 {
									want.rejected = 13
								}
							default:
								want = chainRun{accept: true, counted: true,
									translation: translation{masquerade: !rule.None && !rule.Source.IsValid(), to: leavesUnder(rule, packet)}}
							}
							if run != want {
								ht.Fatalf("%s runs a packet from %s of protocol %d to port %d with first octet %d arriving on %q and leaving by %q in ct state %#x, a reply %v, as %+v, want %+v",
									rule, source, carry.protocol, carry.port, carry.first, arrival, departure, state.state, state.reply, run, want)
							}
						}
					}
				}
			}
		}
	})
}

// Two prefixes of one family, masked as a class's is, never share the name of
// a class of none's chain, two lengths over one address among them, and every
// name fits a chain's name in nf_tables, NFT_CHAIN_MAXNAMELEN of 256 bytes with
// its terminator. Two lengths over a long address part only at the end of a
// long name, which a draw seldom meets, so two such pairs are held as written.
func TestEachPrefixNamesAChainOfItsOwn(t *testing.T) {
	for _, pair := range [][2]string{
		{"2001:db8:1234:5678::/64", "2001:db8:1234:5678::/65"},
		{"2001:db8:aaaa:bbbb:cccc:dddd:eeee:ff00/120", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ff00/121"},
	} {
		a, b := netip.MustParsePrefix(pair[0]), netip.MustParsePrefix(pair[1])
		if noneChain(a) == noneChain(b) {
			t.Errorf("%s and %s both name the chain %s", a, b, noneChain(a))
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		var addresses hegel.Generator[netip.Addr] = hegel.IPAddresses().IPv4()
		bits := 32
		if hegel.Draw(ht, hegel.Booleans()) {
			addresses, bits = unmappedIPv6(), 128
		}
		a := netip.PrefixFrom(hegel.Draw(ht, addresses), hegel.Draw(ht, pbt.Spanning(0, bits))).Masked()
		// a's address at a length no shorter keeps that address, so the two
		// names part only at the length after it
		b := netip.PrefixFrom(a.Addr(), hegel.Draw(ht, pbt.Spanning(a.Bits(), bits)))
		if hegel.Draw(ht, hegel.Booleans()) {
			b = netip.PrefixFrom(hegel.Draw(ht, addresses), hegel.Draw(ht, pbt.Spanning(0, bits))).Masked()
		}
		if a != b && noneChain(a) == noneChain(b) {
			ht.Fatalf("%s and %s both name the chain %s", a, b, noneChain(a))
		}
		if len(noneChain(a)) >= unix.NFT_CHAIN_MAXNAMELEN {
			ht.Fatalf("%s names the chain %s of %d bytes, past the %d nf_tables takes with the terminator", a, noneChain(a), len(noneChain(a)), unix.NFT_CHAIN_MAXNAMELEN)
		}
	})
}
