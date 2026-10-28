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

// Every rule of each direction, translation and timeouts, and every rule taking
// what no flow is tracked for out of the mesh or into it, encodes to
// expressions that, run as nf_tables runs them, take exactly the packets the
// rule is meant for and do to each what the rule says: masquerade, a source
// nat to its address, for none a source nat to the source the packet carries,
// each counted, for a timeout rule its object attached with no count and the
// chain going on past it, and for a packet no flow is tracked for a counted
// drop, or under none a pass with no count. An IPv4 drop takes the ICMP types
// of its message in any state with a counted drop. The packets arrive on and leave by the mesh device, two
// devices whose names start like it, a drawn link whose name often shares a
// prefix with it, another link and this host itself, from sources on either
// side of each edge of the rule's From and one drawn anywhere in its family,
// carrying each protocol and first octet carried names, in a state ct state
// reads, each of them for a rule taking what no flow is tracked for or a
// drop. A rule is refused exactly when its name is too long for a device.
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
		switch hegel.Draw(ht, pbt.Spanning(0, 5)) {
		case 1:
			rule.Source = hegel.Draw(ht, addresses)
		case 2:
			rule.None = true
		case 3:
			rule.Timeouts = Timeouts(hegel.Draw(ht, pbt.Spanning(uint8(UDPTimeouts), uint8(ICMPv6Timeouts))))
		case 4:
			// the In rules translate whatever they take, so only an Out rule passes
			rule.Direction, rule.Untracked = hegel.Draw(ht, hegel.SampledFrom([]Direction{Out, In})), true
			rule.None = rule.Direction == Out && hegel.Draw(ht, hegel.Booleans())
		case 5:
			// the drops are IPv4's alone
			rule.Family, rule.Direction = egress.FamilyIPv4, hegel.Draw(ht, hegel.SampledFrom([]Direction{Out, In}))
			rule.Drops = Message(hegel.Draw(ht, pbt.Spanning(uint8(SourceQuench), uint8(Information))))
		}
		if rule.Family == egress.FamilyIPv4 {
			addresses, bits, destination = hegel.IPAddresses().IPv4(), 32, netip.MustParseAddr("203.0.113.9")
		}
		states := []uint32{hegel.Draw(ht, hegel.SampledFrom(ctStates))}
		if rule.Untracked || rule.Drops != NoMessage {
			states = ctStates
		}
		if hegel.Draw(ht, hegel.WeightedBooleans(3.0/4)) {
			rule.From = netip.PrefixFrom(hegel.Draw(ht, addresses), hegel.Draw(ht, pbt.Spanning(1, bits))).Masked()
		}

		request, err := newRule(rule)
		refused := len(rule.Interface) >= unix.IFNAMSIZ
		if refused != (err != nil) {
			ht.Fatalf("%s encoded with %v, want refused %v", rule, err, refused)
		}
		if refused {
			return
		}
		sources := []netip.Addr{hegel.Draw(ht, addresses)}
		if rule.From.IsValid() {
			first, last := rule.From.Addr(), lastAddress(rule.From)
			sources = append(sources, first, last, first.Prev(), last.Next())
		}
		sources = slices.DeleteFunc(sources, func(a netip.Addr) bool { return !a.IsValid() })
		devices := []string{rule.Interface, rule.Interface + "1", rule.Interface + "e", other, "eth0"}
		for _, arrival := range append([]string{""}, devices...) {
			for _, departure := range devices {
				for _, source := range sources {
					for _, carry := range carried {
						for _, state := range states {
							untracked := state == nftables.CTStateInvalid || state == nftables.CTStateUntracked
							packet := crossing{arrival, departure, source, carry.protocol, carry.port, carry.first, untracked}
							wire := drawnPacket{iif: arrival, source: source, destination: destination}.carrying(carry.protocol, carry.port)
							wire.transport[0] = carry.first
							wire.oif, wire.ctState = departure, state
							run := runChain(ht, []nftables.Request{request}, wire)
							want := chainRun{rule: -1, accept: true}
							switch {
							case !meant(rule, packet):
							case rule.Timeouts != NoTimeouts:
								want.timeouts = timeoutObject + rule.Timeouts.String()
							case rule.Untracked:
								want = chainRun{accept: rule.None, counted: !rule.None}
							case rule.Drops != NoMessage:
								want = chainRun{counted: true}
							default:
								want = chainRun{accept: true, counted: true,
									translation: translation{masquerade: !rule.None && !rule.Source.IsValid(), to: leavesUnder(rule, packet)}}
							}
							if run != want {
								ht.Fatalf("%s runs a packet from %s of protocol %d to port %d with first octet %d arriving on %q and leaving by %q in ct state %#x as %+v, want %+v",
									rule, source, carry.protocol, carry.port, carry.first, arrival, departure, state, run, want)
							}
						}
					}
				}
			}
		}
	})
}
