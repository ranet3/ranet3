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

// Every rule of each direction, translation and timeouts encodes to
// expressions that, run as nf_tables runs them, take exactly the packets the
// rule is meant for and do to each what the rule says: masquerade, a source nat
// to its address, for none a source nat to the source the packet carries, each
// counted, and for a timeout rule its object attached with no count and the
// chain going on past it. The packets arrive on and leave by the mesh device,
// two devices whose names start like it, a drawn link whose name often shares
// a prefix with it, another link and this host itself, from sources on either
// side of each edge of the rule's From and one drawn anywhere in its family,
// carrying each protocol carried names. A rule is refused exactly when its name
// is too long for a device.
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
		switch hegel.Draw(ht, pbt.Spanning(0, 3)) {
		case 1:
			rule.Source = hegel.Draw(ht, addresses)
		case 2:
			rule.None = true
		case 3:
			rule.Timeouts = Timeouts(hegel.Draw(ht, pbt.Spanning(uint8(UDPTimeouts), uint8(ICMPv6Timeouts))))
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
						packet := crossing{arrival, departure, source, carry.protocol, carry.port}
						wire := drawnPacket{iif: arrival, source: source, destination: destination}.carrying(carry.protocol, carry.port)
						wire.oif = departure
						run := runChain(ht, []nftables.Request{request}, wire)
						want := chainRun{rule: -1, accept: true}
						switch {
						case !meant(rule, packet):
						case rule.Timeouts != NoTimeouts:
							want.timeouts = timeoutObject + rule.Timeouts.String()
						default:
							want = chainRun{accept: true, counted: true,
								translation: translation{masquerade: !rule.None && !rule.Source.IsValid(), to: leavesUnder(rule, packet)}}
						}
						if run != want {
							ht.Fatalf("%s runs a packet from %s of protocol %d to port %d arriving on %q and leaving by %q as %+v, want %+v",
								rule, source, carry.protocol, carry.port, arrival, departure, run, want)
						}
					}
				}
			}
		}
	})
}
