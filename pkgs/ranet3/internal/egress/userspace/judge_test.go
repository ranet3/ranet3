// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
)

// Over any bytes a session may hand the exit, the judgment never reads past
// them, answers time exceeded only where the TTL or hop limit is 1 or less,
// and delivers only a whole packet with a TTL or hop limit left toward a
// destination the host does not hold, or toward one the host holds a UDP
// datagram, which the relay judges by its port, or an ICMP error whole in one
// packet about one, which the relay carries back to the mapping that
// hairpinned the datagram
func FuzzJudge(f *testing.F) {
	for _, c := range []judgeCase{
		{ipv4: true, ttl: 64, protocol: 6},
		{ipv4: true, ttl: 1, protocol: 17},
		{ipv4: true, ttl: 64, protocol: protoUncarried, fragment: 2},
		{ttl: 64, protocol: 58, destination: 1},
		{ttl: 64, protocol: 17, fragment: 2, extensions: []byte{0, 60}},
		{ttl: 64, protocol: 6, extensions: []byte{43}, segmentsLeft: 1},
		{ttl: 64, protocol: 17, fragment: 1, afterFragment: 60},
	} {
		f.Add(c.bytes())
	}
	for _, family := range judgeFamilies {
		f.Add(leafRefusal(family.leaf, family.held, family.unreachable, 3, udpDatagram(netip.AddrPortFrom(family.held, 5300), netip.AddrPortFrom(family.leaf, 40000), []byte("reply"))))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		j := judge(raw, heldByHost)
		if j.act == drop {
			return
		}
		var ttl, protocol byte
		var destination netip.Addr
		switch raw[0] >> 4 {
		case 4:
			ttl, protocol, destination = raw[8], raw[9], netip.AddrFrom4([4]byte(raw[16:20]))
		case 6:
			ttl, destination = raw[7], netip.AddrFrom16([16]byte(raw[24:40]))
			protocol, _ = upperLayer6(raw)
		default:
			t.Fatalf("judged %+v a packet of version %d", j, raw[0]>>4)
		}
		switch {
		case j.act == answer && j.kind == netstack.ExitExpired && ttl > 1:
			t.Fatalf("answered expired with %d left", ttl)
		case j.act == deliver && ttl <= 1:
			t.Fatalf("delivered with %d left", ttl)
		case j.act == deliver && (heldByHost(destination) && protocol != protoUDP && !errorAboutDatagram(raw) || unservable(destination)):
			t.Fatalf("delivered protocol %d toward %s", protocol, destination)
		}
	})
}

// errorAboutDatagram is whether raw, a packet the judgment found whole, is an
// ICMP error of its family in one packet quoting a UDP datagram, read through
// gVisor's headers
func errorAboutDatagram(raw []byte) bool {
	switch raw[0] >> 4 {
	case 4:
		ip := header.IPv4(raw)
		if ip.Protocol() != protoICMP || ip.More() || ip.FragmentOffset() != 0 {
			return false
		}
		message := header.ICMPv4(raw[ip.HeaderLength():])
		if len(message) < header.ICMPv4MinimumSize+header.IPv4MinimumSize {
			return false
		}
		quote := header.IPv4(message.Payload())
		kind := message.Type()
		isError := kind == header.ICMPv4DstUnreachable || kind == header.ICMPv4TimeExceeded || kind == header.ICMPv4ParamProblem
		return isError && quote[0]>>4 == 4 && quote.Protocol() == protoUDP
	case 6:
		ip := header.IPv6(raw)
		if ip.NextHeader() != protoICMPv6 {
			return false
		}
		message := header.ICMPv6(raw[header.IPv6MinimumSize:])
		if len(message) < header.ICMPv6MinimumSize+header.IPv6MinimumSize {
			return false
		}
		quote := header.IPv6(message.Payload())
		kind := message.Type()
		isError := kind == header.ICMPv6DstUnreachable || kind == header.ICMPv6PacketTooBig || kind == header.ICMPv6TimeExceeded || kind == header.ICMPv6ParamProblem
		return isError && quote[0]>>4 == 6 && quote.NextHeader() == protoUDP
	}
	return false
}

// judgeFamilies is, by family, a leaf, the address the cases' host holds and
// the type of ICMP's destination unreachable
var judgeFamilies = []struct {
	leaf, held  netip.Addr
	unreachable byte
}{
	{leaf4, judgeDestinations[0][1], 3},
	{leaf6, judgeDestinations[1][1], 1},
}

// Toward an address the host holds the judgment delivers a leaf's ICMP error
// about a UDP datagram, for the relay to carry back to the mapping that
// hairpinned the datagram, and refuses one about a TCP segment
func TestJudgmentDeliversTowardHeldAddressesOnlyErrorsAboutDatagrams(t *testing.T) {
	for _, family := range judgeFamilies {
		held, leaf := netip.AddrPortFrom(family.held, 5300), netip.AddrPortFrom(family.leaf, 40000)
		for _, c := range []struct {
			name   string
			quoted []byte
			want   judgment
		}{
			{"a datagram", udpDatagram(held, leaf, []byte("reply")), judgment{act: deliver}},
			{"a segment", tcpSegment(held, leaf, 1, 1, tcpACK, nil), judgment{act: answer, kind: netstack.ExitProhibited, reason: reasonDestination}},
		} {
			if got := judge(leafRefusal(family.leaf, family.held, family.unreachable, 3, c.quoted), heldByHost); got != c.want {
				t.Errorf("judged an error from %s about %s toward %s %+v, want %+v", family.leaf, c.name, family.held, got, c.want)
			}
		}
	}
}

// The judgment refuses a datagram toward the limited broadcast address, which
// no server holds
func TestJudgmentRefusesTheLimitedBroadcast(t *testing.T) {
	broadcast := udpDatagram(netip.AddrPortFrom(leaf4, 68), netip.AddrPortFrom(packet.LimitedBroadcast, 67), []byte("discover"))
	if got, want := judge(broadcast, heldByHost), (judgment{act: answer, kind: netstack.ExitProhibited, reason: reasonDestination}); got != want {
		t.Errorf("judged a datagram toward %s %+v, want %+v", packet.LimitedBroadcast, got, want)
	}
}
