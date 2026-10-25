// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
)

// the ends of the reads below: an address of this node's own inside the
// overlay and an uplink address the table holds nothing for, by family
var (
	ownSource    = map[int]netip.Addr{4: segAddr("192.0.2.1"), 6: segAddr("3fff::1")}
	uplinkSource = map[int]netip.Addr{4: segAddr("198.51.100.10"), 6: segAddr("2001:db8:a::10")}
)

// unroutedMesh is a recording mesh with the overlay 192.0.2.0/24 and
// 3fff::/20, holding ownSource as its own and the entries set writes
func unroutedMesh(tb testing.TB, set func(*RouteTable)) (*Mesh, *recordingDevice) {
	tb.Helper()
	m, dev := recordingMesh(tb)
	m.SetOverlay([]schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")})
	for _, own := range ownSource {
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(own, own.BitLen()), Local)
	}
	if set != nil {
		set(m.Routes)
	}
	return m, dev
}

// a packet the host routes into the tun toward a destination no route reaches,
// or a hold holds, is answered back into the tun from that destination,
// whether its source is this node's own or an uplink address the mesh holds no
// route to
// over IPv4 a hold counting as a default, and no route, answer network
// unreachable outside the overlay, and a hold that does not count, or the
// overlay, host
// unreachable, RFC 1812 section 5.2.7.1, and over IPv6 no route, RFC 4443
// section 3.1 code 0
func TestTunReadNoRouteReachesIsAnsweredIntoTheTun(t *testing.T) {
	const netUnreachable, hostUnreachable = 0, 1
	for name, read := range map[string]struct {
		family      int
		destination netip.Addr
		set         func(*RouteTable)
		code        byte
	}{
		"ipv4 under a counted hold": {4, segAddr("203.0.113.9"), func(r *RouteTable) {
			r.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), Unreachable)
		}, netUnreachable},
		"ipv4 under a hold that does not count": {4, segAddr("203.0.113.9"), func(r *RouteTable) {
			r.Set(netip.Prefix{}, segPrefix("203.0.113.0/24"), Unreachable)
		}, hostUnreachable},
		"ipv4 with no route":                {4, segAddr("203.0.113.9"), nil, netUnreachable},
		"ipv4 inside the overlay, no route": {4, segAddr("192.0.2.9"), nil, hostUnreachable},
		"ipv6 under a counted hold":         {6, segAddr("2001:db8:c::9"), func(r *RouteTable) { r.Set(netip.Prefix{}, segPrefix("::/0"), Unreachable) }, 0},
		"ipv6 with no route":                {6, segAddr("2001:db8:c::9"), nil, 0},
		"ipv6 inside the overlay, no route": {6, segAddr("3fff::9"), nil, 0},
	} {
		for sourceName, source := range map[string]netip.Addr{"own": ownSource[read.family], "uplink": uplinkSource[read.family]} {
			t.Run(name+" from an "+sourceName+" source", func(t *testing.T) {
				m, dev := unroutedMesh(t, read.set)
				raw := udpPacket(source, read.destination, 200, false)
				_, written := classifyOne(m, dev, raw)
				if len(written) != 1 {
					t.Fatalf("the read put %d packets into the tun, want its answer", len(written))
				}
				if read.family == 6 {
					checkICMPv6(t, written[0], raw, read.destination, 1, read.code, 0)
				} else {
					checkICMPv4(t, written[0], raw, read.destination, 3, read.code, 0)
				}
				if got := m.transitCounts[transitAnswered].Load(); got != 1 {
					t.Errorf("the answer was counted %d times, want once", got)
				}
			})
		}
	}
}

// a read the table answers as this node's own goes unanswered, and so does one
// whose source's bucket is spent
func TestTunReadIsLeftUnansweredWhereItLoopsOrItsSourceIsSpent(t *testing.T) {
	for family := range ownSource {
		m, dev := unroutedMesh(t, nil)
		if _, written := classifyOne(m, dev, udpPacket(uplinkSource[family], ownSource[family], 200, false)); len(written) != 0 {
			t.Errorf("ipv%d: a read to this node's own address put %d packets into the tun", family, len(written))
		}
		for range icmpSourceBurst {
			if !m.takeICMPToken(uplinkSource[family]) {
				t.Fatalf("a fresh bucket of %s held fewer than %d answers", uplinkSource[family], icmpSourceBurst)
			}
		}
		destination := map[int]netip.Addr{4: segAddr("203.0.113.9"), 6: segAddr("2001:db8:c::9")}[family]
		if _, written := classifyOne(m, dev, udpPacket(uplinkSource[family], destination, 200, false)); len(written) != 0 {
			t.Errorf("ipv%d: a read from a spent source was answered", family)
		}
	}
}
