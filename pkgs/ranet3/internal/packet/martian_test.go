// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

import (
	"net/netip"
	"testing"
)

// the addresses RFC 1812 section 5.3.7, RFC 3927 section 7 and RFC 4291 sections 2.5.2, 2.5.3, 2.5.6 and 2.7 name, at each end of every range
// and the unicast addresses beside them, which a router forwards
var martians = []struct {
	address             string
	source, destination bool
	reason              string
}{
	{"0.0.0.0", true, true, "this host on this network, 4.2.2.11 (a), and 0.0.0.0 of 4.2.3.1"},
	{"0.1.2.3", true, true, "a host on network 0, 4.2.2.11 (b)"},
	{"0.255.255.255", true, true, "the last of network 0"},
	{"1.0.0.0", false, false, "the first address past network 0"},
	{"126.255.255.255", false, false, "the last address before network 127"},
	{"127.0.0.1", true, true, "loopback, network 127"},
	{"127.255.255.255", true, true, "the last of network 127"},
	{"128.0.0.0", false, false, "the first address past network 127"},
	{"169.253.255.255", false, false, "the last address before IPv4 link-local"},
	{"169.254.0.0", true, true, "IPv4 link-local, RFC 3927"},
	{"169.254.255.255", true, true, "the last of IPv4 link-local"},
	{"169.255.0.0", false, false, "the first address past IPv4 link-local"},
	{"223.255.255.255", false, false, "the last unicast address before multicast"},
	{"224.0.0.1", true, false, "multicast, not a unicast address, which a destination may be"},
	{"239.255.255.255", true, false, "the last multicast address"},
	{"240.0.0.0", true, true, "class E"},
	{"254.255.255.255", true, true, "class E"},
	{"255.255.255.254", true, true, "class E"},
	{"255.255.255.255", true, false, "the limited broadcast, never a source and kept out of class E's destinations"},
	{"::", true, true, "the unspecified address, 2.5.2"},
	{"::1", true, true, "loopback, 2.5.3"},
	{"::2", false, false, "the address after loopback"},
	{"fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false, false, "the last address before link-local"},
	{"fe80::1", true, true, "link-local, 2.5.6"},
	{"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, true, "the last of link-local"},
	{"fec0::1", false, false, "the first address past link-local"},
	{"ff02::1", true, false, "multicast, never a source, 2.7"},
	{"2001:db8::1", false, false, "global unicast"},
}

func TestMartianSetsAreTheRFCsLists(t *testing.T) {
	for _, m := range martians {
		address := netip.MustParseAddr(m.address)
		if got := InvalidSource(address); got != m.source {
			t.Errorf("%s, %s: InvalidSource is %t, want %t", m.address, m.reason, got, m.source)
		}
		if got := InvalidDestination(address); got != m.destination {
			t.Errorf("%s, %s: InvalidDestination is %t, want %t", m.address, m.reason, got, m.destination)
		}
	}
}
