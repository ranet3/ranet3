// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"net/netip"
	"testing"
)

// droppedHosts are host routes whose own address the mesh forwards no unicast
// packet to
var droppedHosts = []string{
	"127.0.0.1/32", "224.0.0.1/32", "255.255.255.255/32", "0.0.0.0/32", "0.0.0.1/32", "169.254.0.1/32", "240.0.0.1/32",
	"::1/128", "::/128", "fe80::1/128", "ff02::1/128", "::ffff:192.0.2.1/128",
}

// a default reads its middle address, a middle the mesh drops gives way to the
// base plus one, a host route reads itself where the mesh forwards to its
// address, and a prefix holding no address the mesh forwards to, a host route
// among them, reads none
func TestReadAddressStepsPastAMiddleTheMeshDrops(t *testing.T) {
	for _, c := range []struct {
		prefix string
		want   string
	}{
		{"0.0.0.0/0", "128.0.0.0"},
		{"::/0", "8000::"},
		{"192.0.0.0/2", "192.0.0.1"},
		{"126.0.0.0/7", "126.0.0.1"},
		{"203.0.113.0/24", "203.0.113.128"},
		{"198.51.100.7/32", "198.51.100.7"},
		{"2001:db8::/32", "2001:db8:8000::"},
		{"169.252.0.0/14", "169.252.0.1"},
		{"::fffe:0:0/95", "::fffe:0:1"},
		{"0.0.0.0/8", ""},
		{"0.1.0.0/16", ""},
		{"127.0.0.0/8", ""},
		{"169.254.0.0/16", ""},
		{"224.0.0.0/4", ""},
		{"240.0.0.0/4", ""},
		{"224.0.0.0/3", ""},
		{"255.255.255.254/31", ""},
		{"::/127", ""},
		{"fe80::/10", ""},
		{"ff00::/8", ""},
	} {
		got, ok := ReadAddress(netip.MustParsePrefix(c.prefix))
		if want := c.want; ok != (want != "") || ok && got != netip.MustParseAddr(want) {
			t.Errorf("%s reads %s (%v), want %q", c.prefix, got, ok, want)
		}
	}
	for _, host := range droppedHosts {
		if got, ok := ReadAddress(netip.MustParsePrefix(host)); ok {
			t.Errorf("%s reads %s, an address the mesh drops", host, got)
		}
	}
}
