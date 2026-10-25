// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"testing"
)

// refusedHosts are host routes whose own address the kernel's input path
// refuses as a unicast destination
var refusedHosts = []string{
	"127.0.0.1/32", "224.0.0.1/32", "255.255.255.255/32", "0.0.0.0/32",
	"::1/128", "::/128", "fe80::1/128",
}

// a default reads its middle address, a middle the kernel refuses gives way to
// the base plus one, a host route reads itself where the kernel takes its
// address, and a prefix holding no address the kernel routes as unicast, a
// host route among them, reads none
func TestReadAddressStepsPastAMiddleTheKernelRefuses(t *testing.T) {
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
		{"0.1.0.0/16", "0.1.128.0"},
		{"127.0.0.0/8", ""},
		{"224.0.0.0/4", ""},
		{"fe80::/10", ""},
		{"ff00::/8", ""},
	} {
		got, ok := readAddress(netip.MustParsePrefix(c.prefix))
		if want := c.want; ok != (want != "") || ok && got != netip.MustParseAddr(want) {
			t.Errorf("%s reads %s (%v), want %q", c.prefix, got, ok, want)
		}
	}
	for _, host := range refusedHosts {
		if got, ok := readAddress(netip.MustParsePrefix(host)); ok {
			t.Errorf("%s reads %s, an address the kernel refuses", host, got)
		}
	}
}
