// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package egress

import (
	"math/big"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// kernelRefusals is a model of the destinations the kernel's input path
// refuses, as runs of addresses per family width, written from its lines at
// Linux 940de590: ipv4_is_lbcast and ipv4_is_zeronet, which ip_route_input_slow
// reads at net/ipv4/route.c:2331 and :2342, ipv4_is_loopback at :2350 and
// ipv4_is_multicast at :2538 (include/linux/in.h:38-67), then the loopback
// check of net/ipv6/ip6_input.c:255, the multicast and link-local types of
// __ipv6_addr_type (net/ipv6/addrconf_core.c:51-60), which rt6_need_strict
// reads, and the unspecified address of RFC 4291 section 2.5.2
var kernelRefusals = map[int][][2]netip.Addr{
	32: {
		{netip.MustParseAddr("255.255.255.255"), netip.MustParseAddr("255.255.255.255")},
		{netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("0.0.0.0")},
		{netip.MustParseAddr("127.0.0.0"), netip.MustParseAddr("127.255.255.255")},
		{netip.MustParseAddr("224.0.0.0"), netip.MustParseAddr("239.255.255.255")},
	},
	128: {
		{netip.MustParseAddr("::1"), netip.MustParseAddr("::1")},
		{netip.MustParseAddr("::"), netip.MustParseAddr("::")},
		{netip.MustParseAddr("ff00::"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{netip.MustParseAddr("fe80::"), netip.MustParseAddr("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
	},
}

func refusedByKernel(address netip.Addr) bool {
	for _, run := range kernelRefusals[address.BitLen()] {
		if run[0].Compare(address) <= 0 && address.Compare(run[1]) <= 0 {
			return true
		}
	}
	return false
}

// modelCandidates counts the candidates out in integers: a host route's own
// address, and for a wider prefix of size n the base plus n/2, the base plus
// one and the base plus n less two
func modelCandidates(prefix netip.Prefix) []netip.Addr {
	width := prefix.Addr().BitLen()
	if prefix.Bits() == width {
		return []netip.Addr{prefix.Addr()}
	}
	base := new(big.Int).SetBytes(prefix.Addr().AsSlice())
	size := new(big.Int).Lsh(big.NewInt(1), uint(width-prefix.Bits()))
	plus := func(n *big.Int) netip.Addr {
		address, _ := netip.AddrFromSlice(new(big.Int).Add(base, n).FillBytes(make([]byte, width/8)))
		return address
	}
	return []netip.Addr{plus(new(big.Int).Rsh(size, 1)), plus(big.NewInt(1)), plus(new(big.Int).Sub(size, big.NewInt(2)))}
}

// anchorNear draws an address of a width-bit family: an end of a refused run
// or one a step or two either side of it, the end itself drawn outright, and
// one time in four an address drawn anywhere
func anchorNear(tc hegel.TestCase, width int) netip.Addr {
	if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
		if width == 32 {
			return hegel.Draw(tc, hegel.IPAddresses().IPv4())
		}
		return hegel.Draw(tc, hegel.IPAddresses().IPv6())
	}
	runs := kernelRefusals[width]
	end := runs[hegel.Draw(tc, hegel.Integers(0, len(runs)-1))][hegel.Draw(tc, hegel.Integers(0, 1))]
	n := new(big.Int).Add(new(big.Int).SetBytes(end.AsSlice()), big.NewInt(int64(hegel.Draw(tc, pbt.Spanning(-2, 2)))))
	n.Mod(n, new(big.Int).Lsh(big.NewInt(1), uint(width)))
	address, _ := netip.AddrFromSlice(n.FillBytes(make([]byte, width/8)))
	return address
}

// At every prefix length of both families, around each run the kernel refuses
// and anywhere, and for a host route of an address the kernel refuses drawn
// outright, the read address lies in its prefix and is no destination the
// kernel refuses. It is the middle address wherever the kernel takes the
// middle, and otherwise the first of the base plus one and the last address
// less one the kernel takes. A host route reads its own address where the
// kernel takes it and nothing otherwise, and none is read only where the
// kernel takes no candidate
func TestReadAddressIsTheFirstCandidateTheKernelTakes(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		check := func(prefix netip.Prefix) {
			got, ok := readAddress(prefix)
			candidates := modelCandidates(prefix)
			var want netip.Addr
			for _, candidate := range candidates {
				if !refusedByKernel(candidate) {
					want = candidate
					break
				}
			}
			switch {
			case ok && !prefix.Contains(got):
				ht.Fatalf("%s reads %s, outside it", prefix, got)
			case ok && refusedByKernel(got):
				ht.Fatalf("%s reads %s, which the kernel refuses as a destination", prefix, got)
			case !refusedByKernel(candidates[0]) && got != candidates[0]:
				ht.Fatalf("%s reads %s (%v) where the kernel takes its first candidate %s", prefix, got, ok, candidates[0])
			case ok != want.IsValid():
				ht.Fatalf("%s reads %s (%v) where the first candidate the kernel takes is %s (%v)", prefix, got, ok, want, want.IsValid())
			case got != want:
				ht.Fatalf("%s reads %s, where the first candidate the kernel takes is %s", prefix, got, want)
			}
		}
		check(netip.MustParsePrefix(hegel.Draw(ht, hegel.SampledFrom(refusedHosts))))
		for _, width := range []int{32, 128} {
			at := anchorNear(ht, width)
			for bits := 0; bits <= width; bits++ {
				check(netip.PrefixFrom(at, bits).Masked())
			}
		}
	})
}
