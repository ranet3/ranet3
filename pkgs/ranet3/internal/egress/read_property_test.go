// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package egress

import (
	"fmt"
	"math/big"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// meshDrops is a model of the destinations a router forwards no unicast packet
// to, as runs of addresses per family width. IPv4: network 0 and network 127
// (RFC 1812 section 5.3.7, lines 5366-5369), link-local (RFC 3927 section 7,
// lines 1375-1380), the groups of 224.0.0.0 to 239.255.255.255, which name no
// single host (RFC 1112 section 4), and class E (RFC 1812 section 5.3.7, lines
// 5355-5357) with the limited broadcast, which is never forwarded (section
// 5.3.5.1, line 5185). IPv6, from RFC 4291: the unspecified address, never a
// destination (section 2.5.2), loopback, never sent off the node (2.5.3), the
// IPv4-mapped addresses, which stand for IPv4 nodes (2.5.5.2), link-local,
// never forwarded (2.5.6), and the groups (2.7)
var meshDrops = map[int][][2]netip.Addr{
	32: {
		{netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("0.255.255.255")},
		{netip.MustParseAddr("127.0.0.0"), netip.MustParseAddr("127.255.255.255")},
		{netip.MustParseAddr("169.254.0.0"), netip.MustParseAddr("169.254.255.255")},
		{netip.MustParseAddr("224.0.0.0"), netip.MustParseAddr("239.255.255.255")},
		{netip.MustParseAddr("240.0.0.0"), netip.MustParseAddr("255.255.255.255")},
	},
	128: {
		{netip.MustParseAddr("::"), netip.MustParseAddr("::")},
		{netip.MustParseAddr("::1"), netip.MustParseAddr("::1")},
		{netip.MustParseAddr("::ffff:0.0.0.0"), netip.MustParseAddr("::ffff:255.255.255.255")},
		{netip.MustParseAddr("fe80::"), netip.MustParseAddr("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{netip.MustParseAddr("ff00::"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
	},
}

// dropRun is the run of meshDrops holding address, false for none
func dropRun(address netip.Addr) ([2]netip.Addr, bool) {
	for _, run := range meshDrops[address.BitLen()] {
		if run[0].Compare(address) <= 0 && address.Compare(run[1]) <= 0 {
			return run, true
		}
	}
	return [2]netip.Addr{}, false
}

func droppedByMesh(address netip.Addr) bool {
	_, ok := dropRun(address)
	return ok
}

// coveredByDrops is whether every address of prefix lies in some run, walked
// from its first address run by run past its last
func coveredByDrops(prefix netip.Prefix) bool {
	last := lastAddress(prefix)
	for at := prefix.Addr(); ; {
		run, ok := dropRun(at)
		switch {
		case !ok:
			return false
		case run[1].Compare(last) >= 0:
			return true
		}
		at = run[1].Next()
	}
}

// splitPrefixes are prefixes two runs share, or whose middle address lies in a
// run and whose other candidates do not
var splitPrefixes = []string{"224.0.0.0/3", "0.0.0.0/8", "169.254.0.0/16", "240.0.0.0/4", "::fffe:0:0/95", "169.252.0.0/14", "::/127"}

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

// anchorNear draws an address of a width-bit family: an end of a run the mesh
// drops or one a step or two either side of it, the end itself drawn outright,
// and one time in four an address drawn anywhere
func anchorNear(tc hegel.TestCase, width int) netip.Addr {
	if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
		if width == 32 {
			return hegel.Draw(tc, hegel.IPAddresses().IPv4())
		}
		return hegel.Draw(tc, hegel.IPAddresses().IPv6())
	}
	runs := meshDrops[width]
	end := runs[hegel.Draw(tc, hegel.Integers(0, len(runs)-1))][hegel.Draw(tc, hegel.Integers(0, 1))]
	n := new(big.Int).Add(new(big.Int).SetBytes(end.AsSlice()), big.NewInt(int64(hegel.Draw(tc, pbt.Spanning(-2, 2)))))
	n.Mod(n, new(big.Int).Lsh(big.NewInt(1), uint(width)))
	address, _ := netip.AddrFromSlice(n.FillBytes(make([]byte, width/8)))
	return address
}

// drawnPrefixes calls check with a host route the mesh drops the address of and
// a prefix runs share, each drawn outright, then with every prefix length of
// an address drawn near the runs of each family
func drawnPrefixes(ht *hegel.T, check func(netip.Prefix)) {
	check(netip.MustParsePrefix(hegel.Draw(ht, hegel.SampledFrom(droppedHosts))))
	check(netip.MustParsePrefix(hegel.Draw(ht, hegel.SampledFrom(splitPrefixes))))
	for _, width := range []int{32, 128} {
		at := anchorNear(ht, width)
		for bits := 0; bits <= width; bits++ {
			check(netip.PrefixFrom(at, bits).Masked())
		}
	}
}

// At every prefix length of both families, around each run the mesh drops and
// anywhere, and for host routes and prefixes split between runs drawn
// outright, the read address lies in its prefix and is no destination the mesh
// drops. It is the middle address wherever the mesh forwards to the middle, and
// otherwise the first of the base plus one and the last address less one the
// mesh forwards to. A host route reads its own address where the mesh forwards
// to it and nothing otherwise, and none is read only where the mesh forwards to
// no candidate
func TestReadAddressIsTheFirstCandidateTheMeshForwardsTo(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawnPrefixes(ht, func(prefix netip.Prefix) {
			got, ok := ReadAddress(prefix)
			candidates := modelCandidates(prefix)
			var want netip.Addr
			for _, candidate := range candidates {
				if !droppedByMesh(candidate) {
					want = candidate
					break
				}
			}
			switch {
			case ok && !prefix.Contains(got):
				ht.Fatalf("%s reads %s, outside it", prefix, got)
			case ok && droppedByMesh(got):
				ht.Fatalf("%s reads %s, which the mesh drops as a destination", prefix, got)
			case !droppedByMesh(candidates[0]) && got != candidates[0]:
				ht.Fatalf("%s reads %s (%v) where the mesh forwards to its first candidate %s", prefix, got, ok, candidates[0])
			case ok != want.IsValid():
				ht.Fatalf("%s reads %s (%v) where the first candidate the mesh forwards to is %s (%v)", prefix, got, ok, want, want.IsValid())
			case got != want:
				ht.Fatalf("%s reads %s, where the first candidate the mesh forwards to is %s", prefix, got, want)
			}
		})
	})
}

// Over the same prefixes, Validate refuses an advertised prefix exactly where
// the runs the mesh drops cover every address of it, in its fixed words, and
// an IPv4-mapped one for its spelling ahead of that
func TestValidateRefusesExactlyTheAdvertisedPrefixesTheMeshDropsWhole(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawnPrefixes(ht, func(prefix netip.Prefix) {
			var want string
			switch {
			case prefix.Addr().Is4In6():
				want = fmt.Sprintf("egress: cap.egress advertise %s is an IPv4 prefix written as IPv6, so write it as %s", prefix, netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96))
			case coveredByDrops(prefix):
				want = "egress: cap.egress advertise " + prefix.String() + " holds no address the mesh forwards a unicast packet to, so no packet through it reaches an exit"
			}
			var got string
			if err := (Egress{Advertise: []schema.Prefix{{Prefix: prefix}}}).Validate(); err != nil {
				got = err.Error()
			}
			if got != want {
				ht.Fatalf("advertising %s is refused with %q, want %q", prefix, got, want)
			}
		})
	})
}
