// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// a range this node announces that another router announces too is a conflict
// of each exemption overlapping it, the one naming it, one covering it and one
// inside it, under every interface, each naming the offer's router-id and
// carving nothing, and of no exemption beside it. A range of its own no other
// router announces is a conflict of none.
func TestOwnCopiesNameEachExemptionOverlappingTheRange(t *testing.T) {
	p := netip.MustParsePrefix
	exact := egress.Exemption{Interface: "eth1", Prefix: p("203.0.113.0/25")}
	covering := egress.Exemption{Interface: "eth2", Prefix: p("203.0.113.0/24")}
	inside := egress.Exemption{Prefix: p("203.0.113.64/26")}
	beside := egress.Exemption{Interface: "eth1", Prefix: p("203.0.113.128/25")}
	origin := func(prefix netip.Prefix) (string, bool) { return "0102030405060708", prefix == p("203.0.113.0/25") }
	got := OwnCopies([]egress.Exemption{beside, covering, exact, inside}, []netip.Prefix{p("203.0.113.0/25"), p("203.0.113.128/25")}, origin)
	own := func(exemption egress.Exemption) egress.ExemptConflict {
		return egress.ExemptConflict{Exemption: exemption, Prefix: p("203.0.113.0/25"), RouterID: "0102030405060708", Own: true}
	}
	if want := []egress.ExemptConflict{own(inside), own(exact), own(covering)}; !slices.Equal(got, want) {
		t.Errorf("the conflicts are %+v, want %+v", got, want)
	}
	if got := OwnCopies([]egress.Exemption{exact}, nil, origin); len(got) != 0 {
		t.Errorf("with no range of its own the conflicts are %+v, want none", got)
	}
}
