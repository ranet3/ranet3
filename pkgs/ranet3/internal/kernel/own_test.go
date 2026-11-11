// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// rewritingKernel is rejectingKernel on a platform whose kernel rewrites a
// host route out of the tun at an address of the tun's, as darwin's does
type rewritingKernel struct{ *rejectingKernel }

func (rewritingKernel) rewritesOwnRoutes() {}

// ownHarness is a reconciler in mode off with no policy rules on the covering
// fake with darwin's overlay holds, over coverOverlay, cap.table as tbl gives
// it and the tun holding addresses, on a platform whose kernel rewrites a host
// route at an address of the tun's where rewrites is set
func ownHarness(t *testing.T, tbl Table, rewrites bool, addresses ...netip.Prefix) (*Reconciler, *netstack.RouteTable, *rejectingKernel) {
	t.Helper()
	reconciler, table, covering := coveredHarness(t, tbl, Runtime{}, addresses...)
	k := &rejectingKernel{coveringKernel: covering, rejects: map[netip.Prefix]bool{}, others: map[netip.Prefix]string{}}
	var plat platform = k
	if rewrites {
		plat = rewritingKernel{k}
	}
	reconciler.use(plat)
	reconciler.rules = nil
	return reconciler, table, k
}

// holdAt reports whether the fake holds a hold at destination, and whether it
// holds it apart from the tun
func holdAt(k *rejectingKernel, destination netip.Prefix) (held, apart bool) {
	for _, r := range routesAt(k.fakeKernel, destination.String()) {
		if r.Unreachable {
			held, apart = true, apart || k.heldApart(r)
		}
	}
	return held, apart
}

// On a platform whose kernel rewrites a host route at an address of the tun's,
// a route of the mesh's table at one address the tun holds, at the length the
// tun holds it or at another, this node's own, a retracted one or a learned
// one at an address cap.table does not assign, goes in as nothing, and the
// pass counts it neither added nor skipped and warns of it nowhere. On one
// that does not it goes in, a hold as a hold and a learned route as a route
// out of the tun. A route at an address the tun does not hold and a hold wider
// than an address, its network address on the tun or not, go in on both. A
// learned IPv6 route from a source, the one family a source goes in in, does
// as one with none.
func TestRouteAtAnAddressOfTheTunsGoesInOnlyWhereTheKernelKeepsIt(t *testing.T) {
	tun := []netip.Prefix{prefix("192.0.2.1/32"), prefix("192.0.2.16/32"), prefix("3fff:c::1/128"), prefix("3fff:c::2/64")}
	var none netip.Prefix
	for _, c := range []struct {
		name          string
		source, entry netip.Prefix
		value         *netstack.Peer
		own           bool
	}{
		{"this node's own /32 at the tun's /32", none, prefix("192.0.2.1/32"), netstack.Local, true},
		{"this node's own /128 at the tun's /128", none, prefix("3fff:c::1/128"), netstack.Local, true},
		{"this node's own /128 at an address the tun holds as a /64", none, prefix("3fff:c::2/128"), netstack.Local, true},
		{"a retracted /32 at the tun's /32", none, prefix("192.0.2.1/32"), netstack.Unreachable, true},
		{"a retracted /128 at the tun's /128", none, prefix("3fff:c::1/128"), netstack.Unreachable, true},
		{"this node's own /32 off the tun", none, prefix("192.0.2.9/32"), netstack.Local, false},
		{"this node's own /128 off the tun", none, prefix("3fff:c::9/128"), netstack.Local, false},
		{"this node's own /28 holding the tun's address", none, prefix("192.0.2.0/28"), netstack.Local, false},
		{"a retracted /124 holding the tun's address", none, prefix("3fff:c::/124"), netstack.Unreachable, false},
		{"a retracted /28 at the network address the tun holds", none, prefix("192.0.2.16/28"), netstack.Unreachable, false},
		{"a learned /32 at the tun's /32", none, prefix("192.0.2.1/32"), learned, true},
		{"a learned /128 at the tun's /128", none, prefix("3fff:c::1/128"), learned, true},
		{"a learned /128 at an address the tun holds as a /64", none, prefix("3fff:c::2/128"), learned, true},
		{"a learned /32 off the tun", none, prefix("192.0.2.9/32"), learned, false},
		{"a learned /128 off the tun", none, prefix("3fff:c::9/128"), learned, false},
		{"a learned /128 from 3fff:d::/64 at the tun's /128", prefix("3fff:d::/64"), prefix("3fff:c::1/128"), learned, true},
	} {
		hold, kind := c.value != learned, "route out of the tun"
		if hold {
			kind = "hold"
		}
		for _, rewrites := range []bool{false, true} {
			said := logged(t)
			reconciler, table, k := ownHarness(t, Table{}, rewrites, tun...)
			table.Set(c.source, c.entry, c.value)
			if err := reconciler.reconcile(); err != nil {
				t.Fatalf("%s, rewritten %v: %v", c.name, rewrites, err)
			}
			want := !rewrites || !c.own
			if installed := slices.ContainsFunc(routesAt(k.fakeKernel, c.entry.String()), func(r Route) bool { return r.Unreachable == hold && r.Source == c.source }); installed != want {
				t.Errorf("%s, rewritten %v: the kernel holds a %s at %s %v, want %v: %v", c.name, rewrites, kind, c.entry, installed, want, k.snapshot())
			}
			if stats := reconciler.Stats(); stats.Skipped != 0 || stats.Desired != stats.Installed || stats.Added != stats.Installed {
				t.Errorf("%s, rewritten %v: the pass counts %d desired, %d installed, %d added and %d skipped, want each it wants added and none skipped", c.name, rewrites, stats.Desired, stats.Installed, stats.Added, stats.Skipped)
			}
			if strings.Contains(said.String(), "level=WARN") {
				t.Errorf("%s, rewritten %v: the pass warned:\n%s", c.name, rewrites, said)
			}
		}
	}
}

// A pass reads the tun's addresses from its listing of the tun, whoever wrote
// them, and not from cap.table. A hold at an address cap.table assigns goes
// in while the tun does not hold it and leaves once it does, a hold at an
// address another writer put on the tun goes in once that writer takes it
// off, and a pass that cannot list the tun keeps the last listing's
func TestHoldAtAnAddressOfTheTunsFollowsTheTunsListing(t *testing.T) {
	assigned, theirs := prefix("192.0.2.1/32"), prefix("3fff:c::7/128")
	reconciler, table, k := ownHarness(t, Table{Addresses: prefixes(assigned)}, true, theirs)
	table.Set(netip.Prefix{}, assigned, netstack.Local)
	table.Set(netip.Prefix{}, theirs, netstack.Local)
	step := func(what string, fails, wantAssigned, wantTheirs bool) {
		t.Helper()
		if err := reconciler.reconcile(); (err != nil) != fails {
			t.Errorf("%s: the pass returned %v, want an error %v", what, err, fails)
		}
		for _, c := range []struct {
			at   netip.Prefix
			want bool
		}{{assigned, wantAssigned}, {theirs, wantTheirs}} {
			if held, _ := holdAt(k, c.at); held != c.want {
				t.Errorf("%s: the kernel holds a hold at %s %v, want %v: %v", what, c.at, held, c.want, k.snapshot())
			}
		}
	}
	k.failAssign[assigned] = errors.New("operation not permitted")
	step("with the assigned address refused", true, true, false)
	delete(k.failAssign, assigned)
	step("with the assigned address on the tun", false, false, false)
	k.byHand(theirs, false)
	step("with the other writer's address taken off", false, false, true)
	k.byHand(theirs, true)
	k.failAddrs = errors.New("no buffer space available")
	step("with the listing failing", true, false, true)
	k.failAddrs = nil
	step("with the listing back", false, false, false)
}

// A learned route at an overlay prefix of two addresses, one of which the tun
// holds, goes in as its halves beside the prefix's hold apart from the tun. On
// a platform whose kernel rewrites a host route at an address of the tun's the
// half at that address goes in as nothing, no route at all standing there, the
// other half still goes in as a route out of the tun, the hold stays, and a
// second pass adds and skips nothing. On one that does not both halves go in.
func TestHalfOfAnOverlayKeyAtAnAddressOfTheTunsGoesInOnlyWhereTheKernelKeepsIt(t *testing.T) {
	for _, c := range []struct{ key, own, other netip.Prefix }{
		{prefix("198.51.100.0/31"), prefix("198.51.100.1/32"), prefix("198.51.100.0/32")},
		{prefix("3fff:c:0:1::/127"), prefix("3fff:c:0:1::1/128"), prefix("3fff:c:0:1::/128")},
	} {
		for _, rewrites := range []bool{false, true} {
			reconciler, table, k := ownHarness(t, Table{}, rewrites, c.own, coverAddresses[0], coverAddresses[1])
			reconciler.rt.Overlay = append(slices.Clone(coverOverlay), prefixes(c.key)...)
			table.Set(netip.Prefix{}, c.key, learned)
			for pass := range 2 {
				if err := reconciler.reconcile(); err != nil {
					t.Fatalf("%s, rewritten %v, pass %d: %v", c.key, rewrites, pass, err)
				}
				if stats := reconciler.Stats(); stats.Skipped != 0 || pass == 1 && stats.Added != 0 {
					t.Errorf("%s, rewritten %v: pass %d added %d routes and skipped %d, want none skipped and none added again", c.key, rewrites, pass, stats.Added, stats.Skipped)
				}
			}
			out := func(at netip.Prefix) bool {
				return slices.ContainsFunc(routesAt(k.fakeKernel, at.String()), func(r Route) bool { return !r.Unreachable })
			}
			if at := routesAt(k.fakeKernel, c.own.String()); rewrites && len(at) > 0 || !rewrites && !out(c.own) {
				t.Errorf("%s, rewritten %v: the kernel holds %v at the tun's %s, want nothing there where the kernel rewrites it and a route out of the tun where it does not: %v", c.key, rewrites, at, c.own, k.snapshot())
			}
			if !out(c.other) {
				t.Errorf("%s, rewritten %v: the kernel holds no route out of the tun at the other half %s: %v", c.key, rewrites, c.other, k.snapshot())
			}
			if held, apart := holdAt(k, c.key); !held || !apart {
				t.Errorf("%s, rewritten %v: the kernel holds a hold at the key %v, apart from the tun %v, want one apart: %v", c.key, rewrites, held, apart, k.snapshot())
			}
		}
	}
}

// An overlay prefix at an address of the tun's keeps its hold apart from the
// tun, which an entry of the mesh's there does not take away, on a platform
// whose kernel rewrites a host route out of the tun there and on one that does
// not. This node's own entry there is that hold. A learned route there and a
// hold from a source there, which the platform writes out of the tun, go in
// beside it on one that does not and as nothing on one that does.
func TestOverlayPrefixAtAnAddressOfTheTunsKeepsItsHold(t *testing.T) {
	var none netip.Prefix
	for _, c := range []struct {
		name        string
		source, own netip.Prefix
		value       *netstack.Peer
	}{
		{"this node's own /32", none, prefix("198.51.100.7/32"), netstack.Local},
		{"a learned /32", none, prefix("198.51.100.7/32"), learned},
		{"a learned /128", none, prefix("3fff:c::1/128"), learned},
		{"a retracted /128 from 3fff:d::/64", prefix("3fff:d::/64"), prefix("3fff:c::1/128"), netstack.Unreachable},
	} {
		for _, rewrites := range []bool{false, true} {
			reconciler, table, k := ownHarness(t, Table{}, rewrites, prefix("198.51.100.7/32"), coverAddresses[0], coverAddresses[1])
			reconciler.rt.Overlay = append(slices.Clone(coverOverlay), prefixes(c.own)...)
			table.Set(c.source, c.own, c.value)
			if err := reconciler.reconcile(); err != nil {
				t.Fatalf("%s, rewritten %v: %v", c.name, rewrites, err)
			}
			if held, apart := holdAt(k, c.own); !held || !apart {
				t.Errorf("%s, rewritten %v: the kernel holds a hold at %s %v, apart from the tun %v, want one apart: %v", c.name, rewrites, c.own, held, apart, k.snapshot())
			}
			if c.value == netstack.Local {
				continue
			}
			entry := slices.ContainsFunc(routesAt(k.fakeKernel, c.own.String()), func(r Route) bool {
				return !k.heldApart(r) && r.Source == c.source && r.Unreachable == (c.value == netstack.Unreachable)
			})
			if entry == rewrites {
				t.Errorf("%s, rewritten %v: the kernel holds the entry's route out of the tun at %s %v, want %v: %v", c.name, rewrites, c.own, entry, !rewrites, k.snapshot())
			}
		}
	}
}
