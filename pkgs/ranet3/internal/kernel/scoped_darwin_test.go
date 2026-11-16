// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// TestDarwinScopedRouteSelection establishes which sockets reach a route
// carrying RTF_IFSCOPE, which decides whether a Mac can hold an
// address an exit announces without taking the whole default route.
//
// This test owns the utun's file descriptor, so a packet arriving on it proves
// the kernel selected that route, without needing a peer or a second host.
func TestDarwinScopedRouteSelection(t *testing.T) {
	requireNetTest(t)

	device, tun := createUTUNWithFD(t)
	setInterfaceUp(t, device)
	tbl, rt := platformFor(device)
	opened, err := newPlatform(tbl, rt)
	if err != nil {
		t.Fatalf("open the darwin platform on %s: %v", device, err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*routePlatform)

	local := netip.MustParsePrefix("198.51.100.1/24")
	if err := plat.AddAddr(local); err != nil {
		t.Fatalf("assign %s to %s: %v", local, device, err)
	}
	// TEST-NET-3, which cannot collide with anything real on this machine.
	remote := netip.MustParsePrefix("203.0.113.0/24")
	target := netip.MustParseAddr("203.0.113.9")

	t.Run("unscoped route", func(t *testing.T) {
		if err := plat.AddRoute(Route{Destination: remote}); err != nil {
			t.Fatalf("install %s: %v", remote, err)
		}
		t.Cleanup(func() { _ = plat.DelRoute(Route{Destination: remote}) })
		// An ordinary destination route is the kind every macOS VPN installs for
		// split tunneling, and it is reached without scoping anything.
		if !reaches(t, tun, target, netip.Addr{}, 0) {
			t.Error("an unscoped route did not carry a packet from an unbound socket")
		}
		if !reaches(t, tun, target, local.Addr(), 0) {
			t.Error("an unscoped route did not carry a packet from a socket bound to its address")
		}
	})

	t.Run("scoped route", func(t *testing.T) {
		if err := plat.addScopedRoute(remote); err != nil {
			t.Fatalf("install %s scoped to %s: %v", remote, device, err)
		}
		t.Cleanup(func() { _ = plat.delScopedRoute(remote) })

		unbound := reaches(t, tun, target, netip.Addr{}, 0)
		bound := reaches(t, tun, target, local.Addr(), 0)
		boundIf := reaches(t, tun, target, netip.Addr{}, plat.index)

		// Report before asserting: this test exists to answer the question,
		// and the three answers together are the answer.
		t.Logf("scoped route reached by: unbound socket %v, socket bound to %s %v, IP_BOUND_IF %v",
			unbound, local.Addr(), bound, boundIf)
		switch {
		case bound:
			t.Log("binding a source address scopes the lookup: a Mac can hold an " +
				"exit-announced address with a scoped route and keep its own default")
		case boundIf:
			t.Log("only IP_BOUND_IF scopes the lookup, so a scoped route is invisible " +
				"to an ordinary application and a Mac needs either a full tunnel or pf")
		default:
			t.Log("nothing reached the scoped route, so RTF_IFSCOPE is not usable here at all")
		}
		if unbound && !bound {
			t.Error("an unbound socket reached a scoped route while a bound one did not, " +
				"which contradicts what scoping is for")
		}
		if !bound {
			t.Error("a socket bound to an address on the interface did not reach the " +
				"scoped route, so AddRoute must go back to skipping source-specific routes")
		}
	})

	// What the reconciler actually does with an exit's announcement, end to
	// end: a source-specific route installs, is reachable only from an address
	// of ours, is stable across a dump so a pass does not churn it, and comes
	// back out again.
	t.Run("source-specific route through the reconciler", func(t *testing.T) {
		// Scoped is how the kernel keys it, and a dump fills it in, but a route
		// built by hand has to say so, or the withdrawal below goes unscoped
		// and removes nothing.
		announced := Route{Destination: remote, Source: local.Masked(), Scoped: true}
		if err := plat.AddRoute(announced); err != nil {
			t.Fatalf("install %s: %v", announced, err)
		}
		t.Cleanup(func() { _ = plat.DelRoute(announced) })

		if reaches(t, tun, target, netip.Addr{}, 0) {
			t.Error("an unbound socket reached a source-specific route, which would " +
				"mean the Mac's own traffic was captured by the mesh")
		}
		if !reaches(t, tun, target, local.Addr(), 0) {
			t.Error("a socket bound to our address did not reach the source-specific route")
		}

		// The dump has to report it the way it was installed, or every
		// reconcile pass would delete and reinstall it.
		routes, err := plat.Routes()
		if err != nil {
			t.Fatalf("list routes: %v", err)
		}
		found := false
		for _, r := range routes {
			if r.Destination == announced.Destination && r.Source == announced.Source {
				found = true
			}
		}
		if !found {
			t.Fatalf("the dump does not report %s as installed: %v", announced, routes)
		}

		if err := plat.DelRoute(announced); err != nil {
			t.Fatalf("withdraw %s: %v", announced, err)
		}
		if reaches(t, tun, target, local.Addr(), 0) {
			t.Error("the source-specific route still carries traffic after withdrawal")
		}
	})

	// A source prefix that is not ours cannot be expressed by interface scope,
	// and must be refused rather than installed as an ordinary route that would
	// capture everything to that destination.
	t.Run("a source prefix that is not ours is refused", func(t *testing.T) {
		foreign := Route{Destination: remote, Source: netip.MustParsePrefix("192.0.2.0/24")}
		if err := plat.AddRoute(foreign); !errors.Is(err, errRouteSkipped) {
			t.Fatalf("AddRoute reported %v rather than reporting the route skipped", err)
		}
		if reaches(t, tun, target, netip.Addr{}, 0) || reaches(t, tun, target, local.Addr(), 0) {
			t.Error("a source prefix belonging to another node installed a route anyway")
		}
	})
}

// A route holding a listed endpoint goes in unscoped, in mode off and in a
// covered family, so the Mac's own traffic reaches the rest of it through the
// mesh, and the pass cuts the endpoint out of it instead (see cutHoles)
func TestDarwinLeavesARouteHoldingAnEndpointUnscoped(t *testing.T) {
	peer := netip.MustParseAddr("2001:db8:beef::1")
	plat, _ := testPlatform(t, Table{}, Runtime{Underlay: func() []netip.Addr { return []netip.Addr{peer} }})
	if _, err := plat.Routes(); err != nil {
		t.Fatal(err)
	}
	covering := Route{Destination: prefix("2001:db8::/32")}
	for _, families := range [][]Family{nil, {FamilyIPv6}} {
		plat.cover(nil, families, nil, hostTable{})
		if plat.scopeRoute(covering) {
			t.Errorf("covering %v, a /32 holding a peer's endpoint goes in scoped, so the Mac's own traffic misses all of it", families)
		}
	}
}

// A route schema.CapturesTheMachine counts goes in scoped, a split internet and
// a wide prefix as much as a default, so an unbound send meets it only where
// its longest unscoped match leaves by the tun, while one at the floor stays
// unscoped.
func TestDarwinScopesARouteThatCountsAsADefault(t *testing.T) {
	plat, _ := testPlatform(t, Table{}, Runtime{})
	for destination, want := range map[string]bool{
		"::/0":        true,
		"64.0.0.0/2":  true,
		"192.0.0.0/7": true,
		"2000::/3":    true,
		"fd00::/8":    true,
		"192.0.0.0/8": false,
		"2001::/16":   false,
	} {
		if got := plat.scopeRoute(Route{Destination: prefix(destination)}); got != want {
			t.Errorf("%s is scoped %v, want %v", destination, got, want)
		}
	}
}

// scopeLookupFamily is one family's addresses: mesh and other are the two
// utuns' own, held lies inside wide and holds narrow, target lies in narrow,
// beside in wide outside narrow, and aside in held outside narrow. piece is
// the piece of held or wide cut around narrow that holds aside, and foreign a
// source holding no address of either utun.
type scopeLookupFamily struct {
	name                  string
	mesh, other           netip.Prefix
	narrow, held, wide    netip.Prefix
	target, beside, aside netip.Addr
	piece, foreign        netip.Prefix
	cells                 map[string]map[string]scopeLookupWant
}

type scopeLookupCell struct {
	errno       unix.Errno
	utun, other bool
}

func (c scopeLookupCell) String() string {
	return fmt.Sprintf("err=%s utun=%s other=%s", errnoWord(c.errno), readWord(c.utun), readWord(c.other))
}

// scopeLookupWant is a cell as the table holds it. hostErrno leaves the errno
// out for a send the Mac's own routes answer, its default where it has one,
// while no route of the host's leaves by a utun the test made.
type scopeLookupWant struct {
	scopeLookupCell
	hostErrno bool
}

func (w scopeLookupWant) matches(c scopeLookupCell) bool {
	return c.utun == w.utun && c.other == w.other && (w.hostErrno || c.errno == w.errno)
}

func (w scopeLookupWant) String() string {
	if w.hostErrno {
		return fmt.Sprintf("err=any utun=%s other=%s", readWord(w.utun), readWord(w.other))
	}
	return w.scopeLookupCell.String()
}

var (
	scopeCarried = scopeLookupWant{scopeLookupCell: scopeLookupCell{utun: true}}
	scopeRefused = scopeLookupWant{scopeLookupCell: scopeLookupCell{errno: unix.ENETUNREACH}}
	scopeOther   = scopeLookupWant{scopeLookupCell: scopeLookupCell{other: true}}
	scopeHost    = scopeLookupWant{hostErrno: true}
)

var scopeLookupFamilies = []scopeLookupFamily{
	{
		name: "ipv4", mesh: prefix("198.51.100.1/24"), other: prefix("192.0.2.1/24"),
		narrow: prefix("203.0.113.0/28"), held: prefix("203.0.113.0/26"), wide: prefix("203.0.113.0/24"),
		target: netip.MustParseAddr("203.0.113.9"), beside: netip.MustParseAddr("203.0.113.200"),
		aside: netip.MustParseAddr("203.0.113.33"),
		piece: prefix("203.0.113.32/27"), foreign: prefix("192.0.2.128/25"),
		cells: map[string]map[string]scopeLookupWant{
			"isolated":      {"unbound": scopeHost, "address": scopeCarried, "boundif": scopeCarried},
			"other":         {"unbound": scopeOther, "address": scopeCarried, "boundif": scopeCarried},
			"same":          {"unbound": scopeCarried, "address": scopeCarried, "boundif": scopeCarried},
			"removed":       {"unbound": scopeHost},
			"whole":         {"unbound": scopeCarried, "address": scopeCarried, "boundif": scopeCarried},
			"whole.aside":   {"unbound": scopeHost, "address": scopeCarried, "boundif": scopeCarried},
			"wider":         {"unbound": scopeCarried, "address": scopeCarried, "boundif": scopeCarried},
			"wider.aside":   {"unbound": scopeHost, "address": scopeCarried, "boundif": scopeCarried},
			"nested":        {"unbound": scopeCarried, "address": scopeCarried, "boundif": scopeCarried},
			"nested.aside":  {"unbound": scopeCarried, "address": scopeCarried, "boundif": scopeCarried},
			"host":          {"unbound": scopeCarried, "address": scopeCarried, "boundif": scopeCarried},
			"host.aside":    {"unbound": scopeHost, "address": scopeCarried, "boundif": scopeCarried},
			"outer":         {"unbound": scopeCarried, "address": scopeCarried, "boundif": scopeCarried},
			"skipped.aside": {"unbound": scopeHost, "address": scopeCarried, "boundif": scopeCarried},
			"parted":        {"unbound": scopeCarried, "address": scopeCarried, "boundif": scopeCarried},
		},
	},
	{
		name: "ipv6", mesh: prefix("2001:db8:bb::1/64"), other: prefix("2001:db8:aa::1/64"),
		narrow: prefix("2001:db8:ffff::/64"), held: prefix("2001:db8:ffff::/56"), wide: prefix("2001:db8:ffff::/48"),
		target: netip.MustParseAddr("2001:db8:ffff::9"), beside: netip.MustParseAddr("2001:db8:ffff:1::9"),
		aside: netip.MustParseAddr("2001:db8:ffff:2::9"),
		piece: prefix("2001:db8:ffff:2::/63"), foreign: prefix("2001:db8:5::/48"),
		cells: map[string]map[string]scopeLookupWant{
			"isolated":      {"unbound": scopeHost, "address": scopeCarried, "boundif": scopeRefused},
			"other":         {"unbound": scopeOther, "address": scopeCarried, "boundif": scopeRefused},
			"same":          {"unbound": scopeRefused, "address": scopeCarried, "boundif": scopeRefused},
			"removed":       {"unbound": scopeHost},
			"whole":         {"unbound": scopeRefused, "address": scopeCarried, "boundif": scopeRefused},
			"whole.aside":   {"unbound": scopeHost, "address": scopeCarried, "boundif": scopeRefused},
			"wider":         {"unbound": scopeCarried, "address": scopeCarried, "boundif": scopeCarried},
			"wider.aside":   {"unbound": scopeHost, "address": scopeCarried, "boundif": scopeRefused},
			"nested":        {"unbound": scopeCarried, "address": scopeCarried, "boundif": scopeCarried},
			"nested.aside":  {"unbound": scopeRefused, "address": scopeCarried, "boundif": scopeRefused},
			"host":          {"unbound": scopeCarried, "address": scopeCarried, "boundif": scopeCarried},
			"host.aside":    {"unbound": scopeHost, "address": scopeCarried, "boundif": scopeRefused},
			"outer":         {"unbound": scopeRefused, "address": scopeCarried, "boundif": scopeRefused},
			"skipped.aside": {"unbound": scopeHost, "address": scopeCarried, "boundif": scopeRefused},
			"parted":        {"unbound": scopeRefused, "address": scopeCarried, "boundif": scopeRefused},
		},
	},
}

// routeWant is a route by its destination, its interface, and its RTF_REJECT
// and RTF_IFSCOPE
type routeWant struct {
	prefix netip.Prefix
	device string
	flags  int
}

func (w routeWant) matches(a routeAnswer) bool {
	return a.prefix == w.prefix && a.device == w.device && a.flags&(unix.RTF_REJECT|unix.RTF_IFSCOPE) == w.flags
}

func (w routeWant) String() string {
	return fmt.Sprintf("%s flags=%s if=%s", w.prefix, routeFlagNames(w.flags), w.device)
}

var scopeLookupSockets = []string{"unbound", "address", "boundif"}

// A hold scoped to the mesh utun, as scopeRoute installs one, alone, beside a
// wider route on another interface, under a wider unscoped route of the same
// utun, and over a narrower one: whole, as a pass leaves it past the budget of
// pieces, and cut as the reconciler cuts it, under a live route of its own
// and not, under a hold left whole, over a live host route, which the cut
// leaves alone, beside a live route the platform skips, which the cut does
// not leave out, and beside the same route from a source holding the utun's
// address, which the platform writes scoped and a lookup at aside meets. In a
// family the platform holds as addressless the platform skips both the hold
// and the live route. A hold over the parts the endpoint cut leaves of a
// live route around it stays whole. A cell at aside is at an address of the
// hold outside the live route.
// Each cell is logged as `cell <family> <setting> <socket>: ...` for a script
// to read.
func TestDarwinScopedHoldBesideRoutesOfTheSameUTUN(t *testing.T) {
	requireNetTest(t)
	meshName, meshFD := createUTUNWithFD(t)
	setInterfaceUp(t, meshName)
	otherName, otherFD := createUTUNWithFD(t)
	setInterfaceUp(t, otherName)
	mesh := testTUNPlatform(t, meshName)
	other := testTUNPlatform(t, otherName)
	for _, family := range scopeLookupFamilies {
		if err := mesh.AddAddr(family.mesh); err != nil {
			t.Fatalf("assign %s to %s: %v", family.mesh, meshName, err)
		}
		if err := other.AddAddr(family.other); err != nil {
			t.Fatalf("assign %s to %s: %v", family.other, otherName, err)
		}
	}
	waitHoleDAD(t, meshName)
	waitHoleDAD(t, otherName)

	for _, family := range scopeLookupFamilies {
		t.Run(family.name, func(t *testing.T) {
			lab := scopeLookupLab{family: family, mesh: mesh, other: other, meshFD: meshFD, otherFD: otherFD, checked: map[string]bool{}}
			hold := routeWant{prefix: family.narrow, device: meshName, flags: unix.RTF_REJECT | unix.RTF_IFSCOPE}
			installRoute(t, mesh, Route{Destination: family.narrow, Unreachable: true})

			lab.check(t, "isolated", family.target, &hold, nil, scopeLookupSockets...)

			wide := Route{Destination: family.wide}
			installRoute(t, other, wide)
			lab.check(t, "other", family.target, &hold, &routeWant{prefix: family.wide, device: otherName}, scopeLookupSockets...)
			withdrawRoute(t, other, wide)

			installRoute(t, mesh, wide)
			if answer := lookUpRoute(t, family.beside, 0); !(routeWant{prefix: family.wide, device: meshName}).matches(answer) {
				t.Fatalf("an unbound lookup of %s answers %s, want %s unscoped on %s", family.beside, answer.fields(""), family.wide, meshName)
			}
			lab.check(t, "same", family.target, &hold, &hold, scopeLookupSockets...)
			withdrawRoute(t, mesh, wide)

			lab.check(t, "removed", family.target, &hold, nil, "unbound")

			withdrawRoute(t, mesh, Route{Destination: family.narrow, Unreachable: true})
			if answer := lookUpRoute(t, family.target, mesh.index); hold.matches(answer) {
				t.Fatalf("after its withdrawal the lookup of %s scoped to the utun still answers the hold %s", family.target, answer.fields(""))
			}
			wideHold := routeWant{prefix: family.wide, device: meshName, flags: unix.RTF_REJECT | unix.RTF_IFSCOPE}
			narrow := routeWant{prefix: family.narrow, device: meshName}
			piece := routeWant{prefix: family.piece, device: meshName, flags: unix.RTF_REJECT | unix.RTF_IFSCOPE}
			heldWide, liveNarrow := Route{Destination: family.wide, Unreachable: true}, Route{Destination: family.narrow}
			held := Route{Destination: family.held, Unreachable: true}
			lab.setting(t, []Route{heldWide, liveNarrow}, nil, func([]Route) {
				lab.check(t, "whole", family.target, &wideHold, &wideHold, scopeLookupSockets...)
				lab.check(t, "whole.aside", family.aside, &wideHold, nil, scopeLookupSockets...)
			})
			routes := []Route{heldWide, liveNarrow}
			lab.setting(t, routes, routes, func([]Route) {
				lab.check(t, "wider", family.target, &narrow, &narrow, scopeLookupSockets...)
				lab.check(t, "wider.aside", family.aside, &piece, nil, scopeLookupSockets...)
			})
			routes = []Route{wide, held, liveNarrow}
			lab.setting(t, routes, routes, func([]Route) {
				lab.check(t, "nested", family.target, &narrow, &narrow, scopeLookupSockets...)
				lab.check(t, "nested.aside", family.aside, &piece, &piece, scopeLookupSockets...)
			})
			// the hold at held cut around narrow under the hold at wide whole, as
			// a pass leaves them past the budget of pieces
			routes = []Route{held, liveNarrow}
			pieces, _ := cutHolds(routes, routes, mesh.scopeRoute, []netip.Prefix{family.mesh}, nil, holdPieceBudget)
			lab.setting(t, append([]Route{heldWide}, pieces...), nil, func([]Route) {
				lab.check(t, "outer", family.target, &wideHold, &wideHold, scopeLookupSockets...)
			})
			// a live host route at target inside the hold at wide, which the cut
			// leaves alone, answering ahead of the hold
			host := Route{Destination: netip.PrefixFrom(family.target, family.target.BitLen())}
			routes = []Route{host, heldWide}
			lab.setting(t, routes, routes, func(installed []Route) {
				if len(installed) != 2 {
					t.Errorf("the cut makes %v of a hold around a host route, want both as they were", installed)
				}
				hostWant := routeWant{prefix: host.Destination, device: meshName}
				lab.check(t, "host", family.target, &hostWant, &hostWant, scopeLookupSockets...)
				lab.check(t, "host.aside", family.aside, &wideHold, nil, scopeLookupSockets...)
			})
			// a live route at aside from a source the platform skips, as setting
			// asserts, whose addresses the piece holding aside then holds
			skipped := Route{Destination: netip.PrefixFrom(family.aside, family.narrow.Bits()).Masked(), Source: family.foreign}
			routes = []Route{heldWide, liveNarrow, skipped}
			lab.setting(t, routes, routes, func([]Route) {
				lab.check(t, "skipped.aside", family.aside, &piece, nil, scopeLookupSockets...)
			})
			// the same live route from a source holding the utun's address, which
			// the platform writes scoped, as setting asserts, and which a lookup
			// at aside meets
			sourced := Route{Destination: skipped.Destination, Source: family.mesh.Masked()}
			routes = []Route{heldWide, liveNarrow, sourced}
			lab.setting(t, routes, routes, func(installed []Route) {
				if !slices.Contains(installed, sourced) {
					t.Errorf("the setting installs %v, without %s from %s", installed, sourced.Destination, sourced.Source)
				}
				lab.check(t, "sourced.aside", family.aside, &routeWant{prefix: sourced.Destination, device: meshName, flags: unix.RTF_IFSCOPE}, nil)
			})
			// the hold and the live route in a family the platform holds as
			// addressless, both of which the platform skips, as setting asserts
			func() {
				lab.mesh.bare = []Family{familyOf(family.target)}
				defer func() { lab.mesh.bare = nil }()
				routes = []Route{heldWide, liveNarrow}
				lab.setting(t, routes, routes, func(installed []Route) {
					if len(installed) != 0 {
						t.Errorf("the setting installs %v in a family the platform holds as addressless, want none", installed)
					}
				})
			}()
			// the hold at held whole beside the parts the endpoint cut leaves of
			// the live route at wide around aside, which lie inside the hold
			parted := []Route{held}
			for _, part := range without(family.wide, hostPrefixes(family.aside)) {
				parted = append(parted, Route{Destination: part})
			}
			heldWant := routeWant{prefix: family.held, device: meshName, flags: unix.RTF_REJECT | unix.RTF_IFSCOPE}
			lab.setting(t, parted, []Route{wide, held}, func(installed []Route) {
				if len(installed) != len(parted) {
					t.Errorf("the cut makes %d routes of the hold and %d parts of a route around it, want them as they were", len(installed), len(parted)-1)
				}
				lab.check(t, "parted", family.target, &heldWant, &heldWant, scopeLookupSockets...)
			})

			for setting, sockets := range family.cells {
				for socket := range sockets {
					if !lab.checked[setting+" "+socket] {
						t.Errorf("the table holds cell %s %s %s, which no setting sends", family.name, setting, socket)
					}
				}
			}
		})
	}
}

// scopeLookupLab is one family's run on the two utuns, other standing in for
// another interface
type scopeLookupLab struct {
	family          scopeLookupFamily
	mesh, other     *routePlatform
	meshFD, otherFD int
	checked         map[string]bool
}

// installRoute and withdrawRoute delete a route under the scope it went in
// with, since an unscoped delete does not remove a scoped route, and DelRoute
// takes the kernel's ESRCH as done
func installRoute(t *testing.T, on *routePlatform, r Route) {
	t.Helper()
	scoped := r
	scoped.Scoped = on.scopeRoute(r)
	if err := on.AddRoute(r); err != nil {
		t.Fatalf("install %s on %s: %v", r.Destination, on.rt.Interface, err)
	}
	t.Cleanup(func() { _ = on.DelRoute(scoped) })
}

func withdrawRoute(t *testing.T, on *routePlatform, r Route) {
	t.Helper()
	r.Scoped = on.scopeRoute(r)
	if err := on.DelRoute(r); err != nil {
		t.Fatalf("withdraw %s from %s: %v", r.Destination, on.rt.Interface, err)
	}
}

// setting installs routes on the mesh utun, after the reconciler's cut of
// their holds around the live routes of table where table is not nil
// (cutHolds), each skipped by the platform exactly where the cut takes it for
// one the platform does not write (platformWrites), on the utun's address and
// the families the platform holds as addressless, as a pass hands both, runs
// checks with what went in, and withdraws each again under its scope
func (lab *scopeLookupLab) setting(t *testing.T, routes, table []Route, checks func([]Route)) {
	t.Helper()
	tun := []netip.Prefix{lab.family.mesh}
	if table != nil {
		routes, _ = cutHolds(routes, table, lab.mesh.scopeRoute, tun, lab.mesh.bare, holdPieceBudget)
	}
	var installed []Route
	for _, r := range routes {
		err := lab.mesh.AddRoute(r)
		if writes := platformWrites(r, tun, lab.mesh.bare); writes == errors.Is(err, errRouteSkipped) {
			t.Fatalf("installing %s from %s answers %v, where the cut takes it as written: %v", r.Destination, r.Source, err, writes)
		}
		if err != nil && !errors.Is(err, errRouteSkipped) {
			t.Fatalf("install %s on %s: %v", r.Destination, lab.mesh.rt.Interface, err)
		}
		if err == nil {
			scoped := r
			scoped.Scoped = lab.mesh.scopeRoute(r)
			t.Cleanup(func() { _ = lab.mesh.DelRoute(scoped) })
			installed = append(installed, r)
		}
	}
	checks(installed)
	for i := len(installed) - 1; i >= 0; i-- {
		withdrawRoute(t, lab.mesh, installed[i])
	}
}

// check compares each lookup of destination whose want is not nil, and each
// cell the table holds
func (lab *scopeLookupLab) check(t *testing.T, setting string, destination netip.Addr, scoped, unscoped *routeWant, sockets ...string) {
	t.Helper()
	unscopedAnswer := lookUpRoute(t, destination, 0)
	scopedAnswer := lookUpRoute(t, destination, lab.mesh.index)
	if scoped != nil && !scoped.matches(scopedAnswer) {
		t.Errorf("%s: the lookup of %s scoped to the utun answers %s, want %s", setting, destination, scopedAnswer.fields(""), *scoped)
	}
	if unscoped != nil && !unscoped.matches(unscopedAnswer) {
		t.Errorf("%s: the unscoped lookup of %s answers %s, want %s", setting, destination, unscopedAnswer.fields(""), *unscoped)
	}
	for _, socket := range sockets {
		payload := []byte("scope " + lab.family.name + " " + setting + " " + socket)
		source, boundIf := netip.Addr{}, 0
		switch socket {
		case "address":
			source = lab.family.mesh.Addr()
		case "boundif":
			boundIf = lab.mesh.index
		}
		got := scopeLookupCell{errno: sendTo(t, destination, source, boundIf, payload)}
		if got.errno == 0 {
			got.utun = carriedOut(lab.meshFD, destination, payload)
			if !got.utun {
				got.other = carriedOut(lab.otherFD, destination, payload)
			}
		}
		t.Logf("cell %s %s %s: err=%s utun=%s %s %s other=%s", lab.family.name, setting, socket,
			errnoWord(got.errno), readWord(got.utun), unscopedAnswer.fields(""), scopedAnswer.fields("scoped_"), readWord(got.other))
		lab.checked[setting+" "+socket] = true
		if want, ok := lab.family.cells[setting][socket]; ok && !want.matches(got) {
			t.Errorf("cell %s %s %s measured %s, want %s", lab.family.name, setting, socket, got, want)
		}
	}
}

func errnoWord(errno unix.Errno) string {
	if errno == 0 {
		return "none"
	}
	return unix.ErrnoName(errno)
}

func readWord(read bool) string {
	if read {
		return "read"
	}
	return "none"
}

// routeAnswer is the route an RTM_GET names, with no name where the kernel has
// none
type routeAnswer struct {
	name   string
	prefix netip.Prefix
	flags  int
	index  int
	device string
}

func (a routeAnswer) fields(lead string) string {
	if a.name == "" {
		return fmt.Sprintf("%sroute=none %sflags=none %sif=none", lead, lead, lead)
	}
	return fmt.Sprintf("%sroute=%s %sflags=%s %sif=%s", lead, a.name, lead, routeFlagNames(a.flags), lead, a.device)
}

// lookUpRoute is the route RTM_GET answers for destination, scoped to the
// interface at scope where it is nonzero. XNU answers it through rt_lookup
// with that scope, the lookup a send scoped to that interface makes.
func lookUpRoute(t *testing.T, destination netip.Addr, scope int) routeAnswer {
	t.Helper()
	fd, err := lookupSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	seq := int(lookupSeq.Add(1))
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = routeAddr(destination)
	flags := unix.RTF_UP
	if scope != 0 {
		flags |= unix.RTF_IFSCOPE
	}
	raw, err := (&route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_GET,
		Flags:   flags,
		Index:   scope,
		ID:      uintptr(os.Getpid()),
		Seq:     seq,
		Addrs:   addrs,
	}).Marshal()
	if err != nil {
		t.Fatalf("encode a route lookup for %s: %v", destination, err)
	}
	if _, err := unix.Write(fd, raw); errors.Is(err, unix.ESRCH) {
		return routeAnswer{}
	} else if err != nil {
		t.Fatalf("ask for the route to %s scoped to %d: %v", destination, scope, err)
	}
	answer, err := readAnswer(fd, seq, destination)
	if err != nil {
		t.Fatal(err)
	}
	found, ok := dumpedPrefix(answer)
	name := found.String()
	if !ok {
		name = "unknown"
	}
	device := "none"
	if answer.Index != 0 {
		device = fmt.Sprintf("index%d", answer.Index)
		if named, err := net.InterfaceByIndex(answer.Index); err == nil {
			device = named.Name
		}
	}
	return routeAnswer{name: name, prefix: found, flags: answer.Flags, index: answer.Index, device: device}
}

// askRoute is the interface lookUpRoute answers, zero for no route
func askRoute(t *testing.T, destination netip.Addr, index int) int {
	t.Helper()
	return lookUpRoute(t, destination, index).index
}

var routeFlags = []struct {
	bit  int
	name string
}{
	{unix.RTF_UP, "UP"},
	{unix.RTF_GATEWAY, "GATEWAY"},
	{unix.RTF_HOST, "HOST"},
	{unix.RTF_REJECT, "REJECT"},
	{unix.RTF_BLACKHOLE, "BLACKHOLE"},
	{unix.RTF_STATIC, "STATIC"},
	{unix.RTF_CLONING, "CLONING"},
	{unix.RTF_PRCLONING, "PRCLONING"},
	{unix.RTF_WASCLONED, "WASCLONED"},
	{unix.RTF_IFSCOPE, "IFSCOPE"},
}

func routeFlagNames(flags int) string {
	var names []string
	for _, flag := range routeFlags {
		if flags&flag.bit != 0 {
			names = append(names, flag.name)
			flags &^= flag.bit
		}
	}
	if flags != 0 {
		names = append(names, fmt.Sprintf("%#x", flags))
	}
	return strings.Join(names, ",")
}

// addScopedRoute and delScopedRoute install and withdraw a scoped route the
// reconciler would not: a plain destination, which scopeRoute leaves
// unscoped. The pair exists to isolate what RTF_IFSCOPE does to a lookup from
// what the reconciler chooses to do with it, so neither touches the
// bookkeeping. The kernel keys a scoped route separately, so the withdrawal
// has to carry the flag too, or the route stays and the next subtest's install
// collides with it.
func (p *routePlatform) addScopedRoute(destination netip.Prefix) error {
	return p.writeScopedRoute(unix.RTM_ADD, destination)
}

func (p *routePlatform) delScopedRoute(destination netip.Prefix) error {
	return p.writeScopedRoute(unix.RTM_DELETE, destination)
}

func (p *routePlatform) writeScopedRoute(kind int, destination netip.Prefix) error {
	message, err := p.routeMessage(kind, Route{Destination: destination})
	if err != nil {
		return err
	}
	message.Flags |= unix.RTF_IFSCOPE
	return p.sock.WriteRoute(message)
}

// reaches sends one UDP datagram to target and reports whether it arrived on
// the tun descriptor, which only happens if the kernel selected the route out
// of that interface.
func reaches(t *testing.T, tun int, target, source netip.Addr, boundIf int) bool {
	t.Helper()
	drainTUN(tun)
	if errno := sendTo(t, target, source, boundIf, []byte("scope probe")); errno != 0 {
		// no route was selected for this socket
		t.Logf("sendto %s (source %v, boundif %d): %v", target, source, boundIf, errno)
		return false
	}
	return readTUN(tun, 300*time.Millisecond)
}

// sendTo sends payload to target at holePort from a UDP socket of target's
// family, bound to source where it is valid and by IP_BOUND_IF or
// IPV6_BOUND_IF to the interface at boundIf where it is nonzero, and returns
// the errno the send answers
func sendTo(t *testing.T, target, source netip.Addr, boundIf int, payload []byte) unix.Errno {
	t.Helper()
	domain, level, option := unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	sockaddr := func(address netip.Addr, port int) unix.Sockaddr {
		return &unix.SockaddrInet6{Addr: address.As16(), Port: port}
	}
	if target.Is4() {
		domain, level, option = unix.AF_INET, unix.IPPROTO_IP, unix.IP_BOUND_IF
		sockaddr = func(address netip.Addr, port int) unix.Sockaddr {
			return &unix.SockaddrInet4{Addr: address.As4(), Port: port}
		}
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("open a udp socket: %v", err)
	}
	defer unix.Close(fd)
	if boundIf != 0 {
		if err := unix.SetsockoptInt(fd, level, option, boundIf); err != nil {
			t.Fatalf("bind to interface %d: %v", boundIf, err)
		}
	}
	if source.IsValid() {
		if err := unix.Bind(fd, sockaddr(source, 0)); err != nil {
			t.Fatalf("bind to %s: %v", source, err)
		}
	}
	err = unix.Sendto(fd, payload, 0, sockaddr(target, holePort))
	var errno unix.Errno
	if err != nil && !errors.As(err, &errno) {
		t.Fatalf("send to %s: %v", target, err)
	}
	return errno
}

// drainTUN empties anything already queued so a read cannot see an earlier
// probe's packet.
func drainTUN(fd int) {
	_ = unix.SetNonblock(fd, true)
	buf := make([]byte, 2048)
	for {
		if _, err := unix.Read(fd, buf); err != nil {
			return
		}
	}
}

// readTUN waits for one packet, which the kernel prefixes with a four byte
// address family on a utun.
func readTUN(fd int, within time.Duration) bool {
	_ = unix.SetNonblock(fd, true)
	buf := make([]byte, 2048)
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		n, err := unix.Read(fd, buf)
		if err == nil && n > 4 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func requireNetTest(t *testing.T) {
	t.Helper()
	if os.Getenv("RANET3_DARWIN_NETTEST") != "1" {
		t.Skip("set RANET3_DARWIN_NETTEST=1 to run against the real kernel")
	}
	if os.Geteuid() != 0 {
		t.Skip("run as root to create a utun and write routes")
	}
}

// createUTUNWithFD is createUTUN plus the control descriptor, which
// makes the packet observable: a datagram the kernel routes out of this
// interface is readable here and nowhere else.
func createUTUNWithFD(t *testing.T) (string, int) {
	t.Helper()
	const (
		utunControl = "com.apple.net.utun_control"
		// SYSPROTO_CONTROL and UTUN_OPT_IFNAME, neither of which
		// golang.org/x/sys/unix carries.
		sysprotoControl = 2
		utunOptIfname   = 2
	)
	connect := func() (int, error) {
		fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
		if err != nil {
			return -1, fmt.Errorf("open a system control socket: %w", err)
		}
		info := &unix.CtlInfo{}
		copy(info.Name[:], utunControl)
		if err := unix.IoctlCtlInfo(fd, info); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("look up %s: %w", utunControl, err)
		}
		// unit 0 asks for the first free utun rather than naming one, so the
		// test cannot land on a device something else is already using.
		if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("create a utun: %w", err)
		}
		return fd, nil
	}
	// The connect has still failed once with EBUSY, in a full root run, and
	// passed on its own every time after. A busy answer is retried for up to
	// 5 seconds, on a new socket each time, because a refused connect leaves
	// its socket unable to send or receive.
	fd, err := connect()
	busy := 0
	for deadline := time.Now().Add(5 * time.Second); errors.Is(err, unix.EBUSY) && time.Now().Before(deadline); busy++ {
		time.Sleep(10 * time.Millisecond)
		fd, err = connect()
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if busy > 0 {
		t.Logf("the utun control answered busy %d times first", busy)
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		t.Fatalf("read the name of the new utun: %v", err)
	}
	t.Logf("created %s, which goes away with this test", name)
	return name, fd
}
