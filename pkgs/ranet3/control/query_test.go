// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"net/netip"
	"strings"
	"testing"
)

// meshRoutes is a table with a host prefix, the prefix around it, a retracted
// neighbor prefix and both defaults, which between them cover every case the
// queries below have to separate.
func meshRoutes() []Route {
	return []Route{
		{Destination: netip.MustParsePrefix("2001:db8::/32"), Via: "example/core@0", Metric: 212, RouterID: "0102030405060708", Candidates: 4},
		{Destination: netip.MustParsePrefix("2001:db8:1::5/128"), Via: "example/gateway@0", Metric: 96, RouterID: "aabbccddeeff0011", Candidates: 2},
		{Destination: netip.MustParsePrefix("2001:db8:1::/48"), Via: "example/gateway@0", Metric: 116, RouterID: "aabbccddeeff0011", Candidates: 3},
		{Destination: netip.MustParsePrefix("2001:db8:2::/48"), Metric: 65535},
		{Destination: netip.MustParsePrefix("::/0"), From: netip.MustParsePrefix("2001:db8::/32"), Via: "example/exit@0", Metric: 300, RouterID: "1122334455667788", Candidates: 2},
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Metric: 65535},
		{Destination: netip.MustParsePrefix("203.0.113.10/32"), Originated: true},
	}
}

// The longest prefix comes first, because that is the entry the forwarding
// table uses, and the shorter ones follow so a reader sees the fallback.
func TestCoveringPutsTheLongestPrefixFirst(t *testing.T) {
	covering := Covering(meshRoutes(), netip.MustParseAddr("2001:db8:1::5"))
	want := []string{"2001:db8:1::5/128", "2001:db8:1::/48", "2001:db8::/32", "::/0"}
	if len(covering) != len(want) {
		t.Fatalf("%s matched %d routes, want %d: %+v", "2001:db8:1::5", len(covering), len(want), covering)
	}
	for i, prefix := range want {
		if got := covering[i].Destination.String(); got != prefix {
			t.Errorf("match %d is %s, want %s", i, got, prefix)
		}
	}

	// A retracted prefix is held rather than removed exactly so a packet does
	// not follow a shorter one, so it has to be in the answer.
	held := Covering(meshRoutes(), netip.MustParseAddr("2001:db8:2::9"))
	if len(held) == 0 || held[0].Destination.String() != "2001:db8:2::/48" {
		t.Errorf("a retracted prefix is not the longest match: %+v", held)
	}

	// And an address in nothing but a default still finds it, while one in a
	// family the mesh carries nothing for finds nothing beyond the retracted
	// v4 default.
	if got := Covering(meshRoutes(), netip.MustParseAddr("2606:4700::1")); len(got) != 1 {
		t.Errorf("an address outside the mesh matched %+v, want the default alone", got)
	}
}

// Both families count, and nothing but a zero-length prefix over an
// unspecified address does.
func TestDefaultsAreBothFamiliesAndNothingElse(t *testing.T) {
	defaults := Defaults(meshRoutes())
	if len(defaults) != 2 {
		t.Fatalf("%d defaults, want the two: %+v", len(defaults), defaults)
	}
	if defaults[0].Destination.String() != "::/0" || defaults[1].Destination.String() != "0.0.0.0/0" {
		t.Errorf("the defaults are %+v", defaults)
	}
	if got := Defaults(nil); len(got) != 0 {
		t.Errorf("an empty table offered %+v", got)
	}
}

// A node advertising both /1 halves of a family is an exit for that family,
// and the pair is listed. One half alone, two halves from two nodes, or one
// half of each family is not an exit.
func TestDefaultsListANodeAdvertisingBothHalves(t *testing.T) {
	route := func(destination, router string) Route {
		return Route{Destination: netip.MustParsePrefix(destination), Via: "example/" + router + "@0", RouterID: router, Metric: 96}
	}
	routes := []Route{
		route("0.0.0.0/1", "aa"), route("128.0.0.0/1", "aa"),
		route("::/1", "bb"), route("8000::/1", "cc"),
		route("8000::/1", "bb"),
		route("198.51.100.0/24", "aa"),
		{Destination: netip.MustParsePrefix("::/1"), Originated: true},
	}
	var got []string
	for _, r := range Defaults(routes) {
		got = append(got, r.Destination.String()+" "+r.RouterID)
	}
	want := []string{"0.0.0.0/1 aa", "128.0.0.0/1 aa", "::/1 bb", "8000::/1 bb"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Errorf("the exits are %v, want %v", got, want)
	}
	if got := Defaults([]Route{route("0.0.0.0/1", "aa"), route("128.0.0.0/1", "dd")}); len(got) != 0 {
		t.Errorf("halves from two nodes made an exit: %+v", got)
	}
	if got := Defaults([]Route{route("0.0.0.0/1", "ee"), route("8000::/1", "ee")}); len(got) != 0 {
		t.Errorf("one half of each family made an exit: %+v", got)
	}

	var out strings.Builder
	RenderExitNodes(&out, Defaults(routes))
	for _, want := range []string{"0.0.0.0/1", "128.0.0.0/1", "example/aa@0", "selected"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the exit list printed %q, want it to carry %q", out.String(), want)
		}
	}
}

// Only a host prefix is an address this node answers at. A range it carries
// traffic for and a default an exit announces are neither, and announcing one
// prefix twice is one address.
func TestMeshAddressesTakeOnlyTheHostPrefixes(t *testing.T) {
	status := Status{Originate: []Originated{
		{Prefix: netip.MustParsePrefix("203.0.113.10/32")},
		{Prefix: netip.MustParsePrefix("2001:db8:1::5/128")},
		{Prefix: netip.MustParsePrefix("2001:db8:9::/48")},
		{Prefix: netip.MustParsePrefix("::/0"), From: netip.MustParsePrefix("2001:db8::/32")},
		{Prefix: netip.MustParsePrefix("203.0.113.10/32")},
	}}
	got := MeshAddresses(status)
	if len(got) != 2 || got[0].String() != "203.0.113.10" || got[1].String() != "2001:db8:1::5" {
		t.Errorf("the mesh addresses are %v", got)
	}
}

// whois leads with the sentence a reader came for and then shows what the
// address would fall back to.
func TestWhoisNamesThePrefixAndTheNextHop(t *testing.T) {
	var out strings.Builder
	RenderWhois(&out, netip.MustParseAddr("2001:db8:1::5"), Covering(meshRoutes(), netip.MustParseAddr("2001:db8:1::5")))
	for _, want := range []string{"2001:db8:1::5 is in 2001:db8:1::5/128 via example/gateway@0", "::/0"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("whois printed %q, want it to carry %q", out.String(), want)
		}
	}

	out.Reset()
	RenderWhois(&out, netip.MustParseAddr("203.0.113.10"), Covering(meshRoutes(), netip.MustParseAddr("203.0.113.10")))
	if !strings.Contains(out.String(), "originated by this node") {
		t.Errorf("a prefix this node originates printed as %q", out.String())
	}

	out.Reset()
	RenderWhois(&out, netip.MustParseAddr("2001:db8:2::9"), Covering(meshRoutes(), netip.MustParseAddr("2001:db8:2::9")))
	if !strings.Contains(out.String(), "held unreachable") {
		t.Errorf("a retracted prefix printed as %q", out.String())
	}

	out.Reset()
	RenderWhois(&out, netip.MustParseAddr("2001:db8:1::5"), nil)
	if !strings.Contains(out.String(), "no prefix this mesh carries") {
		t.Errorf("an address the mesh does not carry printed as %q", out.String())
	}
}

// The exit list says which default carries traffic and which has been
// withdrawn, because an exit that stopped announcing looks the same as one
// that never did until the state column says otherwise.
func TestExitNodesSayWhichDefaultIsTaken(t *testing.T) {
	var out strings.Builder
	RenderExitNodes(&out, Defaults(meshRoutes()))
	for _, want := range []string{"Destination", "State", "example/exit@0", "selected", "withdrawn", "2001:db8::/32"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the exit list printed %q, want it to carry %q", out.String(), want)
		}
	}

	out.Reset()
	RenderExitNodes(&out, []Route{{Destination: netip.MustParsePrefix("::/0"), Originated: true}})
	if !strings.Contains(out.String(), "advertised by this node") {
		t.Errorf("a default this node announces printed as %q", out.String())
	}

	out.Reset()
	RenderExitNodes(&out, nil)
	if !strings.Contains(out.String(), "No node advertises a default route") {
		t.Errorf("a mesh with no exit printed as %q", out.String())
	}
}

// One address per line and nothing else, so the output goes into a shell
// variable without being cut up first.
func TestAddressesArePrintedOnePerLine(t *testing.T) {
	var out strings.Builder
	RenderAddresses(&out, []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8:1::5")})
	if out.String() != "203.0.113.10\n2001:db8:1::5\n" {
		t.Errorf("the addresses printed as %q", out.String())
	}
}
