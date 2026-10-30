// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// fallbackHarness is a reconciler on the fake in mode 2 under mode, on
// exitPassHost with docker0, its own prefix 203.0.113.0/24 thrown
func fallbackHarness(t *testing.T, mode *ExitMode) (*Reconciler, *fakeKernel) {
	t.Helper()
	network := &hostNetwork{state: exitPassHost("docker0")}
	tbl := Table{Addresses: prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))}.WithMode(mode)
	reconciler, routes, fake := harness(t, tbl, Runtime{Interface: "ranet3", Overlay: exitPassOverlay, Network: network.read})
	routes.Set(netip.Prefix{}, prefix("203.0.113.0/24"), netstack.Local)
	return reconciler, fake
}

// exitPassLAN lists the networks exitPassHost connects eth0 to, public ones from the documentation ranges, so they count as the LAN
var exitPassLAN = []schema.Prefix{schema.MustPrefix("198.51.100.0/24"), schema.MustPrefix("2001:db8:a::/64")}

// uplinkSources is whether the fake holds a rule at 5405 or 5435
func uplinkSources(fake *fakeKernel) bool {
	for rule := range fake.rules {
		if rule.Priority == priorityUplinkSource || rule.Priority == priorityLinkSource {
			return true
		}
	}
	return false
}

// Under fallback = "none" a pass writes the table from the pass's derivation,
// a pass over the same inputs writes nothing, and a reload to "uplink" deletes
// it once, with 5405 kept throughout
func TestFallbackTableFollowsTheMode(t *testing.T) {
	none := &ExitMode{Forward: []string{"docker0"}, Fallback: FallbackNone, Inbound: []string{"22/tcp", "60000-61000/udp"}, LAN: exitPassLAN}
	reconciler, fake := fallbackHarness(t, none)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := fallbackSets{
		tun: "ranet3", forwarded: []string{"docker0"},
		lan4: []netip.Prefix{prefix("198.51.100.0/24")}, lan6: []netip.Prefix{prefix("2001:db8:a::/64")},
		own4: []netip.Prefix{prefix("203.0.113.0/24")},
		tcp:  []Service{{Protocol: "tcp", First: 22, Last: 22}}, udp: []Service{{Protocol: "udp", First: 60000, Last: 61000}},
	}
	if fake.fallback == nil || !reflect.DeepEqual(*fake.fallback, want) {
		t.Fatalf("the pass wrote %+v, want %+v", fake.fallback, want)
	}
	if !uplinkSources(fake) {
		t.Error("with the table reading back the pass left 5405 and 5435 out")
	}
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if fake.fallbackWrites != 1 {
		t.Errorf("a second pass over the same inputs wrote the table again, %d writes in all", fake.fallbackWrites)
	}

	if err := reconciler.SetTable(reconciler.table.WithMode(&ExitMode{Forward: []string{"docker0"}, Fallback: FallbackUplink}), exitPassOverlay, nil); err != nil {
		t.Fatal(err)
	}
	reconciler.adopt()
	for range 2 {
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if fake.fallback != nil || fake.fallbackDeletes != 1 {
		t.Errorf("after a reload to \"uplink\" the fake holds %+v after %d deletes, want none after one", fake.fallback, fake.fallbackDeletes)
	}
	if !uplinkSources(fake) {
		t.Error("after a reload to \"uplink\" 5405 and 5435 are missing")
	}
}

// While the table does not read back as written, or cannot be written, the
// pass leaves 5405 and 5435 out and keeps 5440 and 5450, and puts them back
// once it reads back
func TestFallbackTableThatDoesNotReadBackLeavesTheUplinkSourcesOut(t *testing.T) {
	for name, spoil := range map[string]func(*fakeKernel){
		"another writer's change": func(fake *fakeKernel) { fake.spoiled = "its set lan4 holds { }" },
		"no nf_tables":            func(fake *fakeKernel) { fake.failFallback = errors.New("protocol not supported") },
	} {
		t.Run(name, func(t *testing.T) {
			reconciler, fake := fallbackHarness(t, &ExitMode{Fallback: FallbackNone})
			spoil(fake)
			err := reconciler.reconcile()
			if (err != nil) != (fake.failFallback != nil) {
				t.Errorf("the pass returned %v", err)
			}
			if uplinkSources(fake) {
				t.Error("with the table not reading back the pass kept 5405 or 5435")
			}
			if len(fallbackRules(fake)) == 0 || len(catchAll(fake)) == 0 {
				t.Errorf("with the table not reading back the pass holds 5440 %v and 5445 or 5450 %v", catchAll(fake), fallbackRules(fake))
			}
			fake.spoiled, fake.failFallback = "", nil
			if err := reconciler.reconcile(); err != nil {
				t.Fatal(err)
			}
			if !uplinkSources(fake) {
				t.Error("once the table reads back the pass left 5405 and 5435 out")
			}
		})
	}
}

// A start whose mode does not ask for the table deletes one an earlier
// instance left, once, and the withdrawal deletes the table it wrote
func TestFallbackTableLeftByAnEarlierInstanceGoesAtAStartNotAskingForIt(t *testing.T) {
	reconciler, fake := fallbackHarness(t, &ExitMode{})
	fake.fallback = &fallbackSets{tun: "ranet3"}
	for range 2 {
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if fake.fallback != nil || fake.fallbackDeletes != 1 {
		t.Errorf("a start in mode 2 under \"uplink\" left %+v after %d deletes, want none after one", fake.fallback, fake.fallbackDeletes)
	}

	reconciler, fake = fallbackHarness(t, &ExitMode{Fallback: FallbackNone})
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.withdraw(); err != nil {
		t.Fatal(err)
	}
	if fake.fallback != nil {
		t.Errorf("the withdrawal left %+v", fake.fallback)
	}
}

// A left table whose delete fails is deleted by the withdrawal after it, where
// a kernel without nf_tables is not asked again
func TestFallbackTableWhoseDeleteFailedGoesAtTheWithdrawal(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		left bool
	}{
		"a delete refused once":      {err: syscall.EBUSY},
		"a kernel with no nf_tables": {err: syscall.EPROTONOSUPPORT, left: true},
	} {
		t.Run(name, func(t *testing.T) {
			reconciler, fake := fallbackHarness(t, &ExitMode{})
			fake.fallback = &fallbackSets{tun: "ranet3"}
			fake.failFallback = c.err
			if err := reconciler.reconcile(); err != nil {
				t.Fatal(err)
			}
			fake.failFallback = nil
			if err := reconciler.withdraw(); err != nil {
				t.Fatal(err)
			}
			if left := fake.fallback != nil; left != c.left {
				t.Errorf("after a delete that failed with %v the withdrawal left %+v, want a table left %v", c.err, fake.fallback, c.left)
			}
		})
	}
}

// The LAN is each link's connected networks, forward's links among them,
// less one overlapping the overlay and one schema.CapturesTheMachine counts,
// which is reported, with the carve-outs added
func TestFallbackSetsLeaveOutTheOverlayAndWhatCapturesTheMachine(t *testing.T) {
	lan := []netip.Prefix{prefix("198.51.100.0/24"), prefix("203.0.113.0/25"), prefix("2001:db8:a::/64")}
	view := exitView{on: true, fallback: true, forwarded: []string{"docker0"}, lan: lan, network: NetworkState{
		IPv4: NetworkFamily{Links: []Link{
			{Name: "docker0", Prefixes: []netip.Prefix{prefix("203.0.113.1/25")}},
			{Name: "eth0", Prefixes: []netip.Prefix{prefix("198.51.100.10/24"), prefix("198.51.100.10/6"), prefix("192.0.2.7/24")}},
		}},
		IPv6: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{prefix("2001:db8:a::10/64"), prefix("2001:db8::10/12"), prefix("3fff::7/64")}}}},
	}}
	got := view.fallbackSetsOf("ranet3", exitPassOverlay, nil, []netip.Prefix{prefix("192.0.2.1/32")})
	want := fallbackSets{
		tun: "ranet3", forwarded: []string{"docker0"},
		lan4:     []netip.Prefix{prefix("192.0.2.1/32"), prefix("198.51.100.0/24"), prefix("203.0.113.0/25")},
		lan6:     []netip.Prefix{prefix("2001:db8:a::/64")},
		captured: []netip.Prefix{prefix("196.0.0.0/6"), prefix("2000::/12")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the sets read\n%+v\nwant\n%+v", got, want)
	}
}

// Of a connected network only the parts inside the private and link-local
// ranges and the prefixes lan lists count as the LAN. A network inside a range
// counts whole, one holding a range counts for that range alone and is named
// public, and one outside every range is public and adds nothing. A listed
// prefix takes the part of a network it holds, and adds nothing no link is
// connected to. Each range's first and last networks count, and the networks
// just past either end are public.
func TestFallbackLANIsThePrivateAndLinkLocalPartsOfEachConnectedNetwork(t *testing.T) {
	for _, c := range []struct {
		name               string
		connected, listed  []string
		lan4, lan6, public []string
	}{
		{name: "a public network", connected: []string{"198.51.100.10/24", "2001:db8:a::10/64"}, public: []string{"198.51.100.0/24", "2001:db8:a::/64"}},
		{name: "a public network listed", connected: []string{"198.51.100.10/24", "2001:db8:a::10/64"}, listed: []string{"198.51.100.0/24", "2001:db8:a::/64"},
			lan4: []string{"198.51.100.0/24"}, lan6: []string{"2001:db8:a::/64"}},
		{name: "a listed part of a public network", connected: []string{"198.51.100.10/24", "2001:db8:a::10/64"}, listed: []string{"198.51.100.128/25", "2001:db8:a:0:8000::/65"},
			lan4: []string{"198.51.100.128/25"}, lan6: []string{"2001:db8:a:0:8000::/65"}, public: []string{"198.51.100.0/24", "2001:db8:a::/64"}},
		{name: "a listed network holding a connected one", connected: []string{"198.51.100.10/25"}, listed: []string{"198.51.100.0/24"}, lan4: []string{"198.51.100.0/25"}},
		{name: "a listed prefix no link is connected to", connected: []string{"198.51.100.10/24"}, listed: []string{"203.0.113.0/24", "2001:db8:b::/48"}, public: []string{"198.51.100.0/24"}},
		{name: "a network holding a private range", connected: []string{"172.1.2.3/8", "169.1.2.3/8"},
			lan4: []string{"169.254.0.0/16", "172.16.0.0/12"}, public: []string{"169.0.0.0/8", "172.0.0.0/8"}},
		{name: "a network holding a private range and listed the rest", connected: []string{"172.1.2.3/8"}, listed: []string{"172.0.0.0/8"}, lan4: []string{"172.0.0.0/8"}},
		{name: "a network inside a range", connected: []string{"10.1.2.3/8", "fd00::1/16"}, lan4: []string{"10.0.0.0/8"}, lan6: []string{"fd00::/16"}},
		{
			name: "each range's first and last networks",
			connected: []string{
				"10.0.0.1/24", "10.255.255.1/24", "172.16.0.1/24", "172.31.255.1/24", "192.168.0.1/24", "192.168.255.1/24", "169.254.0.1/24", "169.254.255.1/24",
				"fe80::1/64", "febf:ffff:ffff:ffff::1/64", "fc00::1/64", "fdff:ffff:ffff:ffff::1/64",
			},
			lan4: []string{"10.0.0.0/24", "10.255.255.0/24", "169.254.0.0/24", "169.254.255.0/24", "172.16.0.0/24", "172.31.255.0/24", "192.168.0.0/24", "192.168.255.0/24"},
			lan6: []string{"fc00::/64", "fdff:ffff:ffff:ffff::/64", "fe80::/64", "febf:ffff:ffff:ffff::/64"},
		},
		{
			name: "the networks just past each range",
			connected: []string{
				"9.255.255.1/24", "11.0.0.1/24", "172.15.255.1/24", "172.32.0.1/24", "192.167.255.1/24", "192.169.0.1/24", "169.253.255.1/24", "169.255.0.1/24",
				"fe7f:ffff:ffff:ffff::1/64", "fec0::1/64", "fbff:ffff:ffff:ffff::1/64", "fe00::1/64",
			},
			public: []string{
				"9.255.255.0/24", "11.0.0.0/24", "169.253.255.0/24", "169.255.0.0/24", "172.15.255.0/24", "172.32.0.0/24", "192.167.255.0/24", "192.169.0.0/24",
				"fbff:ffff:ffff:ffff::/64", "fe00::/64", "fe7f:ffff:ffff:ffff::/64", "fec0::/64",
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			var network NetworkState
			for _, text := range c.connected {
				connected := prefix(text)
				family := &network.IPv4
				if connected.Addr().Is6() {
					family = &network.IPv6
				}
				family.Links = append(family.Links, Link{Name: "eth0", Prefixes: []netip.Prefix{connected}})
			}
			view := exitView{on: true, fallback: true, network: network, lan: parsedPrefixes(c.listed)}
			got := view.fallbackSetsOf("ranet3", exitPassOverlay, nil, nil)
			if !slices.Equal(got.lan4, parsedPrefixes(c.lan4)) || !slices.Equal(got.lan6, parsedPrefixes(c.lan6)) || !slices.Equal(got.public, parsedPrefixes(c.public)) {
				t.Errorf("connected to %v and listing %v the LAN reads %v and %v with %v public, want %v and %v with %v public",
					c.connected, c.listed, got.lan4, got.lan6, got.public, c.lan4, c.lan6, c.public)
			}
		})
	}
}

// With lan unwritten the status names exitPassHost's public networks, which the
// table's LAN leaves out, and once lan lists them it names none
func TestFallbackStatusNamesEachPublicNetwork(t *testing.T) {
	for _, c := range []struct {
		lan    []schema.Prefix
		public []netip.Prefix
	}{
		{nil, []netip.Prefix{prefix("198.51.100.0/24"), prefix("2001:db8:a::/64")}},
		{exitPassLAN, nil},
	} {
		reconciler, _ := fallbackHarness(t, &ExitMode{Fallback: FallbackNone, LAN: c.lan})
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		exit := reconciler.Stats().Exit
		if exit == nil || exit.Fallback == nil || !slices.Equal(exit.Fallback.Public, c.public) {
			t.Errorf("with lan %v the status names %+v, want %v public", c.lan, exit, c.public)
		}
	}
}

// FirstPass stays open until Run's first pass has written the table, which the
// start waits on under "none" before it dials a session
func TestFallbackFirstPassEndsWithTheTableWritten(t *testing.T) {
	reconciler, fake := fallbackHarness(t, &ExitMode{Fallback: FallbackNone, LAN: exitPassLAN})
	select {
	case <-reconciler.FirstPass():
		t.Fatal("the first pass ended before Run started")
	default:
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	select {
	case <-reconciler.FirstPass():
	case <-time.After(waitBudget):
		t.Fatalf("the first pass did not end within %s", waitBudget)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.fallbackWrites != 1 || fake.fallback == nil {
		t.Errorf("the first pass ended with %d writes of the table, want it written once", fake.fallbackWrites)
	}
}

// A read of systemd-resolved's servers that fails is logged once, however many
// reads fail after it, and a read that succeeds has the next failure logged
// again
func TestFallbackResolversLogAFailedReadOnceUntilOneSucceeds(t *testing.T) {
	const line = "kernel could not read the DNS servers systemd-resolved queries through each link"
	network := &hostNetwork{state: exitPassHost("docker0")}
	var failure error
	tbl := Table{Addresses: prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))}.WithMode(&ExitMode{Fallback: FallbackNone, LAN: exitPassLAN})
	reconciler, _, _ := harness(t, tbl, Runtime{Interface: "ranet3", Overlay: exitPassOverlay, Network: network.read,
		Resolvers: func() ([]LinkResolver, error) { return nil, failure }})
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	var said strings.Builder
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&said, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, step := range []struct {
		failure error
		said    int
	}{
		{errors.New("varlink: connection refused"), 1},
		{errors.New("varlink: connection refused"), 1},
		{nil, 1},
		{errors.New("varlink: deadline exceeded"), 2},
	} {
		failure = step.failure
		reconciler.FallbackResolvers()
		if got := strings.Count(said.String(), line); got != step.said {
			t.Fatalf("after a read failing with %v the line was written %d times, want %d:\n%s", step.failure, got, step.said, said.String())
		}
	}
}

// parsedPrefixes is each text a prefix, nil for none
func parsedPrefixes(texts []string) []netip.Prefix {
	var out []netip.Prefix
	for _, text := range texts {
		out = append(out, prefix(text))
	}
	return out
}

// The status names the switch holding while no exit is live, passing while the
// mesh's defaults are installed, and not holding with the fault while the
// table does not read back, each with what the drop counted. A pass leaves
// systemd-resolved unasked, and a read of the status asks it for the DNS
// servers it queries through a link beyond the LAN and this node's own
// prefixes. Each change of state is one event, and a reload to "uplink" ends
// the switch with one more and takes it out of the status.
func TestFallbackStatusNamesEachStateOnce(t *testing.T) {
	bus := events.New()
	network := &hostNetwork{state: exitPassHost("docker0")}
	resolvers := []LinkResolver{
		{Link: "eth0", Address: netip.MustParseAddr("198.51.100.53")},
		{Link: "eth0", Address: netip.MustParseAddr("203.0.113.53")},
		{Link: "eth0", Address: netip.MustParseAddr("fe80::53")},
		{Link: "ranet3", Address: netip.MustParseAddr("192.0.2.53")},
		{Link: "eth1", Address: netip.MustParseAddr("2001:db8:f::53")},
		{Link: "eth1", Address: netip.MustParseAddr("203.0.113.153")},
	}
	asked := 0
	tbl := Table{Addresses: prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))}.WithMode(&ExitMode{Fallback: FallbackNone, LAN: exitPassLAN})
	reconciler, routes, fake := harness(t, tbl, Runtime{Interface: "ranet3", Overlay: exitPassOverlay, Network: network.read, Events: bus,
		Resolvers: func() ([]LinkResolver, error) { asked++; return resolvers, nil }})
	routes.Set(netip.Prefix{}, prefix("203.0.113.128/25"), netstack.Local)
	fake.fallbackDropped = 5
	status := func(want FallbackState) *FallbackStatus {
		t.Helper()
		if err := reconciler.reconcile(); err != nil && want != FallbackNotHolding {
			t.Fatal(err)
		}
		exit := reconciler.Stats().Exit
		if exit == nil || exit.Fallback == nil || exit.Fallback.State != want {
			t.Fatalf("the status names the switch as %+v, want %s", exit, want)
		}
		return exit.Fallback
	}
	holding := status(FallbackHolding)
	if holding.Dropped != 5 || holding.DroppedBytes != 300 || holding.Fault != "" {
		t.Errorf("holding reads %+v, want 5 packets of 300 bytes", holding)
	}
	status(FallbackHolding)
	if asked != 0 {
		t.Errorf("two passes asked systemd-resolved %d times, want none", asked)
	}
	beyond := []LinkResolver{resolvers[1], resolvers[4]}
	if got := reconciler.FallbackResolvers(); !reflect.DeepEqual(got, beyond) || asked != 1 {
		t.Errorf("a read names the resolvers %v asking %d times, want %v asking once", got, asked, beyond)
	}
	routes.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	routes.Set(netip.Prefix{}, prefix("::/0"), nil)
	status(FallbackPassing)
	fake.spoiled = "its set lan4 holds { }"
	if fault := status(FallbackNotHolding).Fault; fault != fake.spoiled {
		t.Errorf("not holding names %q, want %q", fault, fake.spoiled)
	}
	fake.spoiled = ""
	status(FallbackPassing)

	if err := reconciler.SetTable(reconciler.table.WithMode(&ExitMode{Fallback: FallbackUplink}), exitPassOverlay, nil); err != nil {
		t.Fatal(err)
	}
	reconciler.adopt()
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if exit := reconciler.Stats().Exit; exit == nil || exit.Fallback != nil {
		t.Errorf("under uplink the status names the switch as %+v", exit)
	}
	var states []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.fallback" }, 0) {
		states = append(states, event.Attrs["was"]+" to "+event.Attrs["state"])
	}
	want := []string{"off to holding", "holding to passing", "passing to not holding", "not holding to passing", "passing to off"}
	if !slices.Equal(states, want) {
		t.Errorf("the switch's events read %v, want %v", states, want)
	}
}
