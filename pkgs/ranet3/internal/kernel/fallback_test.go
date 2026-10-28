// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"errors"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
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
	none := &ExitMode{Forward: []string{"docker0"}, Fallback: FallbackNone, Inbound: []string{"22/tcp", "60000-61000/udp"}}
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

// The LAN is each link's connected networks, forward's links among them,
// less one overlapping the overlay and one schema.CapturesTheMachine counts,
// which is reported, with the carve-outs added
func TestFallbackSetsLeaveOutTheOverlayAndWhatCapturesTheMachine(t *testing.T) {
	view := exitView{on: true, fallback: true, forwarded: []string{"docker0"}, network: NetworkState{
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

// The status names the switch holding while no exit is live, passing while the
// mesh's defaults are installed, and not holding with the fault while the
// table does not read back, each with what the drop counted, the LAN, and the
// DNS servers resolved queries through a link that lie beyond the LAN and this
// node's own prefixes. Each
// change of state is one event, and a reload to "uplink" ends the switch with
// one more and takes it out of the status.
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
	tbl := Table{Addresses: prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))}.WithMode(&ExitMode{Fallback: FallbackNone})
	reconciler, routes, fake := harness(t, tbl, Runtime{Interface: "ranet3", Overlay: exitPassOverlay, Network: network.read, Events: bus,
		Resolvers: func() ([]LinkResolver, error) { return resolvers, nil }})
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
	beyond := []LinkResolver{resolvers[1], resolvers[4]}
	if holding.Dropped != 5 || holding.DroppedBytes != 300 || holding.Fault != "" ||
		!reflect.DeepEqual(holding.LAN, []netip.Prefix{prefix("198.51.100.0/24"), prefix("2001:db8:a::/64")}) || !reflect.DeepEqual(holding.Resolvers, beyond) {
		t.Errorf("holding reads %+v, want 5 packets of 300 bytes, the LAN and the resolvers %v", holding, beyond)
	}
	status(FallbackHolding)
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
