// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// lookingKernel is the fake kernel with the lookup half, answering each read
// by answer, or the whole batch by err, and recording every batch it was asked
type lookingKernel struct {
	*fakeKernel
	answer func(RouteRead) BatchAnswer
	err    error
	asked  [][]RouteRead
}

func (k *lookingKernel) lookups(reads []RouteRead) ([]BatchAnswer, error) {
	k.asked = append(k.asked, slices.Clone(reads))
	if k.err != nil {
		return nil, k.err
	}
	answers := make([]BatchAnswer, len(reads))
	for i, read := range reads {
		answers[i] = k.answer(read)
	}
	return answers, nil
}

// lookingHarness is harness over a lookingKernel whose every lookup the mesh's
// table answers through the tun
func lookingHarness(t *testing.T, tbl Table, rt Runtime) (*Reconciler, *netstack.RouteTable, *lookingKernel) {
	t.Helper()
	if rt.Interface == "" {
		rt.Interface = "ranet0"
	}
	tbl = tbl.Normalized()
	table := netstack.NewRouteTable()
	look := &lookingKernel{fakeKernel: newFakeKernel(t), answer: func(RouteRead) BatchAnswer {
		return BatchAnswer{Route: MatchedRoute{Table: uint32(tbl.ID), NextHops: []NextHop{{Device: rt.Interface}}}}
	}}
	return newReconciler(tbl, rt, tbl.Assigned(rt.Announced), table, look), table, look
}

func refused(errno syscall.Errno) BatchAnswer {
	return BatchAnswer{Err: fmt.Errorf("kernel: look up the route: %w", errno)}
}

func answeredBy(table uint32, device string) BatchAnswer {
	return BatchAnswer{Route: MatchedRoute{Table: table, NextHops: []NextHop{{Device: device}}}}
}

// each answer the kernel gives a lookup is judged as routing.md's lookups end:
// an overlay lookup is the mesh's when it leaves through the tun, whatever
// table answers, or its hold refuses, and taken by anything else, while the
// underlay's marked lookup is taken only when it leaves through the tun
func TestLookupAnswersAreJudgedByWhereTheyEnd(t *testing.T) {
	const mesh, tun = 200, "ranet0"
	for _, test := range []struct {
		name     string
		answer   BatchAnswer
		overlay  bool
		underlay bool
		text     string
	}{
		{"the mesh's table", answeredBy(mesh, tun), false, true, "table 200 dev ranet0"},
		{"main on the tun", answeredBy(uint32(schema.TableMain), tun), false, true, "table main dev ranet0"},
		{"the hold", refused(syscall.EHOSTUNREACH), false, false, "a refusal (no route to host)"},
		{"local on the tun", answeredBy(uint32(schema.TableLocal), tun), false, false, "table local dev ranet0"},
		{"local on another device", answeredBy(uint32(schema.TableLocal), "eth0"), true, false, "table local dev eth0"},
		{"wg-quick's table", answeredBy(51820, "wg0"), true, false, "table 51820 dev wg0"},
		{"tailscale's table", answeredBy(52, "tailscale0"), true, false, "table 52 dev tailscale0"},
		{"main", answeredBy(uint32(schema.TableMain), "eth0"), true, false, "table main dev eth0"},
		{"a prohibit rule", refused(syscall.EACCES), true, false, "a refusal (permission denied)"},
		{"an unreachable rule", refused(syscall.ENETUNREACH), true, false, "a refusal (network is unreachable)"},
		{"a blackhole rule", refused(syscall.EINVAL), true, false, "a refusal (invalid argument)"},
	} {
		for _, underlay := range []bool{false, true} {
			want := test.overlay
			if underlay {
				want = test.underlay
			}
			text, taken := judgeLookup(underlay, test.answer, tun)
			if taken != want || text != test.text {
				t.Errorf("%s, underlay %v: judged %q taken %v, want %q taken %v", test.name, underlay, text, taken, test.text, want)
			}
		}
	}
}

// an overlay lookup asks the first address past the network address that no
// assigned prefix holds, else the first no assigned address equals, the one
// address of a full-length prefix, and none where every address is assigned
func TestLookupAddressSkipsTheNetworkAddressAndEveryAssignedOne(t *testing.T) {
	for _, test := range []struct {
		prefix   netip.Prefix
		assigned []netip.Prefix
		want     netip.Addr
	}{
		{prefix("192.0.2.0/24"), []netip.Prefix{prefix("192.0.2.1/32")}, addr("192.0.2.2")},
		{prefix("192.0.2.0/24"), []netip.Prefix{prefix("192.0.2.1/25")}, addr("192.0.2.128")},
		{prefix("192.0.2.0/24"), []netip.Prefix{prefix("192.0.2.1/26"), prefix("192.0.2.70/26")}, addr("192.0.2.128")},
		{prefix("192.0.2.0/24"), []netip.Prefix{prefix("192.0.2.1/24"), prefix("192.0.2.2/32")}, addr("192.0.2.3")},
		{prefix("192.0.2.0/24"), []netip.Prefix{prefix("192.0.2.1/23")}, addr("192.0.2.2")},
		{prefix("3fff::/20"), []netip.Prefix{prefix("3fff::1/64")}, addr("3fff:0:0:1::")},
		{prefix("192.0.2.0/24"), nil, addr("192.0.2.1")},
		{prefix("192.0.2.7/32"), nil, addr("192.0.2.7")},
		{prefix("192.0.2.7/32"), []netip.Prefix{prefix("192.0.2.7/32")}, netip.Addr{}},
		{prefix("192.0.2.0/31"), []netip.Prefix{prefix("192.0.2.1/32")}, netip.Addr{}},
		{prefix("3fff::/20"), []netip.Prefix{prefix("3fff::1/128")}, addr("3fff::2")},
		{prefix("3fff::/20"), nil, addr("3fff::1")},
	} {
		got, ok := lookupAddress(test.prefix, test.assigned)
		if got != test.want || ok != test.want.IsValid() {
			t.Errorf("%s with %v assigned asks %v (%v), want %v", test.prefix, test.assigned, got, ok, test.want)
		}
	}
}

// a pass asks into each overlay hold it installed and into no prefix it holds
// none for, at the address the assignments leave free
func TestPassAsksIntoEachOverlayHoldItInstalled(t *testing.T) {
	overlay := prefixes(prefix("192.0.2.0/24"), prefix("3fff::/20"), prefix("fe80::/64"))
	reconciler, _, look := lookingHarness(t,
		Table{Addresses: prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))},
		Runtime{Overlay: overlay})
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(look.asked) != 1 {
		t.Fatalf("the pass asked %d batches, want 1", len(look.asked))
	}
	want := []RouteRead{{Destination: addr("192.0.2.2")}, {Destination: addr("3fff::2")}}
	if !slices.Equal(look.asked[0], want) {
		t.Errorf("the pass asked %v, want %v", look.asked[0], want)
	}
	lookups := reconciler.Stats().Lookups
	if len(lookups) != 2 || lookups[0].Prefix != prefix("192.0.2.0/24") || lookups[1].Prefix != prefix("3fff::/20") || lookups[0].Taken || lookups[1].Taken {
		t.Errorf("the pass published %+v, want both holds asked and neither taken", lookups)
	}
}

// the underlay's marked lookup asks each distinct live endpoint once, in
// address order, whatever the mesh's table holds, and a taken lookup no
// longer asked clears once
func TestPassAsksEveryLiveEndpointUnderTheMark(t *testing.T) {
	endpoints := []netip.Addr{addr("2001:db8:a::7"), addr("203.0.113.70"), addr("198.51.100.7"), addr("2001:db8:a::7"), addr("203.0.113.70")}
	bus := events.New()
	reconciler, _, look := lookingHarness(t, Table{}, Runtime{Endpoints: func() []netip.Addr { return endpoints }, Events: bus})
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	var want []RouteRead
	for _, endpoint := range []string{"198.51.100.7", "203.0.113.70", "2001:db8:a::7"} {
		want = append(want, RouteRead{Destination: addr(endpoint), Mark: schema.UnderlayMark})
	}
	if len(look.asked) != 1 || !slices.Equal(look.asked[0], want) {
		t.Fatalf("the pass asked %v, want %v", look.asked, want)
	}
	if got := reconciler.Stats().Lookups; len(got) != 3 || !got[0].Underlay() || !got[0].Taken || got[0].Family != FamilyIPv4 || got[2].Family != FamilyIPv6 {
		t.Errorf("the pass published %+v, want each endpoint taken through the tun", got)
	}

	endpoints = []netip.Addr{addr("198.51.100.7"), addr("2001:db8:a::7")}
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := reconciler.Stats().Lookups; len(got) != 2 {
		t.Errorf("with 2 endpoints live the pass published %+v", got)
	}
	endpoints = nil
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(look.asked) != 2 {
		t.Errorf("with no endpoint live the pass asked %v", look.asked[2:])
	}
	if got := reconciler.Stats().Lookups; len(got) != 0 {
		t.Errorf("with nothing asked the pass published %+v", got)
	}
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.taken" }, 0) {
		got = append(got, event.Attrs["lookup"]+" "+event.Attrs["endpoint"]+" "+event.Attrs["taken"])
	}
	reported := []string{
		"underlay 198.51.100.7 true", "underlay 203.0.113.70 true", "underlay 2001:db8:a::7 true",
		"underlay 203.0.113.70 false",
		"underlay 198.51.100.7 false", "underlay 2001:db8:a::7 false",
	}
	if !slices.Equal(got, reported) {
		t.Errorf("the events are %q, want %q", got, reported)
	}
}

// every live endpoint whose marked lookup the kernel answers through the tun is
// taken and no other, however another program's rule reaches the tun: a goto
// past 5400 meets main at 5410, which answers an endpoint it holds a longer
// route for and passes another on to 5420 (X4), and a lookup of the mesh's
// table for the mark answers every endpoint by its default (X5)
func TestEveryEndpointWhoseMarkedLookupLeavesThroughTheTunIsTaken(t *testing.T) {
	const tun = "ranet0"
	mesh, main := answeredBy(200, tun), answeredBy(uint32(schema.TableMain), "eth0")
	endpoints := []netip.Addr{addr("198.51.100.77"), addr("203.0.113.70"), addr("2001:db8:a::77"), addr("2001:db8:400::7")}
	for _, test := range []struct {
		name    string
		entries []string
		answers []BatchAnswer
		want    []string
	}{{
		name:    "X4",
		entries: []string{"198.51.100.64/26", "203.0.113.64/26", "2001:db8:a::/48", "2001:db8:400::/48"},
		answers: []BatchAnswer{main, mesh, main, mesh},
		want:    []string{"ipv4 203.0.113.70", "ipv6 2001:db8:400::7"},
	}, {
		name:    "X5",
		entries: []string{"0.0.0.0/0", "::/0"},
		answers: []BatchAnswer{mesh, mesh, mesh, mesh},
		want:    []string{"ipv4 198.51.100.77", "ipv4 203.0.113.70", "ipv6 2001:db8:a::77", "ipv6 2001:db8:400::7"},
	}} {
		t.Run(test.name, func(t *testing.T) {
			bus := events.New()
			reconciler, table, look := lookingHarness(t, Table{}, Runtime{
				Interface: tun,
				Endpoints: func() []netip.Addr { return endpoints },
				Events:    bus,
			})
			for _, entry := range test.entries {
				table.Set(netip.Prefix{}, prefix(entry), nil)
			}
			look.answer = func(read RouteRead) BatchAnswer { return test.answers[slices.Index(endpoints, read.Destination)] }
			if err := reconciler.reconcile(); err != nil {
				t.Fatal(err)
			}
			lookups := reconciler.Stats().Lookups
			if len(lookups) != len(endpoints) {
				t.Errorf("the pass asked %+v, want every live endpoint", lookups)
			}
			var taken []string
			for _, lookup := range lookups {
				if lookup.Taken {
					taken = append(taken, fmt.Sprintf("%s %s", lookup.Family, lookup.Address))
				}
			}
			if !slices.Equal(taken, test.want) {
				t.Errorf("taken %q, want %q", taken, test.want)
			}
			var reported []string
			for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.taken" }, 0) {
				reported = append(reported, event.Attrs["family"]+" "+event.Attrs["endpoint"])
			}
			if !slices.Equal(reported, test.want) {
				t.Errorf("the events name %q, want %q", reported, test.want)
			}
		})
	}
}

// a taken underlay lookup whose endpoint moves reports the new endpoint taken
// and the old one no longer asked
func TestMovedEndpointIsReportedByItsAddress(t *testing.T) {
	endpoint := addr("203.0.113.70")
	bus := events.New()
	reconciler, _, _ := lookingHarness(t, Table{}, Runtime{Endpoints: func() []netip.Addr { return []netip.Addr{endpoint} }, Events: bus})
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	endpoint = addr("203.0.113.71")
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.taken" }, 0) {
		got = append(got, event.Attrs["endpoint"]+" "+event.Attrs["taken"])
	}
	if want := []string{"203.0.113.70 true", "203.0.113.71 true", "203.0.113.70 false"}; !slices.Equal(got, want) {
		t.Errorf("the events are %q, want %q", got, want)
	}
}

// a taken lookup is reported once while its answer stands, once more for each
// new answer, and once with taken false when it clears
func TestTakenLookupIsReportedOncePerChange(t *testing.T) {
	bus := events.New()
	reconciler, _, look := lookingHarness(t, Table{}, Runtime{Overlay: prefixes(prefix("192.0.2.0/24")), Events: bus})
	for _, answer := range []BatchAnswer{
		answeredBy(200, "ranet0"),
		answeredBy(51820, "wg0"), answeredBy(51820, "wg0"), answeredBy(51820, "wg0"),
		answeredBy(52, "tailscale0"), answeredBy(52, "tailscale0"),
		refused(syscall.EHOSTUNREACH), refused(syscall.EHOSTUNREACH),
	} {
		look.answer = func(RouteRead) BatchAnswer { return answer }
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.taken" }, 0) {
		got = append(got, event.Attrs["lookup"]+" "+event.Attrs["prefix"]+" "+event.Attrs["answer"]+" "+event.Attrs["taken"])
	}
	want := []string{
		"overlay 192.0.2.0/24 table 51820 dev wg0 true",
		"overlay 192.0.2.0/24 table 52 dev tailscale0 true",
		"overlay 192.0.2.0/24 a refusal (no route to host) false",
	}
	if !slices.Equal(got, want) {
		t.Errorf("the events are %q, want %q", got, want)
	}
}

// a pass that fails asks nothing and leaves the last answers published, and a
// lookup it no longer asks clears once
func TestFailedPassAsksNothingAndKeepsTheLastAnswers(t *testing.T) {
	bus := events.New()
	reconciler, _, look := lookingHarness(t, Table{}, Runtime{Overlay: prefixes(prefix("192.0.2.0/24")), Events: bus})
	look.answer = func(RouteRead) BatchAnswer { return answeredBy(51820, "wg0") }
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	before := reconciler.Stats().Lookups
	rule := (*reconciler.derived.Load())[0]
	look.mu.Lock()
	delete(look.rules, rule)
	look.failAddRule[rule] = errors.New("netlink says no")
	look.mu.Unlock()
	look.answer = func(RouteRead) BatchAnswer { return answeredBy(uint32(schema.TableMain), "eth0") }
	if err := reconciler.reconcile(); err == nil {
		t.Fatal("the pass whose rule add failed reported success")
	}
	if len(look.asked) != 1 {
		t.Errorf("the failed pass asked %v", look.asked[1:])
	}
	if got := reconciler.Stats().Lookups; !slices.Equal(got, before) || len(got) != 1 || !got[0].Taken {
		t.Errorf("the failed pass published %+v, want the last answers %+v", got, before)
	}
	if events := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.taken" }, 0); len(events) != 1 {
		t.Errorf("the failed pass reported %d changes, want the first pass's one", len(events))
	}
}

// a batch that fails leaves the last answers published, warns once however
// many passes it fails, and says once that the lookups answer again
func TestFailedBatchKeepsTheLastAnswersAndWarnsOnce(t *testing.T) {
	logs := captureKernelLogs(t)
	reconciler, _, look := lookingHarness(t, Table{}, Runtime{Overlay: prefixes(prefix("192.0.2.0/24"))})
	look.answer = func(RouteRead) BatchAnswer { return answeredBy(51820, "wg0") }
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	before := reconciler.Stats().Lookups
	look.err = errors.New("netlink says no")
	for range 3 {
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		if got := reconciler.Stats().Lookups; !slices.Equal(got, before) || len(got) != 1 || !got[0].Taken {
			t.Fatalf("a pass whose batch failed published %+v, want the last answers %+v", got, before)
		}
	}
	look.err = nil
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	for _, msg := range []string{
		"kernel could not ask where its overlay and underlay lookups end",
		"kernel can ask where its overlay and underlay lookups end again",
	} {
		if logRecord(t, logs, msg) == nil {
			t.Errorf("no %q in the log:\n%s", msg, logs.String())
		}
	}
}

// a stop reports nothing taken
func TestWithdrawalClearsTheLookups(t *testing.T) {
	reconciler, _, look := lookingHarness(t, Table{}, Runtime{Overlay: prefixes(prefix("192.0.2.0/24"))})
	look.answer = func(RouteRead) BatchAnswer { return answeredBy(51820, "wg0") }
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := reconciler.Stats().Lookups; len(got) != 1 || !got[0].Taken {
		t.Fatalf("the pass published %+v, want the hold taken, so this proves nothing", got)
	}
	err := reconciler.withdraw()
	reconciler.routePass = Stats{}
	reconciler.recordPass(err, 0)
	if got := reconciler.Stats().Lookups; len(got) != 0 {
		t.Errorf("a stopped reconciler publishes %+v", got)
	}
}

// a platform with no lookup half, darwin's, asks and publishes nothing
func TestPlatformWithoutLookupsPublishesNone(t *testing.T) {
	reconciler, _, _ := harness(t, Table{}, Runtime{
		Overlay:   prefixes(prefix("192.0.2.0/24")),
		Endpoints: func() []netip.Addr { return []netip.Addr{addr("192.0.2.9")} },
	})
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := reconciler.Stats().Lookups; got != nil {
		t.Errorf("a platform without lookups published %+v", got)
	}
}
