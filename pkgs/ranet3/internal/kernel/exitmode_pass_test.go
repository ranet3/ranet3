// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/schema"
)

// exitPassOverlay is the overlay every test of this file runs under
var exitPassOverlay = []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")}

// hostNetwork is a network the watch reads, which a test moves between passes
type hostNetwork struct {
	mu    sync.Mutex
	state NetworkState
}

func (h *hostNetwork) read() NetworkState {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

func (h *hostNetwork) set(state NetworkState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state = state
}

// exitPassHost is eth0 carrying both defaults with an uplink address of each family, and the bridges given, each up with no address
func exitPassHost(bridges ...string) NetworkState {
	links := func(uplink string) []Link {
		out := []Link{{Name: "eth0", Prefixes: []netip.Prefix{netip.MustParsePrefix(uplink)}}}
		for _, bridge := range bridges {
			out = append(out, Link{Name: bridge})
		}
		slices.SortFunc(out, func(a, b Link) int { return strings.Compare(a.Name, b.Name) })
		return out
	}
	return NetworkState{
		IPv4: NetworkFamily{Default: DefaultRoute{Interface: "eth0"}, Links: links("198.51.100.10/24")},
		IPv6: NetworkFamily{Default: DefaultRoute{Interface: "eth0"}, Links: links("2001:db8:a::10/64")},
	}
}

// catchAll is the rules at 5440 the fake holds, each as its family and its input link
func catchAll(fake *fakeKernel) []string {
	var out []string
	for rule := range fake.rules {
		if rule.Priority == priorityCatchAll {
			out = append(out, string(rule.Family)+" iif "+rule.IIF)
		}
	}
	slices.Sort(out)
	return out
}

// forwardEvents is each kernel.forward event recorded, as its link, its entry and whether the skip began
func forwardEvents(bus *events.Bus) [][]string {
	var out [][]string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.forward" }, 0) {
		out = append(out, []string{event.Attrs["link"], event.Attrs["entry"], event.Attrs["skipped"]})
	}
	return out
}

// each pass expands forward against the links the watch reads then, so a bridge that comes up after the start follows the mode
// and one that goes leaves it, while the uplink a pattern matches is skipped for as long as a default leaves by it
// with one event when the skip begins and one when it ends, and the pass's status names the links and the skip
func TestExitModeExpandsForwardOnEachPass(t *testing.T) {
	bus := events.New()
	network := &hostNetwork{state: exitPassHost()}
	mode := &ExitMode{Forward: []string{"br-*", "eth*"}}
	tbl := Table{Addresses: prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))}.WithMode(mode)
	reconciler, _, fake := harness(t, tbl, Runtime{Overlay: exitPassOverlay, Network: network.read, Events: bus})

	reconciler.reconcile()
	if got, want := catchAll(fake), []string{"ipv4 iif lo", "ipv6 iif lo"}; !slices.Equal(got, want) {
		t.Errorf("at the start the catch-all reads %v, want %v", got, want)
	}
	skip := ForwardSkip{Entry: "eth*", Link: "eth0", Reason: "the link the IPv4 default leaves by"}
	if status := reconciler.Stats().Exit; status == nil || len(status.Forwarded) != 0 || !slices.Equal(status.Skipped, []ForwardSkip{skip}) || len(status.Unaddressed) != 0 {
		t.Errorf("at the start the status reads %+v, want eth0 skipped and nothing forwarded", status)
	}

	network.set(exitPassHost("br-1", "br-2"))
	reconciler.reconcile()
	if got, want := catchAll(fake), []string{"ipv4 iif br-1", "ipv4 iif br-2", "ipv4 iif lo", "ipv6 iif br-1", "ipv6 iif br-2", "ipv6 iif lo"}; !slices.Equal(got, want) {
		t.Errorf("with two bridges up the catch-all reads %v, want %v", got, want)
	}
	if status := reconciler.Stats().Exit; status == nil || !slices.Equal(status.Forwarded, []string{"br-1", "br-2"}) {
		t.Errorf("with two bridges up the status reads %+v", status)
	}

	gone := exitPassHost("br-2")
	gone.IPv4.Default, gone.IPv6.Default = DefaultRoute{}, DefaultRoute{}
	network.set(gone)
	reconciler.reconcile()
	if got, want := catchAll(fake), []string{"ipv4 iif br-2", "ipv4 iif eth0", "ipv4 iif lo", "ipv6 iif br-2", "ipv6 iif eth0", "ipv6 iif lo"}; !slices.Equal(got, want) {
		t.Errorf("with br-1 gone and no default the catch-all reads %v, want %v", got, want)
	}
	if got, want := forwardEvents(bus), [][]string{{"eth0", "eth*", "true"}, {"eth0", "eth*", "false"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("the skip was recorded as %v, want %v", got, want)
	}
}

// exitEvents is each kernel.exit event recorded, as its family and whether the family is addressed
func exitEvents(bus *events.Bus) [][]string {
	var out [][]string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.exit" }, 0) {
		out = append(out, []string{event.Attrs["family"], event.Attrs["addressed"]})
	}
	return out
}

// the pass a reload runs reads the tun's addresses after its own address step, so the reload's own pass puts the catch-all for the
// host's traffic of a family in where it gives the tun an overlay address of that family, and takes it out where it takes the address off,
// with an event at each edge, mode off and a withdrawal ending the family's state as well
func TestExitModeCatchesAFamilysHostTrafficWhileTheTunHoldsItsAddress(t *testing.T) {
	bus := events.New()
	network := &hostNetwork{state: exitPassHost()}
	without := Table{Addresses: prefixes(prefix("192.0.2.1/32"))}.WithMode(&ExitMode{})
	with := Table{Addresses: prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))}.WithMode(&ExitMode{})
	reconciler, table, fake := harness(t, without, Runtime{Overlay: exitPassOverlay, Network: network.read, Events: bus})
	table.Set(netip.Prefix{}, prefix("2001:db8:5::/48"), nil)
	last := runToRecord(t, reconciler, table, bus)
	holds := func(want ...string) func() bool {
		return func() bool {
			fake.mu.Lock()
			defer fake.mu.Unlock()
			return slices.Equal(catchAll(fake), want)
		}
	}
	awaitPass(t, last, "the first pass, with no IPv6 address on the tun", "start", holds("ipv4 iif lo"))
	for _, step := range []struct {
		what  string
		table Table
		want  []string
	}{
		{"the pass after a reload giving the tun an IPv6 overlay address", with, []string{"ipv4 iif lo", "ipv6 iif lo"}},
		{"the pass after a reload taking it off", without, []string{"ipv4 iif lo"}},
		{"the pass after a reload to mode off", Table{Addresses: without.Addresses}, nil},
		{"the pass after a reload to mode 2 with the IPv6 overlay address", with, []string{"ipv4 iif lo", "ipv6 iif lo"}},
		{"the pass after a reload taking it off again", without, []string{"ipv4 iif lo"}},
	} {
		if err := reconciler.SetTable(step.table, exitPassOverlay, nil); err != nil {
			t.Fatal(err)
		}
		awaitPass(t, last, step.what, "reload", holds(step.want...))
	}
	// the withdrawal's pass is the one recorded after the stop with nothing installed
	before := reconciler.Stats().At
	reconciler.SetEnabled(false)
	waitFor(t, func() bool { stats := reconciler.Stats(); return stats.At.After(before) && stats.Installed == 0 })
	if status := reconciler.Stats().Exit; status != nil {
		t.Errorf("after the withdrawal the status reads %+v, want none", status)
	}
	if got, want := exitEvents(bus), [][]string{{"ipv6", "false"}, {"ipv6", "true"}, {"ipv6", "false"}, {"ipv6", "true"}, {"ipv6", "false"}, {"ipv6", "true"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("the family's edges were recorded as %v, want %v", got, want)
	}
}

// a family counts as addressed by the overlay addresses the tun holds, another writer's as much as cap.table's, and an add of
// cap.table's own that failed or an address outside the overlay addresses nothing
func TestExitModeReadsTheFamiliesFromTheTun(t *testing.T) {
	v4, v6 := prefix("192.0.2.1/32"), prefix("3fff::1/128")
	for _, c := range []struct {
		what            string
		assigned        []schema.Prefix
		byHand, refused []netip.Prefix
		catchAll        []string
		unaddressed     []Family
	}{
		{"cap.table writing an IPv4 overlay address and another writer an IPv6 one", prefixes(v4), []netip.Prefix{v6}, nil,
			[]string{"ipv4 iif lo", "ipv6 iif lo"}, nil},
		{"cap.table writing none and another writer both", nil, []netip.Prefix{v4, v6}, nil,
			[]string{"ipv4 iif lo", "ipv6 iif lo"}, nil},
		{"cap.table's IPv6 address refused by the link", prefixes(v4, v6), nil, []netip.Prefix{v6},
			[]string{"ipv4 iif lo"}, []Family{FamilyIPv6}},
		{"cap.table writing an IPv4 overlay address and an IPv6 one outside the overlay", prefixes(v4, prefix("2001:db8:a::99/128")), nil, nil,
			[]string{"ipv4 iif lo"}, []Family{FamilyIPv6}},
	} {
		network := &hostNetwork{state: exitPassHost()}
		reconciler, _, fake := harness(t, Table{Addresses: c.assigned}.WithMode(&ExitMode{}), Runtime{Overlay: exitPassOverlay, Network: network.read})
		for _, address := range c.byHand {
			fake.addrs[address] = true
		}
		for _, address := range c.refused {
			fake.failAssign[address] = errors.New("the link refuses the address")
		}
		reconciler.reconcile()
		if got := catchAll(fake); !slices.Equal(got, c.catchAll) {
			t.Errorf("%s: the catch-all reads %v, want %v", c.what, got, c.catchAll)
		}
		if status := reconciler.Stats().Exit; status == nil || !slices.Equal(status.Unaddressed, c.unaddressed) {
			t.Errorf("%s: the status reads %+v, want %v unaddressed", c.what, status, c.unaddressed)
		}
	}
}

// a pass in mode 2 that cannot list the tun's addresses cannot tell the families it holds an overlay address of, so it leaves the
// rules and the status as the last pass put them and fails, which has it retried, whether the last pass found both families
// addressed or one unaddressed
func TestExitModeLeavesTheRulesWhileTheTunWillNotList(t *testing.T) {
	for _, c := range []struct {
		what        string
		assigned    []schema.Prefix
		catchAll    []string
		unaddressed []Family
	}{
		{"both families addressed", prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128")), []string{"ipv4 iif lo", "ipv6 iif lo"}, nil},
		{"IPv6 unaddressed", prefixes(prefix("192.0.2.1/32")), []string{"ipv4 iif lo"}, []Family{FamilyIPv6}},
	} {
		network := &hostNetwork{state: exitPassHost()}
		reconciler, _, fake := harness(t, Table{Addresses: c.assigned}.WithMode(&ExitMode{}), Runtime{Overlay: exitPassOverlay, Network: network.read})
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		fake.failAddrs = errors.New("the link will not list")
		if err := reconciler.reconcile(); err == nil {
			t.Errorf("%s: a pass that could not list the tun's addresses succeeded", c.what)
		}
		if got := catchAll(fake); !slices.Equal(got, c.catchAll) {
			t.Errorf("%s: after a pass that could not list the tun's addresses the catch-all reads %v, want %v", c.what, got, c.catchAll)
		}
		if status := reconciler.Stats().Exit; status == nil || !slices.Equal(status.Unaddressed, c.unaddressed) {
			t.Errorf("%s: after a pass that could not list the tun's addresses the status reads %+v, want %v unaddressed", c.what, status, c.unaddressed)
		}
	}
}

// another writer adding an overlay address to the tun, or taking one off, wakes a pass that reads the tun again
func TestExitModeFollowsAnotherWritersAddressOnTheTun(t *testing.T) {
	bus := events.New()
	network := &hostNetwork{state: exitPassHost()}
	reconciler, table, fake := harness(t, Table{}.WithMode(&ExitMode{}), Runtime{Overlay: exitPassOverlay, Network: network.read, Events: bus})
	fake.addressNotes = true
	table.Set(netip.Prefix{}, prefix("2001:db8:5::/48"), nil)
	last := runToRecord(t, reconciler, table, bus)
	holds := func(want ...string) func() bool {
		return func() bool {
			fake.mu.Lock()
			defer fake.mu.Unlock()
			return slices.Equal(catchAll(fake), want)
		}
	}
	awaitPass(t, last, "the first pass, the tun holding no address", "start", holds())
	fake.byHand(prefix("192.0.2.1/32"), true)
	awaitPass(t, last, "the pass after another writer's IPv4 overlay address", "kernel", holds("ipv4 iif lo"))
	fake.byHand(prefix("192.0.2.1/32"), false)
	awaitPass(t, last, "the pass after it is taken off", "kernel", holds())
}

// quietAfter is how long a test waits for a pass that should not come, a few of the settle windows a wake runs after
const quietAfter = 4 * settleDelay

// the pass that adds cap.table's own addresses reads them back, so the wake its own adds raise runs one more pass and that pass changes nothing
func TestExitModeSettlesAfterAddingItsOwnAddresses(t *testing.T) {
	bus := events.New()
	network := &hostNetwork{state: exitPassHost()}
	tbl := Table{Addresses: prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))}.WithMode(&ExitMode{})
	reconciler, table, fake := harness(t, tbl, Runtime{Overlay: exitPassOverlay, Network: network.read, Events: bus})
	fake.addressNotes = true
	table.Set(netip.Prefix{}, prefix("2001:db8:5::/48"), nil)
	last := runToRecord(t, reconciler, table, bus)
	passes := func() int {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return fake.listed
	}
	awaitPass(t, last, "the first pass", "start", func() bool { return passes() >= 2 })
	time.Sleep(quietAfter)
	if got := passes(); got != 2 {
		t.Errorf("the reconciler ran %d passes, want the first and the one its own adds woke", got)
	}
	if got := last(); got != "start" {
		t.Errorf("the last pass that changed anything was woken by %q, want the first", got)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if got, want := catchAll(fake), []string{"ipv4 iif lo", "ipv6 iif lo"}; !slices.Equal(got, want) {
		t.Errorf("the catch-all reads %v, want %v", got, want)
	}
}

// a reload adding cap.exit puts mode 2's rules in on the next pass and one removing it takes them out, in the reconciler already running
// in mode off nothing reads the watch's links
func TestReloadAddingAndRemovingTheModeChangesTheRules(t *testing.T) {
	network := &hostNetwork{state: exitPassHost("docker0")}
	tbl := Table{Addresses: prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))}
	reconciler, _, fake := harness(t, tbl, Runtime{Overlay: exitPassOverlay, Network: network.read})
	reconciler.reconcile()
	off := maps.Clone(fake.rules)
	if len(catchAll(fake)) != 0 || reconciler.Stats().Exit != nil {
		t.Fatalf("in mode off the reconciler holds %v and reports %+v", catchAll(fake), reconciler.Stats().Exit)
	}

	if err := reconciler.SetTable(tbl.WithMode(&ExitMode{Forward: []string{"docker0"}}), exitPassOverlay, nil); err != nil {
		t.Fatal(err)
	}
	if !reconciler.adopt() {
		t.Fatal("the reconciler took no table")
	}
	reconciler.reconcile()
	if got, want := catchAll(fake), []string{"ipv4 iif docker0", "ipv4 iif lo", "ipv6 iif docker0", "ipv6 iif lo"}; !slices.Equal(got, want) {
		t.Errorf("after adding cap.exit the catch-all reads %v, want %v", got, want)
	}
	uplink := Rule{Family: FamilyIPv4, Priority: priorityUplinkSource, From: schema.MustPrefix("198.51.100.10/32"), IIF: loopback, Table: schema.TableMain}
	if !fake.rules[uplink] {
		t.Errorf("after adding cap.exit the reconciler holds no %s", uplink)
	}

	if err := reconciler.SetTable(tbl, exitPassOverlay, nil); err != nil {
		t.Fatal(err)
	}
	reconciler.adopt()
	reconciler.reconcile()
	if !maps.Equal(fake.rules, off) {
		t.Errorf("after removing cap.exit the reconciler holds %v, want mode off's %v", fake.rules, off)
	}
}
