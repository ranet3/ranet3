// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const (
	// selectionWait bounds the wait for a selection to follow a change, many settles long
	selectionWait = 5 * time.Second
	// selectionPoll is how often the wait looks
	selectionPoll = 10 * time.Millisecond
	// selectionQuiet is how long a test waits for a change the selection reads to have been read, a few settles long
	selectionQuiet = 4 * selectionSettle
	// selectionMeshName is the name the recorded host gives ranet3's interface
	selectionMeshName = "mesh0"
	// selectionUplink and selectionOther are interfaces of the recorded host other than ranet3's
	selectionUplink = 2
	selectionOther  = 3
	// selectionOtherName is the name the recorded host gives selectionOther
	selectionOtherName = "en1"
)

// selectionHost is a host whose routing table a test sets, and whose watcher wakes when the test says
type selectionHost struct {
	runningKernel
	t       *testing.T
	mu      sync.Mutex
	entries []dumpEntry
	failing error
	changed chan struct{}
}

func newSelectionHost(t *testing.T, entries ...dumpEntry) *selectionHost {
	return &selectionHost{t: t, entries: entries, changed: make(chan struct{}, 1)}
}

func (h *selectionHost) InterfaceIndex(name string) (int, error) {
	if index, ok := map[string]int{selectionMeshName: selectMesh, selectionOtherName: selectionOther}[name]; ok {
		return index, nil
	}
	return 0, errors.New("no such interface")
}

func (h *selectionHost) Dump() ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failing != nil {
		return nil, h.failing
	}
	return dumpRIB(h.t, h.entries...), nil
}

func (h *selectionHost) Watch(int, int, bool) (Watcher, error) { return h, nil }
func (h *selectionHost) Changed() <-chan struct{}              { return h.changed }
func (h *selectionHost) Close() error                          { return nil }

// set replaces the table, or makes its dump fail with failing, and wakes the watcher
func (h *selectionHost) set(failing error, entries ...dumpEntry) {
	h.mu.Lock()
	h.entries, h.failing = entries, failing
	h.mu.Unlock()
	select {
	case h.changed <- struct{}{}:
	default:
	}
}

// selectionEntry is one dumped route out of index with flags beside RTF_UP
func selectionEntry(index, flags int, destination string) dumpEntry {
	return dumpEntry{index: index, flags: unix.RTF_UP | flags, dst: prefix(destination), gateway: &route.LinkAddr{Index: index}}
}

func openTestSelection(t *testing.T, host Host, mesh string) *Selection {
	t.Helper()
	selection, err := OpenSelection(host, mesh)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = selection.Close() })
	return selection
}

// waitSelection polls until ok holds or selectionWait passed, and reports whether it held
func waitSelection(ok func() bool) bool {
	for deadline := time.Now().Add(selectionWait); !ok(); time.Sleep(selectionPoll) {
		if time.Now().After(deadline) {
			return false
		}
	}
	return true
}

// a dump decodes to the routes the selection reads, and an answer takes the
// longest route a socket scoped to no interface reaches outside ranet3's
// interface, or a link-local zone's interface, named by index or by name
// the multicast, broadcast and down entries sit on an interface the default does not leave by
func TestDarwinSelectionReadsTheDump(t *testing.T) {
	host := newSelectionHost(t,
		dumpEntry{index: selectionUplink, flags: unix.RTF_UP | unix.RTF_GATEWAY, dst: prefix("0.0.0.0/0"), gateway: routeAddr(netip.MustParseAddr("198.51.100.1"))},
		selectionEntry(selectionOther, 0, "203.0.113.0/24"),
		selectionEntry(selectMesh, 0, "203.0.113.0/25"),
		selectionEntry(selectionUplink, unix.RTF_IFSCOPE, "203.0.113.64/26"),
		selectionEntry(selectionUplink, unix.RTF_WASCLONED, "203.0.113.70/32"),
		selectionEntry(selectionOther, unix.RTF_MULTICAST, "224.0.0.0/4"),
		selectionEntry(selectionOther, unix.RTF_BROADCAST, "192.0.2.255/32"),
		dumpEntry{index: selectionOther, dst: prefix("198.51.100.0/24"), gateway: &route.LinkAddr{Index: selectionOther}},
		selectionEntry(selectionOther, unix.RTF_REJECT, "2001:db8:100::/48"),
	)
	selection := openTestSelection(t, host, selectionMeshName)
	for _, test := range []struct {
		address string
		want    int
	}{
		{"203.0.113.70", selectionOther},
		{"192.0.2.1", selectionUplink},
		{"224.0.0.9", selectionUplink},
		{"192.0.2.255", selectionUplink},
		{"198.51.100.9", selectionUplink},
		{"2001:db8:100::9", selectionOther},
		{"2001:db8:200::9", 0},
		{"fe80::9%3", selectionOther},
		{"fe80::9%" + selectionOtherName, selectionOther},
		{"fe80::9%1", 0},
		{"fe80::9%" + selectionMeshName, 0},
	} {
		if got, generation := selection.Interface(netip.MustParseAddr(test.address)); got != test.want || generation != 1 {
			t.Errorf("%s selects interface %d at generation %d, want %d at 1", test.address, got, generation, test.want)
		}
	}
}

// a change the watcher reports is read after the settle and moves the
// generation where the candidate routes changed, a change of none of them
// leaves it, a dump that fails keeps the last answers, and the next dump that
// works is read
func TestDarwinSelectionFollowsTheWatcher(t *testing.T) {
	target := netip.MustParseAddr("203.0.113.9")
	moved := selectionEntry(selectionOther, 0, "203.0.113.0/24")
	host := newSelectionHost(t, selectionEntry(selectionUplink, 0, "203.0.113.0/24"))
	selection := openTestSelection(t, host, selectionMeshName)
	answers := func(index int, generation uint64) bool {
		got, at := selection.Interface(target)
		return got == index && at == generation
	}
	host.set(nil, moved)
	if !waitSelection(func() bool { return answers(selectionOther, 2) }) {
		t.Fatalf("the route moved to interface %d, and %s does not select it at generation 2", selectionOther, target)
	}
	for _, step := range []struct {
		name    string
		failing error
		entries []dumpEntry
	}{
		{"a route on ranet3's interface", nil, []dumpEntry{moved, selectionEntry(selectMesh, 0, "203.0.113.0/25")}},
		{"a dump that fails", errors.New("the dump failed"), nil},
	} {
		host.set(step.failing, step.entries...)
		time.Sleep(selectionQuiet)
		if !answers(selectionOther, 2) {
			got, generation := selection.Interface(target)
			t.Errorf("after %s, %s selects %d at generation %d, want %d at 2", step.name, target, got, generation, selectionOther)
		}
	}
	host.set(nil, selectionEntry(selectionUplink, 0, "203.0.113.0/24"))
	if !waitSelection(func() bool { return answers(selectionUplink, 3) }) {
		t.Errorf("the dump works again with the route back on interface %d, and %s does not select it at generation 3", selectionUplink, target)
	}
}

// a table that cannot be read refuses the start
func TestDarwinSelectionRefusesAnUnreadableTable(t *testing.T) {
	host := newSelectionHost(t)
	host.failing = errors.New("the dump failed")
	if selection, err := OpenSelection(host, selectionMeshName); err == nil {
		_ = selection.Close()
		t.Fatal("a selection opened over a table it could not read")
	}
}

// selectTUN is one test utun with an address of each family, standing in for an uplink or for ranet3's interface
type selectTUN struct {
	name  string
	index int
	plat  *routePlatform
}

func newSelectTUN(t *testing.T, v4, v6 string) *selectTUN {
	t.Helper()
	name, _ := createUTUNWithFD(t)
	setInterfaceUp(t, name)
	tun := &selectTUN{name: name, index: interfaceIndex(t, name), plat: testTUNPlatform(t, name)}
	for _, assigned := range []string{v4, v6} {
		if err := tun.plat.AddAddr(prefix(assigned)); err != nil {
			t.Fatalf("assign %s to %s: %v", assigned, name, err)
		}
	}
	return tun
}

// add installs destination out of tun, scoped to it or not, and returns its withdrawal, which a cleanup runs too
func (tun *selectTUN) add(t *testing.T, destination string, scoped bool) func() {
	t.Helper()
	target := prefix(destination)
	r := Route{Destination: target}
	if target.Addr().Is6() {
		r.Metric = defaultIPv6Metric
	}
	add, del := func() error { return tun.plat.AddRoute(r) }, func() error { return tun.plat.DelRoute(r) }
	if scoped {
		add, del = func() error { return tun.plat.addScopedRoute(target) }, func() error { return tun.plat.delScopedRoute(target) }
	}
	if err := add(); err != nil {
		t.Fatalf("install %s out of %s, scoped %v: %v", target, tun.name, scoped, err)
	}
	withdrawn := false
	withdraw := func() {
		if withdrawn {
			return
		}
		withdrawn = true
		if err := del(); err != nil && !gone(err) {
			t.Errorf("withdraw %s out of %s, scoped %v: %v", target, tun.name, scoped, err)
		}
	}
	t.Cleanup(withdraw)
	return withdraw
}

// askRoute is the interface RTM_GET answers for destination, scoped to index where it is nonzero, and zero for no route
// XNU answers it through rt_lookup with that scope, the lookup a send scoped to index makes
func askRoute(t *testing.T, destination netip.Addr, index int) int {
	t.Helper()
	fd, err := lookupSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	seq := int(lookupSeq.Add(1))
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = routeAddr(destination)
	request := &route.RouteMessage{Version: unix.RTM_VERSION, Type: unix.RTM_GET, Flags: unix.RTF_UP, ID: uintptr(os.Getpid()), Seq: seq, Addrs: addrs}
	if index != 0 {
		request.Flags |= unix.RTF_IFSCOPE
		request.Index = index
	}
	raw, err := request.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fd, raw); errors.Is(err, unix.ESRCH) {
		return 0
	} else if err != nil {
		t.Fatalf("ask for the route to %s scoped to %d: %v", destination, index, err)
	}
	answer, err := readAnswer(fd, seq, destination)
	if err != nil {
		t.Fatal(err)
	}
	return answer.Index
}

// On three test utuns, A and B standing in for uplinks and M for ranet3's
// interface, with routes unscoped and scoped on A and B and routes on M longer
// than A's: the selection with M's routes in names the interface RTM_GET
// names unscoped once M's routes are out, and RTM_GET scoped to that interface
// answers a route on it rather than ESRCH. A target outside every test route
// takes the host's own answer. The interface for each test target is the one
// the table says, so the comparison is about a table this test controls.
func TestDarwinSelectionIsTheKernelsLookupWithTheMeshLeftOut(t *testing.T) {
	requireNetTest(t)
	a := newSelectTUN(t, "198.51.100.1/26", "2001:db8:aa::1/64")
	b := newSelectTUN(t, "198.51.100.65/26", "2001:db8:bb::1/64")
	mesh := newSelectTUN(t, "198.51.100.129/26", "2001:db8:cc::1/64")
	for _, r := range []struct {
		tun         *selectTUN
		destination string
		scoped      bool
	}{
		{a, "203.0.113.0/24", false}, {b, "203.0.113.64/26", false}, {b, "203.0.113.128/25", true}, {a, "203.0.113.200/32", false},
		{a, "2001:db8:100::/48", false}, {b, "2001:db8:100:1::/64", false}, {b, "2001:db8:100:2::/64", true}, {a, "2001:db8:100:8000::9/128", false},
	} {
		r.tun.add(t, r.destination, r.scoped)
	}
	var meshRoutes []func()
	for _, destination := range []string{"203.0.113.0/25", "203.0.113.192/27", "2001:db8:100::/56", "2001:db8:100:8000::/49"} {
		meshRoutes = append(meshRoutes, mesh.add(t, destination, false))
	}
	selection := openTestSelection(t, nil, mesh.name)
	chosen := map[netip.Addr]int{}
	for _, target := range []struct {
		address string
		want    *selectTUN
	}{
		{"203.0.113.9", a}, {"203.0.113.70", b}, {"203.0.113.130", a}, {"203.0.113.195", a}, {"203.0.113.200", a},
		{"2001:db8:100::9", a}, {"2001:db8:100:1::9", b}, {"2001:db8:100:2::9", a}, {"2001:db8:100:8000::9", a}, {"2001:db8:100:8000::a", a},
		{"192.0.2.77", nil}, {"2001:db8:ffff::77", nil},
	} {
		address := netip.MustParseAddr(target.address)
		index, _ := selection.Interface(address)
		if index == mesh.index {
			t.Errorf("%s selects the stand-in for ranet3's interface %s", address, mesh.name)
		}
		if target.want != nil && index != target.want.index {
			t.Errorf("%s selects interface %d, want %s's %d", address, index, target.want.name, target.want.index)
		}
		chosen[address] = index
	}
	for _, withdraw := range meshRoutes {
		withdraw()
	}
	for address, index := range chosen {
		if unscoped := askRoute(t, address, 0); unscoped != index {
			t.Errorf("%s selects interface %d with the stand-in's routes in, and RTM_GET answers %d once they are out", address, index, unscoped)
		}
		if index == 0 {
			continue
		}
		if scoped := askRoute(t, address, index); scoped != index {
			t.Errorf("%s selects interface %d, and RTM_GET scoped to it answers %d, which is ESRCH where 0", address, index, scoped)
		}
	}
}

// a route moved from one test utun to another moves the selection and its generation after the settle
func TestDarwinSelectionFollowsARouteThatMoves(t *testing.T) {
	requireNetTest(t)
	a := newSelectTUN(t, "198.51.100.1/26", "2001:db8:aa::1/64")
	b := newSelectTUN(t, "198.51.100.65/26", "2001:db8:bb::1/64")
	mesh := newSelectTUN(t, "198.51.100.129/26", "2001:db8:cc::1/64")
	destinations := []string{"203.0.113.0/24", "2001:db8:100::/48"}
	targets := []netip.Addr{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8:100::9")}
	var withdrawals []func()
	for _, destination := range destinations {
		withdrawals = append(withdrawals, a.add(t, destination, false))
	}
	selection := openTestSelection(t, nil, mesh.name)
	first := selection.Generation()
	selects := func(tun *selectTUN) bool {
		for _, target := range targets {
			if index, _ := selection.Interface(target); index != tun.index {
				return false
			}
		}
		return true
	}
	if !selects(a) {
		t.Fatalf("the targets do not select %s, which holds their routes", a.name)
	}
	for _, withdraw := range withdrawals {
		withdraw()
	}
	for _, destination := range destinations {
		b.add(t, destination, false)
	}
	if !waitSelection(func() bool { return selects(b) }) {
		t.Fatalf("the routes moved from %s to %s and the targets still do not select it after %s", a.name, b.name, selectionWait)
	}
	if got := selection.Generation(); got <= first {
		t.Errorf("the selection followed the move at generation %d, which was %d before it", got, first)
	}
}

// The premise the reclaim's last condition rests on, asserted on whatever
// machine the suite runs on rather than taken on trust: no interface holds
// both an unscoped default and a scoped one, so a scoped default on the
// interface that also holds the unscoped one is a shape only this tool
// produces. It reads the table and writes nothing.
func TestNoOtherProgramScopesADefaultToThePrimaryInterface(t *testing.T) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		t.Fatal(err)
	}
	// One subtest per family, so a family the host cannot answer for reports
	// itself untested rather than passing. This host carries nine scoped ::/0
	// routes on utuns and no unscoped one, and a single-bodied test skipped
	// quietly on it while claiming the premise held for IPv6.
	for _, destination := range defaultPrefixes {
		t.Run(destination.String(), func(t *testing.T) {
			primary, ok := unscopedDefaultIndex(messages, destination)
			if !ok {
				t.Skipf("this host has no default of this family, so the premise is untested for it")
			}
			scoped := 0
			for _, message := range messages {
				rm, ok := message.(*route.RouteMessage)
				if !ok || rm.Type != unix.RTM_GET || rm.Flags&unix.RTF_IFSCOPE == 0 {
					continue
				}
				if isDefaultKey(rm, destination) && rm.Index == primary {
					scoped++
				}
			}
			t.Logf("the host's default is on index %d, which carries %d scoped defaults", primary, scoped)
			if scoped != 0 {
				t.Errorf("interface %d holds both the unscoped default and %d scoped ones, so the reclaim's last condition does not tell this tool's route from another program's on this host",
					primary, scoped)
			}
		})
	}
}
