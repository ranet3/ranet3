// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const (
	// testLoopback is lo0's index on switchHost, and testOther another
	// program's utun there
	testLoopback = 1
	testOther    = 7
)

// switchHost is a host whose table a test sets and whose route socket keeps
// what reaches it, naming lo0 and another program's utun5
type switchHost struct {
	runningKernel
	t       *testing.T
	entries []dumpEntry
	sent    [][]byte
}

func (h *switchHost) Dump() ([]byte, error) { return dumpRIB(h.t, h.entries...), nil }

func (h *switchHost) InterfaceIndex(name string) (int, error) {
	if name == Loopback {
		return testLoopback, nil
	}
	return 0, errors.New("no such interface")
}

func (h *switchHost) InterfaceName(index int) (string, error) {
	switch index {
	case testLoopback:
		return Loopback, nil
	case testOther:
		return "utun5", nil
	}
	return "", errors.New("no such interface")
}

func (h *switchHost) RouteSocket() (RouteWriter, error) { return h, nil }
func (h *switchHost) WriteRoute(raw []byte) error {
	h.sent = append(h.sent, raw)
	return nil
}
func (h *switchHost) Close() error { return nil }

// rejectEntry is a reject in the switch's shape at destination as a dump reports it
func rejectEntry(destination netip.Prefix) dumpEntry {
	return dumpEntry{index: testLoopback, flags: loopFlags, dst: destination, gateway: routeAddr(loopGateway(destination))}
}

// sentKeys is the type and key of each message in sent, checking each carries
// the rejects' shape: their flags, no interface, and the loopback gateway of
// its family
func sentKeys(t *testing.T, messages []*route.RouteMessage) (kinds []int, keys []netip.Prefix) {
	t.Helper()
	for _, rm := range messages {
		destination, err := addressFromRouteAddrOK(rm.Addrs[unix.RTAX_DST])
		if err != nil {
			t.Fatal(err)
		}
		mask, err := addressFromRouteAddrOK(rm.Addrs[unix.RTAX_NETMASK])
		if err != nil {
			t.Fatal(err)
		}
		bits, _ := maskBits(mask)
		key := netip.PrefixFrom(destination, bits)
		gateway, err := addressFromRouteAddrOK(rm.Addrs[unix.RTAX_GATEWAY])
		if err != nil || gateway != loopGateway(key) || rm.Flags != loopFlags || rm.Index != 0 {
			t.Errorf("the message at %s carries flags %#x, interface %d and gateway %v, want %#x, none and %s",
				key, rm.Flags, rm.Index, rm.Addrs[unix.RTAX_GATEWAY], loopFlags, loopGateway(key))
		}
		kinds, keys = append(kinds, rm.Type), append(keys, key)
	}
	return kinds, keys
}

func addressFromRouteAddrOK(addr route.Addr) (netip.Addr, error) {
	address, ok := addressFromRouteAddr(addr)
	if !ok {
		return netip.Addr{}, errors.New("a message without an address where one was written")
	}
	return address, nil
}

// The switch reads its rejects from the pass's dump alone, adds each it finds
// missing on lo0 in their shape, names another program's route at a key or a
// route of another shape on lo0 as the fault and never takes either over, and
// deletes from a dump of its own every reject of its shape and nothing else
func TestDarwinSwitchWritesReadsAndDeletesTheRejects(t *testing.T) {
	host := &switchHost{t: t}
	plat, sock := testPlatform(t, Table{}, Runtime{})
	plat.host, plat.loopback = host, testLoopback
	sets := fallbackSets{rejects: rejectKeys}
	if _, err := plat.readFallback(sets); !errors.Is(err, errNoLoopDump) {
		t.Errorf("a read before any dump of the pass answered %v, want %v", err, errNoLoopDump)
	}
	if _, err := plat.ownedRoutes(dumpRIB(t)); err != nil {
		t.Fatal(err)
	}
	if read, err := plat.readFallback(sets); err != nil || read.fault != "the reject at 1.0.0.0/8 is missing" {
		t.Errorf("an empty table reads %+v, %v, want the first reject missing", read, err)
	}
	if err := plat.writeFallback(sets, false); err != nil {
		t.Fatal(err)
	}
	kinds, keys := sentKeys(t, sock.messages(t))
	if !slices.Equal(keys, rejectKeys) || slices.ContainsFunc(kinds, func(kind int) bool { return kind != unix.RTM_ADD }) {
		t.Errorf("the write sent %v at %v, want an add at each of %v", kinds, keys, rejectKeys)
	}
	if read, err := plat.readFallback(sets); err != nil || read.fault != "" {
		t.Errorf("after the write the switch reads %+v, %v, want no fault", read, err)
	}

	taken, misshaped := prefix("2000::/3"), prefix("128.0.0.0/1")
	var entries []dumpEntry
	for _, key := range rejectKeys {
		switch key {
		case taken:
			entries = append(entries, dumpEntry{index: testOther, flags: unix.RTF_UP | unix.RTF_STATIC, dst: key, gateway: &route.LinkAddr{Index: testOther}})
		case misshaped:
			blackhole := rejectEntry(key)
			blackhole.flags = unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY | unix.RTF_BLACKHOLE
			entries = append(entries, blackhole)
		default:
			entries = append(entries, rejectEntry(key))
		}
	}
	// a route scoped to the tun at a key is keyed apart and meets no reject
	entries = append(entries, dumpEntry{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE, dst: prefix("1.0.0.0/8"), gateway: ourGateway()})
	if _, err := plat.ownedRoutes(dumpRIB(t, entries...)); err != nil {
		t.Fatal(err)
	}
	want := "the route 128.0.0.0/1 via 127.0.0.1 on lo0 is no reject of the switch's shape"
	if read, _ := plat.readFallback(sets); read.fault != want {
		t.Errorf("the table reads %q, want %q", read.fault, want)
	}
	sock.sent, sock.err = nil, unix.EEXIST
	if err := plat.writeFallback(sets, false); err != nil {
		t.Fatal(err)
	}
	if kinds, keys := sentKeys(t, sock.messages(t)); !slices.Equal(keys, []netip.Prefix{misshaped, taken}) || slices.Contains(kinds, unix.RTM_DELETE) {
		t.Errorf("the rewrite sent %v at %v, want an add at each of %s and %s and no delete", kinds, keys, misshaped, taken)
	}
	plat.loops[misshaped] = ""
	want = "another program's route 2000::/3 on utun5 holds a key of the switch's"
	if read, _ := plat.readFallback(sets); read.fault != want {
		t.Errorf("the table reads %q, want %q", read.fault, want)
	}
	// a member of ours whole out of the tun at a key, whose delete has not gone
	whole := []dumpEntry{{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC, dst: misshaped, gateway: ourGateway()}}
	for _, key := range rejectKeys {
		if key != misshaped {
			whole = append(whole, rejectEntry(key))
		}
	}
	if _, err := plat.ownedRoutes(dumpRIB(t, whole...)); err != nil {
		t.Fatal(err)
	}
	want = "this node's own route 128.0.0.0/1 on interface 42 holds a key of the switch's until it goes in as its halves"
	if read, _ := plat.readFallback(sets); read.fault != want {
		t.Errorf("the table reads %q, want %q", read.fault, want)
	}

	sock.sent, sock.err = nil, nil
	host.entries = entries
	if held, err := plat.holdsFallback(); err != nil || !held {
		t.Errorf("a listing of the rejects answers %v, %v", held, err)
	}
	if err := plat.deleteFallback(); err != nil {
		t.Fatal(err)
	}
	kinds, keys = sentKeys(t, sock.messages(t))
	wantKeys := slices.DeleteFunc(slices.Clone(rejectKeys), func(key netip.Prefix) bool { return key == taken || key == misshaped })
	if !slices.Equal(keys, wantKeys) || slices.ContainsFunc(kinds, func(kind int) bool { return kind != unix.RTM_DELETE }) {
		t.Errorf("the delete sent %v at %v, want a delete at each of %v", kinds, keys, wantKeys)
	}
	host.entries = entries[:0:0]
	for _, entry := range entries {
		if entry.dst == taken || entry.dst == misshaped {
			host.entries = append(host.entries, entry)
		}
	}
	if held, err := plat.holdsFallback(); err != nil || held {
		t.Errorf("a listing of no reject answers %v, %v", held, err)
	}
}

// The start with no reconciler deletes the rejects at the switch's keys and
// leaves a reject of their shape another program wrote at another key, and a
// debug read lists each reject with the sends of IPv4's alone counted
func TestDarwinDeleteFallbackTakesTheRejectsAlone(t *testing.T) {
	host := &switchHost{t: t, entries: []dumpEntry{rejectEntry(prefix("10.0.0.0/8"))}}
	for _, key := range rejectKeys {
		host.entries = append(host.entries, rejectEntry(key))
	}
	read, err := readRejects(host)
	if err != nil || !read.Held || len(read.Rules) != len(rejectKeys) || read.Where != "rejects on lo0" {
		t.Fatalf("the debug read answers %+v, %v, want the %d rejects on lo0", read, err, len(rejectKeys))
	}
	for i, rule := range read.Rules {
		key := rejectKeys[i]
		if rule.Spec != key.String()+" via "+loopGateway(key).String()+" reject" || rule.Counted != key.Addr().Is4() {
			t.Errorf("the reject at %s reads %+v", key, rule)
		}
	}
	if err := deleteRejects(host); err != nil {
		t.Fatal(err)
	}
	var messages []*route.RouteMessage
	for _, raw := range host.sent {
		parsed, err := route.ParseRIB(route.RIBTypeRoute, raw)
		if err != nil || len(parsed) != 1 {
			t.Fatalf("parse back a sent message: %v", err)
		}
		messages = append(messages, parsed[0].(*route.RouteMessage))
	}
	kinds, keys := sentKeys(t, messages)
	if !slices.Equal(keys, rejectKeys) || slices.ContainsFunc(kinds, func(kind int) bool { return kind != unix.RTM_DELETE }) {
		t.Errorf("the start deleted %v at %v, want a delete at each of %v alone", kinds, keys, rejectKeys)
	}
}

// The underlay's selection passes over the switch's rejects, which carry no
// datagram, and keeps another program's reject as a candidate
func TestDarwinSelectionPassesTheSwitchOver(t *testing.T) {
	entries := []dumpEntry{
		{index: testOther, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY, dst: prefix("0.0.0.0/0"), gateway: routeAddr(addr("192.0.2.1"))},
		rejectEntry(prefix("10.0.0.0/8")),
	}
	for _, key := range rejectKeys {
		entries = append(entries, rejectEntry(key))
	}
	routes, err := hostRoutes(dumpRIB(t, entries...))
	if err != nil {
		t.Fatal(err)
	}
	for destination, want := range map[string]string{"203.0.113.7": "0.0.0.0/0", "10.1.2.3": "10.0.0.0/8"} {
		if got, ok := selectRoute(routes, testIndex, addr(destination), 0); !ok || got.destination != prefix(want) {
			t.Errorf("%s selects %+v, want the route at %s", destination, got, want)
		}
	}
}
