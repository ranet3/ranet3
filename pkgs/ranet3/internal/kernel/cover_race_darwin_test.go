// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const raceForeignIndex = 7

// raceRIB is a darwin routing table keyed as the kernel keys one, by the
// destination and whether it is scoped, holding the interface index each
// entry leaves by. An add at a held key meets EEXIST, and a key in release is
// freed right after the first add there is refused, as another program
// withdrawing between two writes of one pass would.
type raceRIB struct {
	runningKernel
	t       *testing.T
	held    map[occupiedKey]int
	release map[occupiedKey]bool
}

func (k *raceRIB) WriteRoute(m *route.RouteMessage) error {
	dst, ok := addressFromRouteAddr(m.Addrs[unix.RTAX_DST])
	if !ok {
		return unix.EINVAL
	}
	mask, ok := addressFromRouteAddr(m.Addrs[unix.RTAX_NETMASK])
	if !ok {
		return unix.EINVAL
	}
	bits, ok := maskBits(mask)
	if !ok {
		return unix.EINVAL
	}
	key := occupiedKey{destination: netip.PrefixFrom(dst, bits).Masked(), scoped: m.Flags&unix.RTF_IFSCOPE != 0}
	switch m.Type {
	case unix.RTM_ADD:
		if _, ok := k.held[key]; ok {
			if k.release[key] {
				delete(k.held, key)
				delete(k.release, key)
			}
			return unix.EEXIST
		}
		k.held[key] = m.Index
	case unix.RTM_DELETE:
		if _, ok := k.held[key]; !ok {
			return unix.ESRCH
		}
		delete(k.held, key)
	}
	return nil
}

func (k *raceRIB) Close() error { return nil }

func (k *raceRIB) Dump() ([]byte, error) {
	var entries []dumpEntry
	for key, index := range k.held {
		flags := unix.RTF_UP | unix.RTF_STATIC
		if key.scoped {
			flags |= unix.RTF_IFSCOPE
		}
		entries = append(entries, dumpEntry{index: index, flags: flags, dst: key.destination, gateway: &route.LinkAddr{Index: index}})
	}
	return dumpRIB(k.t, entries...), nil
}

func (k *raceRIB) Lookup(netip.Addr, netip.Addr) (RouteAnswer, error) {
	return RouteAnswer{}, ErrNoDefaultRoute
}

func newRaceRIB(t *testing.T, foreign netip.Prefix) *raceRIB {
	key := occupiedKey{destination: foreign}
	return &raceRIB{t: t, held: map[occupiedKey]int{key: raceForeignIndex}, release: map[occupiedKey]bool{key: true}}
}

// A member installed at a key another program held when an add of the same
// pass was refused there is this process's own, so the next dump reports it.
func TestDarwinMemberAtAKeyFreedAfterARefusalReadsBackAsOurs(t *testing.T) {
	plat, _ := testPlatform(t, Table{}, Runtime{BoundUnderlay: true})
	upper := prefix("128.0.0.0/1")
	rib := newRaceRIB(t, upper)
	plat.sock, plat.host = rib, rib
	if _, err := plat.Routes(); err != nil {
		t.Fatal(err)
	}
	if err := plat.AddRoute(Route{Destination: upper}); !errors.Is(err, errRouteSkipped) {
		t.Fatalf("the real route at a key another program holds reported %v", err)
	}
	if err := plat.AddRoute(Route{Destination: upper, Cover: true}); err != nil {
		t.Fatalf("the member at the freed key reported %v", err)
	}
	if owner := rib.held[occupiedKey{destination: upper}]; owner != testIndex {
		t.Fatalf("the member did not take the freed key: held by %d", owner)
	}
	actual, err := plat.Routes()
	if err != nil {
		t.Fatal(err)
	}
	if len(actual) != 1 || !actual[0].Cover {
		t.Errorf("the next dump reads back %v, want the member this process installed at %s", actual, upper)
	}
}

// TestRealRouteTakesItsKeyAfterARaceWithAnotherWriter over darwin's own
// record of refused keys: from the pass after the race the real route holds
// the key beside the rest of the IPv4 cover, with nothing skipped and every
// desired route installed.
func TestDarwinRealRouteTakesItsKeyAfterARace(t *testing.T) {
	reconciler, table, _ := harness(t, Table{}, Runtime{Sessions: func() int { return 1 }})
	plat, _ := testPlatform(t, reconciler.Table(), Runtime{BoundUnderlay: true})
	upper := prefix("128.0.0.0/1")
	rib := newRaceRIB(t, upper)
	plat.sock, plat.host = rib, rib
	reconciler.plat = plat
	reconciler.now = func() time.Time { return start }
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	table.Set(netip.Prefix{}, upper, nil)
	for pass := range 4 {
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if pass == 0 {
			continue
		}
		ours := 0
		for key, index := range rib.held {
			if index == testIndex && key.destination.Addr().Is4() {
				ours++
			}
		}
		owner, held := rib.held[occupiedKey{destination: upper}]
		if !held || owner != testIndex || plat.covering[upper] {
			t.Errorf("pass %d: %s held %v by %d as a member %v, want the real route of this process", pass, upper, held, owner, plat.covering[upper])
		}
		if ours != 8 {
			t.Errorf("pass %d: %d IPv4 keys of ours, want the real route and 7 members", pass, ours)
		}
		wantAllInstalled(t, reconciler, fmt.Sprintf("pass %d", pass))
	}
}
