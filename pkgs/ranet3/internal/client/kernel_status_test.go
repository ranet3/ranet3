// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"reflect"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/kernel"
)

// The control surface reports cap.exit's mode as the last pass ran it, each
// forwarded link, skip and unaddressed family, and no mode at all in mode off.
func TestExitStatusReportsThePassAndNothingInModeOff(t *testing.T) {
	if got := kernelExit(nil); got != nil {
		t.Errorf("mode off reports %+v, want no mode", got)
	}
	got := kernelExit(&kernel.ExitStatus{
		Forwarded:   []string{"br-1", "docker0"},
		Skipped:     []kernel.ForwardSkip{{Entry: "e*", Link: "eth0", Reason: "the link the IPv4 default leaves by"}},
		Unaddressed: []kernel.Family{kernel.FamilyIPv6},
	})
	want := &control.KernelExit{
		Forwarded:   []string{"br-1", "docker0"},
		Skipped:     []control.KernelSkip{{Entry: "e*", Link: "eth0", Reason: "the link the IPv4 default leaves by"}},
		Unaddressed: []string{"ipv6"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the pass's mode reports %+v, want %+v", got, want)
	}
}

// the control surface carries the switch's drops once a read of the reconciler's process found them, and none before
func TestExitStatusCarriesTheSwitchsDropsOnceRead(t *testing.T) {
	for _, c := range []struct {
		fallback kernel.FallbackStatus
		want     *control.FallbackDrops
	}{
		{kernel.FallbackStatus{State: kernel.FallbackNotHolding, Fault: "netlink: dump interrupted"}, nil},
		{kernel.FallbackStatus{State: kernel.FallbackHolding, Dropped: 5, DroppedBytes: 300, DropsRead: true}, &control.FallbackDrops{Packets: 5, Bytes: 300}},
		{kernel.FallbackStatus{State: kernel.FallbackNotHolding, Fault: "netlink: dump interrupted", DropsRead: true}, &control.FallbackDrops{}},
	} {
		got := kernelExit(&kernel.ExitStatus{Fallback: &c.fallback}).Fallback
		if !reflect.DeepEqual(got.Dropped, c.want) {
			t.Errorf("the switch %+v reports drops %+v, want %+v", c.fallback, got.Dropped, c.want)
		}
	}
	// macOS's rejects count nothing, which the status says rather than waiting for a read
	if got := kernelExit(&kernel.ExitStatus{Fallback: &kernel.FallbackStatus{State: kernel.FallbackHolding, Uncounted: true}}).Fallback; got.Dropped != nil || !got.Uncounted {
		t.Errorf("an uncounted switch reports %+v, want no drops and uncounted", got)
	}
}

// the control surface carries the reconciler's path as each state reads it, up with the families installed and down with the SID and the table's answer, and none outside mode 3
func TestExitPathStatusCarriesEachState(t *testing.T) {
	via := []netip.Addr{netip.MustParseAddr("3fff:b:0:206::1"), netip.MustParseAddr("3fff:b:0:306::3")}
	source := netip.MustParseAddr("3fff::2")
	for name, c := range map[string]struct {
		path *kernel.PathStatus
		want *control.KernelExitPath
	}{
		"outside mode 3": {},
		"up": {
			&kernel.PathStatus{Via: via, Source: source, Installed: []kernel.Family{kernel.FamilyIPv4, kernel.FamilyIPv6}},
			&control.KernelExitPath{Via: []string{"3fff:b:0:206::1", "3fff:b:0:306::3"}, Source: "3fff::2", State: "up", Installed: []string{"ipv4", "ipv6"}},
		},
		"down": {
			&kernel.PathStatus{Via: via, Source: source, Down: via[1], Verdict: "held"},
			&control.KernelExitPath{Via: []string{"3fff:b:0:206::1", "3fff:b:0:306::3"}, Source: "3fff::2", State: "down", Down: "3fff:b:0:306::3", Verdict: "held"},
		},
	} {
		if got := kernelExitPath(c.path); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: the path reads %+v, want %+v", name, got, c.want)
		}
	}
}

// The control surface carries the reconciler's count of the overlay prefixes its down set refuses, and says where its last pass
// could not list the rules so the count is not known
func TestKernelStatusCarriesTheHeldCountOrThatItIsNotKnown(t *testing.T) {
	table := kernel.Table{ID: kernel.DefaultTable, Proto: kernel.DefaultProtocol}
	for _, stats := range []kernel.Stats{{Held: 2}, {HeldUnknown: true}} {
		got := kernelStatusOf("table 200 protocol 155", table, stats)
		if got.Held != stats.Held || got.HeldUnknown != stats.HeldUnknown {
			t.Errorf("the record %+v reports held %d, unknown %v", stats, got.Held, got.HeldUnknown)
		}
	}
}

// The control surface carries each write the reconciler's last pass owes beside a running set, by prefix
func TestKernelStatusCarriesTheWritesOwed(t *testing.T) {
	table := kernel.Table{ID: kernel.DefaultTable, Proto: kernel.DefaultProtocol}
	owed := []string{"delete the pair of 192.0.2.0/25 (32765, 32764)", "delete the refusal of 3fff::/21 (32765)"}
	if got := kernelStatusOf("table 200 protocol 155", table, kernel.Stats{Owed: owed}); !reflect.DeepEqual(got.Owed, owed) || got.Held != 0 {
		t.Errorf("the record owing %q reports %q and held %d", owed, got.Owed, got.Held)
	}
}
