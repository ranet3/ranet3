// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/schema"
)

// fibLookingKernel is the darwin-keyed fake with darwin's lookup half: it
// answers each read by answer, records every batch it was asked, and judges an
// answer by the route it ends at
type fibLookingKernel struct {
	*rejectingKernel
	tun    string
	answer func(RouteRead) BatchAnswer
	asked  [][]RouteRead
}

func (k *fibLookingKernel) lookups(reads []RouteRead) ([]BatchAnswer, error) {
	k.asked = append(k.asked, slices.Clone(reads))
	answers := make([]BatchAnswer, len(reads))
	for i, read := range reads {
		answers[i] = k.answer(read)
	}
	return answers, nil
}

func (k *fibLookingKernel) judge(prefix netip.Prefix, answer BatchAnswer) (string, bool) {
	return judgeRoute(prefix, answer, k.tun)
}

// endedAt is an answer naming the route at destination out of device, a
// reject where reject, by gateway where it is valid
func endedAt(destination, device string, gateway netip.Addr, reject bool) BatchAnswer {
	route := MatchedRoute{Prefix: prefix(destination), Type: "unicast", NextHops: []NextHop{{Device: device, Gateway: gateway}}}
	if reject {
		route.Type = "unreachable"
	}
	return BatchAnswer{Route: route}
}

// the hold's own reject on the loopback link at its key and a route out of the
// tun are the mesh's, and every other route an overlay lookup ends at is
// taken, a reject of the hold's shape at another key among them and a reject
// at its key on another link or via another gateway, and so is no route at all
func TestRouteAnswersAreJudgedByTheRouteTheyEndAt(t *testing.T) {
	const tun = "utun9"
	hold := prefix("192.0.2.0/24")
	loop := addr("127.0.0.1")
	for _, test := range []struct {
		name   string
		answer BatchAnswer
		text   string
		taken  bool
	}{
		{"the hold", endedAt("192.0.2.0/24", Loopback, loop, true), "192.0.2.0/24 via 127.0.0.1 on " + Loopback + " reject", false},
		{"a half of the mesh's", endedAt("192.0.2.0/25", tun, netip.Addr{}, false), "192.0.2.0/25 on utun9", false},
		{"another program's utun", endedAt("192.0.2.0/25", "utun10", netip.Addr{}, false), "192.0.2.0/25 on utun10", true},
		{"a reject of the hold's shape inside it", endedAt("192.0.2.64/26", Loopback, loop, true), "192.0.2.64/26 via 127.0.0.1 on " + Loopback + " reject", true},
		{"a reject at the key on another link", endedAt("192.0.2.0/24", "en0", netip.Addr{}, true), "192.0.2.0/24 on en0 reject", true},
		{"a reject at the key via loopback on another utun", endedAt("192.0.2.0/24", "utun5", loop, true), "192.0.2.0/24 via 127.0.0.1 on utun5 reject", true},
		{"a reject at the key on the loopback link via another gateway", endedAt("192.0.2.0/24", Loopback, addr("192.0.2.1"), true), "192.0.2.0/24 via 192.0.2.1 on " + Loopback + " reject", true},
		{"the uplink's default", endedAt("0.0.0.0/0", "en0", addr("198.51.100.1"), false), "0.0.0.0/0 via 198.51.100.1 on en0", true},
		{"no route", BatchAnswer{Err: fmt.Errorf("kernel: look up the route: %w", syscall.ENETUNREACH)}, "a refusal (network is unreachable)", true},
	} {
		if text, taken := judgeRoute(hold, test.answer, tun); text != test.text || taken != test.taken {
			t.Errorf("%s: judged %q taken %v, want %q taken %v", test.name, text, taken, test.text, test.taken)
		}
	}
}

// On a platform with one FIB and no underlay mark a pass asks into each hold
// and never under the mark, though sessions send. The hold's reject reads as
// not taken, another interface's longer route inside it as taken in the
// published lookups and in kernel.taken, and a route out of the tun as not
// taken again.
func TestFIBPlatformAsksTheOverlayAloneAndJudgesByRoute(t *testing.T) {
	bus := events.New()
	reconciler, _, covering := rejectingHarness(t, nil, coverAddresses...)
	reconciler.rt.Events = bus
	reconciler.rt.Sends = func() []Send { return bareSends(addr("203.0.113.70")) }
	k := &fibLookingKernel{rejectingKernel: covering, tun: reconciler.rt.Interface}
	reconciler.use(k)
	reconciler.rules = nil
	loop := map[bool]netip.Addr{true: addr("127.0.0.1"), false: netip.IPv6Loopback()}
	held := func(read RouteRead) BatchAnswer {
		key := prefix("3fff:c::/32")
		if read.Destination.Is4() {
			key = prefix("192.0.2.0/24")
		}
		return endedAt(key.String(), Loopback, loop[read.Destination.Is4()], true)
	}
	for _, step := range []struct {
		name   string
		answer func(RouteRead) BatchAnswer
		taken  int
	}{
		{"the holds", held, 0},
		{"another utun's route", func(read RouteRead) BatchAnswer {
			if read.Destination.Is4() {
				return endedAt("192.0.2.0/25", "utun10", netip.Addr{}, false)
			}
			return held(read)
		}, 1},
		{"the mesh's route", func(read RouteRead) BatchAnswer {
			if read.Destination.Is4() {
				return endedAt("192.0.2.0/25", reconciler.rt.Interface, netip.Addr{}, false)
			}
			return held(read)
		}, 0},
	} {
		k.answer = step.answer
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		lookups := reconciler.Stats().Lookups
		taken := 0
		for _, lookup := range lookups {
			taken += boolOrder(lookup.Taken)
			if lookup.Underlay() {
				t.Errorf("%s: the pass published an underlay lookup %+v", step.name, lookup)
			}
		}
		if len(lookups) != 2 || taken != step.taken {
			t.Errorf("%s: the pass published %+v, want both holds asked and %d taken", step.name, lookups, step.taken)
		}
	}
	for _, batch := range k.asked {
		for _, read := range batch {
			if read.Mark != 0 || !slices.ContainsFunc(coverOverlay, func(p schema.Prefix) bool { return p.Contains(read.Destination) }) {
				t.Errorf("the pass asked %+v, want overlay reads alone", read)
			}
		}
	}
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.taken" }, 0) {
		got = append(got, event.Attrs["prefix"]+" "+event.Attrs["answer"]+" "+event.Attrs["taken"])
	}
	want := []string{"192.0.2.0/24 192.0.2.0/25 on utun10 true", "192.0.2.0/24 192.0.2.0/25 on " + reconciler.rt.Interface + " false"}
	if !slices.Equal(got, want) {
		t.Errorf("the events are %q, want %q", got, want)
	}
}
