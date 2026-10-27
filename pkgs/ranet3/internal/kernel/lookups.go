// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"syscall"

	"ranet3.com/pkgs/ranet3/schema"
)

// Lookup is one route lookup a pass asked to find another program's rule ahead
// of the mesh's: an unmarked lookup of Address inside the overlay hold Prefix,
// or, with Prefix invalid, a lookup of a live peer endpoint at Address under the
// underlay's mark. Answer is the kernel's answer as text, and Taken says it is
// not the mesh's for an overlay lookup, or is for the underlay's
type Lookup struct {
	Family  Family
	Prefix  netip.Prefix
	Address netip.Addr
	Answer  string
	Taken   bool
}

// Underlay says the lookup is the underlay's marked one
func (l Lookup) Underlay() bool { return !l.Prefix.IsValid() }

func (l Lookup) asks(other Lookup) bool {
	return l.Family == other.Family && l.Prefix == other.Prefix && (!l.Underlay() || l.Address == other.Address)
}

func (r *Reconciler) lookUp() {
	if r.look == nil {
		return
	}
	var asked []Lookup
	var reads []RouteRead
	for _, hold := range r.overlayHolds(nil) {
		if !r.installed[hold] {
			continue
		}
		address, ok := lookupAddress(hold.Destination, r.addresses)
		if !ok {
			continue
		}
		asked = append(asked, Lookup{Family: familyOf(address), Prefix: hold.Destination, Address: address})
		reads = append(reads, RouteRead{Destination: address})
	}
	if r.rt.Endpoints != nil {
		for _, endpoint := range slices.Compact(slices.SortedFunc(slices.Values(r.rt.Endpoints()), netip.Addr.Compare)) {
			asked = append(asked, Lookup{Family: familyOf(endpoint), Address: endpoint})
			reads = append(reads, RouteRead{Destination: endpoint, Mark: schema.UnderlayMark})
		}
	}
	if len(reads) > 0 {
		answers, err := r.look.lookups(reads)
		if err != nil {
			if !r.lookFailed {
				slog.Warn("kernel could not ask where its overlay and underlay lookups end", "err", err)
			}
			r.lookFailed = true
			return
		}
		if r.lookFailed {
			slog.Info("kernel can ask where its overlay and underlay lookups end again")
		}
		r.lookFailed = false
		for i := range asked {
			asked[i].Answer, asked[i].Taken = judgeLookup(asked[i].Underlay(), answers[i], r.rt.Interface)
		}
	}
	r.report(asked)
}

func (r *Reconciler) report(asked []Lookup) {
	for _, lookup := range asked {
		at := slices.IndexFunc(r.lookups, lookup.asks)
		was := at >= 0 && r.lookups[at].Taken
		switch {
		case lookup.Taken && (!was || r.lookups[at].Answer != lookup.Answer):
			message := "kernel finds an overlay prefix answered outside the mesh's table"
			if lookup.Underlay() {
				message = "kernel finds the underlay's mark answered through the tun"
			}
			r.reportLookup(slog.LevelWarn, message, lookup)
		case !lookup.Taken && was:
			message := "kernel finds an overlay prefix answered through the tun or by a hold again"
			if lookup.Underlay() {
				message = "kernel finds the underlay's mark answered outside the tun again"
			}
			r.reportLookup(slog.LevelInfo, message, lookup)
		}
	}
	for _, lookup := range r.lookups {
		if lookup.Taken && !slices.ContainsFunc(asked, lookup.asks) {
			lookup.Taken = false
			r.reportLookup(slog.LevelInfo, "kernel no longer asks a lookup it found taken", lookup)
		}
	}
	r.lookups = asked
}

func (r *Reconciler) reportLookup(level slog.Level, message string, lookup Lookup) {
	kind, at := "overlay", []slog.Attr{slog.String("prefix", lookup.Prefix.String()), slog.String("address", lookup.Address.String())}
	if lookup.Underlay() {
		kind, at = "underlay", []slog.Attr{slog.String("endpoint", lookup.Address.String())}
	}
	attrs := slices.Concat([]slog.Attr{slog.String("family", string(lookup.Family))}, at, []slog.Attr{slog.String("answer", lookup.Answer)})
	slog.LogAttrs(context.Background(), level, message, attrs...)
	r.rt.Events.Emit("kernel.taken", "", append(attrs, slog.String("lookup", kind), slog.Bool("taken", lookup.Taken))...)
}

// judgeLookup puts the kernel's answer as text and says whether it is taken.
// EHOSTUNREACH is the hold's refusal, and an answer leaving through the tun is
// the mesh's whatever table gave it, but for local's, which delivers here
func judgeLookup(underlay bool, answer BatchAnswer, tun string) (string, bool) {
	if answer.Err != nil {
		text := answer.Err.Error()
		var errno syscall.Errno
		if errors.As(answer.Err, &errno) {
			text = errno.Error()
		}
		return fmt.Sprintf("a refusal (%s)", text), !underlay && !errors.Is(answer.Err, syscall.EHOSTUNREACH)
	}
	route := answer.Route
	text := "table " + schema.TableID(route.Table).String()
	onTun := false
	if len(route.NextHops) > 0 {
		text += " dev " + route.NextHops[0].Device
		onTun = route.NextHops[0].Device == tun
	}
	if underlay {
		return text, onTun && route.Table != uint32(schema.TableLocal)
	}
	return text, !onTun
}

// lookupAddress asks outside every assigned prefix where prefix has room,
// since local answers an assigned address ahead of every rule and main the
// rest of an assigned prefix, and with forwarding on IPv6 local holds the
// subnet-router anycast address of each assigned prefix too. A prefix whose
// every address is assigned asks none
func lookupAddress(prefix netip.Prefix, assigned []netip.Prefix) (netip.Addr, bool) {
	first := prefix.Addr()
	if !prefix.IsSingleIP() {
		first = first.Next()
	}
	for address := first; address.IsValid() && prefix.Contains(address); {
		at := slices.IndexFunc(assigned, func(held netip.Prefix) bool { return held.Contains(address) })
		if at < 0 {
			return address, true
		}
		address = lastAddress(assigned[at]).Next()
	}
	for address := first; address.IsValid() && prefix.Contains(address); address = address.Next() {
		if !slices.ContainsFunc(assigned, func(held netip.Prefix) bool { return held.Addr() == address }) {
			return address, true
		}
	}
	return netip.Addr{}, false
}

func lastAddress(p netip.Prefix) netip.Addr {
	raw := p.Addr().AsSlice()
	for i := range raw {
		keep := p.Bits() - 8*i
		switch {
		case keep <= 0:
			raw[i] = 0xff
		case keep < 8:
			raw[i] |= 0xff >> keep
		}
	}
	last, _ := netip.AddrFromSlice(raw)
	return last
}
