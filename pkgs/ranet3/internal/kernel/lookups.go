// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"syscall"

	"ranet3.com/pkgs/ranet3/schema"
)

// Send is transport's Send: where a live session sends its underlay and what
// its datagrams carry
type Send struct {
	Destination, Source netip.Addr
	Interface           int
	Pair                bool
	PinInterface        int
}

// compare orders sends by the lookup they ask, and a pair's send first among
// one lookup's, so the lookup is asked as the pair's send, which the batch
// asks where an IPv6 pair's interface is gone
func (s Send) compare(other Send) int {
	pair := 0
	if s.Pair != other.Pair {
		pair = 1
		if s.Pair {
			pair = -1
		}
	}
	return cmp.Or(s.Destination.Compare(other.Destination), s.Source.Compare(other.Source), cmp.Compare(s.Interface, other.Interface), pair)
}

func (s Send) asksAs(other Send) bool {
	return s.Destination == other.Destination && s.Source == other.Source && s.Interface == other.Interface
}

// Lookup is one route lookup a pass asked to find another program's rule ahead
// of the mesh's: an unmarked lookup of Address inside the overlay hold Prefix,
// or, with Prefix invalid, the lookup under the underlay's mark of a live
// session's send to Address from Source out of Interface, either absent where
// the send carries none. Interface is named as the pass's lookup of its index
// named it, and by its index where no device held it. Answer is the kernel's
// answer as text, and Taken says it is not the mesh's for an overlay lookup,
// or is for the underlay's
type Lookup struct {
	Family    Family
	Prefix    netip.Prefix
	Address   netip.Addr
	Source    netip.Addr
	Interface string
	index     int
	Answer    string
	Taken     bool
}

// Underlay says the lookup is the underlay's marked one
func (l Lookup) Underlay() bool { return !l.Prefix.IsValid() }

func (l Lookup) asks(other Lookup) bool {
	return l.Family == other.Family && l.Prefix == other.Prefix &&
		(!l.Underlay() || l.Address == other.Address && l.Source == other.Source && l.index == other.index)
}

// fibLooker is a looker over a platform's one FIB, darwin's, whose underlay
// carries no mark a lookup could ask under, so it asks the overlay's lookups
// alone and judges each by the route it ends at
type fibLooker interface {
	looker
	judge(prefix netip.Prefix, answer BatchAnswer) (string, bool)
}

func (r *Reconciler) lookUp() {
	if r.look == nil {
		return
	}
	routed := r.fib != nil
	var asked []Lookup
	var reads []RouteRead
	for _, hold := range r.overlayHolds(nil, nil) {
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
	if r.rt.Sends != nil && !routed {
		for _, send := range slices.CompactFunc(slices.SortedFunc(slices.Values(r.rt.Sends()), Send.compare), Send.asksAs) {
			asked = append(asked, Lookup{Family: familyOf(send.Destination), Address: send.Destination, Source: send.Source, index: send.Interface})
			reads = append(reads, RouteRead{Source: send.Source, Destination: send.Destination, OIF: uint32(send.Interface), Pair: send.Pair, Mark: schema.UnderlayMark})
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
			if routed {
				asked[i].Answer, asked[i].Taken = r.fib.judge(asked[i].Prefix, answers[i])
			} else {
				asked[i].Answer, asked[i].Taken = judgeLookup(asked[i].Underlay(), answers[i], r.rt.Interface)
			}
			if asked[i].index != 0 {
				asked[i].Interface = cmp.Or(answers[i].OIF, strconv.Itoa(asked[i].index))
			}
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
		if lookup.Source.IsValid() {
			at = append(at, slog.String("source", lookup.Source.String()))
		}
		if lookup.Interface != "" {
			at = append(at, slog.String("interface", lookup.Interface))
		}
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
		return refusal(answer.Err), !underlay && !errors.Is(answer.Err, syscall.EHOSTUNREACH)
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

// refusal is a lookup's error as text, its errno's where it carries one
func refusal(err error) string {
	text := err.Error()
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		text = errno.Error()
	}
	return fmt.Sprintf("a refusal (%s)", text)
}

// judgeRoute puts the route an overlay lookup inside the hold at prefix ends
// at as route(8) prints it, and says whether it is taken. The hold's own
// reject on the loopback link is the hold's refusal and a route out of tun is
// the mesh's. Any other route is taken, and so is no route at all, since the
// hold was read back installed.
func judgeRoute(prefix netip.Prefix, answer BatchAnswer, tun string) (string, bool) {
	if answer.Err != nil {
		return refusal(answer.Err), true
	}
	route := answer.Route
	var hop NextHop
	if len(route.NextHops) > 0 {
		hop = route.NextHops[0]
	}
	text := route.Prefix.String()
	if hop.Gateway.IsValid() {
		text += " via " + hop.Gateway.String()
	}
	if hop.Device != "" {
		text += " on " + hop.Device
	}
	reject := route.Type == "unreachable"
	if reject {
		text += " reject"
	}
	hold := reject && route.Prefix == prefix && hop.Device == Loopback && hop.Gateway.IsLoopback()
	return text, !hold && hop.Device != tun
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
