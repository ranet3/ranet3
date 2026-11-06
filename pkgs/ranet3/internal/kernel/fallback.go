// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"syscall"

	"ranet3.com/pkgs/ranet3/schema"
)

// FallbackTable is the nf_tables inet table cap.exit fallback = "none" writes
// on Linux, whose chains let a packet leave by a link outside the mesh only
// where one of their lines passes it, and drop the rest. It carries no owner
// flag, so it outlives the process that wrote it. routing.md's "The kill
// switch on Linux" lists the lines and what each stop leaves of the table. On
// macOS the switch is reject routes on lo0 instead, which "The kill switch on
// macOS" lists.
const FallbackTable = "ranet3_fallback"

// FallbackState is the switch fallback = "none" asks for, as a pass leaves it
type FallbackState string

const (
	// FallbackHolding is the table reading back as written while no exit is
	// live, its chains holding the host's traffic to their lines
	FallbackHolding FallbackState = "holding"
	// FallbackPassing is the table in place while an exit is live, the
	// host's traffic going to it through the tun
	FallbackPassing FallbackState = "passing"
	// FallbackNotHolding is a table that does not read back as written or
	// cannot be written, while 5405 and 5435 stay out
	FallbackNotHolding FallbackState = "not holding"
)

// FallbackStatus is the switch as the last pass left it
type FallbackStatus struct {
	State FallbackState
	// Fault is why the table does not read back, under FallbackNotHolding
	Fault string
	// Dropped and DroppedBytes are the packets and bytes the last lines of
	// both chains have dropped, summed, as the last read that succeeded found
	// them, and DropsRead says a read of this process has. Uncounted says the
	// switch counts nothing it refuses, as darwin's rejects, whose drops are
	// never read
	Dropped, DroppedBytes uint64
	DropsRead             bool
	Uncounted             bool
	// Captured is each connected network left out of the LAN, since its
	// length counts as capturing the machine, empty where the switch passes
	// the LAN by no line, as on darwin
	Captured []netip.Prefix
	// Public is each connected network of a link forward does not name, or of
	// one sharing an address with the overlay each prefix of its part outside
	// the overlay, that the LAN leaves out in whole or in part, since the part
	// lies outside the private and link-local ranges and every prefix cap.exit
	// lan lists
	Public []netip.Prefix
	// tun and passed are the mesh's device and the LAN's and this node's own
	// prefixes the table's lines pass, which FallbackResolvers reads
	tun    string
	passed []netip.Prefix
}

// LinkResolver is a DNS server systemd-resolved queries through one link
type LinkResolver struct {
	Link    string
	Address netip.Addr
}

// FallbackDebug is the switch as a read finds it now, the table
// ranet3_fallback on linux and the rejects on lo0 on darwin, which have no
// hook, priority or sets
type FallbackDebug struct {
	Where    string
	Hook     string
	Priority int
	// Held is whether the kernel holds the switch at all
	Held  bool
	Rules []FallbackDebugRule
	Sets  []FallbackDebugSet
}

// FallbackDebugRule is one line of a chain, by the comment it was written
// under, with what it counted, or on darwin one reject
type FallbackDebugRule struct {
	Chain          string
	Spec           string
	Packets, Bytes uint64
}

// FallbackDebugSet is one named set with its elements, a range that is no
// prefix written as its first and last address
type FallbackDebugSet struct {
	Name     string
	Elements []string
}

// fallbackSets holds what the lines of one pass's table ranet3_fallback read:
// the tun for the oifname line, the links of the forwarded set, the LAN's and
// this node's own prefixes and inbound's ports, derived from the same exitView
// its rules come from. Each prefix list is masked, sorted and each once.
type fallbackSets struct {
	// tun is the mesh's device, which the chain's first line passes with lo
	tun string
	// forwarded is the links forward expands to, whose forwarded traffic the
	// forwarded line does not pass, so it meets the other lines
	forwarded []string
	// lan is each family's LAN, as routing.md's "The kill switch on Linux"
	// lists it
	lan4, lan6 []netip.Prefix
	// own is this node's own prefixes the mesh's table throws, as 5445 reads
	// them, less the carve-outs, which lan holds less the mesh's prefixes
	// inside them
	own4, own6 []netip.Prefix
	// tcp and udp are inbound's services of each protocol, joined
	tcp, udp []Service
	// captured is each connected network left out of lan because it counts as
	// capturing the machine
	captured []netip.Prefix
	// public is each connected network of a link forward does not name, or of
	// one sharing an address with the overlay each prefix of its part outside
	// the overlay, that lan leaves out in whole or in part, lying outside
	// lanRanges and the prefixes cap.exit lan lists
	public []netip.Prefix
}

// lanRanges is the ranges a connected network counts as the LAN inside: the
// private ones of RFC 1918, link-local of RFC 3927 and RFC 4291 section 2.5.6,
// and the unique local ones of RFC 4193
var lanRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("fc00::/7"),
}

// fallbackSetsOf derives the table's sets. carveOuts is each prefix inside the
// overlay the LAN holds.
func (v exitView) fallbackSetsOf(tun string, overlay []schema.Prefix, inbound []Service, carveOuts []netip.Prefix) fallbackSets {
	out := fallbackSets{tun: tun, forwarded: slices.Clone(v.forwarded)}
	slices.Sort(out.forwarded)
	inOverlay := Ranges(SchemaPrefixes(overlay))
	var lan []netip.Prefix
	for _, links := range [][]Link{v.network.IPv4.Links, v.network.IPv6.Links} {
		for _, link := range links {
			for _, prefix := range link.Prefixes {
				network := prefix.Masked()
				if schema.CapturesTheMachine(network, overlay) {
					out.captured = append(out.captured, network)
					continue
				}
				for _, outside := range subtract(Ranges([]netip.Prefix{network}), inOverlay) {
					for _, part := range RangePrefixes(outside) {
						if slices.Contains(v.forwarded, link.Name) {
							// a hostile network reaches the host by an uplink, which forward never names
							lan = append(lan, part)
							continue
						}
						parts := lanParts(part, v.lan)
						lan = append(lan, parts...)
						if !covers(part, parts) {
							out.public = append(out.public, part)
						}
					}
				}
			}
		}
	}
	lan = append(lan, carveOuts...)
	out.lan4, out.lan6 = familyPrefixes(FamilyIPv4, lan), familyPrefixes(FamilyIPv6, lan)
	own := slices.DeleteFunc(slices.Clone(v.own), func(prefix netip.Prefix) bool { return schema.InsideOverlay(prefix, overlay) })
	out.own4, out.own6 = familyPrefixes(FamilyIPv4, own), familyPrefixes(FamilyIPv6, own)
	out.captured = slices.Compact(slices.SortedFunc(slices.Values(out.captured), comparePrefixes))
	out.public = slices.Compact(slices.SortedFunc(slices.Values(out.public), comparePrefixes))
	for _, service := range inbound {
		if service.Protocol == "tcp" {
			out.tcp = append(out.tcp, service)
		} else {
			out.udp = append(out.udp, service)
		}
	}
	return out
}

// lanParts is each part of network inside a range of lanRanges or a prefix of
// listed, but one another part holds, in order. Two prefixes share an address
// only where one holds the other, so a part is network or the range it holds.
func lanParts(network netip.Prefix, listed []netip.Prefix) []netip.Prefix {
	var parts []netip.Prefix
	for _, r := range slices.Concat(lanRanges, listed) {
		r = r.Masked()
		switch {
		case encloses(r, network):
			parts = append(parts, network)
		case network.Bits() < r.Bits() && network.Contains(r.Addr()):
			parts = append(parts, r)
		}
	}
	// in this order a part comes after each part holding it
	var out []netip.Prefix
	for _, part := range slices.SortedFunc(slices.Values(parts), comparePrefixes) {
		if !slices.ContainsFunc(out, func(kept netip.Prefix) bool { return encloses(kept, part) }) {
			out = append(out, part)
		}
	}
	return out
}

// covers reports parts, each inside network and none holding another, in
// order, holding every address of it
func covers(network netip.Prefix, parts []netip.Prefix) bool {
	next, last := network.Addr(), lastAddress(network)
	for _, part := range parts {
		if next.Less(part.Addr()) {
			return false
		}
		end := lastAddress(part)
		if end == last {
			return true
		}
		next = end.Next()
	}
	return false
}

// fallbackFor is the sets of the switch exit asks for, none for a switch of
// reject routes, which passes nothing by a line, and whether it asks for one
func (r *Reconciler) fallbackFor(exit exitView) (fallbackSets, bool) {
	mode := r.table.Mode()
	if !exit.on || !exit.fallback || mode == nil {
		return fallbackSets{}, false
	}
	if r.switchForm().keys != nil {
		return fallbackSets{}, true
	}
	return exit.fallbackSetsOf(r.rt.Interface, r.rt.Overlay, mode.Services(), exit.carvedLAN()), true
}

// applyFallback writes the switch of sets where the pass asks for it,
// rewriting it whenever it does not read back as written, and deletes one an
// earlier pass or instance left where the pass does not ask for it. It
// reports the switch as the pass leaves it, nil where the pass does not ask
// for it. reconcile runs it after the route pass where the pass asks for the
// switch and before it where the pass does not, so on darwin a route of ours
// out of the tun never meets a reject at its key (see splitAtKeys).
func (r *Reconciler) applyFallback(sets fallbackSets, asked bool) (*FallbackStatus, error) {
	sw := r.sw
	if sw == nil {
		r.reportFallbackState(nil)
		return nil, nil
	}
	form := sw.form()
	if !asked {
		r.reportFallbackState(nil)
		if r.fallbackClear {
			return nil, nil
		}
		// a kernel without nf_tables holds no table, so that refusal is not
		// tried again until a pass asks for the table, and any other is
		err := sw.deleteFallback()
		r.fallbackClear = err == nil || withoutNFTables(err)
		if r.fallbackClear {
			r.fallbackDropped, r.fallbackBytes = 0, 0
		}
		if err != nil {
			warnFallbackLeft(form, err)
		}
		return nil, nil
	}
	r.fallbackClear = false
	// a read that fails on a table no write touched keeps the drops the last read found, and a rewrite starts them from zero
	read, err := sw.readFallback(sets)
	r.fallbackDropsRead = r.fallbackDropsRead || err == nil && !form.uncounted
	switch {
	case err != nil:
		read.dropped, read.bytes = r.fallbackDropped, r.fallbackBytes
	case read.fault != "":
		if err = sw.writeFallback(sets, read.remake); err == nil {
			read, err = sw.readFallback(sets)
		}
	}
	r.fallbackDropped, r.fallbackBytes = read.dropped, read.bytes
	if err != nil {
		read.fault = err.Error()
		err = fmt.Errorf("write the kill switch, %s: %w", form.where, err)
	}
	status := &FallbackStatus{
		State: FallbackHolding, Fault: read.fault, Dropped: read.dropped, DroppedBytes: read.bytes, DropsRead: r.fallbackDropsRead, Uncounted: form.uncounted,
		Captured: sets.captured, Public: sets.public, tun: sets.tun, passed: slices.Concat(sets.lan4, sets.lan6, sets.own4, sets.own6),
	}
	switch {
	case read.fault != "":
		status.State = FallbackNotHolding
	case r.capturing:
		status.State = FallbackPassing
	}
	r.reportFallbackState(status)
	return status, err
}

// warnFallbackLeft is the one line for a delete of the switch that failed
func warnFallbackLeft(form fallbackForm, err error) {
	slog.Warn("kernel could not delete a kill switch an earlier instance may have left, which keeps the host's traffic off the uplink until it is deleted",
		"where", form.where, "err", err, "fix", form.fix)
}

// FallbackResolvers is each DNS server systemd-resolved queries now through a
// link outside the mesh at an address outside the LAN, this node's own
// prefixes, loopback and link-local, nil where no pass asked for the table. A
// status read asks resolved, never a pass, so a resolved slow to answer delays
// no withdrawal of 5405 and 5435.
// A read that fails is logged once, until one succeeds.
func (r *Reconciler) FallbackResolvers() []LinkResolver {
	stats := r.stats.Load()
	if stats == nil || stats.Exit == nil || stats.Exit.Fallback == nil || r.rt.Resolvers == nil {
		return nil
	}
	status := stats.Exit.Fallback
	all, err := r.rt.Resolvers()
	if err != nil {
		if !r.resolversFailed.Swap(true) {
			slog.Warn("kernel could not read the DNS servers systemd-resolved queries through each link", "err", err)
		}
		return nil
	}
	r.resolversFailed.Store(false)
	var out []LinkResolver
	for _, resolver := range all {
		address := resolver.Address.Unmap()
		if resolver.Link == status.tun || address.IsLoopback() || address.IsLinkLocalUnicast() ||
			slices.ContainsFunc(status.passed, func(prefix netip.Prefix) bool { return prefix.Contains(address) }) {
			continue
		}
		out = append(out, resolver)
	}
	return out
}

// withoutNFTables reports err as a kernel with no nf_tables to hold a table:
// no netfilter netlink, or none of its nf_tables subsystem, which nfnetlink.c
// answers with EINVAL
func withoutNFTables(err error) bool {
	return errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EINVAL)
}

// reportFallbackState records the switch's state, nil where no pass asks for
// it, with a line each time it or the table's fault changes and an event each
// time the state does
func (r *Reconciler) reportFallbackState(status *FallbackStatus) {
	state, fault := FallbackState(""), ""
	if status != nil {
		state, fault = status.State, status.Fault
	}
	if state == r.fallbackState && fault == r.fallbackFault {
		return
	}
	form := r.switchForm()
	switch state {
	case FallbackNotHolding:
		slog.Warn("kernel's kill switch does not read back as written", "where", form.where, "fault", fault, "detail", form.unheld)
	case FallbackHolding:
		slog.Info("kernel's kill switch holds the host's traffic while no exit is live", "where", form.where)
	case FallbackPassing:
		slog.Info("kernel's kill switch passes the host's traffic to the exit live through the tun", "where", form.where)
	case "":
		slog.Info("kernel's kill switch is no longer asked for", "where", form.where)
	}
	if state != r.fallbackState {
		r.rt.Events.Emit("kernel.fallback", "", slog.String("state", cmp.Or(string(state), "off")), slog.String("was", cmp.Or(string(r.fallbackState), "off")))
	}
	r.fallbackState, r.fallbackFault = state, fault
}

// switchForm is the form of the platform's switch, the zero form on a
// platform with none
func (r *Reconciler) switchForm() fallbackForm {
	if r.sw != nil {
		return r.sw.form()
	}
	return fallbackForm{}
}

// switcher is the optional half of a platform that writes the kill switch,
// the table ranet3_fallback on linux and the rejects on lo0 on darwin. A
// platform without one runs no fallback = "none", which its start refuses.
type switcher interface {
	// writeFallback writes the switch whole, on linux in one transaction with
	// its sets flushed and filled and its chains rewritten, the table deleted
	// first where remake, as the read before it found
	writeFallback(sets fallbackSets, remake bool) error
	// readFallback reads the switch back against what writeFallback writes for sets, the zero fallbackRead where the read fails
	readFallback(fallbackSets) (fallbackRead, error)
	// deleteFallback deletes the switch where one is held, whoever wrote it
	deleteFallback() error
	// holdsFallback is whether a listing finds the switch, whoever wrote it
	holdsFallback() (bool, error)
	form() fallbackForm
}

// fallbackForm is how a platform's switch reads in a log line and a status
type fallbackForm struct {
	// where names the switch, and fix says how an operator deletes one left
	// behind
	where, fix string
	// unheld says what the host's traffic meets while the switch does not
	// read back as written
	unheld string
	// keys is where a switch of reject routes, keyed as the tun's routes are,
	// holds one, as darwin's does, and nil for a table whose lines pass the
	// LAN and this node's own prefixes as fallbackSets derives them, as
	// linux's
	keys []netip.Prefix
	// uncounted says the switch counts nothing it refuses
	uncounted bool
}

// fallbackRead is the table as a read finds it
type fallbackRead struct {
	// fault names the first way the table differs from what was written, a
	// missing table among them, empty where none does
	fault string
	// dropped and bytes are the packets and bytes the last lines of both chains have dropped, summed
	dropped, bytes uint64
	// remake is a table a rewrite cannot mend in place, which goes first
	remake bool
}
