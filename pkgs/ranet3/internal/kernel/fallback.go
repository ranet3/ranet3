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

// FallbackTable is the nf_tables inet table cap.exit fallback = "none" writes,
// whose chains let a packet leave by a link outside the mesh only where one of
// their lines passes it, and drop the rest. routing.md's "The kill switch on
// Linux" lists the lines. It carries no owner flag, so it outlives the process
// that wrote it.
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
	// both chains have dropped, summed, as the pass read them
	Dropped, DroppedBytes uint64
	// Captured is each connected network left out of the LAN, since its
	// length counts as capturing the machine
	Captured []netip.Prefix
	// Public is each connected network left out of the LAN in whole or in
	// part, since the part lies outside the private and link-local ranges and
	// every prefix cap.exit lan lists
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

// FallbackDebug is the table ranet3_fallback as a read finds it now
type FallbackDebug struct {
	Where    string
	Hook     string
	Priority int
	// Held is whether the kernel holds the table at all
	Held  bool
	Rules []FallbackDebugRule
	Sets  []FallbackDebugSet
}

// FallbackDebugRule is one line of a chain, by the comment it was written
// under, with what it counted
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
	// lan is each family's connected networks of the links forward names,
	// whole, and parts of the connected networks of the other links outside
	// the mesh that lie inside lanRanges or a prefix cap.exit lan lists, less
	// the networks overlapping the overlay and those
	// schema.CapturesTheMachine counts, with the carve-outs added
	lan4, lan6 []netip.Prefix
	// own is this node's own prefixes the mesh's table throws, as 5445 reads them
	own4, own6 []netip.Prefix
	// tcp and udp are inbound's services of each protocol, joined
	tcp, udp []Service
	// captured is each connected network left out of lan because it counts as
	// capturing the machine
	captured []netip.Prefix
	// public is each connected network of a link forward does not name that
	// lan leaves out whole or in part, lying outside lanRanges and the
	// prefixes cap.exit lan lists
	public []netip.Prefix
}

// lanRanges is the ranges a connected network counts as the LAN inside: the
// private ones of RFC 1918, link-local of RFC 3927 and RFC 4291 section 2.5.6,
// and the unique local ones of RFC 4193
var lanRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("fc00::/7"),
}

// fallbackSetsOf derives the table's sets. carveOuts is each prefix the LAN
// holds beyond the connected networks the overlay leaves out, which this
// package passes empty.
func (v exitView) fallbackSetsOf(tun string, overlay []schema.Prefix, inbound []Service, carveOuts []netip.Prefix) fallbackSets {
	out := fallbackSets{tun: tun, forwarded: slices.Clone(v.forwarded)}
	slices.Sort(out.forwarded)
	inOverlay := schemaPrefixes(overlay)
	overlaps := func(prefix netip.Prefix) bool { return slices.ContainsFunc(inOverlay, prefix.Overlaps) }
	var lan []netip.Prefix
	for _, links := range [][]Link{v.network.IPv4.Links, v.network.IPv6.Links} {
		for _, link := range links {
			for _, prefix := range link.Prefixes {
				network := prefix.Masked()
				switch {
				case overlaps(network):
				case schema.CapturesTheMachine(network, overlay):
					out.captured = append(out.captured, network)
				case slices.Contains(v.forwarded, link.Name):
					// a hostile network reaches the host by an uplink, which forward never names
					lan = append(lan, network)
				default:
					parts := lanParts(network, v.lan)
					lan = append(lan, parts...)
					if !covers(network, parts) {
						out.public = append(out.public, network)
					}
				}
			}
		}
	}
	lan = append(lan, carveOuts...)
	out.lan4, out.lan6 = familyPrefixes(FamilyIPv4, lan), familyPrefixes(FamilyIPv6, lan)
	out.own4, out.own6 = familyPrefixes(FamilyIPv4, v.own), familyPrefixes(FamilyIPv6, v.own)
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
		case r.Bits() <= network.Bits() && r.Contains(network.Addr()):
			parts = append(parts, network)
		case network.Bits() < r.Bits() && network.Contains(r.Addr()):
			parts = append(parts, r)
		}
	}
	// in this order a part comes after each part holding it
	var out []netip.Prefix
	for _, part := range slices.SortedFunc(slices.Values(parts), comparePrefixes) {
		if !slices.ContainsFunc(out, func(kept netip.Prefix) bool { return kept.Bits() <= part.Bits() && kept.Contains(part.Addr()) }) {
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

func (r *Reconciler) fallbackFor(exit exitView) (fallbackSets, bool) {
	mode := r.table.Mode()
	if !exit.on || !exit.fallback || mode == nil {
		return fallbackSets{}, false
	}
	return exit.fallbackSetsOf(r.rt.Interface, r.rt.Overlay, mode.Services(), nil), true
}

// applyFallback writes the table where the pass asks for it, rewriting it
// whenever it does not read back as written, and deletes one an earlier pass
// or instance left where the pass does not ask for it. It reports the switch
// as the pass leaves it, nil where the pass does not ask for it.
func (r *Reconciler) applyFallback(exit exitView) (*FallbackStatus, error) {
	sw, ok := r.plat.(switcher)
	if !ok {
		r.reportFallbackState(nil)
		return nil, nil
	}
	sets, asked := r.fallbackFor(exit)
	if !asked {
		r.reportFallbackState(nil)
		if r.fallbackClear {
			return nil, nil
		}
		// a kernel without nf_tables holds no table, so that refusal is not
		// tried again until a pass asks for the table, and any other is
		err := sw.deleteFallback()
		r.fallbackClear = err == nil || withoutNFTables(err)
		if err != nil {
			warnFallbackLeft(err)
		}
		return nil, nil
	}
	r.fallbackClear = false
	read, err := sw.readFallback(sets)
	if err == nil && read.fault != "" {
		if err = sw.writeFallback(sets, read.remake); err == nil {
			read, err = sw.readFallback(sets)
		}
	}
	if err != nil {
		read.fault = err.Error()
		err = fmt.Errorf("write table inet %s: %w", FallbackTable, err)
	}
	status := &FallbackStatus{
		State: FallbackHolding, Fault: read.fault, Dropped: read.dropped, DroppedBytes: read.bytes,
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

// warnFallbackLeft is the one line for a delete of the table that failed
func warnFallbackLeft(err error) {
	slog.Warn("kernel could not delete a fallback table an earlier instance may have left, which keeps the host's traffic off the uplink until it is deleted",
		"table", FallbackTable, "err", err, "fix", "nft delete table inet "+FallbackTable)
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
	switch state {
	case FallbackNotHolding:
		slog.Warn("kernel's fallback table does not read back as written, so the host's own lookups from the uplink's addresses reach main only for its routes longer than /0",
			"table", FallbackTable, "fault", fault)
	case FallbackHolding:
		slog.Info("kernel's fallback table holds the host's traffic to the LAN while no exit is live", "table", FallbackTable)
	case FallbackPassing:
		slog.Info("kernel's fallback table passes the host's traffic to the exit live through the tun", "table", FallbackTable)
	case "":
		slog.Info("kernel's fallback table is no longer asked for", "table", FallbackTable)
	}
	if state != r.fallbackState {
		r.rt.Events.Emit("kernel.fallback", "", slog.String("state", cmp.Or(string(state), "off")), slog.String("was", cmp.Or(string(r.fallbackState), "off")))
	}
	r.fallbackState, r.fallbackFault = state, fault
}

// switcher is the optional half of a platform that writes the table
// ranet3_fallback. A platform without one runs no fallback = "none", which its
// start refuses.
type switcher interface {
	// writeFallback writes the table whole in one transaction, its sets
	// flushed and filled and its chains rewritten, the table deleted first
	// where remake, as the read before it found
	writeFallback(sets fallbackSets, remake bool) error
	// readFallback reads the table back against what writeFallback writes for sets
	readFallback(fallbackSets) (fallbackRead, error)
	// deleteFallback deletes the table where one is held, whoever wrote it
	deleteFallback() error
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
