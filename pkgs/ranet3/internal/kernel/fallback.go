// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

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
	// Dropped and DroppedBytes are the packets and bytes the chain's last line
	// has dropped, as the pass read them
	Dropped, DroppedBytes uint64
	// LAN is each connected network the table passes
	LAN []netip.Prefix
	// Captured is each connected network left out of the LAN, since its
	// length counts as capturing the machine
	Captured []netip.Prefix
	// Resolvers is each DNS server systemd-resolved queries through one link
	// that lies beyond the LAN, which the table refuses whether an exit is
	// live or not, since the query leaves by that link
	Resolvers []LinkResolver
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

// FallbackDebugRule is one line of the chain, by the comment it was written
// under, with what it counted
type FallbackDebugRule struct {
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
	// lan is each family's connected networks of the links outside the mesh,
	// less those overlapping the overlay and those schema.CapturesTheMachine
	// counts, with the carve-outs added
	lan4, lan6 []netip.Prefix
	// own is this node's own prefixes the mesh's table throws, as 5445 reads them
	own4, own6 []netip.Prefix
	// tcp and udp are inbound's services of each protocol, joined
	tcp, udp []Service
	// captured is each connected network left out of lan because it counts as
	// capturing the machine
	captured []netip.Prefix
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
				default:
					lan = append(lan, network)
				}
			}
		}
	}
	lan = append(lan, carveOuts...)
	out.lan4, out.lan6 = familyPrefixes(FamilyIPv4, lan), familyPrefixes(FamilyIPv6, lan)
	out.own4, out.own6 = familyPrefixes(FamilyIPv4, v.own), familyPrefixes(FamilyIPv6, v.own)
	out.captured = slices.Compact(slices.SortedFunc(slices.Values(out.captured), comparePrefixes))
	for _, service := range inbound {
		if service.Protocol == "tcp" {
			out.tcp = append(out.tcp, service)
		} else {
			out.udp = append(out.udp, service)
		}
	}
	return out
}

// fallbackFor is the sets of the pass under way, and whether the mode asks
// for the table at all
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
		r.reportFallback("")
		r.reportFallbackState(nil)
		if r.fallbackClear {
			return nil, nil
		}
		// a kernel without nf_tables holds no table, so a failed delete is
		// logged once and not tried again until a pass asks for the table
		r.fallbackClear = true
		if err := sw.deleteFallback(); err != nil {
			slog.Warn("kernel could not delete a fallback table an earlier instance may have left, which keeps the host's traffic off the uplink until it is deleted",
				"table", FallbackTable, "err", err, "fix", "nft delete table inet "+FallbackTable)
		}
		return nil, nil
	}
	r.fallbackClear = false
	read, err := sw.readFallback(sets)
	if err == nil && read.fault != "" {
		if err = sw.writeFallback(sets); err == nil {
			read, err = sw.readFallback(sets)
		}
	}
	if err != nil {
		read.fault = err.Error()
		err = fmt.Errorf("write table inet %s: %w", FallbackTable, err)
	}
	r.reportFallback(read.fault)
	status := &FallbackStatus{
		State: FallbackHolding, Fault: read.fault, Dropped: read.dropped, DroppedBytes: read.bytes,
		LAN: slices.Concat(sets.lan4, sets.lan6), Captured: sets.captured, Resolvers: r.resolversBeyond(sets),
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

// resolversBeyond is each DNS server systemd-resolved queries through a link
// outside the mesh that the table refuses: one outside the LAN, this node's
// own prefixes, loopback and link-local
func (r *Reconciler) resolversBeyond(sets fallbackSets) []LinkResolver {
	if r.rt.Resolvers == nil {
		return nil
	}
	all, err := r.rt.Resolvers()
	if text := errorText(err); text != r.resolversErr {
		if err != nil {
			slog.Warn("kernel could not read the DNS servers systemd-resolved queries through each link", "err", err)
		}
		r.resolversErr = text
	}
	passed := slices.Concat(sets.lan4, sets.lan6, sets.own4, sets.own6)
	var out []LinkResolver
	for _, resolver := range all {
		address := resolver.Address.Unmap()
		if resolver.Link == sets.tun || address.IsLoopback() || address.IsLinkLocalUnicast() ||
			slices.ContainsFunc(passed, func(prefix netip.Prefix) bool { return prefix.Contains(address) }) {
			continue
		}
		out = append(out, resolver)
	}
	return out
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// reportFallbackState records the switch's state, nil where no pass asks for
// it, with an event and a line each time it changes
func (r *Reconciler) reportFallbackState(status *FallbackStatus) {
	state := FallbackState("")
	if status != nil {
		state = status.State
	}
	if state == r.fallbackState {
		return
	}
	switch state {
	case FallbackHolding:
		slog.Info("kernel's fallback table holds the host's traffic to the LAN while no exit is live", "table", FallbackTable)
	case FallbackPassing:
		slog.Info("kernel's fallback table passes the host's traffic to the exit live through the tun", "table", FallbackTable)
	case "":
		slog.Info("kernel's fallback table is no longer asked for", "table", FallbackTable)
	}
	r.rt.Events.Emit("kernel.fallback", "", slog.String("state", cmp.Or(string(state), "off")), slog.String("was", cmp.Or(string(r.fallbackState), "off")))
	r.fallbackState = state
}

// reportFallback logs the table's fault when it begins and when it ends
func (r *Reconciler) reportFallback(fault string) {
	switch {
	case fault == r.fallbackFault:
	case fault != "":
		slog.Warn("kernel's fallback table does not read back as written, so the host's own lookups from the uplink's addresses no longer reach main",
			"table", FallbackTable, "fault", fault)
	default:
		slog.Info("kernel's fallback table reads back as written", "table", FallbackTable)
	}
	r.fallbackFault = fault
}

// switcher is the optional half of a platform that writes the table
// ranet3_fallback. A platform without one runs no fallback = "none", which its
// start refuses.
type switcher interface {
	// writeFallback writes the table whole in one transaction, its sets
	// flushed and filled and its chain rewritten
	writeFallback(fallbackSets) error
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
	// dropped and bytes are the packets and bytes the chain's last line has dropped
	dropped, bytes uint64
}
