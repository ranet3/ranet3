// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
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

// fallbackSets holds the destinations, links and services one pass's table
// ranet3_fallback lets leave by a link outside the mesh, derived from the same
// exitView its rules come from. Each prefix list is masked, sorted and each
// once.
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
// or instance left where the pass does not ask for it. It reports whether the
// table reads back as this pass wrote it.
func (r *Reconciler) applyFallback(exit exitView) (bool, error) {
	sw, ok := r.plat.(switcher)
	if !ok {
		return false, nil
	}
	sets, asked := r.fallbackFor(exit)
	if !asked {
		r.reportFallback("")
		if r.fallbackClear {
			return false, nil
		}
		// a kernel without nf_tables holds no table, so a failed delete is
		// logged once and not tried again until a pass asks for the table
		r.fallbackClear = true
		if err := sw.deleteFallback(); err != nil {
			slog.Warn("kernel could not delete a fallback table an earlier instance may have left, which keeps the host's traffic off the uplink until it is deleted",
				"table", FallbackTable, "err", err, "fix", "nft delete table inet "+FallbackTable)
		}
		return false, nil
	}
	r.fallbackClear = false
	fault, err := sw.readFallback(sets)
	if err == nil && fault != "" {
		if err = sw.writeFallback(sets); err == nil {
			fault, err = sw.readFallback(sets)
		}
	}
	if err != nil {
		fault = err.Error()
		err = fmt.Errorf("write table inet %s: %w", FallbackTable, err)
	}
	r.reportFallback(fault)
	return fault == "", err
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
	// readFallback names the first way the table differs from what
	// writeFallback writes for sets, a missing table among them, empty where
	// none does
	readFallback(fallbackSets) (string, error)
	// deleteFallback deletes the table where one is held, whoever wrote it
	deleteFallback() error
}
