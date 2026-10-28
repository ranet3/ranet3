// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"path"
	"slices"
	"strings"

	"ranet3.com/pkgs/ranet3/schema"
)

// ExitMode is cap.exit, which makes the mesh's default of lowest metric this
// host's default, for its own traffic and for what it forwards from the links
// Forward names. Writing the block turns it on, and the reconciler runs it as
// part of cap.table (see Table.WithMode).
type ExitMode struct {
	// Forward is the links whose forwarded traffic follows the mode as the
	// host's own does, each a link's name or a shell pattern as path.Match reads
	// one, such as docker* or br-*. A link it leaves out keeps the routes it had
	// before ranet3.
	Forward []string `yaml:"forward,omitempty" json:"forward,omitempty" toml:"forward,omitempty"`
}

// loopback is the name Linux gives its loopback link, whose index every lookup of the host's own traffic carries
const loopback = "lo"

// Validate refuses a forward entry that can name no link, an empty one or a
// malformed pattern, and lo by name, whose traffic is the host's own.
func (m ExitMode) Validate() error {
	for _, entry := range m.Forward {
		if entry == "" {
			return errors.New("kernel: cap.exit forward holds an empty entry, which names no link")
		}
		// path.Match parses every part of a pattern whatever the name, so the empty name finds each malformed one
		if _, err := path.Match(entry, ""); err != nil {
			return fmt.Errorf("kernel: cap.exit forward %q: %w", entry, err)
		}
		if entry == loopback {
			return errors.New("kernel: cap.exit forward lo is the loopback link, whose traffic is the host's own and follows the mode already")
		}
	}
	return nil
}

// Normalized is the capability as the reconciler runs it, forward in one order
// and each entry once, so a reload over a list written in another order is no
// change.
func (m ExitMode) Normalized() ExitMode {
	if len(m.Forward) == 0 {
		m.Forward = nil
		return m
	}
	m.Forward = slices.Compact(slices.Sorted(slices.Values(m.Forward)))
	return m
}

// RefuseNamed refuses a forward entry written as a name that is the mesh's tun
// or the link either family's default leaves by now. A pattern matching one is
// skipped where the reconciler expands it, as is a name that becomes the
// uplink later, since the host is the one that moved.
func (m ExitMode) RefuseNamed(tun string, network NetworkState) error {
	for _, entry := range m.Forward {
		if isPattern(entry) {
			continue
		}
		if reason := skipReason(entry, tun, network); reason != "" {
			return fmt.Errorf("kernel: cap.exit forward %s is %s, whose traffic never follows the mode: remove it from forward", entry, reason)
		}
	}
	return nil
}

// ForwardSkip is a link a cap.exit forward entry matches and the mode leaves
// out, with the entry and the reason.
type ForwardSkip struct {
	Entry, Link, Reason string
}

// expandForward is each link the network holds outside the mesh, and the tun,
// that an entry of forward matches, sorted and each once. The tun, lo and the
// link either family's default leaves by are left out, each reported with the
// first entry in forward's order that matched it.
func expandForward(forward []string, tun string, network NetworkState) ([]string, []ForwardSkip) {
	if len(forward) == 0 {
		return nil, nil
	}
	names := make(map[string]bool)
	for _, family := range []NetworkFamily{network.IPv4, network.IPv6} {
		for _, link := range family.Links {
			names[link.Name] = true
		}
	}
	if tun != "" {
		names[tun] = true
	}
	var out []string
	var skipped []ForwardSkip
	for _, name := range slices.Sorted(maps.Keys(names)) {
		// every entry passed Validate, so path.Match reports no error
		at := slices.IndexFunc(forward, func(entry string) bool { matched, _ := path.Match(entry, name); return matched })
		if at < 0 {
			continue
		}
		if reason := skipReason(name, tun, network); reason != "" {
			skipped = append(skipped, ForwardSkip{Entry: forward[at], Link: name, Reason: reason})
			continue
		}
		out = append(out, name)
	}
	return out, skipped
}

// ExitStatus is cap.exit's mode as the last rule pass ran it
type ExitStatus struct {
	// Forwarded is each link forward expanded to, whose forwarded traffic follows the mode
	Forwarded []string
	// Skipped is each link a forward entry matched that the mode leaves out
	Skipped []ForwardSkip
	// Unaddressed is each family the tun carries no overlay address of, which
	// runs mode off's rules
	Unaddressed []Family
}

// exitPass is mode 2 as the pass under way derives it, from the network as
// the watch last read it and the tun's addresses as the pass holds them, and
// its status, nil in mode off. A family counts as addressed by an address
// inside an overlay entry alone, whoever wrote it.
func (r *Reconciler) exitPass(held []netip.Prefix) (exitView, *ExitStatus) {
	mode := r.table.Mode()
	if mode == nil {
		return exitView{}, nil
	}
	var network NetworkState
	if r.rt.Network != nil {
		network = r.rt.Network()
	}
	forwarded, skipped := expandForward(mode.Forward, r.rt.Interface, network)
	status := &ExitStatus{Forwarded: forwarded, Skipped: skipped}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		inOverlay := func(address netip.Prefix) bool {
			return familyOf(address.Addr()) == family && schema.InsideOverlay(netip.PrefixFrom(address.Addr(), address.Addr().BitLen()), r.rt.Overlay)
		}
		if !slices.ContainsFunc(held, inOverlay) {
			status.Unaddressed = append(status.Unaddressed, family)
		}
	}
	return exitView{on: true, network: network, forwarded: forwarded, unaddressed: status.Unaddressed}, status
}

// reportExit records each skip and each family the tun holds no overlay
// address of that now holds and the last pass's status did not as begun, and
// each the last held that now does not as ended, a pass in mode off and a
// withdrawal, whose status is nil, ending all of them, and keeps now as the last
func (r *Reconciler) reportExit(now *ExitStatus) {
	var was, is ExitStatus
	if r.exitStatus != nil {
		was = *r.exitStatus
	}
	if now != nil {
		is = *now
	}
	for _, skip := range is.Skipped {
		if !slices.Contains(was.Skipped, skip) {
			r.reportSkip(slog.LevelWarn, "kernel leaves a link cap.exit forward matches out of the mode", skip, true)
		}
	}
	for _, skip := range was.Skipped {
		if !slices.Contains(is.Skipped, skip) {
			r.reportSkip(slog.LevelInfo, "kernel no longer leaves a link cap.exit forward matched out of the mode", skip, false)
		}
	}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		if before, after := slices.Contains(was.Unaddressed, family), slices.Contains(is.Unaddressed, family); before != after {
			r.reportFamily(family, before)
		}
	}
	r.exitStatus = now
}

func (r *Reconciler) reportFamily(family Family, addressed bool) {
	level, message := slog.LevelWarn, "kernel runs mode off's rules in a family, the tun holding no overlay address of it"
	if addressed {
		level, message = slog.LevelInfo, "kernel no longer counts a family as one the tun holds no overlay address of"
	}
	slog.Log(context.Background(), level, message, "family", string(family))
	r.rt.Events.Emit("kernel.exit", "", slog.String("family", string(family)), slog.Bool("addressed", addressed))
}

func (r *Reconciler) reportSkip(level slog.Level, message string, skip ForwardSkip, skipped bool) {
	attrs := []slog.Attr{slog.String("entry", skip.Entry), slog.String("link", skip.Link), slog.String("reason", skip.Reason)}
	slog.LogAttrs(context.Background(), level, message, attrs...)
	r.rt.Events.Emit("kernel.forward", "", append(attrs, slog.Bool("skipped", skipped))...)
}

// skipReason says why the mode never forwards a link's traffic, or is empty
func skipReason(name, tun string, network NetworkState) string {
	switch name {
	case tun:
		return "the mesh's own tun"
	case loopback:
		return "the loopback link"
	case network.IPv4.Default.Interface:
		return "the link the IPv4 default leaves by"
	case network.IPv6.Default.Interface:
		return "the link the IPv6 default leaves by"
	}
	return ""
}

// isPattern reports an entry holding one of path.Match's special characters,
// which matches a set of names rather than naming one link
func isPattern(entry string) bool { return strings.ContainsAny(entry, `*?[\`) }
