// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
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
