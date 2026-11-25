// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"fmt"
	"math"
	"net/netip"
	"slices"

	"ranet3.com/pkgs/ranet3/schema"
)

// Sourced names IPv6 destinations for a separate table. A zero ID derives
// from the normalized mesh table ID.
type Sourced struct {
	To []schema.Prefix `yaml:"to" json:"to" toml:"to"`
	ID schema.TableID  `yaml:"id,omitempty" json:"id,omitempty" toml:"id,omitempty"`
}

func (s *Sourced) validate(mesh schema.TableID) error {
	if s.ID == 0 {
		if mesh == math.MaxUint32 || uint32(mesh)+1 >= reservedTable && uint32(mesh)+1 <= lastByteTable {
			return fmt.Errorf("kernel: cap.table.sourced id cannot be derived from cap.table.id %d, write id", mesh)
		}
	} else if id := uint32(s.ID); id >= reservedTable && id <= lastByteTable || s.ID == mesh {
		return fmt.Errorf("kernel: cap.table.sourced id %d is reserved or equals cap.table.id", id)
	}
	if len(s.To) == 0 {
		return fmt.Errorf("kernel: cap.table.sourced to names no destination")
	}
	subject := "kernel: cap.table.sourced to"
	if err := schema.CheckPrefixes(subject, s.To, func(prefix netip.Prefix) string {
		switch {
		case !prefix.Addr().Is6():
			return "is not an IPv6 destination"
		case prefix.Bits() < schema.MinSubnetBits6:
			return fmt.Sprintf("is shorter than /%d and counts as a default", schema.MinSubnetBits6)
		default:
			if reason, _ := schema.Unroutable(prefix); reason != "" {
				return reason
			}
			return ""
		}
	}); err != nil {
		return err
	}
	for i, to := range s.To {
		for _, other := range s.To[:i] {
			if to.Overlaps(other.Prefix) {
				return fmt.Errorf("%s %s meets %s, name each destination once", subject, to, other)
			}
		}
	}
	return nil
}

func (s *Sourced) normalized(mesh schema.TableID) *Sourced {
	if s == nil || s.ID != 0 {
		return s
	}
	out := *s
	out.ID = mesh + 1
	return &out
}

// WithSourcedOwn records unsourced announcements from the accepted file, not
// from a mesh snapshot that may still describe the previous file.
func (t Table) WithSourcedOwn(announced []schema.Announce, advertised []netip.Prefix) Table {
	t.ownAnnounced = nil
	if t.Sourced == nil {
		return t
	}
	for _, entry := range announced {
		if entry.From.IsValid() {
			continue
		}
		if canonical, ok := canonicalPrefix(entry.Prefix.Prefix); ok && canonical.Addr().Is6() &&
			canonical.Bits() != 0 && !slices.Contains(advertised, canonical) {
			if _, whole := schema.Unroutable(canonical); !whole {
				t.ownAnnounced = append(t.ownAnnounced, canonical)
			}
		}
	}
	return t
}

// sourcedSources collects exact networks, including nested ones, before the
// tun exists. The network reader already excludes tentative link addresses.
func (t Table) sourcedSources(network func() NetworkState, announced []netip.Prefix) map[netip.Prefix]struct{} {
	sources := make(map[netip.Prefix]struct{})
	add := func(prefix netip.Prefix) {
		if canonical, ok := canonicalPrefix(prefix); ok && canonical.Addr().Is6() &&
			!canonical.Addr().Is4In6() && canonical.Addr().IsGlobalUnicast() && canonical.Bits() > 0 {
			sources[canonical] = struct{}{}
		}
	}
	for _, prefix := range t.ownAnnounced {
		add(prefix)
	}
	if network != nil {
		for _, link := range network().IPv6.Links {
			for _, prefix := range link.Prefixes {
				add(prefix)
			}
		}
	}
	for _, prefix := range t.Assigned(announced) {
		if address := prefix.Addr(); address.Is6() && address.IsGlobalUnicast() {
			add(netip.PrefixFrom(address, address.BitLen()))
		}
	}
	return sources
}

func (t Table) refuseSourcedCapacity(network func() NetworkState, announced []netip.Prefix) error {
	if t.Sourced == nil {
		return nil
	}
	destinations := len(t.Sourced.To)
	pairs := destinations * len(t.sourcedSources(network, announced))
	if destinations <= sourcedPairLimit && pairs <= sourcedPairLimit {
		return nil
	}
	return sourcedCapacityError(destinations, pairs)
}

// PreflightSourcedStartup reads capacity and reserved ownership before the
// daemon constructs the tun or any other managed kernel object.
func PreflightSourcedStartup(t Table, announced []netip.Prefix, tun string) error {
	if t.Sourced == nil {
		return nil
	}
	return preflightSourcedStartup(t.Normalized(), announced, tun)
}

func sourcedCapacityError(destinations, pairs int) error {
	return fmt.Errorf("kernel: cap.table.sourced needs %d destinations and %d destination-source pairs, up to %d IPv6 rules including pair guards (limits: 16 destinations, 16 pairs, 97 rules)",
		destinations, pairs, 1+2*destinations+4*pairs)
}

// SourcedLimits holds file-visible prefixes, not kernel occupancy. Own,
// Announced and Advertised are distinct so a refusal names the setting.
type SourcedLimits struct {
	Overlay                             []schema.Prefix
	Own, Announced, Advertised, Steered []netip.Prefix
}

// Refuse rejects overlay and steering intersections, and own, announced or
// advertised prefixes at or inside a named destination. A broader prefix alone
// does not cause refusal.
func (s *Sourced) Refuse(limits SourcedLimits) error {
	if s == nil {
		return nil
	}
	for _, destination := range s.To {
		to := destination.Prefix
		for _, overlay := range limits.Overlay {
			if overlay.Overlaps(to) {
				return fmt.Errorf("config: cap.table.sourced to %s meets overlay %s", to, overlay)
			}
		}
		for _, own := range limits.Own {
			if to.Contains(own.Addr()) && to.Bits() <= own.Bits() {
				return fmt.Errorf("config: cap.table.sourced to %s holds this node's own %s", to, own)
			}
		}
		for _, announced := range limits.Announced {
			if to.Contains(announced.Addr()) && to.Bits() <= announced.Bits() {
				return fmt.Errorf("config: cap.table.sourced to %s holds cap.route announce %s with a source", to, announced)
			}
		}
		for _, advertised := range limits.Advertised {
			if to.Contains(advertised.Addr()) && to.Bits() <= advertised.Bits() {
				return fmt.Errorf("config: cap.table.sourced to %s holds cap.egress advertise %s", to, advertised)
			}
		}
		for _, steered := range limits.Steered {
			if steered.Overlaps(to) {
				return fmt.Errorf("config: cap.table.sourced to %s meets cap.segment steer to %s", to, steered)
			}
		}
	}
	return nil
}
