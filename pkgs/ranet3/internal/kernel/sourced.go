// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"fmt"
	"math"
	"net/netip"

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
