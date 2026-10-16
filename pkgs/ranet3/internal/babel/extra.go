// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"fmt"
	"maps"
	"slices"

	"ranet3.com/pkgs/ranet3/identity"
)

// ExtraCost charges a neighbor the amount of the most specific key it matches, node, then org, then foreign, and the amounts do not add
type ExtraCost struct {
	Foreign uint16            `yaml:"foreign,omitempty" json:"foreign,omitempty" toml:"foreign,omitempty"`
	Org     map[string]uint16 `yaml:"org,omitempty" json:"org,omitempty" toml:"org,omitempty"`
	Node    map[string]uint16 `yaml:"node,omitempty" json:"node,omitempty" toml:"node,omitempty"`
}

func (e ExtraCost) For(organization string, peer identity.Identity) uint16 {
	if peer.IsZero() {
		return 0
	}
	if amount, ok := e.Node[peer.Node().String()]; ok {
		return amount
	}
	org, _ := peer.NodeParts()
	if amount, ok := e.Org[org]; ok {
		return amount
	}
	if org != organization {
		return e.Foreign
	}
	return 0
}

func (e ExtraCost) Equal(other ExtraCost) bool {
	return e.Foreign == other.Foreign && maps.Equal(e.Org, other.Org) && maps.Equal(e.Node, other.Node)
}

func (e ExtraCost) Nodes() []identity.Identity {
	out := make([]identity.Identity, 0, len(e.Node))
	for _, key := range slices.Sorted(maps.Keys(e.Node)) {
		// Validate refused every key that does not parse
		id, _ := identity.Parse(key)
		out = append(out, id)
	}
	return out
}

func (e ExtraCost) Validate() error {
	if e.Foreign == MetricInfinity {
		return fmt.Errorf("babel: cap.babel cost.extra foreign is %d, and an amount is between 0 and %d", e.Foreign, MetricInfinity-1)
	}
	for _, org := range slices.Sorted(maps.Keys(e.Org)) {
		if org == "" {
			return fmt.Errorf("babel: cap.babel cost.extra org names an empty organization")
		}
		if amount := e.Org[org]; amount == MetricInfinity {
			return fmt.Errorf("babel: cap.babel cost.extra org %q is %d, and an amount is between 0 and %d", org, amount, MetricInfinity-1)
		}
	}
	for _, key := range slices.Sorted(maps.Keys(e.Node)) {
		id, err := identity.Parse(key)
		if err != nil {
			return fmt.Errorf("babel: cap.babel cost.extra node %q: %w", key, err)
		}
		if id != id.Node() {
			return fmt.Errorf("babel: cap.babel cost.extra node %q names an endpoint, and a key is organization/name", key)
		}
		if amount := e.Node[key]; amount == MetricInfinity {
			return fmt.Errorf("babel: cap.babel cost.extra node %q is %d, and an amount is between 0 and %d", key, amount, MetricInfinity-1)
		}
	}
	return nil
}

// RFC 8966 section 3.4.3 asks that "if the txcost is infinite, then the cost is infinite", so infinity stays as it is
// a finite cost stays finite, since the amount prices a path and never withdraws one
func addExtra(cost, extra uint16) uint16 {
	if cost == MetricInfinity {
		return MetricInfinity
	}
	return uint16(min(uint32(cost)+uint32(extra), uint32(MetricInfinity)-1))
}
