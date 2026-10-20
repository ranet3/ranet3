// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

import (
	"cmp"
	"fmt"
	"slices"

	"go.yaml.in/yaml/v3"
	"ranet3.com/pkgs/ranet3/schema"
)

// Segments is the cap.segment capability, parsed straight out of the file: the
// segments this node answers for and the ones it sends its own packets
// through. This tree acts on a routing header in the dataplane rather than
// asking a kernel to, so steering works on every platform: darwin has no
// segment routing and a mobile tunnel provider has no forwarding table at all,
// and neither needs one when the process carrying the packet is the one acting
// on the header. A local segment needs cap.border beside it, which only linux
// runs.
type Segments struct {
	// Source is the outer source address an encapsulation is sent from, which
	// the fleet sets once per node with `ip sr tunsrc`. A steering entry
	// inherits it unless it names its own.
	Source schema.Addr `yaml:"source,omitempty" json:"source,omitzero" toml:"source,omitempty"`
	// Local is the segments this node answers for.
	Local []Segment `yaml:"local,omitempty" json:"local,omitempty" toml:"local,omitempty"`
	// Steer decides which of this node's own packets go through a segment
	// list: the traffic sourced from this node's announced address, through
	// the waypoints and out at a chosen exit.
	Steer []Steer `yaml:"steer,omitempty" json:"steer,omitempty" toml:"steer,omitempty"`
}

// Normalized is the capability as the dataplane runs it: an omitted list and
// an empty one the same, both lists in one order, and every steering entry
// carrying the outer source it will be sent from, the block's own where the
// entry named none. Two configurations are compared through this rather than
// as they were written, so neither a source repeated on the entry that
// inherits it nor the order the entries were listed in is a change, and
// neither costs a restart.
//
// Both lists are read as sets: the local segments become a map keyed by SID
// and the steering entries a trie keyed by their selector, and a duplicate key
// in either is refused rather than resolved by position. An egress segment's
// allow list is a set too, sorted here and refused with a duplicate. The
// segments inside one steering entry are the exception and are left alone,
// because Via is the order a packet visits its waypoints.
func (s Segments) Normalized() Segments {
	if len(s.Local) == 0 {
		s.Local = nil
	} else {
		s.Local = slices.SortedFunc(slices.Values(s.Local), func(a, b Segment) int {
			return cmp.Or(schema.CompareAddr(a.SID, b.SID), cmp.Compare(a.Behavior, b.Behavior))
		})
		for i := range s.Local {
			s.Local[i].Allow = slices.SortedFunc(slices.Values(s.Local[i].Allow), schema.ComparePrefix)
		}
	}
	if len(s.Steer) == 0 {
		s.Steer = nil
		return s
	}
	// Cloned before the entries are touched: the struct is a shallow copy, so
	// writing through it would reach the configuration this only reads.
	s.Steer = slices.Clone(s.Steer)
	for i := range s.Steer {
		if len(s.Steer[i].Via) == 0 {
			s.Steer[i].Via = nil
		}
		if !s.Steer[i].Source.IsValid() {
			s.Steer[i].Source = s.Source
		}
	}
	slices.SortFunc(s.Steer, func(a, b Steer) int {
		return cmp.Or(
			schema.ComparePrefix(a.From, b.From),
			schema.ComparePrefix(a.To, b.To),
			schema.CompareAddr(a.Source, b.Source),
			slices.CompareFunc(a.Via, b.Via, schema.CompareAddr),
		)
	})
	return s
}

func (s Segments) Egress() []Segment {
	var out []Segment
	for _, segment := range s.Local {
		if segment.Deliver == DeliverEgress {
			out = append(out, segment)
		}
	}
	return out
}

// Validate refuses a capability this node could not act on, through the checks
// the two tables' constructors run, so there is one set of rules rather than
// two. The overlay the local table needs belongs to cap.border, so the loader
// checks it where it reads both blocks.
func (s Segments) Validate() error {
	if s.Source.IsValid() && !Usable(s.Source.Addr) {
		// Checked here rather than where the first steering entry needs it,
		// because nothing else reads the field and a node that steers nothing
		// yet would otherwise carry a source it can never send from.
		return fmt.Errorf("srv6: cap.segment source %s cannot address a segment routed packet", s.Source)
	}
	if _, err := localEntries(s.Local); err != nil {
		return err
	}
	_, err := NewSteerTable(s.Steer, s.Source)
	return err
}

// Tables is the pair the dataplane runs on: what this node answers for, each
// SID admitting only an outer source in overlay, and what it steers. Either
// is nil where the capability configures none of it, and every method on both
// works on a nil table.
func (s Segments) Tables(overlay []schema.Prefix) (*LocalTable, *SteerTable, error) {
	local, err := NewLocalTable(s.Local, overlay)
	if err != nil {
		return nil, nil, err
	}
	steering, err := NewSteerTable(s.Steer, s.Source)
	if err != nil {
		return nil, nil, err
	}
	return local, steering, nil
}

func (b *Behavior) UnmarshalText(text []byte) error {
	parsed, err := ParseBehavior(string(text))
	if err != nil {
		return err
	}
	*b = parsed
	return nil
}

func (b Behavior) MarshalText() ([]byte, error) {
	if b != BehaviorEnd && b != BehaviorEndDT46 {
		return nil, fmt.Errorf("srv6: %s has no spelling", b)
	}
	return []byte(b.String()), nil
}

func (b *Behavior) UnmarshalYAML(value *yaml.Node) error {
	return schema.Scalar(value, "a behavior, End or End.DT46", b)
}

func (d *Delivery) UnmarshalText(text []byte) error {
	switch string(text) {
	case "mesh":
		*d = DeliverMesh
	case "egress":
		*d = DeliverEgress
	default:
		return fmt.Errorf("srv6: deliver %q is not mesh or egress", text)
	}
	return nil
}

func (d Delivery) MarshalText() ([]byte, error) {
	if d != DeliverMesh && d != DeliverEgress {
		return nil, fmt.Errorf("srv6: %s has no spelling", d)
	}
	return []byte(d.String()), nil
}

func (d *Delivery) UnmarshalYAML(value *yaml.Node) error {
	return schema.Scalar(value, "a delivery, mesh or egress", d)
}
