// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"ranet3.com/pkgs/ranet3/schema"
)

// This file is the receiving half: the segments this node answers for, and
// what it does with a packet that arrives addressed to one. The sending half
// is Encapsulate in srv6.go.
//
// On linux the fleet spells these as seg6local routes in a table of their own,
// reached by a policy rule, and the kernel acts on them after strongSwan has
// decrypted the packet. Here the same decision is made one step earlier, on
// the decrypted packet before it reaches the tun, which is the only place the
// other three platforms have. The two interoperate: a packet this node
// encapsulates is the same bytes the kernel would have produced, and one the
// kernel acts on is one this table would have acted on the same way.

// Behavior names the action a node takes on a packet addressed to one of its
// own segments, RFC 8986. Only the two this mesh uses are implemented, and a
// configuration naming another is refused rather than accepted and skipped.
type Behavior uint8

const (
	// BehaviorEnd is the waypoint of RFC 8986 section 4.1: move the packet to
	// the next segment and send it on, changing nothing else.
	BehaviorEnd Behavior = iota + 1
	// BehaviorEndDT46 is the exit of section 4.8: strip the outer header and
	// deliver what was inside, whichever family it is.
	BehaviorEndDT46
)

func (b Behavior) String() string {
	switch b {
	case BehaviorEnd:
		return "End"
	case BehaviorEndDT46:
		return "End.DT46"
	}
	return fmt.Sprintf("behavior(%d)", uint8(b))
}

// ParseBehavior reads the spelling an operator writes, which is the one RFC
// 8986 uses and the one `ip route ... encap seg6local action` takes, so a
// configuration converted from the fleet's own reads the same.
func ParseBehavior(name string) (Behavior, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "end":
		return BehaviorEnd, nil
	case "end.dt46":
		return BehaviorEndDT46, nil
	}
	return 0, fmt.Errorf("srv6: behavior %q is not End or End.DT46", name)
}

// Segment is one entry of the cap.segment capability: one local SID and what
// this node does with a packet that arrives on it. The behavior is spelled as
// RFC 8986 spells it and as `ip route ... encap seg6local action` takes it, so
// a converted configuration reads the same.
type Segment struct {
	SID      schema.Addr `yaml:"sid" json:"sid" toml:"sid"`
	Behavior Behavior    `yaml:"behavior" json:"behavior" toml:"behavior"`
	// nil for a segment that delivers to the mesh, and set by EgressSegment
	// alone, so no file names an egress segment
	egress *egress
}

// egress holds the allow list of an End.DT46 segment that delivers to the
// egress device, behind a pointer so that a Segment stays comparable
type egress struct {
	allow []schema.Prefix
}

// EgressSegment is an End.DT46 segment whose inner packet Handle returns as
// ActionEgress, for the egress device, when its outer and its inner source
// both lie inside allow
func EgressSegment(sid schema.Addr, allow []schema.Prefix) Segment {
	return Segment{SID: sid, Behavior: BehaviorEndDT46, egress: &egress{allow: allow}}
}

// ErrSourceRefused is an egress segment's refusal of a packet whose outer or
// inner source is outside its allow list, or whose inner source it cannot read
var ErrSourceRefused = errors.New("srv6: the egress segment's allow list does not hold the packet's source")

func (s Segment) String() string { return s.SID.String() + " " + s.Behavior.String() }

func (e *egress) allows(source netip.Addr) bool {
	for _, prefix := range e.allow {
		if prefix.Contains(source) {
			return true
		}
	}
	return false
}

// LocalTable is the set of segments this node answers for. A nil table answers
// for none, which is every node that configures no segment routing, and every
// method below works on one so a caller never has to ask first.
type LocalTable struct {
	entries map[netip.Addr]Segment
}

// NewLocalTable builds the table, refusing a SID that is not an address this
// node could be reached at. A v4 SID has no meaning, since a segment list is
// carried in an IPv6 routing header, and a duplicate is a configuration whose
// two halves disagree about what this node does.
func NewLocalTable(segments []Segment) (*LocalTable, error) {
	if len(segments) == 0 {
		return nil, nil
	}
	entries := make(map[netip.Addr]Segment, len(segments))
	for _, segment := range segments {
		if !Usable(segment.SID.Addr) {
			return nil, fmt.Errorf("srv6: cap.segment local %s cannot address a segment routed packet", segment.SID)
		}
		if segment.Behavior != BehaviorEnd && segment.Behavior != BehaviorEndDT46 {
			return nil, fmt.Errorf("srv6: cap.segment local %s: %s is not implemented", segment.SID, segment.Behavior)
		}
		if existing, dup := entries[segment.SID.Addr]; dup {
			return nil, fmt.Errorf("srv6: cap.segment local %s is configured as both %s and %s", segment.SID, existing.Behavior, segment.Behavior)
		}
		if segment.egress != nil {
			if len(segment.egress.allow) == 0 {
				return nil, fmt.Errorf("srv6: cap.segment local %s delivers to egress with no allow list, so it would carry any source's traffic", segment.SID)
			}
			// the table is read by every dataplane goroutine and owns its list
			segment.egress = &egress{allow: slices.Clone(segment.egress.allow)}
		}
		entries[segment.SID.Addr] = segment
	}
	return &LocalTable{entries: entries}, nil
}

// Segments is the table in a stable order, for a diagnostic to print.
func (t *LocalTable) Segments() []Segment {
	if t == nil {
		return nil
	}
	out := slices.Collect(maps.Values(t.entries))
	slices.SortFunc(out, func(a, b Segment) int { return a.SID.Compare(b.SID.Addr) })
	return out
}

// Action tells the caller how to treat a packet Handle has looked at.
type Action uint8

const (
	// ActionPass is a packet this table has nothing to say about, which is
	// almost all of them: it goes where it was going.
	ActionPass Action = iota
	// ActionForward is a waypoint's result. The packet was rewritten in place
	// and goes to Result.Next.
	ActionForward
	// ActionDeliver is the result of an exit that delivers to the mesh.
	// Result.Inner is the packet that was inside and Result.Family says which
	// stack it belongs to.
	ActionDeliver
	// ActionEgress is the result of an egress segment, for a packet whose
	// outer and inner sources both lie in its allow list, with Result.Inner
	// and Result.Family as for ActionDeliver.
	ActionEgress
	// ActionDrop is a packet addressed to one of this node's segments that it
	// will not act on, with Result.Err saying why.
	ActionDrop
)

// Result carries Handle's decision.
type Result struct {
	Action Action
	Next   netip.Addr
	Inner  []byte
	Family uint8
	Err    error
}

// Handle decides what this node does with one decrypted packet.
//
// It answers ActionPass for anything not addressed to a segment this node
// holds, which is the common case and costs one map lookup on the IPv6
// packets alone. Only a packet this node is the current segment of is parsed
// any further, so a peer cannot make this node do work by sending it segment
// routing headers addressed elsewhere.
//
// The packet is rewritten in place for a waypoint, as the RFC's own
// pseudocode does, which keeps a forwarded packet off a second buffer.
func (t *LocalTable) Handle(raw []byte) Result {
	if t == nil || len(raw) < ipv6HeaderLen || raw[0]>>4 != 6 {
		return Result{Action: ActionPass}
	}
	destination := netip.AddrFrom16([16]byte(raw[24:40]))
	segment, ours := t.entries[destination]
	if !ours {
		return Result{Action: ActionPass}
	}
	switch segment.Behavior {
	case BehaviorEnd:
		next, err := End(raw)
		if err != nil {
			return Result{Action: ActionDrop, Err: err}
		}
		return Result{Action: ActionForward, Next: next}
	case BehaviorEndDT46:
		// the outer source is checked before anything is parsed, so an unlisted
		// sender is never answered with an ICMP error about its header
		if segment.egress != nil && !segment.egress.allows(netip.AddrFrom16([16]byte(raw[8:24]))) {
			return Result{Action: ActionDrop, Err: ErrSourceRefused}
		}
		inner, family, err := Decap(raw)
		if err != nil {
			return Result{Action: ActionDrop, Err: err}
		}
		if segment.egress == nil {
			return Result{Action: ActionDeliver, Inner: inner, Family: family}
		}
		if source, ok := innerSource(inner, family); !ok || !segment.egress.allows(source) {
			return Result{Action: ActionDrop, Err: ErrSourceRefused}
		}
		return Result{Action: ActionEgress, Inner: inner, Family: family}
	}
	// NewLocalTable refuses anything else, so this is unreachable rather than
	// a case left to fall through into silence.
	return Result{Action: ActionDrop, Err: fmt.Errorf("srv6: %s carries an unimplemented behavior", destination)}
}

// innerSource reads the source the egress device's stack will read, which
// takes the family from the version nibble rather than from the next header
func innerSource(inner []byte, family uint8) (netip.Addr, bool) {
	if version, err := innerNextHeader(inner); err != nil || version != family {
		return netip.Addr{}, false
	}
	if family == NextHeaderIPv4 {
		return netip.AddrFrom4([4]byte(inner[12:16])), true
	}
	return netip.AddrFrom16([16]byte(inner[8:24])), true
}
