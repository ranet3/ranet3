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
// encapsulates is the same bytes the kernel would have produced.

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
	// Deliver is the table End.DT46 hands the inner packet to, the parameter
	// RFC 8986 section 4.8 gives the behavior
	Deliver Delivery `yaml:"deliver,omitempty" json:"deliver,omitempty" toml:"deliver,omitempty"`
	// Allow holds the outer and inner sources a segment delivering to egress
	// carries, and is refused with any other delivery
	Allow []schema.Prefix `yaml:"allow,omitempty" json:"allow,omitempty" toml:"allow,omitempty"`
}

// Delivery is where an End.DT46 segment hands the packet it decapsulated.
type Delivery uint8

const (
	// DeliverMesh hands it to the mesh's forwarding decision, which writes it to the tun, hands it to the exit, forwards it to a peer whatever cap.transit says, answers it or drops it
	// a file omitting deliver means it
	DeliverMesh Delivery = iota
	// DeliverEgress hands it to the node's exit to leave the mesh under
	// cap.egress's translation, and only for a packet whose outer and inner
	// sources both lie in Allow
	DeliverEgress
)

func (d Delivery) String() string {
	switch d {
	case DeliverMesh:
		return "mesh"
	case DeliverEgress:
		return "egress"
	}
	return fmt.Sprintf("delivery(%d)", uint8(d))
}

// ErrSourceRefused is a local SID's refusal of a packet for its source: at
// every SID an outer source outside the overlay, and at an egress segment an
// outer or inner source outside its allow list, or an inner source it cannot
// read
var ErrSourceRefused = errors.New("srv6: the segment does not admit the packet's source")

// errOutsideOverlay is ErrSourceRefused for an outer source outside the
// overlay, made once so a refused packet allocates nothing
var errOutsideOverlay = fmt.Errorf("%w: its outer source lies outside cap.border overlay", ErrSourceRefused)

// String is the segment as the file spells it, its delivery and allow list
// only where it writes them
func (s Segment) String() string {
	parts := []string{s.SID.String(), s.Behavior.String()}
	if s.Deliver != DeliverMesh {
		parts = append(parts, "deliver", s.Deliver.String())
	}
	if len(s.Allow) > 0 {
		parts = append(parts, "allow")
		for _, prefix := range s.Allow {
			parts = append(parts, prefix.String())
		}
	}
	return strings.Join(parts, " ")
}

func (s Segment) allows(source netip.Addr) bool {
	for _, prefix := range s.Allow {
		if prefix.Contains(source) {
			return true
		}
	}
	return false
}

// checkAllow refuses an allow list that would make an egress segment an open
// proxy, or that a packet could never pass
func (s Segment) checkAllow() error {
	if len(s.Allow) == 0 {
		return fmt.Errorf("srv6: cap.segment local %s delivers to egress with no allow list, so it would carry any source's traffic", s.SID)
	}
	err := schema.CheckPrefixes(fmt.Sprintf("srv6: cap.segment local %s allow", s.SID), s.Allow, func(prefix netip.Prefix) string {
		switch {
		case prefix.Bits() == 0:
			return "admits every address of its family, which makes the segment an open proxy"
		case schema.BelowSourceFloor(prefix):
			return fmt.Sprintf("is shorter than /%d for IPv4 or /%d for IPv6, the unit IANA delegates to a regional registry, so it admits holders the mesh has nothing to do with", schema.MinSourceBits4, schema.MinSourceBits6)
		}
		return ""
	})
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(s.Allow, func(entry schema.Prefix) bool { return entry.Addr().Is6() }) {
		return fmt.Errorf("srv6: cap.segment local %s allow holds no IPv6 prefix, and the outer source of a segment routed packet is always IPv6, so no packet could pass", s.SID)
	}
	return nil
}

// LocalTable is the set of segments this node answers for. A nil table answers
// for none, which is every node that configures no segment routing, and every
// method below works on one so a caller never has to ask first.
type LocalTable struct {
	entries map[netip.Addr]Segment
	// overlay is the IPv6 prefixes of cap.border's overlay, the only outer
	// sources any SID of entries acts on
	overlay []netip.Prefix
}

// NewLocalTable builds the table, refusing a SID that is not an address this
// node could be reached at. A v4 SID has no meaning, since a segment list is
// carried in an IPv6 routing header, and a duplicate is a configuration whose
// two halves disagree about what this node does.
//
// Every SID refuses a packet whose outer source lies outside overlay's IPv6
// prefixes, the per-node list of RFC 8754 section 5.1 item 2. A node writing
// cap.border drops those sources arriving from outside the mesh, so a host
// beyond the mesh reaches no SID through it, whatever the SID delivers to. A
// node that forwards without cap.border is only warned at load, and passes a
// forged overlay source on to every SID. An outer source is always IPv6, so a
// table holding a SID and no IPv6 prefix of overlay is refused.
func NewLocalTable(segments []Segment, overlay []schema.Prefix) (*LocalTable, error) {
	entries, err := localEntries(segments)
	if err != nil || entries == nil {
		return nil, err
	}
	table := &LocalTable{entries: entries}
	for _, prefix := range overlay {
		if prefix.Addr().Is6() {
			table.overlay = append(table.overlay, prefix.Prefix)
		}
	}
	if len(table.overlay) == 0 {
		return nil, fmt.Errorf("srv6: cap.segment local %s would refuse every packet, since cap.border overlay holds no IPv6 prefix to admit an outer source from", segments[0].SID)
	}
	return table, nil
}

// localEntries checks segments and keys them by SID, nil for none
func localEntries(segments []Segment) (map[netip.Addr]Segment, error) {
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
			return nil, fmt.Errorf("srv6: cap.segment local %s is written twice, as %s and as %s", segment.SID, existing, segment)
		}
		switch {
		case segment.Deliver != DeliverMesh && segment.Deliver != DeliverEgress:
			return nil, fmt.Errorf("srv6: cap.segment local %s: %s is not mesh or egress", segment.SID, segment.Deliver)
		case segment.Deliver == DeliverEgress && segment.Behavior == BehaviorEnd:
			return nil, fmt.Errorf("srv6: cap.segment local %s: deliver egress belongs to End.DT46, and End hands the packet to its next segment", segment.SID)
		case segment.Deliver == DeliverMesh && len(segment.Allow) > 0:
			return nil, fmt.Errorf("srv6: cap.segment local %s: allow is read only with deliver = \"egress\"", segment.SID)
		}
		if segment.Deliver == DeliverEgress {
			if err := segment.checkAllow(); err != nil {
				return nil, err
			}
			// the table is read by every dataplane goroutine and owns its list
			segment.Allow = slices.Clone(segment.Allow)
		}
		entries[segment.SID.Addr] = segment
	}
	return entries, nil
}

// Holds reports whether address is one of the table's SIDs
func (t *LocalTable) Holds(address netip.Addr) bool {
	if t == nil {
		return false
	}
	_, ok := t.entries[address]
	return ok
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

// admits is whether an outer source lies in the overlay
func (t *LocalTable) admits(source netip.Addr) bool {
	for _, prefix := range t.overlay {
		if prefix.Contains(source) {
			return true
		}
	}
	return false
}

// refuses is the refusal of source, a packet's outer source, at segment, nil for one it admits
// every SID asks the overlay first, and an egress segment then its allow list
func (t *LocalTable) refuses(segment *Segment, source netip.Addr) error {
	switch {
	case !t.admits(source):
		return errOutsideOverlay
	case segment.Deliver == DeliverEgress && !segment.allows(source):
		return ErrSourceRefused
	}
	return nil
}

// Admission is the segment at a packet's destination and its answer to the packet's outer source, which Handle asks before it reads anything else
type Admission struct {
	Segment Segment
	// Overlay is the source lying in the overlay, which every SID asks first
	// Allowed is it lying in an egress segment's allow list, which only such a segment asks, of a source Overlay admits
	Overlay, Allowed bool
	// Err is the refusal Handle drops the packet with, nil for a source both admit
	Err error
}

// Admit is the admission of source, an outer source, at the segment at sid, as Handle's refusal answers it, false where the table holds no sid
func (t *LocalTable) Admit(sid, source netip.Addr) (Admission, bool) {
	if t == nil {
		return Admission{}, false
	}
	segment, ours := t.entries[sid]
	if !ours {
		return Admission{}, false
	}
	err := t.refuses(&segment, source)
	return Admission{Segment: segment, Overlay: err != errOutsideOverlay, Allowed: segment.Deliver == DeliverEgress && err == nil, Err: err}, true
}

// Action tells the caller how to treat a packet Handle has looked at.
type Action uint8

const (
	// ActionPass is a packet this table has nothing to say about, which is
	// almost all of them: it goes where it was going.
	ActionPass Action = iota
	// ActionForward is a waypoint's result. The packet was rewritten in place
	// and goes to Result.Next. Result.SID is the segment of this node it was
	// addressed to.
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
	SID    netip.Addr
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
// routing headers addressed elsewhere. One from an outer source the segment
// does not admit is refused before that, so it is never answered.
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
	source := netip.AddrFrom16([16]byte(raw[8:24]))
	if err := t.refuses(&segment, source); err != nil {
		return Result{Action: ActionDrop, Err: err}
	}
	switch segment.Behavior {
	case BehaviorEnd:
		next, err := End(raw)
		if err != nil {
			return Result{Action: ActionDrop, Err: err}
		}
		return Result{Action: ActionForward, Next: next, SID: destination}
	case BehaviorEndDT46:
		egress := segment.Deliver == DeliverEgress
		inner, family, err := Decap(raw)
		if err != nil {
			return Result{Action: ActionDrop, Err: err}
		}
		if !egress {
			return Result{Action: ActionDeliver, Inner: inner, Family: family}
		}
		if source, ok := innerSource(inner, family); !ok || !segment.allows(source) {
			return Result{Action: ActionDrop, Err: ErrSourceRefused}
		}
		return Result{Action: ActionEgress, Inner: inner, Family: family}
	}
	// NewLocalTable refuses anything else, so this is unreachable rather than
	// a case left to fall through into silence.
	return Result{Action: ActionDrop, Err: fmt.Errorf("srv6: %s carries an unimplemented behavior", destination)}
}

// innerSource reads the source the host's stack will read off the tun, which
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
