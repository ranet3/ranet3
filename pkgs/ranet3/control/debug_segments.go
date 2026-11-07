// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// PathDebugSegments is cap.segment: each local segment, each cap.segment
// steer policy, cap.exit via's path, the overhead the longest list takes,
// and the node's segment counters
const PathDebugSegments = PathDebug + "segments"

func init() {
	debugRead(PathDebugSegments, "segments", SegmentsSource.DebugSegments)
}

// SegmentsSource is a Source that reads its cap.segment
type SegmentsSource interface {
	DebugSegments() SegmentsInfo
}

// SegmentsInfo is cap.segment as a debug read finds it: Segments in SID
// order, Steering absent on a node that steers nothing, and Counters always,
// as SegmentCounters is in Status
type SegmentsInfo struct {
	Segments []LocalSegment  `json:"segments,omitempty"`
	Steering *Steering       `json:"steering,omitempty"`
	Counters SegmentCounters `json:"counters"`
}

// LocalSegment is one SID this node answers for, its delivery and allow list
// where it is an End.DT46, and Egress where it delivers to the exit
type LocalSegment struct {
	SID      netip.Addr     `json:"sid"`
	Behavior string         `json:"behavior"`
	Deliver  string         `json:"deliver,omitempty"`
	Allow    []netip.Prefix `json:"allow,omitempty"`
	Egress   *SegmentEgress `json:"egress,omitempty"`
}

// SegmentEgress is an egress segment's part of the exit: whether the egress
// SIDs are announced, and the families the mesh hands to the exit through them
type SegmentEgress struct {
	Served bool     `json:"served"`
	Ready  []string `json:"ready,omitempty"`
}

// Steering is the policies deciding which of this node's own packets go
// through a segment list: Enabled false while they are stopped, Overhead the
// most any adds, cap.exit via's path among them, which the tun's MTU leaves
// room for, each cap.segment steer policy in the order it was written, and
// Via, cap.exit via's path, which a stop of steering leaves on, absent where
// the node has none
type Steering struct {
	Enabled  bool          `json:"enabled"`
	Overhead int           `json:"overhead"`
	Policies []SteerPolicy `json:"policies"`
	Via      *SteerPolicy  `json:"via,omitempty"`
}

// SteerPolicy is one steering policy: its selector, a half absent where the
// entry left it out and both for cap.exit via's path, the outer source, the
// segments in the order visited and the bytes it adds in front of a packet
type SteerPolicy struct {
	From     netip.Prefix `json:"from,omitzero"`
	To       netip.Prefix `json:"to,omitzero"`
	Source   netip.Addr   `json:"source"`
	Path     []netip.Addr `json:"path"`
	Overhead int          `json:"overhead"`
}

// Segments reads cap.segment with its policies and counters
func (c *Client) Segments() (SegmentsInfo, error) { return read[SegmentsInfo](c, PathDebugSegments) }

// RenderSegments writes each local segment, cap.exit via's path, the steering
// policies as a table where there are any, then the counters
func RenderSegments(w io.Writer, info SegmentsInfo) {
	if len(info.Segments) == 0 && info.Steering == nil {
		fmt.Fprintln(w, "No local segment and no steering policy")
	}
	var rows [][]string
	for _, segment := range info.Segments {
		rows = append(rows, []string{"Segment", segmentText(segment)})
	}
	if s := info.Steering; s != nil {
		state := "on"
		if !s.Enabled {
			state = "stopped"
		}
		rows = append(rows, []string{"Steering", fmt.Sprintf("%s, the tun's MTU leaving %d B for the longest segment list", state, s.Overhead)})
		if v := s.Via; v != nil {
			rows = append(rows, []string{"Exit path", fmt.Sprintf("%s from %s, %d B, on whether or not steering is stopped", pathText(*v), v.Source, v.Overhead)})
		}
	}
	c := info.Counters
	counters := [][]string{
		{"Counters", fmt.Sprintf("%d forwarded, %d delivered, %d dropped, %d answered, %d egressed, %d refused, %d not ready",
			c.Forwarded, c.Delivered, c.Dropped, c.Answered, c.Egressed, c.Refused, c.NotReady)},
		{"Steered", fmt.Sprintf("%d steered, %d too large to encapsulate, %d with no route to their first segment", c.Steered, c.Unsteered, c.Unrouted)},
	}
	s := info.Steering
	if s == nil || len(s.Policies) == 0 {
		pairs(w, append(rows, counters...))
		return
	}
	pairs(w, rows)
	policies := make([][]string, 0, len(s.Policies))
	for _, policy := range s.Policies {
		policies = append(policies, []string{selectorText(policy), policy.Source.String(), pathText(policy), fmt.Sprintf("%d B", policy.Overhead)})
	}
	indented(w, func(w io.Writer) { table(w, []string{"Selects", "Source", "Path", "Overhead"}, policies) })
	pairs(w, counters)
}

// segmentText is a segment as the file spells it, then an egress segment's
// part of the exit
func segmentText(s LocalSegment) string {
	parts := []string{s.SID.String(), s.Behavior}
	if s.Deliver != "" {
		parts = append(parts, "deliver "+s.Deliver)
	}
	if len(s.Allow) > 0 {
		allow := make([]string, 0, len(s.Allow))
		for _, prefix := range s.Allow {
			allow = append(allow, prefix.String())
		}
		parts = append(parts, "allow "+strings.Join(allow, " "))
	}
	text := strings.Join(parts, " ")
	if e := s.Egress; e != nil {
		served := "served"
		if !e.Served {
			served = "not served"
		}
		ready := "ready for none"
		if len(e.Ready) > 0 {
			ready = "ready for " + strings.Join(e.Ready, " ")
		}
		text += ", " + served + ", " + ready
	}
	return text
}

// selectorText is a policy's selector as the file spells it
func selectorText(p SteerPolicy) string {
	var parts []string
	if p.From.IsValid() {
		parts = append(parts, "from "+p.From.String())
	}
	if p.To.IsValid() {
		parts = append(parts, "to "+p.To.String())
	}
	return strings.Join(parts, " ")
}

// pathText is a policy's segment list as the file spells it
func pathText(p SteerPolicy) string {
	path := make([]string, 0, len(p.Path))
	for _, segment := range p.Path {
		path = append(path, segment.String())
	}
	return strings.Join(path, " ")
}
