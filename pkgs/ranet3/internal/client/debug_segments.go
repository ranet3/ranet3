// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/srv6"
)

// DebugSegments is cap.segment as the mesh holds it now: each local segment,
// an egress segment with whether its SID is served and the families the mesh
// hands to the exit, each steering policy, and the counters ranet3 status
// reports
func (c *Client) DebugSegments() control.SegmentsInfo {
	info := control.SegmentsInfo{Counters: segmentCounters(c.Mesh.SegmentCounters())}
	egress := c.segmentEgress()
	for _, segment := range c.Mesh.Segments().Segments() {
		info.Segments = append(info.Segments, localSegment(segment, egress))
	}
	table := c.Mesh.Steering()
	if policies := table.Policies(); policies != nil {
		steering := &control.Steering{Enabled: c.Mesh.SteeringEnabled(), Overhead: table.Overhead()}
		for _, policy := range policies {
			steering.Policies = append(steering.Policies, steerPolicyOf(policy))
		}
		info.Steering = steering
	}
	return info
}

// segmentEgress is an egress segment's part of the exit now: whether the
// egress SIDs are served, and the families the mesh hands to the exit
func (c *Client) segmentEgress() control.SegmentEgress {
	return control.SegmentEgress{Served: c.servesEgressSIDs(), Ready: readyFamilies(c.Mesh.EgressReady())}
}

// localSegment is segment on the wire, with egress where it delivers to the
// exit
func localSegment(segment srv6.Segment, egress control.SegmentEgress) control.LocalSegment {
	local := control.LocalSegment{SID: segment.SID.Addr, Behavior: segment.Behavior.String()}
	if segment.Behavior == srv6.BehaviorEndDT46 {
		local.Deliver = segment.Deliver.String()
	}
	for _, prefix := range segment.Allow {
		local.Allow = append(local.Allow, prefix.Prefix)
	}
	if segment.Deliver == srv6.DeliverEgress {
		local.Egress = &egress
	}
	return local
}

// steerPolicyOf is policy on the wire
func steerPolicyOf(policy srv6.Policy) control.SteerPolicy {
	return control.SteerPolicy{From: policy.From, To: policy.To, Source: policy.Source, Path: policy.Path, Overhead: policy.Overhead()}
}
