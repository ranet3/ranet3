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
	ready := readyFamilies(c.Mesh.EgressReady())
	served := c.servesEgressSIDs()
	for _, segment := range c.Mesh.Segments().Segments() {
		local := control.LocalSegment{SID: segment.SID.Addr, Behavior: segment.Behavior.String()}
		if segment.Behavior == srv6.BehaviorEndDT46 {
			local.Deliver = segment.Deliver.String()
		}
		for _, prefix := range segment.Allow {
			local.Allow = append(local.Allow, prefix.Prefix)
		}
		if segment.Deliver == srv6.DeliverEgress {
			local.Egress = &control.SegmentEgress{Served: served, Ready: ready}
		}
		info.Segments = append(info.Segments, local)
	}
	table := c.Mesh.Steering()
	if policies := table.Policies(); policies != nil {
		steering := &control.Steering{Enabled: c.Mesh.SteeringEnabled(), Overhead: table.Overhead()}
		for _, policy := range policies {
			steering.Policies = append(steering.Policies, control.SteerPolicy{
				From: policy.From, To: policy.To, Source: policy.Source, Path: policy.Path, Overhead: policy.Overhead(),
			})
		}
		info.Steering = steering
	}
	return info
}
