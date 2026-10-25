// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"slices"

	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

// RouteLookups answers the egress translator's route lookups through the
// kernel's batch, one socket a pass, so the translator makes no system call of
// its own and imports nothing of the kernel's
func RouteLookups(lookups []kernelexit.Lookup) ([]kernelexit.Answer, error) {
	reads := make([]kernel.RouteRead, len(lookups))
	for i, lookup := range lookups {
		reads[i] = kernel.RouteRead{Source: lookup.Source, Destination: lookup.Destination, IIF: lookup.IIF, Reply: lookup.Reply}
	}
	batch, err := kernel.RouteGetBatch(reads)
	if err != nil {
		return nil, err
	}
	answers := make([]kernelexit.Answer, len(batch))
	for i, answer := range batch {
		answers[i] = kernelexit.Answer{
			Route:    lookupRoute(answer.Route),
			Err:      answer.Err,
			ReplyIIF: answer.ReplyIIF,
			Reply:    lookupRoute(answer.Reply),
			ReplyErr: answer.ReplyErr,
		}
	}
	return answers, nil
}

func lookupRoute(route kernel.MatchedRoute) kernelexit.Route {
	hops := make([]kernelexit.Hop, len(route.NextHops))
	for i, hop := range route.NextHops {
		hops[i] = kernelexit.Hop{Device: hop.Device, Dead: hop.Dead, LinkDown: hop.LinkDown}
	}
	return kernelexit.Route{Type: route.Type, Hops: hops}
}

// EgressMembers is the prefixes the egress translator's lookups read from, out
// of the mesh's table and the overlay in force at each call
func (c *Client) EgressMembers() []netip.Prefix {
	return memberPrefixes(c.Mesh.Routes.Snapshot(), c.config().Overlay())
}

// memberPrefixes is each destination routes sends by the tun to another node:
// one with no source prefix and a peer that is neither this node nor a hold,
// inside an entry of overlay and overlapping none of this node's own entries.
// An own entry counting as a default under the overlay is left out of that
// test, since an exit originates one for what it carries out of the mesh and
// holds no address in it by that
func memberPrefixes(routes []sadr.Route[*netstack.Peer], overlay []schema.Prefix) []netip.Prefix {
	var own []netip.Prefix
	for _, route := range routes {
		if (route.Value == netstack.Local || route.Value == netstack.Assigned) && !schema.CapturesTheMachine(route.Destination, overlay) {
			own = append(own, route.Destination)
		}
	}
	var members []netip.Prefix
	for _, route := range routes {
		peer := route.Value
		if route.Source.IsValid() || peer == nil || peer == netstack.Local || peer == netstack.Assigned || peer == netstack.Unreachable {
			continue
		}
		inside := slices.ContainsFunc(overlay, func(entry schema.Prefix) bool {
			return entry.Bits() <= route.Destination.Bits() && entry.Contains(route.Destination.Addr())
		})
		if inside && !slices.ContainsFunc(own, route.Destination.Overlaps) {
			members = append(members, route.Destination)
		}
	}
	return members
}
