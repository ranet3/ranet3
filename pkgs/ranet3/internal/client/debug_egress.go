// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/egress"
)

// exitDebugger is an exit whose backend holds rules in the host's packet
// filter, which it reads now for a debug read
type exitDebugger interface {
	Debug() egress.ExitDebug
}

// DebugEgress is the exit as a debug read finds it: its status, and where its
// backend holds rules, each rule with its counter read now and each family's
// readiness as the last pass judged it
func (c *Client) DebugEgress() control.EgressInfo {
	exit := c.exit.Load()
	if exit == nil {
		return control.EgressInfo{}
	}
	detailed, ok := (*exit).(exitDebugger)
	if !ok {
		return control.EgressInfo{Enabled: true, Status: egressStatus((*exit).Status())}
	}
	debug := detailed.Debug()
	info := control.EgressInfo{Enabled: true, Status: egressStatus(debug.Status), ReadErr: debug.ReadErr}
	for _, rule := range debug.Rules {
		info.Rules = append(info.Rules, control.EgressRule{Spec: rule.Spec, Wanted: rule.Wanted, Held: rule.Held, Counter: rule.Counter, Packets: rule.Packets, Bytes: rule.Bytes})
	}
	for _, family := range debug.Families {
		reading := control.EgressFamily{Family: egress.FamilyName(family.Family), Ready: family.Ready, Why: family.Why, Unwritten: family.Unwritten, Forwarding: family.Forwarding}
		for i, lookup := range family.Lookups {
			looked := control.EgressLookup{Source: lookup.Source, Destination: lookup.Destination, IIF: lookup.IIF, Reply: lookup.Reply, Answered: i < len(family.Answers)}
			if looked.Answered {
				answer := family.Answers[i]
				looked.Route, looked.Err = egressRoute(answer.Route, answer.Err)
				if lookup.Reply {
					looked.ReplyIIF = answer.ReplyIIF
					looked.ReplyRoute, looked.ReplyErr = egressRoute(answer.Reply, answer.ReplyErr)
				}
			}
			reading.Lookups = append(reading.Lookups, looked)
		}
		info.Families = append(info.Families, reading)
	}
	for _, setting := range debug.RPFilter {
		wire := control.RouteSetting{Name: setting.Name, Value: setting.Value}
		if setting.Value == "" {
			wire.Err = "unreadable"
		}
		info.RPFilter = append(info.RPFilter, wire)
	}
	return info
}

// egressRoute is a lookup's answer on the wire, the route absent where the
// lookup failed
func egressRoute(route egress.Route, err error) (*control.EgressRoute, string) {
	if err != nil {
		return nil, err.Error()
	}
	out := &control.EgressRoute{Type: route.Type}
	for _, hop := range route.Hops {
		out.NextHops = append(out.NextHops, control.RouteNextHop{Dev: hop.Device, Dead: hop.Dead, LinkDown: hop.LinkDown})
	}
	return out, ""
}
