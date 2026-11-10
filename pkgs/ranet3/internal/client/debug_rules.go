// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"cmp"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/transport"
)

// lookups reads the lookups the reconciler's last pass whose batch answered
// asked, for the status, the debug view and the metrics, and none on a node
// with no cap.table
func (c *Client) lookups() []kernel.Lookup {
	if read := c.reconcilerNow().Lookups; read != nil {
		return read()
	}
	return nil
}

// DebugRules reads every policy rule the kernel holds and the antispoof
// filter's chains, each through a socket of its own, so neither the reconciler's nor the
// filter's run goroutine shares one with a reader. Where the transport names
// each underlay datagram's interface, on darwin, it lists beside them the
// interface each live session's datagrams name, or the interface of the pin
// they carry
func (c *Client) DebugRules() control.RulesInfo {
	dump := c.ruleDump
	if dump == nil {
		dump = kernel.DumpRules
	}
	info := control.RulesInfo{Policy: []control.PolicyRule{}, Missing: []control.PolicyRule{}}
	held, err := dump()
	switch {
	case errors.Is(err, kernel.ErrUnsupported):
		info.PolicyErr = "this platform has no policy rules"
	case err != nil:
		info.PolicyErr = err.Error()
	}
	proto, wanted := c.ruleOwners()
	for _, rule := range held {
		info.Policy = append(info.Policy, policyRuleOf(rule, proto, wanted))
	}
	for _, lookup := range c.lookups() {
		kind := "overlay"
		if lookup.Underlay() {
			kind = "underlay"
		}
		info.Lookups = append(info.Lookups, control.RuleLookup{
			Lookup: kind, Family: string(lookup.Family), Prefix: lookup.Prefix, Address: lookup.Address,
			Source: lookup.Source, Interface: lookup.Interface, Answer: lookup.Answer, Taken: lookup.Taken,
		})
	}
	if c.underlayRoutes != nil {
		info.Lookups = append(info.Lookups, underlayLookups(c.underlayRoutes, c.underlayPaths())...)
	}
	if info.PolicyErr == "" {
		for _, rule := range wanted {
			if !slices.Contains(held, rule) {
				missing := policyRule(rule)
				missing.Owned, missing.Wanted = true, true
				info.Missing = append(info.Missing, missing)
			}
		}
	}
	status := c.kernel()
	info.Steered = steeredDefaults(status)
	if f := c.border.Load(); f != nil {
		info.Border = borderTable((*f).Debug())
	} else if on := c.unenforcedOn(); on != "" {
		info.Border = &control.BorderTable{UnenforcedOn: on}
	}
	if exit := status.Exit; exit != nil && exit.Fallback != nil {
		info.Fallback = c.fallbackTable(*exit.Fallback)
	}
	return info
}

// underlayRoutes is the selection the transport names each underlay datagram's interface from, as the rules view reads it
type underlayRoutes interface {
	// Route is the route a datagram to addr is selected by and the name of its interface, false where no route holds it
	Route(addr netip.Addr) (netip.Prefix, string, bool)
}

// underlayPath is where one live session's datagrams go: the address the selection answers for and the interface of the pin they carry,
// by name or index, empty where the selection names it
type underlayPath struct {
	address netip.Addr
	pin     string
}

// underlayPaths is where the hub sends the datagrams of each live session, as its mux answers it
func (c *Client) underlayPaths() []underlayPath {
	var paths []underlayPath
	for _, session := range c.sessions.snapshot() {
		if send := session.session.Mux().Sends(); send.Destination.IsValid() {
			paths = append(paths, underlayPathOf(send, interfaceName))
		}
	}
	return paths
}

// underlayPathOf is the path of send, a link-local destination zoned by the interface it leaves by, with name naming an interface by its index
func underlayPathOf(send transport.Send, name func(int) string) underlayPath {
	path := underlayPath{address: send.Destination}
	if path.address.Is6() && path.address.IsLinkLocalUnicast() && send.Interface != 0 {
		path.address = path.address.WithZone(name(send.Interface))
	}
	if send.PinInterface != 0 {
		path.pin = name(send.PinInterface)
	}
	return path
}

// interfaceName is the name of interface index, or its index where the host names none
func interfaceName(index int) string {
	if link, err := net.InterfaceByIndex(index); err == nil {
		return link.Name
	}
	return strconv.Itoa(index)
}

// underlayLookups is one underlay row per distinct path in address order: the interface of its pin, by name or index,
// or else the route routes selects its address by and that route's interface,
// or no route where none holds the address or where it is a link-local address that names no interface
// never taken, since neither is ranet3's interface
func underlayLookups(routes underlayRoutes, paths []underlayPath) []control.RuleLookup {
	paths = slices.Clone(paths)
	slices.SortFunc(paths, func(a, b underlayPath) int {
		return cmp.Or(a.address.Compare(b.address), cmp.Compare(a.pin, b.pin))
	})
	paths = slices.Compact(paths)
	rows := make([]control.RuleLookup, 0, len(paths))
	for _, path := range paths {
		family := kernel.FamilyIPv4
		if !path.address.Unmap().Is4() {
			family = kernel.FamilyIPv6
		}
		row := control.RuleLookup{Lookup: "underlay", Family: string(family), Address: path.address, Answer: "no route"}
		switch {
		case path.pin != "":
			row.Answer = "dev " + path.pin
		case path.address.Is6() && path.address.IsLinkLocalUnicast() && path.address.Zone() == "":
			// an unzoned link-local address names no interface, so no route is asked
		default:
			if prefix, device, ok := routes.Route(path.address); ok {
				row.Prefix, row.Answer = prefix, "dev "+device
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// fallbackTable is the kill switch as a read apart from the reconciler's
// finds it, beside the state the reconciler's last pass gave it
func (c *Client) fallbackTable(state control.KernelFallback) *control.FallbackTable {
	read := c.fallbackRead
	if read == nil {
		read = kernel.ReadFallback
	}
	debug, err := read()
	table := &control.FallbackTable{
		Where: debug.Where, Hook: debug.Hook, Priority: debug.Priority, State: state.State, Reason: state.Reason, Held: debug.Held,
		Rules: []control.FallbackTableRule{}, Sets: []control.FallbackTableSet{},
	}
	if err != nil {
		table.Err = err.Error()
	}
	for _, rule := range debug.Rules {
		table.Rules = append(table.Rules, control.FallbackTableRule{Chain: rule.Chain, Spec: rule.Spec, Packets: rule.Packets, Bytes: rule.Bytes})
	}
	for _, set := range debug.Sets {
		table.Sets = append(table.Sets, control.FallbackTableSet{Name: set.Name, Elements: set.Elements})
	}
	return table
}

// steeredDefaults is mode 3's two defaults as the reconciler's last pass left them, nil outside mode 3
func steeredDefaults(status control.KernelStatus) *control.SteeredDefaults {
	path := status.ExitPath
	if path == nil {
		return nil
	}
	out := &control.SteeredDefaults{Table: status.Table, State: path.State, Down: path.Down, Verdict: path.Verdict}
	for _, route := range []control.SteeredDefault{{Family: "ipv4", To: netip.MustParsePrefix("0.0.0.0/0")}, {Family: "ipv6", To: netip.MustParsePrefix("::/0")}} {
		route.Installed = slices.Contains(path.Installed, route.Family)
		out.Routes = append(out.Routes, route)
	}
	return out
}

func policyRule(rule kernel.DumpedRule) control.PolicyRule {
	policy := control.PolicyRule{
		Family: string(rule.Family), Priority: rule.Priority,
		To: rule.To, From: rule.From, IIF: rule.IIF, OIF: rule.OIF,
		FWMark: rule.FWMark, FWMask: rule.FWMask, L3mdev: rule.L3mdev, Invert: rule.Invert,
		Action: rule.Action, Table: rule.Table, Goto: rule.Goto, Protocol: rule.Protocol,
		Unread: rule.Unread.Names(),
	}
	if bits, ok := rule.Suppress.Bits(); ok {
		policy.Suppress = &bits
	}
	return policy
}

// borderTable is the antispoof filter's chains and sets as the wire carries them
func borderTable(debug egress.BorderDebug) *control.BorderTable {
	table := &control.BorderTable{
		Where: debug.Where, Ready: debug.Ready, Unready: debug.Unready, Err: debug.Err,
		PF:     borderPF(debug.PF),
		Chains: make([]control.BorderChain, 0, len(debug.Chains)),
		Sets:   make([]control.BorderSet, 0, len(debug.Sets)),
	}
	if debug.PF != nil {
		for _, enabler := range debug.PF.Enablers {
			table.Enablers = append(table.Enablers, control.BorderEnabler{PID: enabler.PID, Name: enabler.Name})
		}
	}
	if !debug.PassAt.IsZero() {
		table.ReadAt, table.ReadAgo = debug.PassAt.UTC(), control.Duration(time.Since(debug.PassAt))
	}
	for _, reading := range debug.Chains {
		chain := control.BorderChain{Name: reading.Name, Hook: reading.Hook, Priority: reading.Priority, Rules: make([]control.BorderChainRule, 0, len(reading.Rules))}
		for _, rule := range reading.Rules {
			chain.Rules = append(chain.Rules, control.BorderChainRule{
				Spec: rule.Spec, Verdict: rule.Verdict, Reason: rule.Reason, Family: rule.Family,
				Held: rule.Held, Packets: rule.Packets, Bytes: rule.Bytes,
			})
		}
		table.Chains = append(table.Chains, chain)
	}
	for _, set := range debug.Sets {
		elements := make([]string, 0, len(set.Elements))
		for _, r := range set.Elements {
			elements = append(elements, r.String())
		}
		table.Sets = append(table.Sets, control.BorderSet{Kind: set.Kind, Name: set.Name, Elements: elements})
	}
	return table
}
