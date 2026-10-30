// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"cmp"
	"errors"
	"net/netip"
	"slices"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/transport"
)

// SetReconcilerRules hands the debug view the rules the route reconciler derived, as SetKernelStatus hands it the reconciler's status
func (c *Client) SetReconcilerRules(read func() []kernel.DumpedRule) {
	c.reconcilerRules.Store(&read)
}

// SetReconcilerLookups hands the status, the debug view and the metrics the
// lookups the route reconciler's last pass whose batch answered asked, as
// SetReconcilerRules hands its rules
func (c *Client) SetReconcilerLookups(read func() []kernel.Lookup) {
	c.reconcilerLookups.Store(&read)
}

// lookups reads the lookups through the reader SetReconcilerLookups took, and
// none on a node with no cap.table
func (c *Client) lookups() []kernel.Lookup {
	if read := c.reconcilerLookups.Load(); read != nil {
		return (*read)()
	}
	return nil
}

// DebugRules reads every policy rule the kernel holds and the border filter's
// chain, each through a socket of its own, so neither the reconciler's nor the
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
			Lookup: kind, Family: string(lookup.Family), Prefix: lookup.Prefix, Address: lookup.Address, Answer: lookup.Answer, Taken: lookup.Taken,
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
	if f := c.border.Load(); f != nil {
		info.Border = borderChain((*f).Debug())
	}
	return info
}

// underlayRoutes is the selection the transport names each underlay datagram's interface from, as the rules view reads it
type underlayRoutes interface {
	// Route is the route a datagram to addr is selected by and the name of its interface, false where no route holds it
	Route(addr netip.Addr) (netip.Prefix, string, bool)
}

// underlayPaths is where the hub sends the datagrams of each live session, its endpoint's zone and pin kept
func (c *Client) underlayPaths() []transport.UnderlayPath {
	var paths []transport.UnderlayPath
	for _, session := range c.sessions.snapshot() {
		if endpoint := session.session.Mux().Endpoint(); endpoint != nil {
			if path, ok := c.hub.SendsBy(endpoint); ok {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

// underlayLookups is one underlay row per distinct path in address order: the interface of its pin, by name or index,
// or else the route routes selects its address by and that route's interface, or no route
// never taken, since neither is ranet3's interface
func underlayLookups(routes underlayRoutes, paths []transport.UnderlayPath) []control.RuleLookup {
	paths = slices.Clone(paths)
	slices.SortFunc(paths, func(a, b transport.UnderlayPath) int {
		return cmp.Or(a.Address.Compare(b.Address), cmp.Compare(a.Pin, b.Pin))
	})
	paths = slices.Compact(paths)
	rows := make([]control.RuleLookup, 0, len(paths))
	for _, path := range paths {
		family := kernel.FamilyIPv4
		if !path.Address.Unmap().Is4() {
			family = kernel.FamilyIPv6
		}
		row := control.RuleLookup{Lookup: "underlay", Family: string(family), Address: path.Address, Answer: "no route"}
		if path.Pin != "" {
			row.Answer = "dev " + path.Pin
		} else if prefix, device, ok := routes.Route(path.Address); ok {
			row.Prefix, row.Answer = prefix, "dev "+device
		}
		rows = append(rows, row)
	}
	return rows
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

// borderChain is the border filter's chain as the wire carries it
func borderChain(debug egress.BorderDebug) *control.BorderChain {
	chain := &control.BorderChain{
		Where: debug.Where, Hook: debug.Hook, Priority: debug.Priority,
		Ready: debug.Ready, Unready: debug.Unready, Err: debug.Err,
		Rules: make([]control.BorderChainRule, 0, len(debug.Rules)),
	}
	if !debug.PassAt.IsZero() {
		chain.ReadAt, chain.ReadAgo = debug.PassAt.UTC(), control.Duration(time.Since(debug.PassAt))
	}
	for _, rule := range debug.Rules {
		chain.Rules = append(chain.Rules, control.BorderChainRule{
			Spec: rule.Spec, Verdict: rule.Verdict, Reason: rule.Reason, Family: rule.Family,
			Held: rule.Held, Packets: rule.Packets, Bytes: rule.Bytes,
		})
	}
	return chain
}
