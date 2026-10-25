// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"errors"
	"slices"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
)

// SetReconcilerRules hands the debug view the rules the route reconciler derived, as SetKernelStatus hands it the reconciler's status
func (c *Client) SetReconcilerRules(read func() []kernel.DumpedRule) {
	c.reconcilerRules.Store(&read)
}

// DebugRules reads every policy rule the kernel holds and the border filter's
// chain, each through a socket of its own, so neither the reconciler's nor the
// filter's run goroutine shares one with a reader
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
	proto := uint8(kernel.DefaultProtocol)
	if table := c.config().Cap.Table; table != nil {
		proto = table.Normalized().Proto
	}
	var wanted []kernel.DumpedRule
	if read := c.reconcilerRules.Load(); read != nil {
		wanted = (*read)()
	}
	for _, rule := range held {
		policy := policyRule(rule)
		policy.Owned = rule.Protocol == proto
		policy.Wanted = policy.Owned && slices.Contains(wanted, rule)
		info.Policy = append(info.Policy, policy)
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

func policyRule(rule kernel.DumpedRule) control.PolicyRule {
	policy := control.PolicyRule{
		Family: string(rule.Family), Priority: rule.Priority,
		To: rule.To, From: rule.From, IIF: rule.IIF, OIF: rule.OIF,
		FWMark: rule.FWMark, FWMask: rule.FWMask, L3mdev: rule.L3mdev, Invert: rule.Invert,
		Action: rule.Action, Table: rule.Table, Goto: rule.Goto, Protocol: rule.Protocol,
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
