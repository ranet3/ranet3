// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"errors"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
)

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
	proto, wanted := uint8(kernel.DefaultProtocol), []kernel.Rule(nil)
	if table := c.config().Cap.Table; table != nil {
		normalized := table.Normalized()
		proto, wanted = normalized.Proto, normalized.Rules
	}
	for _, rule := range held {
		policy := policyRule(rule)
		policy.Owned = rule.Protocol == proto
		policy.Wanted = policy.Owned && wantsRule(wanted, rule)
		info.Policy = append(info.Policy, policy)
	}
	if info.PolicyErr == "" {
		for _, rule := range wanted {
			if !holdsRule(held, rule, proto) {
				info.Missing = append(info.Missing, wantedRule(rule, proto))
			}
		}
	}
	if f := c.border.Load(); f != nil {
		info.Border = borderChain((*f).Debug())
	}
	return info
}

func policyRule(rule kernel.DumpedRule) control.PolicyRule {
	return control.PolicyRule{
		Family: string(rule.Family), Priority: rule.Priority,
		To: rule.To, From: rule.From, IIF: rule.IIF, OIF: rule.OIF,
		FWMark: rule.FWMark, FWMask: rule.FWMask, L3mdev: rule.L3mdev, Invert: rule.Invert,
		Action: rule.Action, Table: rule.Table, Protocol: rule.Protocol,
	}
}

func wantedRule(rule kernel.Rule, proto uint8) control.PolicyRule {
	return control.PolicyRule{
		Family: string(rule.Family), Priority: rule.Priority,
		To: rule.To.Prefix, From: rule.From.Prefix, IIF: rule.IIF,
		FWMark: rule.FWMark, FWMask: rule.FWMask,
		Action: "lookup", Table: uint32(rule.Table), Protocol: proto, Owned: true, Wanted: true,
	}
}

// heldAs reports a dumped rule holding what a rule cap.table asks for does,
// with a mask of all ones read as the absent mask the kernel stores it as
func heldAs(held kernel.DumpedRule, rule kernel.Rule) bool {
	mask := held.FWMask
	if mask == ^uint32(0) {
		mask = 0
	}
	want := rule.FWMask
	if want == ^uint32(0) {
		want = 0
	}
	return held.Family == rule.Family && held.Priority == rule.Priority &&
		held.To == rule.To.Prefix && held.From == rule.From.Prefix &&
		held.IIF == rule.IIF && held.OIF == "" && !held.L3mdev && !held.Invert &&
		held.FWMark == rule.FWMark && mask == want &&
		held.Action == "lookup" && held.Table == uint32(rule.Table)
}

func wantsRule(wanted []kernel.Rule, held kernel.DumpedRule) bool {
	for _, rule := range wanted {
		if heldAs(held, rule) {
			return true
		}
	}
	return false
}

func holdsRule(held []kernel.DumpedRule, rule kernel.Rule, proto uint8) bool {
	for _, dumped := range held {
		if dumped.Protocol == proto && heldAs(dumped, rule) {
			return true
		}
	}
	return false
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
