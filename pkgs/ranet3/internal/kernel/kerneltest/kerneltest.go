// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package kerneltest holds the down set a stop of the kernel reconciler leaves,
// for the tests of other packages to compare a dump of the rules with. It
// restates routing.md's "The overlay while a node is down" rather than taking
// the rules from the reconciler. Only tests import it.
package kerneltest

import (
	"slices"

	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/schema"
)

// DownSet is the down set of overlay as the kernel dumps it under
// kernel.DefaultProtocol: for each prefix of length n, 32765 refusing it and
// 32764 looking main up to it for a route of length n or longer
func DownSet(overlay []schema.Prefix) []kernel.DumpedRule {
	var out []kernel.DumpedRule
	for _, prefix := range overlay {
		family := kernel.FamilyIPv4
		if prefix.Addr().Is6() {
			family = kernel.FamilyIPv6
		}
		out = append(out,
			kernel.DumpedRule{Family: family, Priority: 32765, To: prefix.Prefix, Action: "unreachable", Protocol: kernel.DefaultProtocol},
			kernel.DumpedRule{Family: family, Priority: 32764, To: prefix.Prefix, Action: "lookup", Table: uint32(schema.TableMain),
				Suppress: kernel.SuppressUpTo(prefix.Bits() - 1), Protocol: kernel.DefaultProtocol},
		)
	}
	return out
}

// NotDownSet compares the rules of kernel.DefaultProtocol in dumped with the
// down set of overlay: extra is each such rule outside the set and each second
// copy of a rule of it, and missing each rule of the set dumped lacks, both
// empty where a stop left exactly the down set
func NotDownSet(dumped []kernel.DumpedRule, overlay []schema.Prefix) (extra, missing []kernel.DumpedRule) {
	down := DownSet(overlay)
	seen := map[kernel.DumpedRule]bool{}
	for _, rule := range dumped {
		if rule.Protocol == kernel.DefaultProtocol && (!slices.Contains(down, rule) || seen[rule]) {
			extra = append(extra, rule)
		}
		seen[rule] = true
	}
	for _, rule := range down {
		if !slices.Contains(dumped, rule) {
			missing = append(missing, rule)
		}
	}
	return extra, missing
}
