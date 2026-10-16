// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// Every rule a capability installs reads back from its own message as itself,
// whichever selectors it carries. One that did not would be deleted and
// installed again on every pass, with a window each time in which the traffic
// it steers follows another table.
func TestEveryInstalledRuleReadsBackFromItsOwnMessage(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		table := Table{Rules: []Rule{hegel.Draw(ht, writtenRules())}}
		ht.Assume(table.Validate() == nil)
		plat, conn := writePlatform(t)
		for _, rule := range table.Normalized().Rules {
			conn.replies = []nlMessage{{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(rule)}}
			got, err := plat.Rules()
			if err != nil {
				ht.Fatal(err)
			}
			if len(got) != 1 || got[0] != rule {
				ht.Fatalf("%s read back from its own message as %v", rule, got)
			}
		}
	})
}
