// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package pf

import (
	"math"
	"regexp"
	"slices"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// child is one anchor below com.apple, the only place this tree writes rules
var child = regexp.MustCompile(`^com\.apple/[A-Za-z0-9._-]{1,63}$`)

// every pfctl command the package issues, over any run of loads, table loads,
// withdrawals, releases and reads of anchors good and bad, the main ruleset's
// call and an interface's skip among the reads, over an anchor listing tables
// a load defines and tables it does not, names holding a tab or a newline
// among them: each -f, -F and table command but
// show carries -a with one child of com.apple, -F flushes only an anchor's
// filter, translation or dummynet rules or its tables, never all, no command
// stops or starts pf, and a write to any other anchor is refused before it
// reaches pfctl
func TestEveryWriteStaysInsideOneChildOfComApple(t *testing.T) {
	anchors := []string{
		"com.apple/ranet3", "com.apple/ranet3-exit", "com.apple/a.b_c", "com.apple/" + strings.Repeat("r", 63),
		"com.apple/" + strings.Repeat("r", 64), "com.apple", "com.apple/", "com.apple/*", "com.apple/ranet3/inner",
		"ranet3", "", "/", "other/ranet3", "com.apple/ranet3 -F all",
	}
	listings := [][]Table{nil, {{Name: "ranet3_overlay", Const: true}}, {{Name: "stray"}, {Name: "x\ty"}, {Name: "x\ny"}, {Name: "ranet3_carved", Const: true}}}
	pbt.Check(t, func(ht *hegel.T) {
		var calls [][]string
		held := hegel.Draw(ht, hegel.SampledFrom(listings))
		c := Ctl{run: func(stdin string, args ...string) (string, error) {
			calls = append(calls, args)
			if slices.Contains(args, "Tables") && slices.Contains(args, "-s") {
				return tableListing(args[1], held...), nil
			}
			return "", nil
		}}
		for range hegel.Draw(ht, pbt.Spanning(1, 8)) {
			anchor := hegel.Draw(ht, hegel.SampledFrom(anchors))
			before := len(calls)
			var err error
			write := false
			switch hegel.Draw(ht, hegel.Integers(0, 7)) {
			case 0:
				write, err = true, c.Load(anchor, hegel.Draw(ht, hegel.Composite(drawRuleset)))
			case 1:
				write, err = true, c.Withdraw(anchor)
			case 2:
				err = c.Release(hegel.Draw(ht, pbt.Spanning[uint64](1, math.MaxUint64)))
			case 3:
				_, err = c.Read(anchor)
			case 4:
				_, err = c.Calls()
			case 5:
				_, err = c.References()
			case 6:
				write, err = true, c.LoadTables(anchor, hegel.Draw(ht, hegel.Composite(drawRuleset)).Tables)
			case 7:
				_, err = c.Skipped()
			}
			if write && !child.MatchString(anchor) && (err == nil || len(calls) != before) {
				ht.Fatalf("a write to %q ran %v and returned %v", anchor, calls[before:], err)
			}
		}
		for _, args := range calls {
			for i, a := range args {
				switch a {
				case "-d", "-e", "-E":
					ht.Fatalf("%v stops or starts pf", args)
				case "-F":
					if i+1 == len(args) || !slices.Contains([]string{"rules", "nat", "dummynet", "Tables"}, args[i+1]) {
						ht.Fatalf("%v flushes more than an anchor's rules or tables", args)
					}
				}
			}
			table := slices.Index(args, "-T")
			if !slices.Contains(args, "-f") && !slices.Contains(args, "-F") && (table < 0 || table+1 < len(args) && args[table+1] == "show") {
				continue
			}
			at := slices.Index(args, "-a")
			if at < 0 || at+1 == len(args) || !child.MatchString(args[at+1]) {
				ht.Fatalf("%v writes outside one child of com.apple", args)
			}
		}
	})
}
