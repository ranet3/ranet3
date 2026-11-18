// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/pf"
)

// earlierPFTables is the names an earlier filter gave its anchor's tables,
// written apart from the filter's own
var earlierPFTables = []string{"ranet3_overlay", "ranet3_carved"}

// The first pass of a start over the anchor an earlier filter left, its rules
// reading its tables under the names it gave them, one of the tables persist,
// which pf keeps once no rule reads it, ends with the anchor holding what a
// start over an empty anchor writes, no earlier table among them, and the
// filter ready
func TestPfBorderRetiresTheEarlierTables(t *testing.T) {
	ctl := requirePF(t)
	mesh := newPFUTUN(t)
	mesh.owned(t)
	fresh := startPF(t, mesh.name, t.TempDir())
	read, err := ctl.Read(pfAnchor)
	if err != nil {
		t.Fatal(err)
	}
	want := read.Ruleset()
	if err := fresh.stop(nil); err != nil {
		t.Fatal(err)
	}
	pfLoad(t, pfAnchor, "table <"+earlierPFTables[0]+"> const { 192.0.2.0/24, 3fff:10::/32 }\n"+
		"table <"+earlierPFTables[1]+"> persist const { 198.51.100.0/24 }\n"+
		"pass in quick on lo0 from <"+earlierPFTables[0]+"> to any no state label \"accept via lo0\"\n"+
		"block drop in quick on ! "+mesh.name+" inet from <"+earlierPFTables[1]+"> to any label \"drop ipv4 source @carved4\"\n")
	earlier, err := ctl.Read(pfAnchor)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range earlierPFTables {
		if !slices.ContainsFunc(earlier.Tables, func(table pf.Table) bool { return table.Name == name }) {
			t.Fatalf("the earlier anchor holds the tables %+v, want <%s> among them", earlier.Tables, name)
		}
	}
	run := startPF(t, mesh.name, t.TempDir())
	if read, err = ctl.Read(pfAnchor); err != nil {
		t.Fatal(err)
	}
	for _, table := range read.Tables {
		if slices.Contains(earlierPFTables, table.Name) {
			t.Errorf("after the first pass over the earlier anchor it holds the table <%s>", table.Name)
		}
	}
	if !read.Ruleset().Equal(want) {
		t.Errorf("after the first pass over the earlier anchor it holds %+v, where a start over an empty anchor wrote %+v", read.Ruleset(), want)
	}
	if stats := run.filter.Stats(); !stats.Ready {
		t.Errorf("after the first pass over the earlier anchor the filter reads not ready: %s", stats.Unready)
	}
}
