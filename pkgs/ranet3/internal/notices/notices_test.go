// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package notices

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The notice is generated, so the thing worth holding is not its text but that
// nobody added a dependency and shipped without regenerating it. A direct
// requirement gets added by hand, so every one of them has to be
// named here, and nothing may be named that go.mod no longer requires at all.
//
// The check reads go.mod rather than asking the toolchain because a nix build
// has neither a module cache nor an in-tree vendor directory, so `go list` and
// go version -m both come back empty there and a check that used them would
// pass by finding nothing.
func TestEveryDirectRequirementIsNoticed(t *testing.T) {
	body, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	direct, all := requirements(string(body))
	if len(direct) == 0 {
		t.Fatal("go.mod names no direct requirement, which cannot be right")
	}
	// a heading inside a license text is no section, though a substring search
	// would take it for one
	noticed := sections(ThirdParty)
	for _, module := range direct {
		if !slices.Contains(noticed, module) {
			t.Errorf("%s is a direct requirement with no license section: run the formatter", module)
		}
	}
	self := modulePath(string(body))
	for _, module := range noticed {
		if module == self {
			continue
		}
		if !all[module] {
			t.Errorf("%s has a license section and go.mod does not require it: run the formatter", module)
		}
	}
}

// Every section carries its license text between one pair of code fences, so
// an entry reduced to a heading says a module was noticed when nothing about
// it was reproduced. A license text with a bare fence line of its own would put
// parse out of step and hide every heading after it, which shows up here as a
// section holding more than its own two fence lines.
func TestEverySectionCarriesItsLicense(t *testing.T) {
	for _, s := range parse(ThirdParty) {
		fences := fenceLines(s.body)
		if fences != 2 || len(s.body) < 200 {
			t.Errorf("%s carries %d bytes and %d fence lines, want 2 around one license block", s.module, len(s.body), fences)
		}
	}
}

// The module's own license is the first section, because the MIT notice of
// the code it carries from Nick Cao's ranet-lite has to travel with every
// binary.
func TestOwnLicenseComesFirst(t *testing.T) {
	notice := parse(ThirdParty)
	if len(notice) == 0 || notice[0].module != "ranet3.com/pkgs/ranet3" {
		t.Fatal("the first section is not this module's own license")
	}
	// reuse would count the holder named below among this file's own
	// REUSE-IgnoreStart
	wants := []string{"Functional Source License", "Copyright (c) 2026 Nick Cao"}
	// REUSE-IgnoreEnd
	for _, want := range wants {
		if !strings.Contains(notice[0].body, want) {
			t.Errorf("this module's section does not carry %q", want)
		}
	}
}

// The module's own section is license.txt as it stands. The generator reads
// that file, and a change to it that the formatter has not carried into the
// notice would leave a binary printing the old text.
func TestOwnLicenseMatchesItsFile(t *testing.T) {
	own, err := os.ReadFile("../../license.txt")
	if err != nil {
		t.Fatal(err)
	}
	notice := parse(ThirdParty)
	if len(notice) == 0 {
		t.Fatal("the notice has no section")
	}
	// the generator trims trailing newlines, which the comparison has to match
	if fencedText(notice[0].body) != strings.TrimRight(string(own), "\n") {
		t.Error("the first section is not license.txt as it stands: run the formatter")
	}
}

var (
	requireLine = regexp.MustCompile(`^\s*([^\s/][^\s]*\.[^\s]*/[^\s]+)\s+v\S+(\s*//\s*indirect)?\s*$`)
	sectionLine = regexp.MustCompile(`^## (\S+)$`)
)

// requirements splits go.mod's require blocks into the modules written by
// hand and every module named at all.
func requirements(body string) (direct []string, all map[string]bool) {
	all = map[string]bool{}
	for line := range strings.SplitSeq(body, "\n") {
		match := requireLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		all[match[1]] = true
		if match[2] == "" {
			direct = append(direct, match[1])
		}
	}
	return direct, all
}

// modulePath is the module go.mod declares, whose own license opens the
// notice rather than being a requirement of it.
func modulePath(body string) string {
	for line := range strings.SplitSeq(body, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// section is one module's heading and the text under it, up to the next heading.
type section struct{ module, body string }

// fence opens and closes the block that holds a license text.
const fence = "```"

// parse splits the notice into its sections. A line inside a code fence never
// opens one, because a license text is embedded as it is and the Functional
// Source License holds lines that read as headings. A bare fence line inside a
// license text flips the state out of step, which
// TestEverySectionCarriesItsLicense reports rather than letting every later
// heading go unseen.
func parse(text string) []section {
	var out []section
	fenced := false
	for line := range strings.SplitSeq(text, "\n") {
		if line == fence {
			fenced = !fenced
		}
		if match := sectionLine.FindStringSubmatch(line); match != nil && !fenced {
			out = append(out, section{module: match[1]})
		} else if len(out) > 0 {
			out[len(out)-1].body += line + "\n"
		}
	}
	return out
}

// fenceLines counts the bare fence lines in text.
func fenceLines(text string) int {
	n := 0
	for line := range strings.SplitSeq(text, "\n") {
		if line == fence {
			n++
		}
	}
	return n
}

// fencedText is the text between a section's opening fence and its closing one.
func fencedText(body string) string {
	var out []string
	inside := false
	for line := range strings.SplitSeq(body, "\n") {
		if line == fence {
			if inside {
				break
			}
			inside = true
			continue
		}
		if inside {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func sections(text string) []string {
	var out []string
	for _, s := range parse(text) {
		out = append(out, s.module)
	}
	return out
}
