// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package notices

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// testOnly is the direct requirements that no binary links. The notice lists
// what the built binary contains, so a section for one of these would
// reproduce a license for code that nobody is given. A module belongs here
// while no package a binary links imports it. The property engine is one:
// internal/pbt imports it and only test files import internal/pbt.
var testOnly = []string{
	"hegel.dev/go/hegel",
}

// The notice is generated, so the thing worth holding is not its text but that
// nobody added a dependency and shipped without regenerating it. A direct
// requirement gets added by hand, so every one of them has to be
// named here, except the ones only tests use, and nothing may be named that
// go.mod no longer requires at all.
//
// The check reads go.mod rather than asking the toolchain. A nix build has no
// module cache and builds from the vendor directory it links into the module
// root, where `go list -m all` refuses to compute the module graph and go
// version -m names no dependency of the binary it built. A check that asked
// either would fail there or pass by finding nothing.
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
		if slices.Contains(testOnly, module) {
			continue
		}
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

// The exemption above rests on a fact that neither go.mod nor the notice can
// show, which is that no package a binary links imports a module it names. A
// daemon package that began to import one would link that module into every
// release with no section in the notice, while the test above went on skipping
// it. So the source is read for the imports. The files are found by walking the
// tree and their headers parsed, for the reason the test above gives for not
// asking the toolchain.
//
// The walk covers what the go tool counts as this module's packages. A nix
// build puts a vendor directory in the module root with the source of every
// module the build uses, hegel among them, and none of that is this module's
// code.
func TestOnlyTestsImportTestOnlyModules(t *testing.T) {
	body, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	// internal/pbt may import the engine, and only test files may import
	// internal/pbt
	pbtPath := modulePath(string(body)) + "/internal/pbt"
	root := os.DirFS("../..")
	looked := 0
	err = fs.WalkDir(root, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name != "." && outsideModule(root, name) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		imports, err := importsOf(root, name)
		if err != nil {
			return err
		}
		looked++
		for _, imported := range imports {
			if within(imported, pbtPath) {
				t.Errorf("%s imports %s, which only test files may import: it would link the property engine into a binary with no notice for it", name, imported)
			}
			if strings.HasPrefix(name, "internal/pbt/") {
				continue
			}
			for _, module := range testOnly {
				if within(imported, module) {
					t.Errorf("%s imports %s, from a module only tests may use: import it from a test file or through internal/pbt, or take the module out of testOnly and run the formatter", name, imported)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if looked == 0 {
		t.Fatal("the walk found no Go file outside the tests, which cannot be right")
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

// outsideModule is whether the go tool leaves a directory out of ./..., which
// it does for testdata, for vendor, for a name starting with a dot or an
// underscore, and for a directory holding a go.mod of its own, since that one
// is another module.
func outsideModule(root fs.FS, dir string) bool {
	base := path.Base(dir)
	if base == "testdata" || base == "vendor" || strings.HasPrefix(base, ".") || strings.HasPrefix(base, "_") {
		return true
	}
	_, err := fs.Stat(root, path.Join(dir, "go.mod"))
	return err == nil
}

// importsOf is the paths a Go file imports, read from its header alone so that
// a file which does not compile still answers.
func importsOf(root fs.FS, name string) ([]string, error) {
	src, err := fs.ReadFile(root, name)
	if err != nil {
		return nil, err
	}
	file, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, spec := range file.Imports {
		imported, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, imported)
	}
	return out, nil
}

// within is whether an import path names a package or one below it. A bare
// prefix test would take hegel.dev/go/hegelx for a package of hegel.dev/go/hegel.
func within(imported, root string) bool {
	return imported == root || strings.HasPrefix(imported, root+"/")
}
