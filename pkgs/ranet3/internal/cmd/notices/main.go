// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Command notices writes internal/notices/third_party.md, the notice that has
// to travel with a binary built from this tree.
//
// Apache 2.0 and the BSD and MIT licenses all require their text and their
// copyright line to be reproduced in a distribution, and a Go binary is a
// distribution of every module linked into it. The file this writes is
// embedded in the daemon and printed by `ranet3 licenses`, so the
// obligation travels with the binary rather than with the repository.
//
// Only modules actually linked are listed. The module graph is far larger than
// the link set, because one dependency's own test and tooling requirements
// reach it, and nothing in that tail is distributed.
//
// The formatter regenerates the file. A nix build has no module cache to read
// license texts from, which rules out running this there, and the tests in
// internal/notices hold the committed file instead: its sections against
// go.mod and its first section against license.txt.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
}

func run() error {
	cache, err := output("go", "env", "GOMODCACHE")
	if err != nil {
		return err
	}
	modules, err := linkedModules()
	if err != nil {
		return err
	}
	own, err := os.ReadFile("license.txt")
	if err != nil {
		return fmt.Errorf("read this module's license: %w", err)
	}
	var out strings.Builder
	out.WriteString(header)
	fmt.Fprintf(&out, "\n## ranet3.com/pkgs/ranet3\n\nThis module's own license, from `license.txt`.\n\n```\n%s\n```\n",
		strings.TrimRight(string(own), "\n"))
	for _, m := range modules {
		text, from, err := license(cache, m)
		if err != nil {
			return err
		}
		fmt.Fprintf(&out, "\n## %s\n\n%s.\n\n```\n%s\n```\n", m.path, from, strings.TrimRight(text, "\n"))
	}
	path := filepath.Join("internal", "notices", "third_party.md")
	return os.WriteFile(path, []byte(out.String()), 0o644)
}

const header = `# Third party notices

Every module linked into a ranet3 binary, with the license it is under, this one first.
` + "`ranet3 licenses`" + ` prints this same text out of the binary.

This file is generated. Run the formatter rather than editing it.
`

// module is one linked dependency. dir is the directory go.mod replaces it
// with, relative to this module's root, and empty for a module of the cache.
type module struct{ path, version, dir string }

// linkedModules is the modules the built binary actually contains, read back
// out of the binary rather than asked of the source tree. `go list -deps`
// reports no module for a package when the build is vendored, which a nix
// build's is, so asking the source gives an empty answer there and a correct
// one here. The binary answers the same way everywhere. It is also the more
// honest question, since the obligation attaches to what is distributed.
func linkedModules() ([]module, error) {
	binary := filepath.Join(os.TempDir(), "ranet3-notices-subject")
	defer os.Remove(binary)
	if _, err := output("go", "build", "-o", binary, "./cmd/ranet3"); err != nil {
		return nil, err
	}
	listed, err := output("go", "version", "-m", binary)
	if err != nil {
		return nil, err
	}
	return modulesOf(listed)
}

// modulesOf is the modules `go version -m` lists for a binary.
func modulesOf(listed string) ([]module, error) {
	seen := map[module]bool{}
	var last module
	for line := range strings.SplitSeq(listed, "\n") {
		// "\tdep\t<path>\t<version>\t<hash>", and a replaced module adds a
		// "=>" line naming the replacement, and the replacement ships.
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) < 3 || (fields[0] != "dep" && fields[0] != "=>") {
			continue
		}
		// A directory ships under the path it replaces, and has no version.
		if fields[0] == "=>" && isDir(fields[1]) {
			delete(seen, last)
			last.dir = fields[1]
			seen[last] = true
			continue
		}
		last = module{path: fields[1], version: fields[2]}
		seen[last] = true
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("no modules reported by go version -m, which cannot be right")
	}
	modules := slices.Collect(maps(seen))
	slices.SortFunc(modules, func(a, b module) int { return strings.Compare(a.path, b.path) })
	return modules, nil
}

func maps(set map[module]bool) func(func(module) bool) {
	return func(yield func(module) bool) {
		for m := range set {
			if !yield(m) {
				return
			}
		}
	}
}

// isDir is whether a replacement names a directory rather than a module, as
// go.mod tells them apart.
func isDir(replacement string) bool {
	return strings.HasPrefix(replacement, "./") || strings.HasPrefix(replacement, "../") || filepath.IsAbs(replacement)
}

// license reads one module's license out of the module cache, or out of the
// directory that replaces it, and says where it came from. A module whose
// license this cannot find is an error rather than an omission, because the
// point of the file is that nothing is missing from it.
func license(cache string, m module) (text, from string, err error) {
	if m.dir != "" {
		return copied(m)
	}
	dir := filepath.Join(cache, escape(m.path)+"@"+m.version)
	for _, candidate := range []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt"} {
		body, err := os.ReadFile(filepath.Join(dir, candidate))
		if err == nil {
			return string(body), fmt.Sprintf("%s %s, from `%s`", m.path, m.version, candidate), nil
		}
	}
	return "", "", fmt.Errorf("no license file in %s", dir)
}

// copied is the license of a module copied into the directory that replaces
// it. Its LICENSE names no holder, so the holders are the ones its REUSE.toml
// gives the files under the license it gives LICENSE.
func copied(m module) (text, from string, err error) {
	body, err := os.ReadFile(filepath.Join(m.dir, "LICENSE"))
	if err != nil {
		return "", "", fmt.Errorf("read the license of %s: %w", m.path, err)
	}
	var reuse struct {
		Annotations []struct {
			Path    any    `toml:"path"`
			Holders any    `toml:"SPDX-FileCopyrightText"`
			License string `toml:"SPDX-License-Identifier"`
		} `toml:"annotations"`
	}
	if _, err := toml.DecodeFile(filepath.Join(m.dir, "REUSE.toml"), &reuse); err != nil {
		return "", "", fmt.Errorf("read the holders of %s: %w", m.path, err)
	}
	var licensed string
	for _, a := range reuse.Annotations {
		if slices.Contains(values(a.Path), "LICENSE") {
			licensed = a.License
		}
	}
	var holders []string
	for _, a := range reuse.Annotations {
		for _, holder := range values(a.Holders) {
			if a.License == licensed && !slices.Contains(holders, holder) {
				holders = append(holders, holder)
			}
		}
	}
	if licensed == "" || len(holders) == 0 {
		return "", "", fmt.Errorf("%s/REUSE.toml gives LICENSE no license, or names no holder under it", m.dir)
	}
	var out strings.Builder
	for _, holder := range holders {
		fmt.Fprintf(&out, "Copyright (c) %s\n", holder)
	}
	fmt.Fprintf(&out, "\n%s", body)
	return out.String(), fmt.Sprintf("%s in `%s`, from `LICENSE` and the holders `REUSE.toml` names", m.path, m.dir), nil
}

// values is a REUSE.toml key that holds one string or an array of them.
func values(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// escape is the module cache's spelling of a path: an uppercase letter becomes
// an exclamation mark and its lowercase, so BurntSushi is !burnt!sushi.
func escape(path string) string {
	var out strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			out.WriteByte('!')
			out.WriteRune(r + ('a' - 'A'))
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

func output(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Stderr = os.Stderr
	body, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(body)), nil
}
