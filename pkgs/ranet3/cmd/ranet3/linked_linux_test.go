// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package main

import (
	"debug/elf"
	"debug/gosym"
	"os"
	"strings"
	"testing"
)

// gvisorModule is the module of the userspace stack the darwin daemon's exit
// runs, which the Linux daemon, whose exit is the kernel's, never links
const gvisorModule = "gvisor.dev/gvisor"

// TestLinuxDaemonLinksNoUserspaceStack reads the functions this package's
// binary links from its line table and finds none of gVisor's, so the stack
// stays a dependency of the darwin daemon alone. The line table, unlike the
// build information's modules and the symbol table, is there in a vendored
// build and in a stripped one alike.
func TestLinuxDaemonLinksNoUserspaceStack(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()
	lines, text := binary.Section(".gopclntab"), binary.Section(".text")
	if lines == nil || text == nil {
		t.Fatal("the binary carries no line table to read its functions from")
	}
	data, err := lines.Data()
	if err != nil {
		t.Fatal(err)
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Funcs) == 0 {
		t.Fatal("the line table names no function, so it cannot show gVisor absent")
	}
	linked := 0
	for _, function := range table.Funcs {
		if strings.HasPrefix(function.Name, gvisorModule+"/") {
			if linked == 0 {
				t.Errorf("the linux daemon links %s", function.Name)
			}
			linked++
		}
	}
	if linked != 0 {
		t.Errorf("%d functions of %s in all", linked, gvisorModule)
	}
}
