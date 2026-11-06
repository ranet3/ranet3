// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"path/filepath"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// sysctlSteps is the most steps a drawn path takes before its tail
const sysctlSteps = 5

// every path Sysctl reads something at ends at a file under /proc/sys
// the tails name a file under /proc/sys and files that exist outside it
func TestSysctlReadsOnlyUnderProcSys(t *testing.T) {
	steps := []string{"..", ".", "kernel"}
	tails := []string{"kernel/ostype", "self/stat", "proc/self/stat", "version"}
	pbt.Check(t, func(ht *hegel.T) {
		var parts []string
		if hegel.Draw(ht, hegel.WeightedBooleans(1.0/8)) {
			parts = append(parts, "")
		}
		for range hegel.Draw(ht, pbt.Spanning(0, sysctlSteps)) {
			parts = append(parts, hegel.Draw(ht, hegel.SampledFrom(steps)))
		}
		path := strings.Join(append(parts, hegel.Draw(ht, hegel.SampledFrom(tails))), "/")
		end := filepath.Join(sysctlRoot, path)
		if got := Sysctl(path); got != "" && !strings.HasPrefix(end, sysctlRoot+"/") {
			ht.Fatalf("%q read %q at %s", path, got, end)
		}
	})
}
