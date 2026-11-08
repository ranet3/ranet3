// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"go/build"
	"path/filepath"
	"strings"
	"testing"
)

const (
	module      = "ranet3.com/pkgs/ranet3"
	thisPackage = module + "/internal/egress/userspace"
	rawPackage  = thisPackage + "/raw"
	// moduleRoot is the module's directory from this package's
	moduleRoot = "../../.."
)

// a phone's build of the exit reaches no raw socket: no package of the
// module that the exit imports for android or ios, however far down,
// imports raw
func TestPhoneBuildsImportNoRawSocket(t *testing.T) {
	root, err := filepath.Abs(moduleRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"android", "ios"} {
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = goos, "arm64", false
		if path, ok := reaches(t, ctx, root, thisPackage, rawPackage); ok {
			t.Errorf("for %s the exit imports %s through %s", goos, rawPackage, strings.Join(path, " <- "))
		}
	}
}

// reaches walks the module's packages from start under ctx and returns the
// chain of imports to target where one reaches it
func reaches(t *testing.T, ctx build.Context, root, start, target string) ([]string, bool) {
	t.Helper()
	parent := map[string]string{start: ""}
	queue := []string{start}
	for len(queue) > 0 {
		at := queue[0]
		queue = queue[1:]
		pkg, err := ctx.ImportDir(filepath.Join(root, strings.TrimPrefix(at, module)), 0)
		if err != nil {
			t.Fatalf("read %s for %s: %v", at, ctx.GOOS, err)
		}
		for _, imported := range pkg.Imports {
			if _, seen := parent[imported]; seen || !strings.HasPrefix(imported, module+"/") {
				continue
			}
			parent[imported] = at
			if imported == target {
				var path []string
				for p := imported; p != ""; p = parent[p] {
					path = append(path, p)
				}
				return path, true
			}
			queue = append(queue, imported)
		}
	}
	return nil, false
}
