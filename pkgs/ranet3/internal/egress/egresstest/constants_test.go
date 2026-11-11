// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
	"testing"
)

// every package constant whose name ends in Port lies outside the range the
// leaf's kernel gives its sockets ports from
// the code is type checked without its imports, which leaves the values of
// its own constants whole
func TestEveryConstantNamedPortLiesOutsideTheLeafsRange(t *testing.T) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	var parsed []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(files, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, file)
	}
	config := types.Config{Error: func(error) {}}
	pkg, _ := config.Check("egresstest", files, parsed, nil)
	found := 0
	for _, name := range pkg.Scope().Names() {
		c, ok := pkg.Scope().Lookup(name).(*types.Const)
		if !ok || !strings.HasSuffix(name, "Port") {
			continue
		}
		found++
		if c.Val().Kind() != constant.Int {
			t.Errorf("%s: the constant %s, named a port, holds %s, no integer", files.Position(c.Pos()), name, c.Val())
			continue
		}
		if port, _ := constant.Int64Val(c.Val()); port >= leafEphemeralLow && port <= leafEphemeralHigh {
			t.Errorf("%s: the constant %s = %d, named a port, lies in the leaf's range of %d to %d", files.Position(c.Pos()), name, port, leafEphemeralLow, leafEphemeralHigh)
		}
	}
	if found == 0 {
		t.Fatal("the package holds no constant whose name ends in Port")
	}
}
