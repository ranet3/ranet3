// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
	"testing"
)

// each verdict a step of the package's rows marks is the last act of its path: a statement of its own in the step's
// body that a return follows in its block or that ends the step, and no condition or assertion after it returns or
// fails unjudged
// a step is a method of the rows that steps hands its step function or that judged is handed, and a mark in a helper
// a step calls, of a step's shape or not, is no step's
// a step is named only as the last argument of step or judged, or uncalled in a top-level Test function, as one
// handing it to t.Run
// the check does not read judged's result called in place inside a step, r.judged(r.portReuse)(t), or a local
// function named step that a step hands another step
func TestEachVerdictMarkIsTheLastActOfItsPath(t *testing.T) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	var parsed []*ast.File
	steps, handed := map[string]bool{}, map[*ast.SelectorExpr]bool{}
	for _, name := range names {
		file, err := parser.ParseFile(files, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, file)
		stepNames(file, steps, handed)
	}
	marks := 0
	for _, file := range parsed {
		for _, run := range stepsRun(file, steps, handed) {
			t.Errorf("%s names the step %s where neither step nor judged takes it, nor a Test function hands it on uncalled", files.Position(run.Pos()), run.Sel.Name)
		}
		placed := map[*ast.CallExpr]bool{}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil && isRowsMethod(fn) && steps[fn.Name.Name] {
				placeVerdicts(fn.Body, placed)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && isVerdict(call) {
				marks++
				if !placed[call] {
					t.Errorf("%s marks a verdict that is not a step's statement of its own, followed by a return or ending the step's body", files.Position(call.Pos()))
				}
			}
			return true
		})
	}
	if marks == 0 {
		t.Fatal("no step of the package marks a verdict")
	}
}

// placeVerdicts marks in placed each verdict call under body that is a statement of its own that a return follows in
// its block or that ends body, a function literal's left out
func placeVerdicts(body *ast.BlockStmt, placed map[*ast.CallExpr]bool) {
	ast.Inspect(body, func(node ast.Node) bool {
		var list []ast.Stmt
		switch node := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.BlockStmt:
			list = node.List
		case *ast.CaseClause:
			list = node.Body
		case *ast.CommClause:
			list = node.Body
		}
		for i, stmt := range list {
			statement, ok := stmt.(*ast.ExprStmt)
			if !ok {
				continue
			}
			call, ok := statement.X.(*ast.CallExpr)
			if !ok || !isVerdict(call) {
				continue
			}
			if i+1 < len(list) {
				_, placed[call] = list[i+1].(*ast.ReturnStmt)
			} else {
				placed[call] = node == body
			}
		}
		return true
	})
}

// stepNames adds to steps the name of each method value file hands a call of step or of judged as its last argument,
// the methods judged runs, read from the calls in steps and the calls of judged, and adds each such method value to
// handed
func stepNames(file *ast.File, steps map[string]bool, handed map[*ast.SelectorExpr]bool) {
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		var called string
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			called = fun.Name
		case *ast.SelectorExpr:
			called = fun.Sel.Name
		}
		if method, ok := call.Args[len(call.Args)-1].(*ast.SelectorExpr); ok && (called == "step" || called == "judged") {
			steps[method.Sel.Name] = true
			handed[method] = true
		}
		return true
	})
}

// stepsRun gives each selector of a step in file that step or judged does not take as its last argument, but for a
// naming in a top-level function whose name starts with Test that does not call the step, as a test handing a step
// to t.Run does
func stepsRun(file *ast.File, steps map[string]bool, handed map[*ast.SelectorExpr]bool) []*ast.SelectorExpr {
	var runs []*ast.SelectorExpr
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		inTest := ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test")
		ast.Inspect(decl, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && inTest {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok && steps[selector.Sel.Name] {
					runs = append(runs, selector)
				}
			}
			if selector, ok := node.(*ast.SelectorExpr); ok && !inTest && steps[selector.Sel.Name] && !handed[selector] {
				runs = append(runs, selector)
			}
			return true
		})
	}
	return runs
}

// isRowsMethod reports whether fn is a method of *rows
func isRowsMethod(fn *ast.FuncDecl) bool {
	return fn.Recv != nil && len(fn.Recv.List) == 1 && types.ExprString(fn.Recv.List[0].Type) == "*rows"
}

// isVerdict reports whether call calls a method named verdict
func isVerdict(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "verdict"
}
