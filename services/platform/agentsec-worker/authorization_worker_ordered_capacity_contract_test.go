package main

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// A capacity fixture that removes retry/heartbeat/deadline options or silently
// diverges from the shipped workflow cannot establish activity integration.
// This source guard supplements the actual server history/native assertions.
func TestOrderedCapacityProductionActivityContract(t *testing.T) {
	options := func(name, function string) string {
		t.Helper()
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal("capacity activity source absent")
		}
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, name, body, 0)
		if err != nil {
			t.Fatal("capacity activity source syntax")
		}
		var found []*ast.CompositeLit
		for _, declaration := range file.Decls {
			f, ok := declaration.(*ast.FuncDecl)
			if !ok || f.Name.Name != function {
				continue
			}
			ast.Inspect(f.Body, func(n ast.Node) bool {
				v, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				typeName, ok := v.Type.(*ast.SelectorExpr)
				if ok && typeName.Sel.Name == "ActivityOptions" {
					found = append(found, v)
				}
				return true
			})
		}
		if len(found) != 1 {
			t.Fatal("exactly one activity options contract required")
		}
		var out bytes.Buffer
		// Use a fresh file set so formatting depends on syntax, not line layout.
		if format.Node(&out, token.NewFileSet(), found[0]) != nil {
			t.Fatal("activity options format")
		}
		return out.String()
	}
	production := options(filepath.Join("..", "orchestration", "security_agent_workflow.go"), "SecurityAgentWorkflow")
	fixture := options("authorization_worker_ordered_capacity_temporal_test.go", "orderedCapacityApplyWorkflow")
	if fixture != production {
		t.Fatal("capacity fixture changed the production activity retry/deadline/heartbeat contract")
	}
}
