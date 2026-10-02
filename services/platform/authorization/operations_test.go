package authorization

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

// The public CoreOperations inventory excludes installed exports. Extract the
// actual composition definitions, including conditional arrays and append calls,
// so adding or changing a product route cannot silently escape model coverage.
func TestOperationCoverage(t *testing.T) {
	files, err := filepath.Glob("../apiserver/*.go")
	if err != nil {
		t.Fatal(err)
	}
	trees := map[string]*ast.File{}
	arrays := map[string]*ast.CompositeLit{}
	for _, path := range files {
		if len(path) > 8 && path[len(path)-8:] == "_test.go" {
			continue
		}
		tree, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		trees[path] = tree
		ast.Inspect(tree, func(node ast.Node) bool {
			value, ok := node.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, name := range value.Names {
				if i < len(value.Values) {
					if literal, ok := value.Values[i].(*ast.CompositeLit); ok {
						arrays[name.Name] = literal
					}
				}
			}
			return true
		})
	}
	source := map[string]OperationPolicy{}
	fresh := map[string]bool{}
	ast.Inspect(trees["../apiserver/composition.go"], func(node ast.Node) bool {
		if fn, ok := node.(*ast.FuncDecl); ok && fn.Name.Name == "requiresFreshAuthentication" {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CaseClause); ok {
					for _, expr := range c.List {
						fresh[astString(expr)] = true
					}
				}
				return true
			})
		}
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		kind, ok := literal.Type.(*ast.Ident)
		if !ok {
			return true
		}
		if kind.Name == "OperationDefinition" && len(literal.Elts) == 5 {
			p := OperationPolicy{Method: astString(literal.Elts[0]), Path: astString(literal.Elts[1]), ID: astString(literal.Elts[2]), Permission: astString(literal.Elts[3])}
			if list, ok := literal.Elts[4].(*ast.CompositeLit); ok {
				for _, entry := range list.Elts {
					p.Security = append(p.Security, astString(entry))
				}
			}
			source[p.ID] = p
		}
		if kind.Name == "Operation" {
			p := keyedPolicy(literal)
			if p.ID != "" {
				source[p.ID] = p
			}
		}
		return true
	})
	ast.Inspect(trees["../apiserver/composition.go"], func(node ast.Node) bool {
		loop, ok := node.(*ast.RangeStmt)
		if !ok {
			return true
		}
		name, ok := loop.X.(*ast.Ident)
		if !ok {
			return true
		}
		array := arrays[name.Name]
		if array == nil {
			return true
		}
		permission := ""
		ast.Inspect(loop.Body, func(n ast.Node) bool {
			literal, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if kind, ok := literal.Type.(*ast.Ident); ok && kind.Name == "Operation" {
				permission = keyedPolicy(literal).Permission
			}
			return true
		})
		if permission != "" {
			for _, entry := range array.Elts {
				literal, ok := entry.(*ast.CompositeLit)
				if !ok {
					t.Fatal("unrecognized optional operation definition")
				}
				p := keyedPolicy(literal)
				p.Permission = permission
				if p.ID == "" {
					t.Fatal("optional operation lacks explicit ID")
				}
				source[p.ID] = p
			}
		}
		return true
	})
	actual := Operations()
	if len(source) == 0 || len(actual) != len(source) {
		t.Fatalf("operation coverage: model=%d source=%d", len(actual), len(source))
	}
	seen := map[string]bool{}
	counts := map[string]int{}
	for _, p := range actual {
		want, ok := source[p.ID]
		if !ok || seen[p.ID] {
			t.Errorf("unknown/duplicate policy %s", p.ID)
		}
		seen[p.ID] = true
		if p.Method != want.Method || p.Path != want.Path || p.Permission != want.Permission || p.Relation != want.Permission {
			t.Errorf("operation mismatch %s: model=%#v source=%#v", p.ID, p, want)
		}
		if p.Relation != "" && !permissions[p.Relation] {
			t.Errorf("unmodeled permission: %s", p.Relation)
		}
		if p.Surface == "core" {
			if p.FreshAuth != fresh[p.ID] || len(p.Security) != len(want.Security) {
				t.Errorf("credential precondition drift: %s", p.ID)
			}
			for _, scheme := range want.Security {
				if !contains(p.Security, scheme) {
					t.Errorf("credential drift %s %s", p.ID, scheme)
				}
			}
		}
		counts[p.Permission]++
	}
	t.Logf("verified %d composed operations; permission counts: %v", len(source), counts)
}
func astString(expr ast.Expr) string {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return ""
	}
	value, _ := strconv.Unquote(literal.Value)
	return value
}
func keyedPolicy(literal *ast.CompositeLit) OperationPolicy {
	p := OperationPolicy{}
	for _, entry := range literal.Elts {
		kv, ok := entry.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		value := astString(kv.Value)
		switch key.Name {
		case "OperationID":
			p.ID = value
		case "Pattern":
			p.Path = value
		case "Permission":
			p.Permission = value
		case "Method":
			p.Method = value
			if selector, ok := kv.Value.(*ast.SelectorExpr); ok {
				switch selector.Sel.Name {
				case "MethodGet":
					p.Method = "GET"
				case "MethodPost":
					p.Method = "POST"
				}
			}
		}
	}
	return p
}
