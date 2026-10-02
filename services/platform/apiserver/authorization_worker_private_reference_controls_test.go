package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const privateReferenceFrozen = "/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-private-reference-ElYf0U"

func privateReferenceTestInput(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	read := func(name string) []byte {
		b, e := os.ReadFile(filepath.Join(privateReferenceFrozen, "services/platform/migrations/ordered_current", name))
		if e != nil {
			t.Fatal("fixed packet missing")
		}
		return b
	}
	return read("private-reference-contract.json"), read("private-reference-ddl.sql"), read("private-reference-select.sql")
}
func privateReferenceTestContract(t *testing.T) privateReferenceContract {
	t.Helper()
	raw, _, _ := privateReferenceTestInput(t)
	var c struct {
		Rules []struct {
			ID, Kind string
			Fields   []string
		}
		FieldTypes                                    map[string]map[string]string
		CategoryMaxRows, RuleMaxRows                  map[string]int
		MaxRows, MaxBytes                             int
		ExpectedRoutineFacts                          []json.RawMessage
		ReferencePostgres, ServerVersionNum, Pgcrypto string
	}
	if json.Unmarshal(raw, &c) != nil {
		t.Fatal("fixed fixture")
	}
	result := privateReferenceContract{Routines: c.ExpectedRoutineFacts, Postgres: c.ReferencePostgres, ServerVersionNum: c.ServerVersionNum, Pgcrypto: c.Pgcrypto, Shape: orderedSupplementShape{Fields: c.FieldTypes, CategoryMaxRows: c.CategoryMaxRows, RuleMaxRows: c.RuleMaxRows, MaxRows: c.MaxRows, MaxBytes: c.MaxBytes}}
	for _, r := range c.Rules {
		result.Shape.Rules = append(result.Shape.Rules, orderedSupplementRule{ID: r.ID, Kind: r.Kind, Fields: r.Fields})
	}
	return result
}

func TestPrivateReferenceArtifactContract(t *testing.T) {
	raw, ddl, query := privateReferenceTestInput(t)
	t.Run("fixed", func(t *testing.T) {
		c, e := verifyPrivateReferenceInput(raw, ddl, query)
		if e != nil || len(c.Routines) != 4 || c.Shape.MaxRows != 39 || len(c.Shape.Rules) != 11 {
			t.Fatal("fixed contract not admitted")
		}
	})
	for _, mode := range []string{"contract", "ddl", "query", "empty"} {
		t.Run(mode, func(t *testing.T) {
			a, b, c := raw, ddl, query
			switch mode {
			case "contract":
				a = append(append([]byte{}, a...), ' ')
			case "ddl":
				b = []byte("SELECT 'secret'")
			case "query":
				c = []byte("SELECT 'secret'")
			case "empty":
				a = nil
			}
			if _, e := verifyPrivateReferenceInput(a, b, c); e == nil {
				t.Fatal("changed input accepted")
			}
		})
	}
}

func TestPrivateReferenceRows(t *testing.T) {
	c := privateReferenceTestContract(t)
	complete := privateReferenceShapedRows(c)
	if e := checkPrivateReferenceRows(c, complete); e != nil {
		t.Fatal("complete shaped fixture refused")
	}
	for _, kind := range []string{"namespace", "relation", "column", "constraint", "index", "type"} {
		t.Run("missing-"+kind, func(t *testing.T) {
			rows := []json.RawMessage{}
			for _, raw := range complete {
				var r struct{ Kind string }
				json.Unmarshal(raw, &r)
				if r.Kind != kind {
					rows = append(rows, raw)
				}
			}
			if checkPrivateReferenceRows(c, rows) == nil {
				t.Fatal("missing declared category admitted")
			}
		})
	}
	for _, mode := range []string{"missing", "duplicate", "source", "acl", "owner", "config", "extra", "zero-policy", "zero-trigger", "zero-view", "zero-rewrite", "cap"} {
		t.Run(mode, func(t *testing.T) {
			rows := append([]json.RawMessage{}, complete...)
			switch mode {
			case "missing":
				rows = rows[:3]
			case "duplicate":
				rows = append(rows, rows[0])
			case "source", "acl", "owner", "config", "extra":
				var r map[string]any
				json.Unmarshal(rows[0], &r)
				r["fact"].(map[string]any)[mode] = "different"
				rows[0], _ = json.Marshal(r)
			default:
				kind := strings.TrimPrefix(mode, "zero-")
				if mode == "cap" {
					kind = "namespace"
				}
				for _, rule := range c.Shape.Rules {
					if rule.Kind != kind {
						continue
					}
					n := 1
					if mode == "cap" {
						n = 2
					}
					for i := 0; i < n; i++ {
						fact := map[string]any{}
						for _, f := range rule.Fields {
							fact[f] = nil
						}
						key, _ := json.Marshal([]string{rule.ID, strings.Repeat("x", i+1)})
						r, _ := json.Marshal(map[string]any{"kind": kind, "identity": string(key), "fact": fact})
						rows = append(rows, r)
					}
				}
			}
			if e := checkPrivateReferenceRows(c, rows); e == nil {
				t.Fatal("changed/missing/overflow source facts accepted")
			}
		})
	}
}

// Shape-only orchestration fixture. Null metadata is not exported or claimed as
// a PostgreSQL reference; native nonroutine values must come from the fixed SQL.
func privateReferenceShapedRows(c privateReferenceContract) []json.RawMessage {
	rows := append([]json.RawMessage{}, c.Routines...)
	for _, r := range c.Shape.Rules {
		if r.Kind == "routine" {
			continue
		}
		for i := 0; i < c.Shape.RuleMaxRows[r.ID]; i++ {
			fact := map[string]any{}
			for _, f := range r.Fields {
				fact[f] = nil
			}
			key, _ := json.Marshal([]string{r.ID, strings.Repeat("fixture", i+1)})
			raw, _ := json.Marshal(map[string]any{"kind": r.Kind, "identity": string(key), "fact": fact})
			rows = append(rows, raw)
		}
	}
	return rows
}

// These controls exercise our transaction orchestration, not PostgreSQL semantics.
// Removing a rollback, post-admission, frame/cancellation check must expose rows.
func TestPrivateReferenceCleanupBoundary(t *testing.T) {
	c := privateReferenceTestContract(t)
	complete := privateReferenceShapedRows(c)
	stages := []string{"", "original", "write-begin", "write-configure", "before-admission", "before-absence", "ddl", "role", "collector", "empty", "collect", "ignored-emit", "cancel", "write-rollback", "restored", "after-absence", "read-begin", "read-configure", "read-frame", "post-admission", "read-rollback", "final-frame", "final-absence"}
	for _, failure := range stages {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			original := orderedSupplementFrame{Session: "zasp_test", Role: "zasp_test", SearchPath: "public", TimeZone: "Etc/UTC", Postgres: c.Postgres, ServerVersionNum: c.ServerVersionNum, Pgcrypto: c.Pgcrypto}
			calls := []string{}
			begins, execs, frames, admissions, absents, rollbacks := 0, 0, 0, 0, 0, 0
			disposed := false
			step := func(name string) error {
				calls = append(calls, name)
				if failure == name {
					return errors.New("private backend secret")
				}
				return nil
			}
			cleanup := func(ctx context.Context) {
				d, ok := ctx.Deadline()
				if ctx.Err() != nil || !ok || time.Until(d) > 3*time.Second {
					t.Fatal("cleanup not independently bounded")
				}
			}
			io := privateReferenceIO{
				Begin: func(_ context.Context, ro bool) error {
					begins++
					if ro != (begins == 2) {
						t.Fatal("wrong transaction mode")
					}
					if begins == 1 {
						return step("write-begin")
					}
					return step("read-begin")
				},
				Exec: func(_ context.Context, sql string) error {
					execs++
					name := []string{"write-configure", "ddl", "role", "read-configure"}[execs-1]
					return step(name)
				},
				Frame: func(context.Context) (orderedSupplementFrame, error) {
					frames++
					name := []string{"original", "collector", "restored", "read-frame", "final-frame"}[frames-1]
					f := original
					if name == "collector" {
						f.Role = "zasp_discovery_authority"
						f.SearchPath = "pg_catalog"
						f.TimeZone = "UTC"
					}
					if name == "read-frame" {
						f.SearchPath = "pg_catalog"
						f.TimeZone = "UTC"
						f.ReadOnly = true
					}
					if failure == name {
						f.ServerVersionNum = "wrong"
					}
					return f, step(name)
				},
				Admission: func(context.Context) error {
					admissions++
					if admissions == 1 {
						return step("before-admission")
					}
					return step("post-admission")
				},
				Absent: func(context.Context) error {
					absents++
					return step([]string{"before-absence", "after-absence", "final-absence"}[absents-1])
				},
				Empty: func(context.Context) error { return step("empty") },
				Collect: func(_ context.Context, emit func(json.RawMessage) error) error {
					if e := step("collect"); e != nil {
						return e
					}
					if failure == "cancel" {
						cancel()
						return ctx.Err()
					}
					if failure == "ignored-emit" {
						_ = emit(json.RawMessage(`{"bad":"secret"}`))
						return nil
					}
					for _, r := range complete {
						if e := emit(r); e != nil {
							return e
						}
					}
					return nil
				},
				Rollback: func(ctx context.Context) error {
					cleanup(ctx)
					rollbacks++
					if rollbacks == 1 {
						return step("write-rollback")
					}
					return step("read-rollback")
				},
				Dispose: func(ctx context.Context) error { cleanup(ctx); disposed = true; return nil },
			}
			got, err := runPrivateReferenceBoundary(ctx, c, "fixed-DDL", io)
			if (err != nil) != (failure != "") {
				t.Fatal("boundary outcome", failure)
			}
			if failure == "" {
				if !reflect.DeepEqual(got.Rows, complete) || got.Collector.ReadOnly || disposed {
					t.Fatal("successful write capture changed")
				}
				want := []string{"original", "write-begin", "write-configure", "before-admission", "before-absence", "ddl", "role", "collector", "empty", "collect", "write-rollback", "restored", "after-absence", "read-begin", "read-configure", "read-frame", "post-admission", "read-rollback", "final-frame", "final-absence"}
				if !reflect.DeepEqual(calls, want) {
					t.Fatal("order/cleanup changed", calls)
				}
			} else {
				if got.Rows != nil || !disposed {
					t.Fatal("failure retained rows/connection")
				}
				if strings.Contains(err.Error(), "secret") {
					t.Fatal("backend detail exposed")
				}
			}
		})
	}
}
