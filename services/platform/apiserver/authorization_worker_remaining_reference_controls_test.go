package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRemainingReferenceActualPacket(t *testing.T) {
	input, err := loadRemainingReference(remainingPacket)
	if err != nil {
		t.Fatal(err)
	}
	if len(input.Paths) != 20 || len(input.Shape.Rules) != 64 || input.Shape.MaxRows != 9623 || input.Shape.MaxBytes != 16777216 || len(input.RawInputRuleIDs) != 16 || supplementSHA(input.SQL) != remainingQuerySHA {
		t.Fatal("incomplete pinned packet")
	}
	// Maxima must not be turned into fabricated declaration-derived row counts.
	if err := checkOrderedSupplementRows(input.Shape, []json.RawMessage{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"snapshot-manifest.json", remainingP7 + "ordered-current-supplementary-select3.sql", "services/platform/migrations/tools/ordered-current-catalog.mjs"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for _, path := range input.Paths {
				rel, e := filepath.Rel(remainingPacket, path)
				if e != nil {
					t.Fatal(e)
				}
				raw, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				target := filepath.Join(dir, rel)
				if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(target, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			path := filepath.Join(dir, name)
			f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
			if e != nil {
				t.Fatal(e)
			}
			_, e = f.WriteString("\n")
			f.Close()
			if e != nil {
				t.Fatal(e)
			}
			if _, e = loadRemainingReference(dir); e == nil {
				t.Fatal("changed pinned input accepted")
			}
		})
	}
}

func TestRemainingReferenceClosedMode(t *testing.T) {
	if enabled, e := remainingReferenceMode("", nil); e != nil || enabled {
		t.Fatal("default not delegated")
	}
	if enabled, e := remainingReferenceMode("1", nil); e != nil || !enabled {
		t.Fatal("explicit mode refused")
	}
	for _, mode := range []string{"true", "2", "catalog"} {
		if _, e := remainingReferenceMode(mode, nil); e == nil {
			t.Fatal("unknown mode accepted")
		}
	}
	for _, key := range []string{"ZASP_ORDERED_PRIVATE_REFERENCE_CAPTURE", "ZASP_ORDERED_SUPPLEMENT_CAPTURE", "ZASP_ORDERED_POLICY_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_CAPTURE", "ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_READINESS_ATTRIBUTION"} {
		if _, e := remainingReferenceMode("1", map[string]string{key: "1"}); e == nil {
			t.Fatalf("overlap %s accepted", key)
		}
	}
}

// Only database IO is doubled. The real read-only transaction boundary, row
// verifier, envelope and filesystem publisher are consumed together below.
func remainingTestIO(input remainingReferenceInput, fault string, cancel context.CancelFunc) (orderedSupplementIO, *[]string) {
	calls := []string{}
	active, role := false, false
	frames := 0
	io := orderedSupplementIO{
		Begin: func(ctx context.Context) error { calls = append(calls, "begin"); active = true; return nil },
		Exec: func(ctx context.Context, sql string) error {
			calls = append(calls, sql)
			if strings.HasPrefix(sql, "SET LOCAL ROLE") {
				role = true
			}
			if sql == "RESET ROLE" {
				role = false
			}
			return nil
		},
		Frame: func(ctx context.Context) (orderedSupplementFrame, error) {
			frames++
			f := orderedSupplementFrame{Session: "zasp_test", Role: "zasp_test", SearchPath: "\"$user\", public", TimeZone: "America/Los_Angeles", Postgres: input.Postgres, ServerVersionNum: input.ServerVersionNum, Pgcrypto: input.Pgcrypto}
			if active && role {
				f.Role = "zasp_discovery_authority"
				f.SearchPath = "pg_catalog"
				f.TimeZone = "UTC"
				f.ReadOnly = true
			}
			if fault == "version" {
				f.ServerVersionNum = "180004"
			}
			if fault == "postgres" {
				f.Postgres = "another build"
			}
			if fault == "extension" {
				f.Pgcrypto = "1.5"
			}
			if fault == "session" {
				f.Session = "zasp_e2e"
			}
			if active && role {
				switch fault {
				case "role":
					f.Role = "zasp_test"
				case "path":
					f.SearchPath = "public, pg_catalog"
				case "timezone":
					f.TimeZone = "America/Los_Angeles"
				case "read-write":
					f.ReadOnly = false
				}
			}
			if fault == "restore" && frames == 3 {
				f.TimeZone = "UTC"
			}
			if fault == "cancel-after-restoration" && frames == 3 {
				cancel()
			}
			return f, nil
		},
		Admission: func(ctx context.Context) error {
			calls = append(calls, "admission")
			if fault == "admission" || fault == "post-admission" && strings.Count(strings.Join(calls, "|"), "admission") == 2 {
				return errors.New("refused")
			}
			return nil
		},
		Collect: func(ctx context.Context, emit func(json.RawMessage) error) error {
			calls = append(calls, "collect")
			if fault == "cancel" {
				cancel()
			}
			if fault == "collect" {
				return errors.New("refused")
			}
			if fault == "stream-bytes" {
				return emit(json.RawMessage(strings.Repeat("x", input.Shape.MaxBytes+1)))
			}
			if fault == "stream-duplicate" {
				r := input.Shape.Rules[0]
				fact := map[string]any{}
				for _, f := range r.Fields {
					fact[f] = nil
				}
				identity, _ := json.Marshal([]string{r.ID, "same"})
				raw, _ := json.Marshal(map[string]any{"kind": r.Kind, "identity": string(identity), "fact": fact})
				if err := emit(raw); err != nil {
					return err
				}
				return emit(raw)
			}
			return nil
		},
		Rollback: func(ctx context.Context) error {
			calls = append(calls, "rollback")
			active = false
			if ctx.Err() != nil {
				return errors.New("cancelled cleanup")
			}
			d, ok := ctx.Deadline()
			if !ok || time.Until(d) > 3*time.Second {
				return errors.New("unbounded cleanup")
			}
			if fault == "rollback" {
				return errors.New("refused")
			}
			return nil
		},
		Dispose: func(ctx context.Context) error {
			calls = append(calls, "dispose")
			if ctx.Err() != nil {
				return errors.New("cancelled disposal")
			}
			d, ok := ctx.Deadline()
			if !ok || time.Until(d) > 3*time.Second {
				return errors.New("unbounded disposal")
			}
			return nil
		},
	}
	return io, &calls
}

func TestRemainingReferenceReadOnlyPublication(t *testing.T) {
	input, e := loadRemainingReference(remainingPacket)
	if e != nil {
		t.Fatal(e)
	}
	for _, fault := range []string{"", "version", "postgres", "extension", "session", "role", "path", "timezone", "read-write", "admission", "post-admission", "collect", "stream-bytes", "stream-duplicate", "rollback", "restore", "cancel", "cancel-after-restoration", "output-exists"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			io, calls := remainingTestIO(input, fault, cancel)
			out := filepath.Join(t.TempDir(), "reference.json")
			if fault == "output-exists" {
				if e := os.WriteFile(out, []byte("retained"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			pub, e := captureRemainingReference(ctx, input, io, out)
			if fault != "" {
				if e == nil {
					t.Fatal("failure published")
				}
				if fault == "output-exists" {
					raw, _ := os.ReadFile(out)
					if string(raw) != "retained" {
						t.Fatal("overwritten")
					}
				} else if _, e := os.Stat(out); !os.IsNotExist(e) {
					t.Fatal("failure left output")
				}
				if !strings.Contains(strings.Join(*calls, "|"), "dispose") {
					t.Fatal("failure did not dispose")
				}
				entries, err := os.ReadDir(filepath.Dir(out))
				if err != nil {
					t.Fatal(err)
				}
				want := 0
				if fault == "output-exists" {
					want = 1
				}
				if len(entries) != want {
					t.Fatal("failure left temporary files")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			raw, e := os.ReadFile(out)
			if e != nil {
				t.Fatal(e)
			}
			info, _ := os.Stat(out)
			if info.Mode().Perm() != 0600 || pub.FileSHA256 != supplementSHA(raw) || pub.PayloadSHA256 != supplementSHA(raw[:len(raw)-1]) {
				t.Fatal("publication evidence")
			}
			var envelope map[string]json.RawMessage
			if supplementJSON(raw, &envelope) != nil || string(envelope["format"]) != `"ordered-current-remaining-reference-v1"` || string(envelope["rolledBack"]) != "true" || string(envelope["frameRestored"]) != "true" || string(envelope["rawInputDisposition"]) == "" {
				t.Fatal("wrong envelope")
			}
			joined := strings.Join(*calls, "|")
			if strings.Count(joined, "admission") != 2 || !strings.Contains(joined, "statement_timeout='10s'") || !strings.Contains(joined, "lock_timeout='3s'") || !strings.Contains(joined, "pg_advisory_xact_lock_shared") || !strings.HasSuffix(joined, "rollback") {
				t.Fatal("transaction contract", joined)
			}
		})
	}
}

func TestRemainingReferenceActualTypedLimits(t *testing.T) {
	input, e := loadRemainingReference(remainingPacket)
	if e != nil {
		t.Fatal(e)
	}
	r := input.Shape.Rules[0]
	fact := map[string]any{}
	for _, f := range r.Fields {
		fact[f] = nil
	}
	row := func(id string) json.RawMessage {
		identity, _ := json.Marshal([]string{r.ID, id})
		raw, _ := json.Marshal(map[string]any{"kind": r.Kind, "identity": string(identity), "fact": fact})
		return raw
	}
	if e := checkOrderedSupplementRows(input.Shape, []json.RawMessage{row("one")}); e != nil {
		t.Fatal(e)
	}
	if e := checkOrderedSupplementRows(input.Shape, []json.RawMessage{row("one"), row("one")}); e == nil {
		t.Fatal("duplicate allowed")
	}
	rows := []json.RawMessage{}
	for i := 0; i <= input.Shape.RuleMaxRows[r.ID]; i++ {
		rows = append(rows, row(strings.Repeat("x", i+1)))
	}
	if e := checkOrderedSupplementRows(input.Shape, rows); e == nil {
		t.Fatal("per-rule cap allowed")
	}
	// Per-kind and total bounds remain active in the actual decoded contract.
	tooMany := make([]json.RawMessage, input.Shape.MaxRows+1)
	if e := checkOrderedSupplementRows(input.Shape, tooMany); e == nil {
		t.Fatal("total cap allowed")
	}
	zero := input.Shape
	zero.CategoryMaxRows = map[string]int{}
	zero.RuleMaxRows = map[string]int{}
	for k, v := range input.Shape.CategoryMaxRows {
		zero.CategoryMaxRows[k] = v
	}
	for k, v := range input.Shape.RuleMaxRows {
		zero.RuleMaxRows[k] = v
	}
	zero.CategoryMaxRows[r.Kind] = 0
	for _, rule := range zero.Rules {
		if rule.Kind == r.Kind {
			zero.RuleMaxRows[rule.ID] = 0
		}
	}
	if e := checkOrderedSupplementRows(zero, []json.RawMessage{}); e != nil {
		t.Fatal(e)
	}
	if e := checkOrderedSupplementRows(zero, []json.RawMessage{row("unexpected")}); e == nil {
		t.Fatal("zero universe permitted a row")
	}
	fact[r.Fields[0]] = map[string]any{"not": "typed"}
	if e := checkOrderedSupplementRows(input.Shape, []json.RawMessage{row("bad")}); e == nil {
		t.Fatal("untyped value allowed")
	}
}
