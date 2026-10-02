package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestGlobalExecutionControlStrictResult(t *testing.T) {
	for _, body := range []string{
		`{}`, `null`, `[]`, `true`, `{"version":2,"replayed":false}`,
		`{"enabled":null,"version":2,"replayed":false}`, `{"enabled":false,"version":null,"replayed":false}`, `{"enabled":false,"version":2,"replayed":null}`,
		`{"enabled":false,"version":2}`, `{"enabled":false,"replayed":false}`,
		`{"enabled":false,"version":2,"replayed":false,"extra":0}`,
		`{"Enabled":false,"version":2,"replayed":false}`, `{"enabled":false,"Version":2,"replayed":false}`, `{"enabled":false,"version":2,"Replayed":false}`,
		`{"enabled":false,"enabled":true,"version":2,"replayed":false}`, `{"enabled":false,"version":2,"version":3,"replayed":false}`, `{"enabled":false,"version":2,"replayed":false,"replayed":true}`,
		`{"enabled":"false","version":2,"replayed":false}`, `{"enabled":0,"version":2,"replayed":false}`, `{"enabled":false,"version":2,"replayed":"false"}`,
		`{"enabled":false,"version":"2","replayed":false}`, `{"enabled":false,"version":0,"replayed":false}`, `{"enabled":false,"version":-1,"replayed":false}`,
		`{"enabled":false,"version":2.0,"replayed":false}`, `{"enabled":false,"version":2e0,"replayed":false}`, `{"enabled":false,"version":9223372036854775808,"replayed":false}`,
		`{"enabled":false,"version":2,"replayed":false} {}`, `{"enabled":false,"version":2,"replayed":false} trailing`, `{"enabled":false,"version":2,"replayed":false`,
		strings.Repeat(" ", 1024) + `{"enabled":false,"version":2,"replayed":false}`,
	} {
		if result, err := decodeGlobalExecutionControlResult(body); err == nil || result != (GlobalExecutionControlResult{}) {
			t.Fatalf("accepted malformed result %q: %+v %v", body, result, err)
		}
	}
	for _, body := range []string{`{"enabled":false,"version":2,"replayed":false}`, ` {"replayed":false,"version":2,"enabled":false} `} {
		if result, err := decodeGlobalExecutionControlResult(body); err != nil || result != (GlobalExecutionControlResult{Version: 2}) {
			t.Fatal("valid result rejected", result, err)
		}
	}
	if result, err := decodeGlobalExecutionControlResult(`{"enabled":true,"version":9223372036854775807,"replayed":true}`); err != nil || !result.Enabled || !result.Replayed || result.Version != 1<<63-1 {
		t.Fatal("bounded integer result rejected", result, err)
	}
}

// A permissive decoder, wrong release pins or success before commit breaks this boundary.
func TestGlobalExecutionControlTransport(t *testing.T) {
	request := GlobalExecutionControlRequest{Enabled: false, ExpectedVersion: 1, RequestID: "pid_7f560001-0000-4000-8000-000000000001", CorrelationID: "global-stop-test"}
	for _, operation := range []string{"read", "set"} {
		for _, mode := range []string{"success", "replay", "malformed", "query-error", "begin-error", "commit-error", "rollback-error", "canceled", "nil-context"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				body := `{"enabled":false,"version":2,"replayed":false}`
				if mode == "malformed" {
					body = `{"version":2,"replayed":false}`
				}
				if mode == "replay" {
					body = `{"enabled":false,"version":2,"replayed":true}`
				}
				tx := &fakeTransaction{rows: []Row{fakeRow{values: []any{body}}}}
				db := &fakeDatabase{transaction: tx}
				privateErr := errors.New("postgres" + "://private:secret@host/internal SQL receipt")
				switch mode {
				case "begin-error":
					db.beginError = privateErr
				case "query-error":
					tx.queryErrorAt = 1
				case "commit-error":
					tx.commitError = privateErr
				case "rollback-error":
					tx.queryErrorAt = 1
					tx.rollbackError = privateErr
				}
				ctx := context.Background()
				if mode == "canceled" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				if mode == "nil-context" {
					ctx = nil
				}
				runner, _ := NewRunner(db)
				var got GlobalExecutionControlResult
				var err error
				if operation == "read" {
					got, err = runner.ReadGlobalExecutionControl(ctx)
				} else {
					got, err = runner.SetGlobalExecutionControl(ctx, request)
				}
				success := mode == "success" || mode == "replay"
				if (err == nil) != success {
					t.Fatalf("unexpected result %+v %v", got, err)
				}
				if !success && (got != (GlobalExecutionControlResult{}) || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "receipt")) {
					t.Fatal("failure exposed result or database detail", got, err)
				}
				events := strings.Join(db.events, "\n")
				if success && (!strings.Contains(events, "commit") || strings.Contains(events, "rollback") || got.Version != 2 || got.Enabled || got.Replayed != (mode == "replay")) {
					t.Fatal("success was not committed/validated", got, events)
				}
				if mode == "malformed" && (strings.Contains(events, "commit") || !strings.Contains(events, "rollback")) {
					t.Fatal("malformed result committed", events)
				}
				if tx.queries > 0 {
					wantSQL := globalReadSQL
					args := []any{ProductionSecurityAgentExistingTests().Checksum(), SecurityAgentExistingTestsFingerprint()}
					if operation == "set" {
						wantSQL = globalSetSQL
						args = append(args, false, int64(1), request.RequestID, request.CorrelationID)
					}
					if tx.queries != 1 || tx.execs != 0 || !strings.Contains(events, "query:"+wantSQL+"\n"+argumentEvent(args)) {
						t.Fatal("wrong SQL or positional authority/intent parameters", events)
					}
				}
			})
		}
	}
	for _, runner := range []*Runner{nil, {}} {
		if _, err := runner.ReadGlobalExecutionControl(context.Background()); !errors.Is(err, ErrInvalidRunner) {
			t.Fatal("nil reader accepted")
		}
		if _, err := runner.SetGlobalExecutionControl(context.Background(), request); !errors.Is(err, ErrInvalidRunner) {
			t.Fatal("nil writer accepted")
		}
	}
}
