package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type singleRecoveryRelayObservation struct {
	mu                                  sync.Mutex
	started                             time.Time
	failure, completed, class, sqlstate string
	current, elapsed, total             string
}

type singleRecoveryRelayObservationDatabaseWrapper struct {
	delegate    apiserver.JSONDatabase
	observation *singleRecoveryRelayObservation
}

func observeSingleTestRecoveryRelay(database apiserver.JSONDatabase, start func(context.Context, orchestration.SingleTestRecoveryRef) error) (*singleTestRecoveryRelay, *singleRecoveryRelayObservation) {
	observation := &singleRecoveryRelayObservation{started: time.Now(), failure: "none", completed: "none", class: "none", sqlstate: "none", elapsed: "lt1s", total: "lt1s"}
	wrapper := &singleRecoveryRelayObservationDatabaseWrapper{delegate: database, observation: observation}
	return &singleTestRecoveryRelay{database: wrapper, start: func(ctx context.Context, reference orchestration.SingleTestRecoveryRef) error {
		observation.begin("start")
		started := time.Now()
		err := start(ctx, reference)
		if err != nil {
			observation.fail("start", singleRecoveryRelayErrorClass(ctx, err, false), "none", time.Since(started))
		} else {
			observation.complete("start")
		}
		return err
	}}, observation
}

func (o *singleRecoveryRelayObservation) summary(err error) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err == nil && o.current == "pending" && o.failure == "none" {
		o.completed = "pending"
	}
	if err != nil && o.failure == "none" {
		o.failure = o.current
		if o.failure == "" {
			o.failure = "overall"
		}
		o.class = singleRecoveryRelayErrorClass(nil, err, o.failure == "pending" || o.failure == "attempt" || o.failure == "ack")
		o.sqlstate = "none"
		o.elapsed = singleRecoveryRelayElapsed(time.Since(o.started))
	}
	o.total = singleRecoveryRelayElapsed(time.Since(o.started))
	return fmt.Sprintf("recovery-relay failure=%s completed=%s class=%s sqlstate=%s elapsed=%s total=%s", o.failure, o.completed, o.class, o.sqlstate, o.elapsed, o.total)
}

func (o *singleRecoveryRelayObservation) begin(stage string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.current = stage
	if stage == "attempt" && o.failure == "none" {
		o.completed = "pending"
	}
}

func (o *singleRecoveryRelayObservation) complete(stage string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.completed = stage
}

func (o *singleRecoveryRelayObservation) fail(stage, class, sqlstate string, elapsed time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failure != "none" {
		return
	}
	o.failure, o.class, o.sqlstate, o.elapsed = stage, class, sqlstate, singleRecoveryRelayElapsed(elapsed)
}

func (d *singleRecoveryRelayObservationDatabaseWrapper) SchemaVersion(ctx context.Context) (string, error) {
	return d.delegate.SchemaVersion(ctx)
}

func (d *singleRecoveryRelayObservationDatabaseWrapper) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	stage := singleRecoveryRelayQueryStage(query)
	if stage == "" {
		return d.delegate.QueryJSON(ctx, query, args...)
	}
	d.observation.begin(stage)
	started := time.Now()
	raw, err := d.delegate.QueryJSON(ctx, query, args...)
	if err != nil {
		class, sqlstate := recoveryContentionQueryError(ctx, err)
		d.observation.fail(stage, class, sqlstate, time.Since(started))
		return raw, err
	}
	if stage == "attempt" || stage == "ack" {
		if strings.TrimSpace(string(raw)) == "true" {
			d.observation.complete(stage)
		} else {
			d.observation.fail(stage, "response", "none", time.Since(started))
		}
	}
	return raw, nil
}

func (d *singleRecoveryRelayObservationDatabaseWrapper) Exec(ctx context.Context, statement string, args ...any) error {
	return d.delegate.Exec(ctx, statement, args...)
}

func singleRecoveryRelayQueryStage(query string) string {
	switch query {
	case singleRecoveryPendingSQL:
		return "pending"
	case singleRecoveryAttemptSQL:
		return "attempt"
	case singleRecoveryAckSQL:
		return "ack"
	default:
		return ""
	}
}

func singleRecoveryRelayErrorClass(ctx context.Context, err error, response bool) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) || ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) || ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return "canceled"
	}
	if response && errors.Is(err, orchestration.ErrConflict) {
		return "response"
	}
	switch recoveryContentionResult(err) {
	case "conflict":
		return "conflict"
	case "unavailable":
		return "unavailable"
	case "invalid":
		return "invalid"
	default:
		return "other"
	}
}

type singleRecoveryRelayObservationCall struct {
	ctx   context.Context
	query string
	args  []any
	live  bool
}

type singleRecoveryRelayObservationStep struct {
	raw json.RawMessage
	err error
}

type singleRecoveryRelayObservationDatabase struct {
	steps map[string]singleRecoveryRelayObservationStep
	calls []singleRecoveryRelayObservationCall
}

func (*singleRecoveryRelayObservationDatabase) SchemaVersion(context.Context) (string, error) {
	return "fixed", nil
}

func (d *singleRecoveryRelayObservationDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	d.calls = append(d.calls, singleRecoveryRelayObservationCall{ctx: ctx, query: query, args: append([]any(nil), args...), live: ctx != nil && ctx.Err() == nil})
	step, ok := d.steps[query]
	if !ok {
		return json.RawMessage(`true`), nil
	}
	return step.raw, step.err
}

func (*singleRecoveryRelayObservationDatabase) Exec(context.Context, string, ...any) error {
	return nil
}

func singleRecoveryRelayObservationPending(t *testing.T) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal([]orchestration.SingleTestRecoveryRef{workerRecoveryRef()})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSingleRecoveryRelayObservationStagesAndDelegation(t *testing.T) {
	secret := "postgres" + "://private:secret@host/request-body"
	for _, test := range []struct {
		name        string
		steps       map[string]singleRecoveryRelayObservationStep
		start       error
		wantErr     error
		want        string
		wantQueries []string
	}{
		{
			name:        "pending query",
			steps:       map[string]singleRecoveryRelayObservationStep{singleRecoveryPendingSQL: {err: &pgconn.PgError{Code: "57014", Message: secret}}},
			wantErr:     orchestration.ErrUnavailable,
			want:        "recovery-relay failure=pending completed=none class=query sqlstate=57014 elapsed=lt1s total=lt1s",
			wantQueries: []string{singleRecoveryPendingSQL},
		},
		{
			name:        "pending response",
			steps:       map[string]singleRecoveryRelayObservationStep{singleRecoveryPendingSQL: {raw: json.RawMessage(`null`)}},
			wantErr:     orchestration.ErrConflict,
			want:        "recovery-relay failure=pending completed=none class=response sqlstate=none elapsed=lt1s total=lt1s",
			wantQueries: []string{singleRecoveryPendingSQL},
		},
		{
			name:        "attempt query",
			steps:       map[string]singleRecoveryRelayObservationStep{singleRecoveryPendingSQL: {raw: singleRecoveryRelayObservationPending(t)}, singleRecoveryAttemptSQL: {err: &pgconn.PgError{Code: "40001", Message: secret}}},
			wantErr:     orchestration.ErrConflict,
			want:        "recovery-relay failure=attempt completed=pending class=query sqlstate=40001 elapsed=lt1s total=lt1s",
			wantQueries: []string{singleRecoveryPendingSQL, singleRecoveryAttemptSQL},
		},
		{
			name:        "start dependency",
			steps:       map[string]singleRecoveryRelayObservationStep{singleRecoveryPendingSQL: {raw: singleRecoveryRelayObservationPending(t)}, singleRecoveryAttemptSQL: {raw: json.RawMessage(`true`)}},
			start:       orchestration.ErrUnavailable,
			wantErr:     orchestration.ErrUnavailable,
			want:        "recovery-relay failure=start completed=attempt class=unavailable sqlstate=none elapsed=lt1s total=lt1s",
			wantQueries: []string{singleRecoveryPendingSQL, singleRecoveryAttemptSQL},
		},
		{
			name:        "ack deadline",
			steps:       map[string]singleRecoveryRelayObservationStep{singleRecoveryPendingSQL: {raw: singleRecoveryRelayObservationPending(t)}, singleRecoveryAttemptSQL: {raw: json.RawMessage(`true`)}, singleRecoveryAckSQL: {err: context.DeadlineExceeded}},
			wantErr:     orchestration.ErrUnavailable,
			want:        "recovery-relay failure=ack completed=start class=deadline sqlstate=none elapsed=lt1s total=lt1s",
			wantQueries: []string{singleRecoveryPendingSQL, singleRecoveryAttemptSQL, singleRecoveryAckSQL},
		},
		{
			name:        "complete",
			steps:       map[string]singleRecoveryRelayObservationStep{singleRecoveryPendingSQL: {raw: singleRecoveryRelayObservationPending(t)}, singleRecoveryAttemptSQL: {raw: json.RawMessage(`true`)}, singleRecoveryAckSQL: {raw: json.RawMessage(`true`)}},
			want:        "recovery-relay failure=none completed=ack class=none sqlstate=none elapsed=lt1s total=lt1s",
			wantQueries: []string{singleRecoveryPendingSQL, singleRecoveryAttemptSQL, singleRecoveryAckSQL},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := &singleRecoveryRelayObservationDatabase{steps: test.steps}
			startCalls := 0
			var startContext context.Context
			startLive := false
			relay, observation := observeSingleTestRecoveryRelay(database, func(ctx context.Context, got orchestration.SingleTestRecoveryRef) error {
				startCalls++
				startContext = ctx
				startLive = ctx != nil && ctx.Err() == nil
				if got != workerRecoveryRef() {
					t.Fatal("start reference changed")
				}
				return test.start
			})
			err := relay.RunOnce(context.Background())
			if !errors.Is(err, test.wantErr) || (err == nil) != (test.wantErr == nil) {
				t.Fatalf("error=%v want=%v", err, test.wantErr)
			}
			if got := observation.summary(err); got != test.want || strings.Contains(got, secret) {
				t.Fatalf("summary=%q want=%q", got, test.want)
			}
			queries := make([]string, len(database.calls))
			for i, call := range database.calls {
				queries[i] = call.query
				if call.ctx == nil || !call.live {
					t.Fatal("query context changed")
				}
				if call.query != singleRecoveryPendingSQL && (len(call.args) != 1 || reflect.TypeOf(call.args[0]) != reflect.TypeOf(json.RawMessage{})) {
					t.Fatal("query arguments changed")
				}
			}
			if !reflect.DeepEqual(queries, test.wantQueries) {
				t.Fatalf("queries=%v want=%v", queries, test.wantQueries)
			}
			wantStarts := 0
			if test.name == "start dependency" || test.name == "ack deadline" || test.name == "complete" {
				wantStarts = 1
			}
			if startCalls != wantStarts || wantStarts == 1 && (startContext == nil || !startLive) {
				t.Fatal("start delegation changed")
			}
		})
	}
}

func TestSingleRecoveryRelayObservationUnknownAndElapsedBounds(t *testing.T) {
	database := &singleRecoveryRelayObservationDatabase{steps: map[string]singleRecoveryRelayObservationStep{"SELECT private($1)": {raw: json.RawMessage(`{"ok":true}`)}}}
	relay, observation := observeSingleTestRecoveryRelay(database, func(context.Context, orchestration.SingleTestRecoveryRef) error { return nil })
	observed := relay.database
	ctx := context.WithValue(context.Background(), struct{ key string }{"fixed"}, "preserved")
	raw, err := observed.QueryJSON(ctx, "SELECT private($1)", "fixed")
	if err != nil || string(raw) != `{"ok":true}` || len(database.calls) != 1 || database.calls[0].ctx != ctx || fmt.Sprint(database.calls[0].args) != "[fixed]" {
		t.Fatal("unknown query delegation changed")
	}
	if got := observation.summary(errors.New("private body")); strings.Contains(got, "private") || !strings.Contains(got, "failure=overall") || !strings.Contains(got, "class=other") {
		t.Fatalf("unknown error escaped or disappeared: %s", got)
	}
	for _, test := range []struct {
		duration time.Duration
		want     string
	}{{0, "lt1s"}, {time.Second, "lt5s"}, {5 * time.Second, "lt10s"}, {10 * time.Second, "lt30s"}, {30 * time.Second, "ge30s"}} {
		if got := singleRecoveryRelayElapsed(test.duration); got != test.want {
			t.Fatalf("elapsed(%s)=%s want=%s", test.duration, got, test.want)
		}
	}
}

func singleRecoveryRelayElapsed(elapsed time.Duration) string {
	switch {
	case elapsed < time.Second:
		return "lt1s"
	case elapsed < 5*time.Second:
		return "lt5s"
	case elapsed < 10*time.Second:
		return "lt10s"
	case elapsed < 30*time.Second:
		return "lt30s"
	default:
		return "ge30s"
	}
}
