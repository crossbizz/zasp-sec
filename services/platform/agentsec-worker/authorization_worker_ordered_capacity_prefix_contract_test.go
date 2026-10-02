package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func TestOrderedCapacityPrefixSocketsOutliveObserver(t *testing.T) {
	owner, err := pgxpool.ParseConfig("postgres://owner@127.0.0.1/fixture")
	if err != nil {
		t.Fatal(err)
	}
	originalLifetime, originalIdle := owner.MaxConnLifetime, owner.MaxConnIdleTime
	cfg := orderedCapacityPrefixPoolConfig(owner, "registered", nil)
	began := time.Now()
	observerEnd := began.Add(4 * time.Minute)
	// Pinned pgx constructs maxAgeTime as creation+lifetime and destroys a
	// socket on Acquire once that time passes. Zero means immediate expiry.
	if !began.Add(cfg.MaxConnLifetime).After(observerEnd) || cfg.MaxConnIdleTime <= 4*time.Minute {
		t.Fatal("tracked sockets retire before diagnostic observer can finish")
	}
	if owner.ConnConfig.User != "owner" || owner.MaxConnLifetime != originalLifetime || owner.MaxConnIdleTime != originalIdle {
		t.Fatal("profiler changed original pool ownership/configuration")
	}
	if cfg.ConnConfig.User != "registered" || cfg.MaxConns != 2 {
		t.Fatal("tracked pool registration or socket bound changed")
	}
}

func TestOrderedCapacityPrefixSetupClassesAreRedacted(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{errOrderedPrefixReplacement, "replacement-socket"},
		{errors.Join(errOrderedPrefixVerification, errors.New("secret connection details")), "socket-verification"},
		{errOrderedPrefixAuthority, "socket-authority"},
		{context.DeadlineExceeded, "deadline"},
		{errors.New("secret connection details"), "other"},
	} {
		if orderedCapacityPrefixSetupClass(c.err) != c.want {
			t.Fatal("setup error escaped redacted classes")
		}
	}
}

func TestOrderedCapacityPrefixMode(t *testing.T) {
	for _, c := range []struct {
		prefix, capacity string
		want, invalid    bool
	}{
		{"", "", false, false}, {"", "100", false, false}, {"1", "100", true, false},
		{"3", "100", true, false}, {"2", "100", false, true}, {"4", "100", false, true},
		{"1", "", false, true}, {"yes", "100", false, true}, {"1", "99", false, true},
	} {
		got, err := orderedCapacityPrefixMode(c.prefix, c.capacity)
		if got != c.want || (err != nil) != c.invalid {
			t.Fatal("prefix selection did not fail closed")
		}
	}
}

type orderedPrefixDownstream struct{ cancelled bool }

func (d *orderedPrefixDownstream) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	d.cancelled = ctx.Err() != nil
	return ctx
}
func (*orderedPrefixDownstream) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestOrderedCapacityPrefixStopsOnlyAfterAcknowledgedDifferentTarget(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		ack, fail, foreign, same bool
		want                     bool
	}{
		{name: "committed-boundary", ack: true, want: true},
		{name: "missing-ack"}, {name: "failed-ack", ack: true, fail: true},
		{name: "foreign-ack", ack: true, foreign: true}, {name: "same-target", ack: true, same: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			start := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: "org", WorkspaceID: "workspace", EnvironmentID: "environment", RunID: "run"}}
			downstream := &orderedPrefixDownstream{}
			p := &orderedCapacityPrefixTrace{start: start, step: "step", cancel: cancel, next: downstream}
			request := func(device, run, operation string) json.RawMessage {
				b, err := json.Marshal(map[string]any{"organization_id": "org", "workspace_id": "workspace", "environment_id": "environment", "run_id": run, "step_id": "step", "generation": 1, "operation": operation, "payload": map[string]any{"device_id": device, "phase": "apply"}})
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			prepare := func(device string) {
				p.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: `SELECT zasp_authorization80_worker.prepare_ordered68_policy($1,$2::jsonb)`, Args: []any{"ordered68.application.source", request(device, "run", "source")}})
			}
			prepare("device-a")
			if tc.ack {
				run := "run"
				if tc.foreign {
					run = "foreign"
				}
				ackctx := p.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: `SELECT zasp_temporal68.delivery($1::jsonb)`, Args: []any{request("device-a", run, "ack")}})
				var err error
				if tc.fail {
					err = errors.New("refused")
				}
				p.TraceQueryEnd(ackctx, nil, pgx.TraceQueryEndData{Err: err})
				if ctx.Err() != nil {
					t.Fatal("cancelled before repository acknowledgement validation")
				}
			}
			device := "device-b"
			if tc.same {
				device = "device-a"
			}
			prepare(device)
			if p.stopped != tc.want || (ctx.Err() != nil) != tc.want {
				t.Fatal("invalid prefix stop boundary")
			}
			if downstream.cancelled != tc.want {
				t.Fatal("downstream tracer did not receive cancellation before execution")
			}
			if tc.want {
				prepare("device-c")
				if p.nextDevice != "device-b" {
					t.Fatal("stop boundary overwritten")
				}
			}
		})
	}
}

func TestOrderedCapacityPrefixPrecancelledCannotPass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &orderedCapacityPrefixTrace{cancel: cancel, firstDevice: "first", armed: true}
	p.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: `SELECT zasp_authorization80_worker.prepare_ordered68_policy($1,$2::jsonb)`, Args: []any{"ordered68.application.source", json.RawMessage(`{}`)}})
	if p.stopped {
		t.Fatal("preexisting cancellation counted as a completed prefix")
	}
}

func TestOrderedCapacityPrefixCallbackBound(t *testing.T) {
	callback := func(string, func() int32) {}
	for _, tc := range []struct {
		mode      string
		callbacks []func(string, func() int32)
		want      bool
	}{
		{"", nil, true}, {"1", []func(string, func() int32){callback}, true},
		{"3", []func(string, func() int32){callback}, true}, {"3", nil, false},
		{"1", nil, false}, {"", []func(string, func() int32){callback}, false},
		{"1", []func(string, func() int32){nil}, false}, {"1", []func(string, func() int32){callback, callback}, false},
	} {
		if orderedCapacityPrefixCallbackValid(tc.mode, tc.callbacks) != tc.want {
			t.Fatal("callback selection could escape intended diagnostic mode")
		}
	}
}

func TestOrderedCapacityPrefixThreeAcknowledgementsBeforeFourthCapture(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	downstream := &orderedPrefixDownstream{}
	p := &orderedCapacityPrefixTrace{targetLimit: 3, start: orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: "org", WorkspaceID: "workspace", EnvironmentID: "environment", RunID: "run"}}, step: "step", cancel: cancel, next: downstream}
	setup := p.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: `SELECT zasp_authorization80_worker.revision($1)`, Args: []any{"private-org"}})
	p.TraceQueryEnd(setup, nil, pgx.TraceQueryEndData{})
	request := func(device, operation string) json.RawMessage {
		b, err := json.Marshal(map[string]any{"organization_id": "org", "workspace_id": "workspace", "environment_id": "environment", "run_id": "run", "step_id": "step", "generation": 1, "operation": operation, "payload": map[string]any{"device_id": device, "phase": "apply"}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for index, device := range []string{"a", "b", "c"} {
		qctx := p.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: `SELECT zasp_authorization80_worker.prepare_ordered68_policy($1,$2::jsonb)`, Args: []any{"ordered68.application.source", request(device, "source")}})
		p.TraceQueryEnd(qctx, nil, pgx.TraceQueryEndData{})
		if ctx.Err() != nil || p.invalid {
			t.Fatal("three-target observer stopped before three genuine acknowledgement boundaries")
		}
		revision := p.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: `SELECT zasp_authorization80_worker.revision($1)`, Args: []any{"private-org"}})
		p.TraceQueryEnd(revision, nil, pgx.TraceQueryEndData{})
		ackctx := p.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: `SELECT zasp_temporal68.delivery($1::jsonb)`, Args: []any{request(device, "ack")}})
		p.TraceQueryEnd(ackctx, nil, pgx.TraceQueryEndData{})
		if ctx.Err() != nil {
			t.Fatal("observer cancelled before product can commit and validate acknowledgement")
		}
		if len(p.timings) != 1+3*(index+1) {
			t.Fatal("timing missed a completed SQL call")
		}
		for _, call := range p.timings[1+3*index:] {
			if call.ordinal != index+1 || call.elapsed < 0 || call.phase == "" || call.class != "ok" {
				t.Fatalf("incorrect target timing attribution: ordinal=%d phase=%q class=%q", call.ordinal, call.phase, call.class)
			}
		}
	}
	p.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: `SELECT zasp_authorization80_worker.prepare_ordered68_policy($1,$2::jsonb)`, Args: []any{"ordered68.application.source", request("d", "source")}})
	if !p.stopped || p.invalid || !downstream.cancelled || p.nextDevice != "d" {
		t.Fatal("fourth capture was not cancelled before execution")
	}
	if len(p.timings) != 10 || p.timings[0].ordinal != 0 || p.timings[0].phase != "authorize/revision" || len(p.walls) != 3 || len(p.devices) != 3 {
		t.Fatal("setup or cancelled next capture contaminated target timing")
	}
}

func TestOrderedCapacityPrefixThreeRefusesIncompleteOrRepeatedBoundaries(t *testing.T) {
	for _, mode := range []string{"missing-ack", "failed-ack", "foreign-ack", "old-target", "stale-ack", "invalid-limit"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := &orderedCapacityPrefixTrace{targetLimit: 3, start: orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: "org", WorkspaceID: "workspace", EnvironmentID: "environment", RunID: "run"}}, step: "step", cancel: cancel}
			if mode == "invalid-limit" {
				p.targetLimit = 2
			}
			request := func(device, run, operation string) json.RawMessage {
				b, err := json.Marshal(map[string]any{"organization_id": "org", "workspace_id": "workspace", "environment_id": "environment", "run_id": run, "step_id": "step", "generation": 1, "operation": operation, "payload": map[string]any{"device_id": device, "phase": "apply"}})
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			prepare := func(device string) {
				p.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: `SELECT zasp_authorization80_worker.prepare_ordered68_policy($1,$2::jsonb)`, Args: []any{"ordered68.application.source", request(device, "run", "source")}})
			}
			ack := func(device, run string) context.Context {
				return p.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: `SELECT zasp_temporal68.delivery($1::jsonb)`, Args: []any{request(device, run, "ack")}})
			}
			prepare("a")
			oldAck := ack("a", "run")
			p.TraceQueryEnd(oldAck, nil, pgx.TraceQueryEndData{})
			prepare("b")
			switch mode {
			case "failed-ack":
				p.TraceQueryEnd(ack("b", "run"), nil, pgx.TraceQueryEndData{Err: errors.New("refused")})
			case "foreign-ack":
				p.TraceQueryEnd(ack("b", "foreign"), nil, pgx.TraceQueryEndData{})
			case "old-target":
				p.TraceQueryEnd(ack("b", "run"), nil, pgx.TraceQueryEndData{})
				prepare("a")
			case "stale-ack":
				p.TraceQueryEnd(oldAck, nil, pgx.TraceQueryEndData{})
			}
			prepare("c")
			if !p.invalid || p.stopped || ctx.Err() != nil {
				t.Fatal("invalid sequence counted as completed measurement")
			}
		})
	}
}

func TestOrderedCapacityPrefixTimingsClosedAndBounded(t *testing.T) {
	p := &orderedCapacityPrefixTrace{}
	ctx := context.Background()
	unknown := p.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: "SELECT private_secret", Args: []any{"private argument"}})
	p.TraceQueryEnd(unknown, nil, pgx.TraceQueryEndData{Err: errors.New("private error")})
	if len(p.timings) != 0 {
		t.Fatal("unknown SQL entered timing output")
	}
	for range 1001 {
		qctx := p.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: `SELECT zasp_authorization80_worker.revision($1)`, Args: []any{"private argument"}})
		p.TraceQueryEnd(qctx, nil, pgx.TraceQueryEndData{Err: errors.New("private error")})
	}
	if !p.invalid || len(p.timings) != 1000 {
		t.Fatal("timing bounds did not fail closed")
	}
	for _, call := range p.timings {
		if call.ordinal != 0 || call.phase != "authorize/revision" || call.class != "other" {
			t.Fatal("timing output leaked non-allowlisted data")
		}
	}
}
