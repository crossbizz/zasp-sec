package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func orderedCapacityPrefixMode(prefix, capacity string) (bool, error) {
	if prefix == "" {
		return false, nil
	}
	if (prefix != "1" && prefix != "3") || capacity != "100" {
		return false, errors.New("invalid prefix mode")
	}
	return true, nil
}

func orderedCapacityPrefixCallbackValid(mode string, callbacks []func(string, func() int32)) bool {
	return mode == "" && len(callbacks) == 0 || (mode == "1" || mode == "3") && len(callbacks) == 1 && callbacks[0] != nil
}

// A successful ack query only arms this tracer. Cancellation occurs at the next
// different device's preparation, after the serial product has committed and
// validated the preceding acknowledgement. The native oracle checks both sides.
type orderedCapacityPrefixTrace struct {
	targetLimit             int // Zero retains the original one-target observer.
	next                    pgx.QueryTracer
	start                   orchestration.StartRequest
	step                    string
	cancel                  context.CancelFunc
	mu                      sync.Mutex
	firstDevice, nextDevice string
	armed, stopped          bool
	invalid                 bool
	began, ended            time.Time
	devices                 []string
	targetBegan             time.Time
	walls                   []time.Duration
	timings                 []orderedCapacityPrefixTiming
}
type orderedCapacityPrefixAckKey struct{}
type orderedCapacityPrefixTimingKey struct{}
type orderedCapacityPrefixTiming struct {
	ordinal      int
	phase, class string
	began        time.Time
	elapsed      time.Duration
}

func (p *orderedCapacityPrefixTrace) request(v any) (workerOrderedPolicyRequest, string, bool) {
	var raw []byte
	switch b := v.(type) {
	case json.RawMessage:
		raw = b
	case []byte:
		raw = b
	default:
		return workerOrderedPolicyRequest{}, "", false
	}
	var q workerOrderedPolicyRequest
	var payload struct {
		Device string `json:"device_id"`
		Phase  string `json:"phase"`
	}
	if json.Unmarshal(raw, &q) != nil || json.Unmarshal(q.Payload, &payload) != nil || payload.Device == "" ||
		q.OrganizationID != p.start.Ref.OrganizationID || q.WorkspaceID != p.start.Ref.WorkspaceID || q.EnvironmentID != p.start.Ref.EnvironmentID || q.RunID != p.start.Ref.RunID || q.StepID != p.step || q.Generation != 1 {
		return q, "", false
	}
	if q.Operation == "ack" && payload.Phase != "apply" {
		return q, "", false
	}
	return q, payload.Device, true
}
func (p *orderedCapacityPrefixTrace) TraceQueryStart(ctx context.Context, c *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	p.mu.Lock()
	limit := p.targetLimit
	if limit == 0 {
		limit = 1
	}
	if limit != 1 && limit != 3 {
		p.invalid = true
	}
	if ctx.Err() == nil && !p.stopped && !p.invalid {
		op := ""
		if len(q.Args) > 0 {
			op, _ = q.Args[0].(string)
		}
		if q.SQL == `SELECT zasp_authorization80_worker.prepare_ordered68_policy($1,$2::jsonb)` && len(q.Args) == 2 && op == "ordered68.application.source" {
			if request, device, ok := p.request(q.Args[1]); ok && request.Operation == "source" {
				seen := false
				for _, prior := range p.devices {
					if prior == device {
						seen = true
					}
				}
				if p.firstDevice == "" {
					p.firstDevice = device
					p.began = time.Now()
					p.targetBegan = p.began
					p.devices = append(p.devices, device)
				} else if p.armed && !seen {
					now := time.Now()
					p.walls = append(p.walls, now.Sub(p.targetBegan))
					if len(p.devices) == limit {
						p.nextDevice, p.stopped, p.ended = device, true, now
						p.cancel()
					} else {
						p.devices = append(p.devices, device)
						p.targetBegan, p.armed = now, false
					}
				} else {
					p.invalid = true
				}
			} else {
				p.invalid = true
			}
		}
		if q.SQL == `SELECT zasp_temporal68.delivery($1::jsonb)` && len(q.Args) == 1 {
			if request, device, ok := p.request(q.Args[0]); ok && request.Operation == "ack" && len(p.devices) > 0 && device == p.devices[len(p.devices)-1] {
				ctx = context.WithValue(ctx, orderedCapacityPrefixAckKey{}, len(p.devices))
			}
		}
	}
	// Ordinal zero is setup/initial Apply, never a target latency sample. The
	// cancelled next capture is excluded; its downstream tracer still sees cancel.
	if ctx.Err() == nil && !p.stopped && !p.invalid {
		phase := orderedCapacityTraceLabel(q.SQL, q.Args)
		if phase == "" {
			phase = orderedTestTraceLabel(q.SQL, q.Args)
		}
		if phase != "" {
			ctx = context.WithValue(ctx, orderedCapacityPrefixTimingKey{}, orderedCapacityPrefixTiming{ordinal: len(p.devices), phase: phase, began: time.Now()})
		}
	}
	p.mu.Unlock()
	if p.next != nil {
		ctx = p.next.TraceQueryStart(ctx, c, q)
	}
	return ctx
}
func (p *orderedCapacityPrefixTrace) TraceQueryEnd(ctx context.Context, c *pgx.Conn, q pgx.TraceQueryEndData) {
	p.mu.Lock()
	if ack, _ := ctx.Value(orderedCapacityPrefixAckKey{}).(int); ack > 0 && ack == len(p.devices) && q.Err == nil && ctx.Err() == nil && !p.stopped && !p.invalid {
		p.armed = true
	}
	if call, ok := ctx.Value(orderedCapacityPrefixTimingKey{}).(orderedCapacityPrefixTiming); ok {
		call.elapsed, call.class = time.Since(call.began), orderedCapacityClass(q.Err)
		if len(p.timings) >= 1000 {
			p.invalid = true
		} else {
			p.timings = append(p.timings, call)
		}
	}
	p.mu.Unlock()
	if p.next != nil {
		p.next.TraceQueryEnd(ctx, c, q)
	}
}

func assertOrderedCapacityPrefix(t *testing.T, ctx context.Context, owner *pgxpool.Pool, product *temporalSecurityAgentProduct, start orchestration.StartRequest, step string, calls func() int32, trace *orderedCapacityTrace, config workerRuntimeConfig, checker authorization.Checker, login string) {
	t.Helper()
	mode := os.Getenv("ZASP_P7_ORDERED_POLICY_PREFIX")
	if valid, err := orderedCapacityPrefixMode(mode, "100"); err != nil || !valid {
		t.Fatal("explicit closed prefix mode required")
	}
	limit := 1
	if mode == "3" {
		limit = 3
	}
	profileCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	stop := &orderedCapacityPrefixTrace{targetLimit: limit, next: trace, start: start, step: step, cancel: cancel}
	var tracking string
	var baseline int64
	if err := owner.QueryRow(ctx, `SELECT current_setting('track_functions'),coalesce((SELECT sum(calls)::bigint FROM pg_stat_user_functions),0)`).Scan(&tracking, &baseline); err != nil || tracking != "none" || baseline != 0 {
		t.Fatal("prefix requires isolated untracked database")
	}
	// Only newly opened, pinned sockets track functions. Defaults are restored
	// before product binding; replacement sockets must refuse rather than silently
	// lose coverage. All preceding/projector sockets remain untracked.
	pools := make([]*pgxpool.Pool, 0, 2)
	defer func() {
		for _, p := range pools {
			p.Close()
		}
	}()
	for _, principal := range []string{login, "temporal_compensation_test_login"} {
		pools = append(pools, orderedCapacityPrefixPool(t, ctx, owner, principal, stop))
	}
	copyProduct := *product
	database := func(pool *pgxpool.Pool) apiserver.JSONDatabase {
		d, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
		if err != nil {
			t.Fatal("prefix database construction")
		}
		return d
	}
	copyProduct.executor, copyProduct.compensation = database(pools[0]), database(pools[1])
	if err := bindTemporalWorkerAuthorization(ctx, config, checker, &copyProduct, pools); err != nil {
		t.Fatal("prefix actual product binding", orderedCapacityClass(err))
	}
	// Flush setup work before resetting this isolated fixture's counters. Holding
	// both sockets at once makes the flush exhaustive, not a pool lottery.
	for _, pool := range pools {
		func() {
			var held []*pgxpool.Conn
			defer func() {
				for _, c := range held {
					c.Release()
				}
			}()
			for range 2 {
				c, err := pool.Acquire(ctx)
				if err != nil {
					t.Fatal("prefix flush acquire")
				}
				held = append(held, c)
				if _, err = c.Exec(ctx, `SELECT pg_stat_force_next_flush()`); err != nil {
					t.Fatal("prefix setup flush")
				}
			}
		}()
	}
	if _, err := owner.Exec(ctx, `SELECT pg_stat_reset()`); err != nil {
		t.Fatal("prefix isolated statistics reset")
	}
	if err := owner.QueryRow(ctx, `SELECT coalesce(sum(calls),0)::bigint FROM pg_stat_user_functions`).Scan(&baseline); err != nil || baseline != 0 {
		t.Fatal("prefix statistics reset was not isolated")
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=100 AND bool_and(state='planned') FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=($1,$2,$3,$4,$5,'apply')`, start.Ref.OrganizationID, start.Ref.WorkspaceID, start.Ref.EnvironmentID, start.Ref.RunID, step).Scan(&exact); err != nil || !exact {
		t.Fatal("prefix requires actual hundred planned targets")
	}
	// Match the function-statistics window: binding/prewarming is not Apply.
	stop.mu.Lock()
	stop.timings = nil
	stop.mu.Unlock()
	began := time.Now()
	err := copyProduct.Apply(profileCtx, start)
	elapsed := time.Since(began)
	for _, pool := range pools {
		pool.Close()
	}
	orderedCapacityPrefixStats(t, ctx, owner)
	stop.mu.Lock()
	stopped, first, next, wall, invalid := stop.stopped, stop.firstDevice, stop.nextDevice, stop.ended.Sub(stop.began), stop.invalid
	devices := append([]string(nil), stop.devices...)
	walls := append([]time.Duration(nil), stop.walls...)
	timings := append([]orderedCapacityPrefixTiming(nil), stop.timings...)
	stop.mu.Unlock()
	t.Log("prefix direct Apply elapsed_ms", elapsed.Milliseconds(), "expected_targets", limit, "completed_targets", len(walls), "targets_wall_ms", wall.Milliseconds(), "class", orderedCapacityClass(err), "signer_calls", calls())
	for ordinal, duration := range walls {
		t.Log("prefix target", ordinal+1, "wall_ms", duration.Milliseconds())
	}
	for _, call := range timings {
		t.Log("prefix SQL ordinal", call.ordinal, "phase", call.phase, "elapsed_us", call.elapsed.Microseconds(), "class", call.class)
	}
	if !stopped || invalid || len(devices) != limit || len(walls) != limit || first == "" || next == "" || first == next || !errors.Is(err, context.Canceled) || calls() != int32(2*limit) {
		t.Fatal("prefix did not reach the exact validated next-target boundary")
	}
	bounded, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()
	if err := owner.QueryRow(bounded, `WITH targets AS (
 SELECT * FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=($1,$2,$3,$4,$5,'apply')
 ), deliveries AS (
 SELECT * FROM zasp_temporal68.deliveries WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=($1,$2,$3,$4,$5,'apply')
 ), scopes AS (
 SELECT * FROM zasp_authorization80_worker.ordered_policy_scope WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)
 ) SELECT
 (SELECT count(*)=100 AND count(*) FILTER(WHERE state='planned')=100-$7::int AND count(*) FILTER(WHERE state='stored' AND device_id=ANY($6::text[]))=$7 AND count(*) FILTER(WHERE state='verified')=0 FROM targets)
 AND (SELECT count(*)=$7 AND count(DISTINCT device_id)=$7 AND bool_and(device_id=ANY($6::text[]) AND state='acknowledged' AND read_at IS NOT NULL AND acknowledged_at IS NOT NULL) FROM deliveries)
 AND (SELECT count(*)=$7 FROM targets t JOIN deliveries d USING(organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id,credential_id,desired_generation) WHERE t.device_id=ANY($6::text[]) AND d.generation=1 AND d.source_sequence=t.sequence AND d.source_digest=t.envelope_digest)
 AND (SELECT count(*)=3*$7 AND bool_and(device_id=ANY($6::text[])) FROM scopes)
 AND (SELECT count(*)=$7 AND bool_and(n=3 AND ops=3) FROM (SELECT device_id,count(*) n,count(DISTINCT operation) ops FROM scopes GROUP BY device_id) s)
 AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5) AND receipt_kind='temporary_policy_applied.v1')
 AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5))
 AND EXISTS(SELECT 1 FROM zasp_temporal68.effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5) AND state='started' AND jsonb_array_length(snapshot->'targets')=100)
 AND EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4) AND plan->'steps'->0->>'ttl_seconds'='600')
 AND NOT zasp_authorization80_worker.runtime_ready()`, start.Ref.OrganizationID, start.Ref.WorkspaceID, start.Ref.EnvironmentID, start.Ref.RunID, step, devices, limit).Scan(&exact); err != nil || !exact {
		t.Fatal("prefix persisted exact-source ack no-next-capture oracle failed", orderedCapacityClass(err))
	}
	t.Log("prefix native oracle: actual_targets", 100, "stored", limit, "planned", 100-limit, "verified", 0, "acknowledged", limit, "policy_scopes", 3*limit, "signatures", calls(), "application_receipts", 0, "controls", 0, "diagnostic only")
}

func orderedCapacityPrefixPool(t *testing.T, ctx context.Context, owner *pgxpool.Pool, login string, tracer pgx.QueryTracer) *pgxpool.Pool {
	t.Helper()
	if login == "" {
		t.Fatal("prefix registered login required")
	}
	var prior *string
	if err := owner.QueryRow(ctx, `SELECT (SELECT split_part(v,'=',2) FROM unnest(rolconfig) v WHERE v LIKE 'track_functions=%') FROM pg_roles WHERE rolname=$1`, login).Scan(&prior); err != nil || prior != nil && *prior != "none" {
		t.Fatal("prefix login default is not untracked")
	}
	restore := "ALTER ROLE " + pgx.Identifier{login}.Sanitize() + " RESET track_functions"
	if prior != nil {
		restore = "ALTER ROLE " + pgx.Identifier{login}.Sanitize() + " SET track_functions TO 'none'"
	}
	restored := false
	defer func() {
		if !restored {
			bounded, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := owner.Exec(bounded, restore); err != nil {
				t.Error("prefix role default restoration failed")
			}
		}
	}()
	if _, err := owner.Exec(ctx, "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" SET track_functions TO 'all'"); err != nil {
		t.Fatal("prefix tracking enable")
	}
	cfg := orderedCapacityPrefixPoolConfig(owner.Config(), login, tracer)
	var opened atomic.Int32
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		if opened.Add(1) > 2 {
			return errOrderedPrefixReplacement
		}
		var mode, principal string
		if err := c.QueryRow(ctx, `SELECT current_setting('track_functions'),session_user`).Scan(&mode, &principal); err != nil {
			return errors.Join(errOrderedPrefixVerification, err)
		}
		if mode != "all" || principal != login {
			return errOrderedPrefixAuthority
		}
		return nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("prefix tracked pool")
	}
	t.Cleanup(pool.Close)
	var held []*pgxpool.Conn
	defer func() {
		for _, c := range held {
			c.Release()
		}
	}()
	for range 2 {
		c, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal("prefix socket prewarm", "class", orderedCapacityPrefixSetupClass(err), "opened", opened.Load(), "lifetime_retired", pool.Stat().MaxLifetimeDestroyCount(), "idle_retired", pool.Stat().MaxIdleDestroyCount())
		}
		held = append(held, c)
	}
	if _, err := owner.Exec(ctx, restore); err != nil {
		t.Fatal("prefix immediate role restoration")
	}
	restored = true
	return pool
}

func orderedCapacityPrefixPoolConfig(owner *pgxpool.Config, login string, tracer pgx.QueryTracer) *pgxpool.Config {
	cfg := owner.Copy()
	cfg.ConnConfig.User = login
	cfg.ConnConfig.Tracer = tracer
	cfg.MaxConns = 2
	cfg.MinConns = 0
	// pgx5.10 treats zero lifetime as immediate expiry, not disabled recycling.
	// These sockets must outlive the entire four-minute diagnostic observer.
	cfg.MaxConnLifetime = 10 * time.Minute
	cfg.MaxConnIdleTime = 10 * time.Minute
	return cfg
}

var (
	errOrderedPrefixReplacement  = errors.New("prefix replacement socket")
	errOrderedPrefixVerification = errors.New("prefix socket verification")
	errOrderedPrefixAuthority    = errors.New("prefix socket authority")
)

func orderedCapacityPrefixSetupClass(err error) string {
	for _, entry := range []struct {
		err   error
		class string
	}{
		{errOrderedPrefixReplacement, "replacement-socket"},
		{errOrderedPrefixVerification, "socket-verification"},
		{errOrderedPrefixAuthority, "socket-authority"},
	} {
		if errors.Is(err, entry.err) {
			return entry.class
		}
	}
	return orderedCapacityClass(err)
}

func orderedCapacityPrefixStats(t *testing.T, ctx context.Context, owner *pgxpool.Pool) {
	t.Helper()
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := owner.Exec(bounded, `SELECT pg_stat_clear_snapshot()`); err != nil {
		t.Fatal("prefix statistics snapshot")
	}
	rows, err := owner.Query(bounded, `SELECT funcid::bigint,schemaname,funcname,pg_get_function_identity_arguments(funcid),calls,total_time,self_time FROM pg_stat_user_functions WHERE calls>0 ORDER BY self_time DESC,schemaname,funcname,funcid LIMIT 1000`)
	if err != nil {
		t.Fatal("prefix statistics unavailable")
	}
	defer rows.Close()
	safe := regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	safeArguments := regexp.MustCompile(`^[A-Za-z0-9_., \[\]"()]*$`)
	count := 0
	for rows.Next() {
		var schema, name, arguments string
		var oid, calls int64
		var total, self float64
		if rows.Scan(&oid, &schema, &name, &arguments, &calls, &total, &self) != nil || !safe.MatchString(schema) || !safe.MatchString(name) || len(arguments) > 2048 || !safeArguments.MatchString(arguments) {
			t.Fatal("unsafe statistics shape")
		}
		t.Logf("prefix function oid=%d schema=%s name=%s identity_arguments=%q calls=%d total_ms=%.3f self_ms=%.3f", oid, schema, name, arguments, calls, total, self)
		count++
	}
	if rows.Err() != nil || count == 0 || count == 1000 {
		t.Fatal("prefix statistics incomplete")
	}
	t.Log("prefix statistics cover whole direct Apply prefix, including inspect/reserve/start replay; absent SQL functions may be inlined, not zero-cost; inclusive times must not be summed")
}
