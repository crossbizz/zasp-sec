package apiserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Native-only observation: callbacks perform no I/O and cannot select SQL,
// return results, change errors, extend deadlines or grant authority.
type pkceNativeObservation struct {
	mu                      sync.Mutex
	enabled                 bool
	generation              uint64
	leaseMS, providerMS     int64
	leaseLive, providerLive bool
	phases                  [8]pkceNativePhase
}
type pkceNativePhase struct {
	count                                           int
	elapsedMS, maxMS                                int64
	failed, contextDone, deadline, canceled, capped bool
	sqlState                                        string
}
type pkceNativeTraceStamp struct {
	generation uint64
	phase      int
	started    time.Time
}
type pkceNativeQueryKey struct{}
type pkceNativeAcquireKey struct{}

const pkceNativeMaxMS int64 = 120000

var pkceNativePhases = [8]string{"pool-acquire", "tx-begin", "set-role", "source", "revision", "begin-attempt", "commit", "rollback"}
var _ pgx.QueryTracer = (*pkceNativeObservation)(nil)
var _ pgxpool.AcquireTracer = (*pkceNativeObservation)(nil)

func pkceNativeBoundMS(d time.Duration) int64 {
	n := d.Milliseconds()
	if n < 0 {
		return 0
	}
	if n > pkceNativeMaxMS {
		return pkceNativeMaxMS
	}
	return n
}
func (o *pkceNativeObservation) start(lease, provider time.Time) {
	now := time.Now()
	o.mu.Lock()
	defer o.mu.Unlock()
	o.generation++
	o.enabled = true
	o.phases = [8]pkceNativePhase{}
	o.leaseMS = pkceNativeBoundMS(lease.Sub(now))
	o.providerMS = pkceNativeBoundMS(provider.Sub(now))
	o.leaseLive = lease.After(now)
	o.providerLive = provider.After(now)
}
func pkceNativeQueryPhase(sql string) int {
	switch sql {
	case "begin isolation level read committed":
		return 1
	case "SET LOCAL ROLE zasp_outbox_worker":
		return 2
	case "SELECT zasp_connector_maintenance.source($1::jsonb,$2,$3)", "SELECT zasp_connector_maintenance.observation($1::jsonb,$2,$3)":
		return 3
	case "SELECT zasp_connector_maintenance.revision($1,$2,$3)":
		return 4
	case "SELECT zasp_connector_maintenance.begin_attempt($1::jsonb,$2,$3::json,$4,$5)":
		return 5
	case "commit":
		return 6
	case "rollback":
		return 7
	default:
		return -1
	}
}
func (o *pkceNativeObservation) stamp(ctx context.Context, key any, phase int) context.Context {
	if ctx == nil {
		return ctx
	}
	o.mu.Lock()
	active, generation := o.enabled, o.generation
	o.mu.Unlock()
	if !active {
		return ctx
	}
	return context.WithValue(ctx, key, pkceNativeTraceStamp{generation: generation, phase: phase, started: time.Now()})
}
func (o *pkceNativeObservation) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	// Arguments and arbitrary statements are never copied into an observation.
	return o.stamp(ctx, pkceNativeQueryKey{}, pkceNativeQueryPhase(data.SQL))
}
func (o *pkceNativeObservation) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	o.end(ctx, pkceNativeQueryKey{}, data.Err)
}
func (o *pkceNativeObservation) TraceAcquireStart(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireStartData) context.Context {
	return o.stamp(ctx, pkceNativeAcquireKey{}, 0)
}
func (o *pkceNativeObservation) TraceAcquireEnd(ctx context.Context, _ *pgxpool.Pool, data pgxpool.TraceAcquireEndData) {
	o.end(ctx, pkceNativeAcquireKey{}, data.Err)
}
func pkceNativeSQLState(err error) string {
	var p *pgconn.PgError
	if !errors.As(err, &p) || p == nil || len(p.Code) != 5 {
		return "none"
	}
	for _, r := range p.Code {
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z') {
			return "none"
		}
	}
	return p.Code
}
func (o *pkceNativeObservation) end(ctx context.Context, key any, err error) {
	if ctx == nil {
		return
	}
	stamp, ok := ctx.Value(key).(pkceNativeTraceStamp)
	if !ok || stamp.phase < 0 || stamp.phase >= len(o.phases) {
		return
	}
	elapsed := time.Since(stamp.started)
	ms := pkceNativeBoundMS(elapsed)
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.enabled || stamp.generation != o.generation {
		return
	}
	p := &o.phases[stamp.phase]
	if p.count >= 16 {
		p.capped = true
		return
	}
	p.count++
	if elapsed < 0 || elapsed.Milliseconds() > pkceNativeMaxMS || p.elapsedMS+ms > pkceNativeMaxMS {
		p.capped = true
	}
	p.elapsedMS += ms
	if p.elapsedMS > pkceNativeMaxMS {
		p.elapsedMS = pkceNativeMaxMS
	}
	if ms > p.maxMS {
		p.maxMS = ms
	}
	p.failed = p.failed || err != nil
	p.contextDone = p.contextDone || ctx.Err() != nil
	p.deadline = p.deadline || errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
	p.canceled = p.canceled || errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled)
	if state := pkceNativeSQLState(err); state != "none" && p.sqlState == "" {
		p.sqlState = state
	}
}
func (o *pkceNativeObservation) stop() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.enabled = false
	lines := []string{fmt.Sprintf("connector pkce budget initial_lease_ms=%d initial_provider_ms=%d lease_live=%t provider_live=%t", o.leaseMS, o.providerMS, o.leaseLive, o.providerLive)}
	for i, p := range o.phases {
		if p.count == 0 {
			continue
		}
		state := p.sqlState
		if state == "" {
			state = "none"
		}
		lines = append(lines, fmt.Sprintf("connector pkce phase=%s count=%d elapsed_ms=%d max_ms=%d failed=%t context_done=%t deadline=%t canceled=%t SQLSTATE=%s capped=%t", pkceNativePhases[i], p.count, p.elapsedMS, p.maxMS, p.failed, p.contextDone, p.deadline, p.canceled, state, p.capped))
	}
	return lines
}

func TestPKCENativeObservationBoundaries(t *testing.T) {
	t.Run("closed statements and no payload or error disclosure", func(t *testing.T) {
		o := &pkceNativeObservation{}
		o.start(time.Now().Add(time.Minute), time.Now().Add(time.Second))
		for _, sql := range []string{"private-secret-query", "commit; private-secret-query", "SELECT zasp_connector_maintenance.begin_attempt(secret)"} {
			ctx := o.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: sql, Args: []any{"private-secret-argument"}})
			o.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: &pgconn.PgError{Code: "XX000", Message: "private-secret-error"}})
		}
		if len(o.stop()) != 1 {
			t.Fatal("unknown SQL produced a phase")
		}
		o.start(time.Now().Add(time.Minute), time.Now().Add(time.Second))
		for _, sql := range []string{"begin isolation level read committed", "SET LOCAL ROLE zasp_outbox_worker", "SELECT zasp_connector_maintenance.source($1::jsonb,$2,$3)", "SELECT zasp_connector_maintenance.observation($1::jsonb,$2,$3)", "SELECT zasp_connector_maintenance.revision($1,$2,$3)", "SELECT zasp_connector_maintenance.begin_attempt($1::jsonb,$2,$3::json,$4,$5)", "commit", "rollback"} {
			ctx := o.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: sql, Args: []any{"private-secret-argument"}})
			o.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: &pgconn.PgError{Code: "57014", Message: "private-secret-error"}})
		}
		lines := o.stop()
		if len(lines) != 8 {
			t.Fatal("fixed phases were lost")
		}
		joined := strings.Join(lines, "\n")
		if strings.Contains(joined, "private-secret") || strings.Contains(joined, "SELECT ") || !strings.Contains(joined, "SQLSTATE=57014") {
			t.Fatal("diagnostic grammar or redaction changed")
		}
		if !strings.Contains(joined, "phase=source count=2 ") {
			t.Fatal("atomic source observation escaped its existing category")
		}
		if pkceNativeSQLState(&pgconn.PgError{Code: "secret"}) != "none" || pkceNativeSQLState(errors.New("private-secret-error")) != "none" {
			t.Fatal("arbitrary error became SQLSTATE")
		}
	})
	t.Run("context values deadlines cancellation and inactive delegation remain", func(t *testing.T) {
		type key struct{}
		parent, cancel := context.WithDeadline(context.WithValue(context.Background(), key{}, "original"), time.Now().Add(time.Minute))
		defer cancel()
		o := &pkceNativeObservation{}
		data := pgx.TraceQueryStartData{SQL: "commit"}
		if o.TraceQueryStart(parent, nil, data) != parent {
			t.Fatal("inactive hook changed context")
		}
		o.start(time.Now().Add(time.Minute), time.Now().Add(time.Second))
		ctx := o.TraceQueryStart(parent, nil, data)
		a, okA := parent.Deadline()
		b, okB := ctx.Deadline()
		if a != b || okA != okB || ctx.Value(key{}) != "original" {
			t.Fatal("context contract changed")
		}
		cancel()
		if ctx.Err() != parent.Err() {
			t.Fatal("parent cancellation lost")
		}
		err := errors.New("original failure")
		o.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: err})
		if !strings.Contains(strings.Join(o.stop(), "\n"), "context_done=true deadline=false canceled=true") {
			t.Fatal("cancellation not classified")
		}
		if err.Error() != "original failure" {
			t.Fatal("error mutated")
		}
	})
	t.Run("bounded aggregate cap and stale capture isolation", func(t *testing.T) {
		o := &pkceNativeObservation{}
		o.start(time.Now().Add(time.Hour), time.Now().Add(-time.Hour))
		old := o.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: "commit"})
		for i := 0; i < 20; i++ {
			ctx := context.WithValue(context.Background(), pkceNativeAcquireKey{}, pkceNativeTraceStamp{generation: o.generation, phase: 0, started: time.Now().Add(-time.Hour)})
			o.TraceAcquireEnd(ctx, nil, pgxpool.TraceAcquireEndData{Err: context.DeadlineExceeded})
		}
		lines := o.stop()
		if len(lines) != 2 || !strings.Contains(lines[0], "initial_lease_ms=120000 initial_provider_ms=0") || !strings.Contains(lines[1], "count=16 elapsed_ms=120000 max_ms=120000") || !strings.HasSuffix(lines[1], "capped=true") {
			t.Fatal("aggregate escaped bounds")
		}
		o.start(time.Now().Add(time.Second), time.Now().Add(time.Second))
		o.TraceQueryEnd(old, nil, pgx.TraceQueryEndData{})
		if len(o.stop()) != 1 {
			t.Fatal("previous capture contaminated next window")
		}
	})
}
