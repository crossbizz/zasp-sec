package apiserver

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type healthProbeDriver struct {
	mu        sync.Mutex
	calls     int
	queries   []string
	arguments [][]any
	refuse    bool
	query     func(context.Context, string, ...any) PostgresRow
}

func (d *healthProbeDriver) QueryRow(ctx context.Context, q string, args ...any) PostgresRow {
	d.mu.Lock()
	d.calls++
	d.queries = append(d.queries, q)
	d.arguments = append(d.arguments, append([]any(nil), args...))
	refuse := d.refuse
	d.mu.Unlock()
	if d.query != nil {
		return d.query(ctx, q, args...)
	}
	return healthProbeRow{refuse: refuse}
}
func (*healthProbeDriver) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected write")
}
func (*healthProbeDriver) Close() error { return nil }
func (*healthProbeDriver) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("unexpected product transaction")
}

type healthProbeRow struct{ refuse bool }

func (r healthProbeRow) Scan(dest ...any) error {
	if r.refuse {
		return errors.New("controlled metadata refusal")
	}
	for _, v := range dest {
		p, ok := v.(*bool)
		if !ok {
			return errors.New("unexpected metadata shape")
		}
		*p = true
	}
	return nil
}
func healthProbeDB(t *testing.T) (*PostgresJSONDatabase, *healthProbeDriver) {
	t.Helper()
	driver := &healthProbeDriver{}
	db, err := NewPostgresJSONDatabase(driver)
	if err != nil || db.RequireCurrentAuthorization() != nil {
		t.Fatal("fixture")
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, driver
}

func TestCurrentAuthorizationHealthProbeScope(t *testing.T) {
	core, cd := healthProbeDB(t)
	agent, ad := healthProbeDB(t)
	other, od := healthProbeDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var escaped context.Context
	err := WithCurrentAuthorizationHealthProbe(ctx, core, agent, strings.Repeat("a", 64), nil, func(probe context.Context) error {
		escaped = probe
		checksum, audit := authorizationRuntimeChecksums()
		for _, candidate := range []struct {
			driver *healthProbeDriver
			role   string
		}{{cd, "zasp_discovery_api"}, {ad, "zasp_security_agent_api"}} {
			if candidate.driver.calls != 1 || candidate.driver.queries[0] != postgresAuthorizationRuntimeReadySQL || !reflect.DeepEqual(candidate.driver.arguments[0], []any{checksum, audit, strings.Repeat("a", 64), candidate.role}) {
				t.Fatal("missing exact role-specific admission")
			}
		}
		var checks sync.WaitGroup
		for range 20 {
			checks.Add(1)
			go func() {
				defer checks.Done()
				if v, e := core.SchemaVersion(probe); e != nil || v != ProductionRecoverySchemaVersion {
					t.Error("scoped core schema", e)
				}
				if _, e := agent.SchemaVersion(probe); e != nil {
					t.Error(e)
				}
				if _, e := core.QueryJSON(probe, postgresDiscoveryPrincipalReadySQL, DiscoveryDatabaseAuthorityAPI); e != nil {
					t.Error("concurrent principal metadata", e)
				}
			}()
		}
		checks.Wait()
		for _, tc := range []struct {
			db   *PostgresJSONDatabase
			q    string
			args []any
		}{
			{core, postgresProductionRecoveryReadinessSQL, []any{migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint()}},
			{core, postgresDiscoveryPrincipalReadySQL, []any{DiscoveryDatabaseAuthorityAPI}},
			{agent, postgresRecoverySecurityAgentReadySQL, []any{migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint()}},
			{agent, postgresApprovalNotificationAuthorityReadySQL, []any{migrations.ProductionApprovalNotification().Checksum(), migrations.ProductionApprovalNotificationSemanticFingerprint()}},
		} {
			if _, e := tc.db.QueryJSON(probe, tc.q, tc.args...); e != nil {
				t.Fatal("scoped fixed metadata", e)
			}
		}
		if cd.calls != 1 || ad.calls != 1 {
			t.Fatal("duplicate covered queries", cd.calls, ad.calls)
		}
		if _, e := core.QueryJSON(probe, "SELECT private_product_data()"); !errors.Is(e, ErrAuthorizationDenied) {
			t.Fatal("health observation admitted product SQL", e)
		}
		if e := core.Exec(probe, "UPDATE private_product_data SET allowed=true"); !errors.Is(e, ErrAuthorizationDenied) {
			t.Fatal("health observation admitted product write", e)
		}
		if _, e := core.QueryJSON(probe, postgresProductionRecoveryReadinessSQL, "bad", "bad"); e == nil {
			t.Fatal("pin validation bypass")
		}
		if _, e := core.QueryJSON(probe, postgresDiscoveryPrincipalReadySQL, "zasp_security_agent_api"); e == nil {
			t.Fatal("argument validation bypass")
		}
		if _, e := other.SchemaVersion(probe); e != nil || od.calls != 1 {
			t.Fatal("cross-database reuse")
		}
		before := cd.calls
		if _, e := core.QueryJSON(probe, postgresRecoverySecurityAgentReadySQL, migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint()); e != nil || cd.calls != before+1 {
			t.Fatal("cross-role reuse", e)
		}
		before = cd.calls
		if _, e := core.CurrentAuthorizationSourceReady(probe, 56, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()); e != nil || cd.calls != before+1 {
			t.Fatal("source check skipped", e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	before := cd.calls
	if _, e := core.SchemaVersion(escaped); !errors.Is(e, ErrRepositoryOperation) || cd.calls != before {
		t.Fatal("escaped cancelled context admitted metadata", e)
	}
	deadline, _ := escaped.Deadline()
	detached, stop := context.WithDeadline(context.WithoutCancel(escaped), deadline)
	defer stop()
	if _, e := core.SchemaVersion(detached); e != nil || cd.calls != before+1 {
		t.Fatal("inactive escaped seal suppressed fresh SQL", e)
	}
	cd.mu.Lock()
	cd.refuse = true
	cd.mu.Unlock()
	called := false
	if WithCurrentAuthorizationHealthProbe(ctx, core, agent, strings.Repeat("a", 64), nil, func(context.Context) error { called = true; return nil }) == nil || called {
		t.Fatal("next probe reused stale DDL/revocation observation")
	}
}

func TestCurrentAuthorizationHealthProbeCancellationAndAdmission(t *testing.T) {
	t.Run("parallel cancel and join", func(t *testing.T) {
		core, cd := healthProbeDB(t)
		agent, ad := healthProbeDB(t)
		started := make(chan struct{})
		joined := make(chan struct{})
		cd.query = func(ctx context.Context, _ string, _ ...any) PostgresRow {
			<-started
			return healthProbeRow{refuse: true}
		}
		ad.query = func(ctx context.Context, _ string, _ ...any) PostgresRow {
			close(started)
			<-ctx.Done()
			close(joined)
			return healthProbeRow{refuse: true}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if WithCurrentAuthorizationHealthProbe(ctx, core, agent, strings.Repeat("a", 64), nil, func(context.Context) error { t.Fatal("callback after refusal"); return nil }) == nil {
			t.Fatal("accepted")
		}
		select {
		case <-joined:
		default:
			t.Fatal("probe escaped join")
		}
	})
	t.Run("closed cancellation and scope expiry", func(t *testing.T) {
		core, cd := healthProbeDB(t)
		agent, _ := healthProbeDB(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if WithCurrentAuthorizationHealthProbe(ctx, core, agent, strings.Repeat("a", 64), nil, func(probe context.Context) error {
			cancel()
			if _, e := core.SchemaVersion(probe); e == nil {
				t.Fatal("cancel bypass")
			}
			deadline, _ := probe.Deadline()
			detached, stop := context.WithDeadline(context.WithoutCancel(probe), deadline)
			defer stop()
			before := cd.calls
			if _, e := core.SchemaVersion(detached); e != nil || cd.calls != before+1 {
				t.Fatal("detached cancellation bypassed fresh SQL", e)
			}
			return nil
		}) == nil {
			t.Fatal("cancelled gate passed")
		}
		ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
		defer cancel2()
		if WithCurrentAuthorizationHealthProbe(ctx2, core, agent, strings.Repeat("a", 64), nil, func(probe context.Context) error {
			_ = core.Close()
			if _, e := core.SchemaVersion(probe); e == nil {
				t.Fatal("closed bypass")
			}
			return nil
		}) != nil {
			t.Fatal("callback result changed")
		}
	})
	t.Run("invalid scope inputs", func(t *testing.T) {
		core, _ := healthProbeDB(t)
		agent, _ := healthProbeDB(t)
		cb := func(context.Context) error { t.Fatal("invalid scope callback"); return nil }
		if WithCurrentAuthorizationHealthProbe(context.Background(), core, agent, strings.Repeat("a", 64), nil, cb) == nil {
			t.Fatal("unbounded scope")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if WithCurrentAuthorizationHealthProbe(ctx, core, core, strings.Repeat("a", 64), nil, cb) == nil {
			t.Fatal("same database roles")
		}
		if WithCurrentAuthorizationHealthProbe(ctx, core, agent, "bad", nil, cb) == nil {
			t.Fatal("invalid key")
		}
	})
}
