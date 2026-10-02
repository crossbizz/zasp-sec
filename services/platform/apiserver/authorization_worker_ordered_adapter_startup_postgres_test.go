package apiserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

type orderedStartupJSONDatabase struct{ pool *pgxpool.Pool }

func (d orderedStartupJSONDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	var raw json.RawMessage
	err := d.pool.QueryRow(ctx, query, args...).Scan(&raw)
	return raw, err
}

// Diagnostic only: same installed profile, selected adapter principal and
// worker keys as the actual child, before any Block/Test effect. Ready must not
// make an FGA Check; the trap enforces that without inventing tuple grants.
func TestP7OrderedAdapterStartup(t *testing.T) {
	runTemporalExecutorPolicyFixtureWithHook(t, false, nil, func(ctx context.Context, owner, _, _ *pgx.Conn, o, w, e, _, actor string, _ policy.GatewayPolicyKeys, _ ed25519.PrivateKey) bool {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
		defer cancel()
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		var missing string
		if err := owner.QueryRow(ctx, `SELECT principal_name FROM public.zasp_red_team_principal_bindings WHERE authority_role='zasp_red_team_adapter'`).Scan(&missing); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("startup baseline did not reproduce absent registration", orderedStartupErrorClass(err))
		}
		t.Log("startup baseline adapter-login", "no-rows")
		installOrderedRunnerAdapterPrincipals(t, ctx, owner)
		installAutomaticSourceFixture(t, ctx, owner)
		runner := workerMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionTemporalFindingResponse, runner.UpProductionAuthorizationTemporalProfile, runner.UpProductionAuthorizationWorkerProfile} {
			if err := up(ctx); err != nil {
				t.Fatal("startup profile installation", err)
			}
		}
		var login string
		if err := owner.QueryRow(ctx, `SELECT principal_name FROM public.zasp_red_team_principal_bindings WHERE authority_role='zasp_red_team_adapter'`).Scan(&login); err != nil || login == "" {
			t.Fatal("startup adapter-login", orderedStartupErrorClass(err))
		}
		poolFor := func(login string) *pgxpool.Pool {
			cfg, err := pgxpool.ParseConfig(owner.Config().ConnString())
			if err != nil {
				t.Fatal("startup database config")
			}
			cfg.ConnConfig.User, cfg.MaxConns = login, 2
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				t.Fatal("startup database pool", orderedStartupErrorClass(err))
			}
			t.Cleanup(pool.Close)
			return pool
		}
		adapter, comp := poolFor(login), poolFor("temporal_compensation_test_login")
		forwardKey, _ := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{91}, 32))
		compKey, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{92}, 32))
		for _, entry := range []struct {
			purpose authorization.WorkerPurpose
			key     *authorization.WorkerKey
		}{{authorization.WorkerForward, forwardKey}, {authorization.CapturedCompensation, compKey}} {
			if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(entry.purpose), entry.key.Version(), entry.key.Verifier()); err != nil {
				t.Fatal("startup verifier registration", orderedStartupErrorClass(err))
			}
		}
		trap := &orderedPolicyNoForwardChecks{}
		// Syntactically valid constructor pins are unused by Ready; this
		// diagnostic makes no claim about a store/model or forward permission.
		forward, err := authorization.NewWorkerAdapter(adapter, trap, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAW", forwardKey)
		if err != nil {
			t.Fatal("startup adapter constructor", orderedStartupErrorClass(err))
		}
		compensation, err := authorization.NewWorkerExecutor(comp, nil, "", "", compKey)
		if err != nil {
			t.Fatal("startup compensation constructor", orderedStartupErrorClass(err))
		}
		for _, entry := range []struct {
			label     string
			worker    *authorization.WorkerExecutor
			operation authorization.WorkerOperation
		}{{"forward-resolve", forward, "ordered68.adapter.resolve"}, {"captured-complete", compensation, "ordered68.adapter.complete"}} {
			bounded, done := context.WithTimeout(ctx, 10*time.Second)
			began := time.Now()
			err := entry.worker.ReadyFor(bounded, entry.operation)
			done()
			t.Log("startup stage", entry.label, "class", orderedStartupErrorClass(err), "elapsed_ms", time.Since(began).Milliseconds())
			if err != nil {
				t.Error("startup worker readiness", entry.label, orderedStartupErrorClass(err))
			}
		}
		for _, entry := range []struct {
			label, sql string
			args       []any
		}{
			{"native68-adapter", `SELECT zasp_temporal68.adapter_ready($1,$2)`, []any{migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint()}},
			{"adapter-key", `SELECT zasp_authorization80_worker.adapter_key_ready($1,$2)`, []any{string(authorization.WorkerForward), forwardKey.Version()}},
			{"native68-principal", `SELECT zasp_temporal68.adapter_principal_ready()`, nil},
			{"current74", `SELECT zasp_temporal74.current_ready()`, nil},
			{"worker-catalog", `SELECT zasp_authorization80_worker.catalog_ready()`, nil},
		} {
			bounded, done := context.WithTimeout(ctx, 10*time.Second)
			var value bool
			err := adapter.QueryRow(bounded, entry.sql, entry.args...).Scan(&value)
			done()
			t.Log("startup predicate", entry.label, "value", value, "class", orderedStartupErrorClass(err))
		}
		journal, err := redteamadapter.NewWorkerOrderedTestPostgresJournal(orderedStartupJSONDatabase{adapter}, migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint(), forward, compensation)
		if err != nil {
			t.Fatal("startup journal constructor", orderedStartupErrorClass(err))
		}
		err = journal.Ready(ctx)
		t.Log("startup stage", "journal-ready", "class", orderedStartupErrorClass(err))
		if err != nil {
			t.Error("actual journal startup", orderedStartupErrorClass(err))
		}
		if trap.calls != 0 {
			t.Fatal("generic readiness performed a forward permission check")
		}
		return true
	})
}

func orderedStartupErrorClass(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return "no-rows"
	}
	var native *pgconn.PgError
	if errors.As(err, &native) {
		return "sqlstate-" + native.Code
	}
	for _, entry := range []struct {
		err   error
		class string
	}{{authorization.ErrInvalid, "invalid"}, {authorization.ErrDenied, "denied"}, {authorization.ErrConflict, "conflict"}, {authorization.ErrUnavailable, "unavailable"}, {redteamadapter.ErrAdapter, "adapter"}, {context.DeadlineExceeded, "deadline"}, {context.Canceled, "cancelled"}} {
		if errors.Is(err, entry.err) {
			return entry.class
		}
	}
	return "other"
}

// Existing registered25 provisioning, before profile installation. No Test
// effect, permission tuple, adapter intent or receipt is inserted here.
func installOrderedRunnerAdapterPrincipals(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	worker, adapter := orderedTestConnections(t, ctx, owner)
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	workerErr, adapterErr := worker.Close(cleanup), adapter.Close(cleanup)
	if workerErr != nil || adapterErr != nil {
		t.Fatal("registered adapter setup connection cleanup")
	}
	var registered bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(principal_name='ordered_test_red_adapter') FROM public.zasp_red_team_principal_bindings WHERE authority_role='zasp_red_team_adapter'`).Scan(&registered); err != nil || !registered {
		t.Fatal("registered adapter setup did not persist exact binding", orderedStartupErrorClass(err))
	}
}
