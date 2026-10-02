package apiserver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentRelease62RegistrationWaitPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, _, _, _, _, _ string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		writer, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Rollback(ctx)
		if _, err = writer.Exec(ctx, `UPDATE zasp_ordered_public62.registration SET checksum=repeat('0',64)`); err != nil {
			t.Fatal(err)
		}
		contender, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer contender.Close(ctx)
		var pid int32
		if err = contender.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		attempt, cancel := context.WithCancel(ctx)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- precisionMigrationRunner(t, contender).DownProductionSecurityAgentPublic(attempt) }()
		joined := false
		defer func() {
			cancel()
			if !joined {
				<-done
			}
		}()
		waiting := false
		var query string
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if err = writer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='zasp_ordered_public62.registration'::regclass AND mode='AccessExclusiveLock' AND NOT granted)`, pid).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				if err = writer.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&query); err != nil {
					t.Fatal(err)
				}
				break
			}
		}
		if err = writer.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		result := <-done
		joined = true
		if !waiting || !strings.HasPrefix(query, "LOCK TABLE ") || !errors.Is(result, migrations.ErrInvalidState) {
			t.Fatalf("down did not freeze registration before readiness: waiting=%t query=%s result=%v", waiting, query, result)
		}
		var retained bool
		if err = owner.QueryRow(ctx, `SELECT to_regclass('zasp_ordered_public62.registration') IS NOT NULL`).Scan(&retained); err != nil || !retained {
			t.Fatal("drift discarded registration", retained, err)
		}
	})
}

func TestSecurityAgentRelease62RegistrationDriftPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, _, _, _, _, _ string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		for name, drift := range map[string]string{
			"extension-checksum":      `UPDATE zasp_ordered_public62.registration SET checksum=repeat('0',64)`,
			"extension-fingerprint":   `UPDATE zasp_ordered_public62.registration SET fingerprint=repeat('0',64)`,
			"missing-registration":    `DELETE FROM zasp_ordered_public62.registration`,
			"live-definition":         `ALTER FUNCTION zasp_ordered_public62.authorize(text,text,text,text,boolean) IMMUTABLE`,
			"owner":                   `ALTER FUNCTION zasp_ordered_public62.api(text,text,jsonb) OWNER TO ` + pgx.Identifier{owner.Config().User}.Sanitize(),
			"acl":                     `GRANT EXECUTE ON FUNCTION zasp_ordered_public62.definition(text,text,text,text,bigint,boolean) TO zasp_security_agent_api`,
			"table-rls":               `ALTER TABLE zasp_ordered_public62.registration DISABLE ROW LEVEL SECURITY`,
			"table-grant":             `GRANT SELECT ON zasp_ordered_public62.registration TO PUBLIC`,
			"unexpected-trigger":      `CREATE TRIGGER extension_drift BEFORE UPDATE ON zasp_ordered_public62.registration FOR EACH ROW EXECUTE FUNCTION zasp_sa_multistep_prior.immutable_admission()`,
			"predecessor-checksum":    `UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=61`,
			"predecessor-fingerprint": `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_fingerprint'`,
			"missing-predecessor":     `DELETE FROM zasp_schema_versions WHERE version=61`,
			"predecessor-live":        `ALTER FUNCTION zasp_sa_multistep_prior.context(text,text,text,text) IMMUTABLE`,
		} {
			t.Run(name, func(t *testing.T) {
				tx, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if _, err = tx.Exec(ctx, drift); err != nil {
					t.Fatal(err)
				}
				var ready bool
				if err = tx.QueryRow(ctx, `SELECT zasp_ordered_public62.ready($1,$2)`, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint()).Scan(&ready); err != nil || ready {
					t.Fatal("drift reported ready", ready, err)
				}
				runner, _ := migrations.NewRunner(&registeredMultistepDatabase{connection: owner, t: t, outer: tx})
				if err = runner.UpProductionSecurityAgentPublic(ctx); err == nil {
					t.Fatal("drift install replay accepted")
				}
				if err = runner.DownProductionSecurityAgentPublic(ctx); err == nil {
					t.Fatal("drift down accepted")
				}
			})
		}
	})
}

func TestSecurityAgentRelease62DirectInstallFencePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, _, _, _, _, _ string) {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, `DELETE FROM zasp_schema_versions WHERE version=61`); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, migrations.ProductionSecurityAgentPublic().UpSQL()); err == nil {
			t.Fatal("direct extension installation accepted missing predecessor")
		}
	})
}

func TestSecurityAgentRelease62PredecessorDownFencePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, _, _, _, _, _ string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.DownProductionSecurityAgentMultistep(ctx); err == nil {
			t.Fatal("release61 rollback orphaned public extension")
		}
		if err := runner.DownProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.DownProductionSecurityAgentMultistep(ctx); err != nil {
			t.Fatal("release61 down after extension removal", err)
		}
		if v, err := runner.Version(ctx); err != nil || v != 60 {
			t.Fatal("predecessor restoration", v, err)
		}
	})
}

func TestSecurityAgentRelease62ConcurrentUseDownPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		if _, err := api.Exec(ctx, `BEGIN`); err != nil {
			t.Fatal(err)
		}
		defer api.Exec(ctx, `ROLLBACK`)
		if _, err := public62Call(ctx, api, public62Request(o, w, e, actor, "ready")); err != nil {
			t.Fatal(err)
		}
		contender, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer contender.Close(ctx)
		var pid int32
		if err = contender.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		attempt, cancel := context.WithCancel(ctx)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- precisionMigrationRunner(t, contender).DownProductionSecurityAgentPublic(attempt) }()
		joined := false
		defer func() {
			cancel()
			if !joined {
				<-done
			}
		}()
		waiting := false
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)`, pid).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
		}
		if _, err = api.Exec(ctx, `COMMIT`); err != nil {
			t.Fatal(err)
		}
		err = <-done
		joined = true
		if !waiting || err != nil {
			t.Fatal("down did not serialize behind public use", waiting, err)
		}
		if _, err = public62Call(ctx, api, public62Request(o, w, e, actor, "ready")); err == nil {
			t.Fatal("half-installed facade callable after down")
		}
		if err = runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		restarted, err := pgx.ConnectConfig(ctx, api.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer restarted.Close(ctx)
		if got, err := public62Call(ctx, restarted, public62Request(o, w, e, actor, "ready")); err != nil || got["ready"] != true {
			t.Fatal("restart/reinstall readiness", got, err)
		}
	})
}
