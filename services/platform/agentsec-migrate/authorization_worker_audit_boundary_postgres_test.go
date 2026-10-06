package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This additional owned fixture exercises the audited boundary after a genuine
// CLI installation. Historical native fixtures and their deadlines stay intact.
func TestAuditWorkerComposedNativeBoundary(t *testing.T) {
	buildCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	if output, err := exec.CommandContext(buildCtx, "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("owned CLI build: %v %s", err, output)
	}
	dsn := startMigrationPostgres(t)
	ctx, stop := context.WithTimeout(context.Background(), 8*time.Minute)
	defer stop()
	owner := connectMigrationPostgres(t, ctx, dsn)
	defer owner.Close(context.Background())
	operator := "zasp_test"
	values := map[string]string{migrationPrincipalEnvironment: operator, postgresDSNEnvironment: dsn, "ZASP_MIGRATION_TIMEOUT": "7m"}
	for i, key := range []string{discoveryAPIPrincipalEnvironment, discoveryWorkerPrincipalEnvironment, runtimeIngestPrincipalEnvironment, runtimeWorkerPrincipalEnvironment, outboxWorkerPrincipalEnvironment, runtimeGatewayPrincipalEnvironment, discoverySchedulerPrincipalEnvironment, projectionRiskPrincipalEnvironment, projectionGraphPrincipalEnvironment, projectionSearchPrincipalEnvironment, runtimeCoordinatorPrincipalEnvironment, runtimeArchivePrincipalEnvironment, runtimeIndexPrincipalEnvironment, runtimeCorrelationPrincipalEnvironment, runtimeProjectionPrincipalEnvironment, gatewayControlPrincipalEnvironment, securityAgentAPIPrincipalEnvironment, securityAgentWorkerPrincipalEnvironment, securityAgentActionPrincipalEnvironment, redTeamWorkerPrincipalEnvironment, redTeamOutboxPrincipalEnvironment, redTeamAdapterPrincipalEnvironment, attackLabControllerPrincipalEnvironment, attackLabOutboxPrincipalEnvironment, attackLabProxyPrincipalEnvironment, recoveryWorkerPrincipalEnvironment, recoveryOutboxPrincipalEnvironment, policyDeploymentPrincipalEnvironment, "ZASP_TEMPORAL_EXECUTOR_DB_PRINCIPAL", "ZASP_TEMPORAL_COMPENSATION_DB_PRINCIPAL"} {
		name := fmt.Sprintf("profile_login_%02d", i)
		values[key] = name
		if _, err := owner.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.CommandContext(ctx, binary, "up-authorization-runtime-profile")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range values {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("genuine composed install: %v %s", err, output)
	}
	var ready bool
	if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() AND zasp_authorization80_audit.catalog_ready()`).Scan(&ready); err != nil || !ready {
		t.Fatal("native composed baseline", err)
	}
	auditWorkerNativeBoundaryAssertions(t, ctx, owner)
}

func auditWorkerNativeBoundaryAssertions(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	var signatures []string
	if err := owner.QueryRow(ctx, `SELECT array_agg(signature ORDER BY signature) FROM zasp_authorization80_worker.predecessor_functions WHERE signature LIKE 'zasp_authorization80_audit.%' OR signature='zasp_sa_attack_lab_live_fingerprint()'`).Scan(&signatures); err != nil || len(signatures) != 13 {
		t.Fatal("audit runtime boundary is not fully bound", err)
	}
	for _, signature := range signatures {
		t.Run("live-frame/"+signature, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			// These identities were read from the exact newly installed owned catalog.
			if _, err = tx.Exec(ctx, "ALTER FUNCTION "+signature+" SET search_path=public,pg_catalog"); err != nil {
				t.Fatal(err)
			}
			var ready bool
			if err = tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready()`).Scan(&ready); err != nil || ready {
				t.Fatal("live boundary frame drift admitted", err)
			}
		})
	}
	var saved []string
	if err := owner.QueryRow(ctx, `SELECT array_agg(signature ORDER BY signature) FROM zasp_authorization80_audit.predecessor_functions`).Scan(&saved); err != nil || len(saved) != 6 {
		t.Fatal("saved original roster", err)
	}
	for _, signature := range saved {
		t.Run("saved-original/"+signature, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err = tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `UPDATE zasp_authorization80_audit.predecessor_functions SET definition=definition||' ' WHERE signature=$1`, signature); err != nil {
				t.Fatal(err)
			}
			var ready bool
			if err = tx.QueryRow(ctx, `SELECT zasp_authorization80_audit.catalog_ready()`).Scan(&ready); err != nil || ready {
				t.Fatal("saved predecessor drift admitted", err)
			}
		})
	}
	for _, catalogValue := range []string{"false", "NULL::boolean"} {
		t.Run("lazy-"+catalogValue, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err = tx.Exec(ctx, `CREATE OR REPLACE FUNCTION zasp_authorization80_audit.catalog_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $body$ SELECT `+catalogValue+` $body$;
CREATE OR REPLACE FUNCTION zasp_authorization80_audit.projected57() RETURNS text LANGUAGE plpgsql STABLE SET search_path=pg_catalog,public AS $body$ BEGIN RAISE EXCEPTION USING ERRCODE='22000',MESSAGE='owned audit projection poison';END $body$;`); err != nil {
				t.Fatal(err)
			}
			var outsideAuthority bool
			if err = tx.QueryRow(ctx, `SELECT current_user<>'zasp_discovery_authority'`).Scan(&outsideAuthority); err != nil || !outsideAuthority {
				t.Fatal("owned nonauthority frame missing", err)
			}
			var originalRoot *string
			if err = tx.QueryRow(ctx, `SELECT zasp_temporal77.base67_fingerprint()`).Scan(&originalRoot); err != nil {
				t.Fatal("nonauthority original recipe demanded poison projection", err)
			}
			if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
				t.Fatal(err)
			}
			var result *string
			if err = tx.QueryRow(ctx, `SELECT public.zasp_sa_attack_lab_live_fingerprint()`).Scan(&result); err != nil || result != nil {
				t.Fatal("catalog false/NULL demanded projected57", err)
			}
			var root *string
			if err = tx.QueryRow(ctx, `SELECT zasp_temporal77.base67_fingerprint()`).Scan(&root); err != nil {
				t.Fatal("graph fallback demanded poison projection", err)
			}
			var rejected bool
			if err = tx.QueryRow(ctx, `SELECT zasp_temporal68.predecessor_ready('wrong','wrong')`).Scan(&rejected); err != nil || rejected {
				t.Fatal("cheap predecessor guard changed", err)
			}
			_, err = tx.Exec(ctx, `SELECT zasp_authorization80_audit.projected57()`)
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "22000" || !strings.Contains(pgerr.Message, "owned audit projection poison") {
				t.Fatal("poison control did not execute", err)
			}
		})
	}
	t.Run("immutability", func(t *testing.T) {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		_, err = tx.Exec(ctx, `UPDATE zasp_authorization80_audit.predecessor_functions SET definition=definition`)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Fatal("normal saved predecessor rewrite was admitted", err)
		}
	})
	var ready bool
	if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() AND zasp_authorization80_audit.catalog_ready()`).Scan(&ready); err != nil || !ready {
		t.Fatal("owned drift rollback did not restore original catalog", err)
	}
}
