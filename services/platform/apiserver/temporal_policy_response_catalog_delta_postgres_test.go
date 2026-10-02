package apiserver

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Diagnostic only: installation80 is still refused. Success proves the exact
// catalog-row differences, not compatibility or application authority.
func TestTemporalPolicyResponseDomainCatalogRowsPostgres(t *testing.T) {
	multistepVersionedExistingTestFixture(t, func(parent context.Context, owner, _ *pgx.Conn, _, _, _, _, _ string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 3*time.Minute)
		defer cancel()
		var principal string
		if err := owner.QueryRow(ctx, `SELECT session_user`).Scan(&principal); err != nil || principal != "zasp_e2e" {
			t.Fatal("canonical migration principal", principal, err)
		}
		t.Logf("session_user=%s source80=%s", principal, migrations.ProductionAuthorizationEnforcement().Checksum())
		var inside80 map[string]bool
		db := &policyDomainRowsDatabase{policyLineageDatabase: &policyLineageDatabase{connection: owner, t: t}, capture: func(ctx context.Context, tx pgx.Tx) {
			inside80 = policyDomainRows(t, ctx, tx, "inside80")
		}}
		runner, err := migrations.NewRunner(db)
		if err != nil {
			t.Fatal(err)
		}
		for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay, runner.UpProductionSecurityAgentMultistep} {
			if err := up(ctx); err != nil {
				t.Fatal("canonical prerequisites", err)
			}
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE policy81_scheduler LOGIN INHERIT;CREATE ROLE policy81_risk LOGIN INHERIT;CREATE ROLE policy81_graph LOGIN INHERIT;CREATE ROLE policy81_search LOGIN INHERIT;SELECT zasp_execution_register_principals(session_user,'policy81_scheduler','security_agent_v33_discovery_worker_login','policy81_risk','policy81_graph','policy81_search')`); err != nil {
			t.Fatal(err)
		}
		for _, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests, runner.UpProductionTemporalDiscovery, runner.UpProductionTemporalAdmission, runner.UpProductionTemporalTestExecutor, runner.UpProductionTemporalTestSelector, runner.UpProductionTemporalHumanAdmission, runner.UpProductionTemporalAutomaticSources, runner.UpProductionTemporalFindingResponse} {
			if err := up(ctx); err != nil {
				t.Fatal("Temporal predecessor", err)
			}
		}
		before79 := policyDomainRows(t, ctx, owner, "after78")
		if err := runner.UpProductionAuthorizationProjection(ctx); err != nil {
			t.Fatal("projection79", err)
		}
		after79 := policyDomainRows(t, ctx, owner, "after79")
		if err := runner.UpProductionAuthorizationEnforcement(ctx); !errors.Is(err, migrations.ErrInvalidState) {
			t.Fatalf("expected composed80 refusal, got %v", err)
		}
		if inside80 == nil {
			t.Fatal("missing pre-rollback80 catalog capture")
		}
		added79, removed79 := policyDomainDelta(t, "78-to79", before79, after79)
		want79 := []string{"trigger|zasp_discovery_syncs|zasp_authorization79_capture", "trigger|zasp_integration_connections|zasp_authorization79_capture", "trigger|zasp_integrations|zasp_authorization79_capture", "trigger|zasp_inventory_entities|zasp_authorization79_capture"}
		if strings.Join(added79, "\n") != strings.Join(want79, "\n") || len(removed79) != 0 {
			t.Fatalf("unexpected79 domain delta added=%v removed=%v", added79, removed79)
		}
		added80, removed80 := policyDomainDelta(t, "79-to80", after79, inside80)
		want80 := "trigger|zasp_inventory_entities|zasp_authorization79_capture"
		if len(added80) != 1 || len(removed80) != 1 || added80[0] != want80 || removed80[0] != want80 {
			t.Fatalf("unexpected80 domain delta added=%v removed=%v", added80, removed80)
		}
		t.Log("exact four79 additions and one80 trigger replacement confirmed; all other72 domain identity rows unchanged; composed80 remains refused")
	}, func(t *testing.T) string { return startDisposablePostgresAs(t, "zasp_e2e") })
}

type policyDomainRowsDatabase struct {
	*policyLineageDatabase
	capture func(context.Context, pgx.Tx)
}

func (d *policyDomainRowsDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &policyDomainRowsTransaction{policyLineageTransaction: policyLineageTransaction{integrationMigrationTransaction: integrationMigrationTransaction{transaction: tx}, t: d.t}, capture: d.capture}, nil
}

type policyDomainRowsTransaction struct {
	policyLineageTransaction
	capture func(context.Context, pgx.Tx)
}

func (tx *policyDomainRowsTransaction) QueryRow(ctx context.Context, q string, args ...any) migrations.Row {
	r := tx.policyLineageTransaction.QueryRow(ctx, q, args...).(*policyLineageRow)
	if q == `SELECT zasp_authorization80.ready($1)` {
		r.onResult = func() { tx.capture(ctx, tx.transaction) }
	}
	return r
}

func policyDomainRows(t *testing.T, ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, stage string) map[string]bool {
	t.Helper()
	var source, expected string
	if err := db.QueryRow(ctx, `SELECT prosrc,zasp_temporal72.domain_catalog() FROM pg_proc WHERE oid='zasp_temporal72.domain_catalog()'::regprocedure`).Scan(&source, &expected); err != nil {
		t.Fatal(err)
	}
	at := strings.LastIndex(source, ") SELECT ")
	if at < 0 {
		t.Fatal("domain catalog CTE shape changed")
	}
	rows, err := db.Query(ctx, source[:at+1]+` SELECT value FROM identities ORDER BY value`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	values := []string{}
	result := map[string]bool{}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		if result[value] {
			t.Fatal("duplicate exact domain catalog row")
		}
		result[value] = true
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	actual := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(values, "\n"))))
	if actual != expected {
		t.Fatal("extracted domain rows do not reproduce live fingerprint")
	}
	t.Logf("domain rows stage=%s count=%d fingerprint=%s", stage, len(values), actual)
	return result
}

func policyDomainDelta(t *testing.T, stage string, before, after map[string]bool) ([]string, []string) {
	t.Helper()
	compare := func(left, right map[string]bool, direction string) []string {
		result := []string{}
		for value := range left {
			if right[value] {
				continue
			}
			parts := strings.SplitN(value, "|", 4)
			if len(parts) != 4 || parts[0] != "trigger" {
				t.Fatalf("unexpected non-trigger domain change stage=%s direction=%s row_sha256=%x", stage, direction, sha256.Sum256([]byte(value)))
			}
			id := strings.Join(parts[:3], "|")
			result = append(result, id)
			t.Logf("domain delta stage=%s direction=%s identity=%s row_sha256=%x", stage, direction, id, sha256.Sum256([]byte(value)))
		}
		sort.Strings(result)
		return result
	}
	return compare(after, before, "added"), compare(before, after, "removed")
}
