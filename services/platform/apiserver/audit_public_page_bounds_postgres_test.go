//go:build darwin || linux

package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAuditExportPublicPageTerminalTransportCounterexample(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	const id = "pid_79830001-0000-4000-8000-000000000001"
	auditPublicPageSeed(t, ctx, f, id, "page.edge", `{}`, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	fill := 900000
	for attempt := 0; attempt < 3; attempt++ {
		metadata := map[string]string{strings.Repeat("k", fill): ""}
		for i := 0; i < 31; i++ {
			metadata[fmt.Sprintf("small-%02d", i)] = ""
		}
		body, _ := json.Marshal(metadata)
		if _, err := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET metadata=$1::jsonb WHERE id=$2`, string(body), id); err != nil {
			t.Fatal(err)
		}
		_, more, raw := auditPublicPageRead(t, ctx, f, `{"action":"page.edge"}`, nil, nil, 100)
		if more {
			t.Fatal("single terminal row declared continuation")
		}
		var private struct {
			Items []json.RawMessage `json:"items"`
		}
		if json.Unmarshal(raw, &private) != nil {
			t.Fatal("private decode")
		}
		// This is the real standard-library serialization of the prescribed
		// public shape, not a claim that the future Go HTTP writer is installed.
		wire, err := json.Marshal(map[string]any{"items": private.Items, "page_info": map[string]any{"has_more": false, "next_cursor": nil}})
		if err != nil {
			t.Fatal(err)
		}
		size := len(wire) + 1
		if size == 1048576 {
			if len(raw) != 1048576+49 {
				t.Fatal("terminal private overhead changed", len(raw))
			}
			t.Logf("actual SQL private=%d prescribed public marshal plus newline=%d", len(raw), size)
			return
		}
		fill += 1048576 - size
	}
	t.Fatal("failed to reach exact terminal hard edge")
}

func TestAuditExportPublicPageSourceWaitAndRollback(t *testing.T) {
	for _, mode := range []string{"source-graph", "source-group", "source-expiry", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			auditExportPublicPolicyMutations(t, ctx, f)
			auditExportPublicTestMutations(t, ctx, f)
			if mode == "source-group" {
				f.groupScope(t, ctx)
			}
			auditPublicPageRead(t, ctx, f, `{}`, nil, nil, 50)
			if mode == "rollback" {
				var before, after string
				query := `SELECT jsonb_build_object('policy',(SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM zasp_workflow_audit a),'test',(SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM zasp_red_team_audit a))::text`
				if err := f.admin.QueryRow(ctx, query).Scan(&before); err != nil {
					t.Fatal(err)
				}
				if err := precisionMigrationRunner(t, f.admin).DownProductionAuditExports(ctx); err != nil {
					t.Fatal("history-only Down", err)
				}
				if err := f.admin.QueryRow(ctx, query).Scan(&after); err != nil || before != after {
					t.Fatal("Down changed retained producer history", err)
				}
				var ready bool
				if err := f.api.QueryRow(ctx, `SELECT zasp_production_runtime_precision_readiness($1,$2)`, migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&ready); err != nil || !ready {
					t.Fatal("kept-open51 readiness not restored", err)
				}
				if _, err := f.api.Exec(ctx, auditPublicPageSQL, auditPublicPageArgs(f, `{}`, nil, nil, 50)...); auditExportSQLState(err) != "42883" {
					t.Fatal("Down retained page authority", err)
				}
				installAuditExports(t, ctx, f.admin)
				items, more, _ := auditPublicPageRead(t, ctx, f, `{}`, nil, nil, 50)
				if len(items) != 11 || more {
					t.Fatal("reinstalled page lost history")
				}
				return
			}
			if mode == "source-expiry" {
				if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE token_digest=$1`, f.digest[:]); err != nil {
					t.Fatal(err)
				}
			}
			err := auditExportBlockedCall(t, ctx, f, auditPublicPageSQL, auditPublicPageArgs(f, `{}`, nil, nil, 50), `LOCK TABLE zasp_admin_audit IN ACCESS EXCLUSIVE MODE`, nil, func(tx pgx.Tx) error {
				var err error
				switch mode {
				case "source-graph":
					_, err = tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
				case "source-group":
					_, err = tx.Exec(ctx, `DELETE FROM zasp_identity_member_groups WHERE organization_id=$1 AND principal_id=$2`, f.identity.Scope.OrganizationID().String(), f.identity.PrincipalID.String())
				case "source-expiry":
					_, err = tx.Exec(ctx, `SELECT pg_sleep(2.1)`)
				}
				return err
			})
			want := "55000"
			if mode == "source-group" {
				want = "42501"
			}
			if mode == "source-expiry" {
				want = "28000"
			}
			if auditExportSQLState(err) != want {
				t.Fatal("source wait hid current authority loss", mode, err)
			}
		})
	}
}

func TestAuditExportPublicPageStoredFieldAndOrgBoundaries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	policies := auditExportPublicPolicyMutations(t, ctx, f)
	const id = "pid_79830002-0000-4000-8000-000000000001"
	at := time.Date(2001, 1, 1, 0, 0, 0, 123456000, time.UTC)
	auditPublicPageSeed(t, ctx, f, id, "page.old", `{}`, at)
	// Same organization, another stored scope stays visible. Equal ID in a
	// foreign organization is not part of this viewer's collision domain.
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET workspace_id='pid_79830003-0000-4000-8000-000000000001',environment_id='pid_79830004-0000-4000-8000-000000000001',outcome='rejected' WHERE id=$1;`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit SELECT 'pid_79830005-0000-4000-8000-000000000001',workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at FROM zasp_admin_audit WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	items, more, _ := auditPublicPageRead(t, ctx, f, `{"action":"page.old","outcome":"denied","from":"2001-01-01T00:00:00.123456Z","to":"2001-01-01T00:00:00.123457Z"}`, nil, nil, 1)
	if len(items) != 1 || more {
		t.Fatal("historical organization-wide row missing")
	}
	items, _, _ = auditPublicPageRead(t, ctx, f, `{"action":"page.old","to":"2001-01-01T00:00:00.123456Z"}`, nil, nil, 1)
	if len(items) != 0 {
		t.Fatal("exclusive upper timestamp changed")
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_workflow_audit SET resource_kind='integration' WHERE audit_id=$1`, policies[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.api.Exec(ctx, auditPublicPageSQL, auditPublicPageArgs(f, `{"action":"policy.create"}`, nil, nil, 1)...); auditExportSQLState(err) != "55000" {
		t.Fatal("malformed eligible policy disappeared", err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_workflow_audit SET resource_kind='policy' WHERE audit_id=$1`, policies[0].ID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		target string
		valid  bool
	}{{strings.Repeat("😀", 64), true}, {strings.Repeat("😀", 64) + "x", false}, {strings.Repeat("界", 128), true}, {"", false}} {
		_, sourceErr := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET target_id=$1 WHERE organization_id=$2 AND id=$3`, tc.target, f.identity.Scope.OrganizationID().String(), id)
		if tc.target == "" {
			if auditExportSQLState(sourceErr) != "23514" {
				t.Fatal("released source admitted empty target", sourceErr)
			}
			continue
		}
		if err := sourceErr; err != nil {
			t.Fatal(err)
		}
		_, err := f.api.Exec(ctx, auditPublicPageSQL, auditPublicPageArgs(f, `{"action":"page.old"}`, nil, nil, 1)...)
		if tc.valid && err != nil || !tc.valid && auditExportSQLState(err) != "55000" {
			t.Fatal("target UTF16 public semantics", tc.valid, err)
		}
	}
}

func TestAuditExportPublicPageActorPredicate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	const first = "pid_79850001-0000-4000-8000-000000000001"
	const second = "pid_79850001-0000-4000-8000-000000000002"
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	auditPublicPageSeed(t, ctx, f, first, "page.actor", `{}`, at)
	auditPublicPageSeed(t, ctx, f, second, "page.actor", `{}`, at)
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET actor_id='pid_79850002-0000-4000-8000-000000000001' WHERE id=$1`, second); err != nil {
		t.Fatal(err)
	}
	filter, _ := json.Marshal(map[string]string{"actor_id": f.identity.PrincipalID.String()})
	items, more, _ := auditPublicPageRead(t, ctx, f, string(filter), nil, nil, 50)
	if len(items) != 1 || more || string(items[0]["id"]) != fmt.Sprintf("%q", first) {
		t.Fatal("actor predicate ignored/misbound")
	}
	items, more, _ = auditPublicPageRead(t, ctx, f, `{"actor_id":"pid_79850003-0000-4000-8000-000000000001"}`, nil, nil, 50)
	if len(items) != 0 || more {
		t.Fatal("unknown valid actor exposed unfiltered rows")
	}
}
