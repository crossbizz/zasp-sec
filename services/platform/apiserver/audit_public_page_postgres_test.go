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

const auditPublicPageSQL = `SELECT zasp_audit_export_public_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`

func auditPublicPageArgs(f auditExportPG, filters string, afterTime any, afterID any, limit int) []any {
	args := append([]any{}, f.createArgs()[:6]...)
	return append(args, filters, afterTime, afterID, limit, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint())
}

func auditPublicPageRead(t *testing.T, ctx context.Context, f auditExportPG, filters string, afterTime, afterID any, limit int) ([]map[string]json.RawMessage, bool, []byte) {
	t.Helper()
	var raw []byte
	if err := f.api.QueryRow(ctx, auditPublicPageSQL, auditPublicPageArgs(f, filters, afterTime, afterID, limit)...).Scan(&raw); err != nil {
		t.Fatal("page read", auditExportSQLState(err), err)
	}
	var page struct {
		Items   []map[string]json.RawMessage `json:"items"`
		HasMore bool                         `json:"has_more"`
	}
	var shape map[string]json.RawMessage
	if json.Unmarshal(raw, &page) != nil || json.Unmarshal(raw, &shape) != nil || len(shape) != 2 || shape["items"] == nil || shape["has_more"] == nil || len(page.Items) > limit || len(page.Items) == 0 && page.HasMore || len(raw) > 1048576+4096 {
		t.Fatal("invalid bounded page envelope")
	}
	for _, item := range page.Items {
		if len(item) != 9 {
			t.Fatal("item shape")
		}
	}
	return page.Items, page.HasMore, raw
}

func auditPublicPageSeed(t *testing.T, ctx context.Context, f auditExportPG, id, action string, metadata any, at time.Time) {
	t.Helper()
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,$4,$5,$6,'policy-page','succeeded',$7::jsonb,$8)`, f.identity.Scope.OrganizationID().String(), f.identity.Scope.WorkspaceID().String(), f.identity.Scope.EnvironmentID().String(), id, f.identity.PrincipalID.String(), action, metadata, at); err != nil {
		t.Fatal(err)
	}
}

func TestAuditExportPublicPageCallerValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx) // Deliberately no export API registration.
	_, _, _ = auditPublicPageRead(t, ctx, f, `{}`, nil, nil, 50)
	for _, filter := range []string{`null`, `[]`, `{"Action":"policy.create"}`, `{"action":null}`, `{"action":""}`, `{"action":"identity_provider.createSsoConnection"}`, `{"actor_id":"wrong"}`, `{"outcome":"rejected"}`, `{"from":"2026-02-30T00:00:00.000000Z"}`, `{"from":"2026-01-01T00:00:00Z"}`, `{"from":"2026-01-01T00:00:00.0000010Z"}`, `{"from":"2026-01-01T00:00:00.000000Z","to":"2026-01-01T00:00:00.000000Z"}`, `{"to":"2026-01-01T00:00:00.000000+00:00"}`} {
		_, err := f.api.Exec(ctx, auditPublicPageSQL, auditPublicPageArgs(f, filter, nil, nil, 50)...)
		if auditExportSQLState(err) != "22023" {
			t.Fatalf("caller filter %s: %v", filter, err)
		}
	}
	for _, change := range []func([]any){func(a []any) { a[7] = time.Now() }, func(a []any) { a[8] = "pid_79900001-0000-4000-8000-000000000001" }, func(a []any) { a[9] = 0 }, func(a []any) { a[9] = 101 }, func(a []any) { a[9] = nil }, func(a []any) { a[6] = `{"action":"` + strings.Repeat("a", 1025) + `"}` }} {
		a := auditPublicPageArgs(f, `{}`, nil, nil, 50)
		change(a)
		_, err := f.api.Exec(ctx, auditPublicPageSQL, a...)
		if auditExportSQLState(err) != "22023" {
			t.Fatal("malformed typed caller", err)
		}
	}
	for _, tc := range []struct {
		index int
		value any
		state string
	}{{4, strings.Repeat("a", 32), "28000"}, {5, strings.Repeat("x", 32), "42501"}, {1, "pid_79900001-0000-4000-8000-000000000001", "28000"}, {10, strings.Repeat("0", 64), "55000"}, {11, strings.Repeat("0", 64), "55000"}} {
		a := auditPublicPageArgs(f, `{}`, nil, nil, 50)
		a[tc.index] = tc.value
		if tc.index == 4 {
			a[4] = []byte(strings.Repeat("a", 32))
		}
		_, err := f.api.Exec(ctx, auditPublicPageSQL, a...)
		if auditExportSQLState(err) != tc.state {
			t.Fatal("authority rejection", tc.index, auditExportSQLState(err), err)
		}
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp()-interval '1 day' WHERE token_digest=$1`, f.digest[:]); err != nil {
		t.Fatal(err)
	}
	auditPublicPageRead(t, ctx, f, `{}`, nil, nil, 50)
	worker, outbox := auditExportWorkerConnections(t, ctx, f)
	for _, connection := range []*pgx.Conn{f.api, worker, outbox} {
		for _, query := range []string{`SELECT * FROM zasp_audit_export_public_source_v1`, `SELECT * FROM zasp_red_team_audit`, `SELECT zasp_audit_export_public_utf16('x',512)`} {
			if _, err := connection.Exec(ctx, query); auditExportSQLState(err) != "42501" {
				t.Fatal("raw/private permission widened", err)
			}
		}
	}
	for _, connection := range []*pgx.Conn{worker, outbox, f.admin} {
		if _, err := connection.Exec(ctx, auditPublicPageSQL, auditPublicPageArgs(f, `{}`, nil, nil, 50)...); err == nil {
			t.Fatal("wrong registered page principal accepted")
		}
	}
}

func TestAuditExportPublicPageMetadataAndPrefix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	const id = "pid_79900001-0000-4000-8000-000000000001"
	at := time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)
	for _, tc := range []struct {
		name, metadata string
		valid          bool
	}{
		{"empty-values", `{"":"","number":1.2300,"boolean":true,"nested":{"a":1}}`, true},
		{"large-key", `{"` + strings.Repeat("k", 140000) + `":"x"}`, true},
		{"fallback", `{"` + strings.Repeat("k", 800000) + `":"x"}`, true},
		{"non-bmp512", `{"x":"` + strings.Repeat("😀", 256) + `"}`, true},
		{"non-bmp513", `{"x":"` + strings.Repeat("😀", 256) + `a"}`, false},
		{"bmp512", `{"x":"` + strings.Repeat("界", 512) + `"}`, true},
		{"null", `{"x":null}`, false},
		{"invalid-later-value", `{"a":"accepted","z":null}`, false},
		{"compressed-logical-oversize", `{"` + strings.Repeat("k", 1048833) + `":"x"}`, false},
		{"escapes", `{"<>&\u2028\u2029\t\"\\":"<>&\u2028\u2029\t\"\\"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auditPublicPageSeed(t, ctx, f, id, "page.metadata", tc.metadata, at)
			defer func() {
				if _, err := f.admin.Exec(ctx, `DELETE FROM zasp_admin_audit WHERE id=$1`, id); err != nil {
					t.Error(err)
				}
			}()
			var raw []byte
			err := f.api.QueryRow(ctx, auditPublicPageSQL, auditPublicPageArgs(f, `{"action":"page.metadata"}`, nil, nil, 1)...).Scan(&raw)
			if !tc.valid {
				if auditExportSQLState(err) != "55000" || len(raw) != 0 {
					t.Fatal("invalid source did not refuse page", err)
				}
				return
			}
			if err != nil {
				t.Fatal("legal list metadata rejected", err)
			}
			var page struct {
				Items []struct {
					Metadata map[string]string `json:"metadata"`
				} `json:"items"`
			}
			if json.Unmarshal(raw, &page) != nil || len(page.Items) != 1 {
				t.Fatal("metadata page")
			}
			var expected map[string]string
			var projected []byte
			if err := f.admin.QueryRow(ctx, `SELECT jsonb_object_agg(key,value) FROM jsonb_each_text($1::jsonb)`, tc.metadata).Scan(&projected); err != nil || json.Unmarshal(projected, &expected) != nil {
				t.Fatal(err)
			}
			got, _ := json.Marshal(page.Items[0].Metadata)
			want, _ := json.Marshal(expected)
			if string(got) != string(want) {
				t.Fatal("list projection changed retained values")
			}
		})
	}
	for count := 32; count <= 33; count++ {
		metadata := map[string]string{}
		for i := 0; i < count; i++ {
			metadata[fmt.Sprint(i)] = ""
		}
		body, _ := json.Marshal(metadata)
		auditPublicPageSeed(t, ctx, f, id, "page.metadata", string(body), at)
		_, err := f.api.Exec(ctx, auditPublicPageSQL, auditPublicPageArgs(f, `{"action":"page.metadata"}`, nil, nil, 1)...)
		if (count == 32 && err != nil) || (count == 33 && auditExportSQLState(err) != "55000") {
			t.Fatal("property bound", count, err)
		}
		if _, err = f.admin.Exec(ctx, `DELETE FROM zasp_admin_audit WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= 3; i++ {
		auditPublicPageSeed(t, ctx, f, fmt.Sprintf("pid_79900002-0000-4000-8000-%012d", i), "page.prefix", `{"`+strings.Repeat("k", 300000)+`":"x"}`, at)
	}
	items, more, _ := auditPublicPageRead(t, ctx, f, `{"action":"page.prefix"}`, nil, nil, 100)
	if len(items) != 2 || !more {
		t.Fatal("soft prefix did not retain two rows")
	}
	var after string
	json.Unmarshal(items[1]["id"], &after)
	items, more, _ = auditPublicPageRead(t, ctx, f, `{"action":"page.prefix"}`, at, after, 100)
	var last string
	json.Unmarshal(items[0]["id"], &last)
	if len(items) != 1 || more || last != "pid_79900002-0000-4000-8000-000000000001" {
		t.Fatal("soft-deferred row skipped")
	}
	// A malformed lookahead refuses even when the first item fits; a candidate
	// beyond limit+1 is not expanded until a later page selects it.
	auditPublicPageSeed(t, ctx, f, id, "page.prefix", `{"x":null}`, at.Add(-time.Second))
	auditPublicPageRead(t, ctx, f, `{"action":"page.prefix"}`, nil, nil, 1)
	_, err := f.api.Exec(ctx, auditPublicPageSQL, auditPublicPageArgs(f, `{"action":"page.prefix"}`, at, after, 1)...)
	if auditExportSQLState(err) != "55000" {
		t.Fatal("invalid lookahead hidden", err)
	}
}

func TestAuditExportPublicPageCandidateGuards(t *testing.T) {
	for _, pair := range []string{"admin-policy", "admin-test", "policy-test"} {
		for _, different := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/different-time-%t", pair, different), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				f := auditExportPGFixture(t, ctx)
				auditExportPublicPolicyMutations(t, ctx, f)
				auditExportPublicTestMutations(t, ctx, f)
				var id, action string
				var at time.Time
				source := `SELECT audit_id,created_at FROM zasp_workflow_audit WHERE operation='createPolicy' AND resource_id='policy-public-history'`
				action = "policy.create"
				if pair != "admin-policy" {
					source = `SELECT audit_id,created_at FROM zasp_red_team_audit WHERE event_kind='red_team_definition_created'`
					action = "test.create"
				}
				if err := f.admin.QueryRow(ctx, source).Scan(&id, &at); err != nil {
					t.Fatal(err)
				}
				competingTime := at
				if different {
					competingTime = at.Add(-24 * time.Hour)
				}
				if pair == "policy-test" {
					_, err := f.admin.Exec(ctx, `INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version,created_at) SELECT organization_id,workspace_id,environment_id,$1,'pid_79810001-0000-4000-8000-000000000001',principal_id,'updatePolicy','policy',resource_id,1,$2 FROM zasp_workflow_audit WHERE operation='createPolicy' AND resource_id='policy-public-history'`, id, competingTime)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					auditPublicPageSeed(t, ctx, f, id, "excluded.competitor", `{}`, competingTime)
				}
				// The competitor fails the action predicate; different-time variants
				// also fail from. Neither restriction belongs on identity probes.
				filter, _ := json.Marshal(map[string]string{"action": action, "from": at.UTC().Format("2006-01-02T15:04:05.000000Z")})
				for _, keyset := range []bool{false, true} {
					var afterTime, afterID any
					if keyset {
						afterTime = at.Add(time.Microsecond)
						afterID = id
					}
					var raw []byte
					err := f.api.QueryRow(ctx, auditPublicPageSQL, auditPublicPageArgs(f, string(filter), afterTime, afterID, 1)...).Scan(&raw)
					if auditExportSQLState(err) != "55000" || len(raw) != 0 {
						t.Fatal("filtered-out same-org collision escaped", keyset, err)
					}
				}
				if different {
					// Move only the explicit collision fixture above the keyset. The
					// original producer retains its exact ID and occurrence time.
					statement := `UPDATE zasp_admin_audit SET occurred_at=$1 WHERE organization_id=$2 AND id=$3`
					if pair == "policy-test" {
						statement = `UPDATE zasp_workflow_audit SET created_at=$1 WHERE organization_id=$2 AND audit_id=$3`
					}
					if _, err := f.admin.Exec(ctx, statement, at.Add(24*time.Hour), f.identity.Scope.OrganizationID().String(), id); err != nil {
						t.Fatal(err)
					}
					query, _ := json.Marshal(map[string]string{"action": action})
					if _, err := f.api.Exec(ctx, auditPublicPageSQL, auditPublicPageArgs(f, string(query), at.Add(time.Microsecond), id, 1)...); auditExportSQLState(err) != "55000" {
						t.Fatal("newer competing identity hidden by keyset", err)
					}
				}
			})
		}
	}
}

func TestAuditExportPublicPagePostWaitAuthority(t *testing.T) {
	for _, mode := range []string{"graph", "session-revoked", "membership-revoked", "permission-revoked", "group-revoked", "expired"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			if mode == "group-revoked" {
				f.groupScope(t, ctx)
			}
			args := auditPublicPageArgs(f, `{}`, nil, nil, 50)
			lock := `SELECT 1 FROM zasp_product_sessions WHERE token_digest=$1 FOR UPDATE`
			lockArgs := []any{f.digest[:]}
			if mode == "membership-revoked" {
				lock = `SELECT 1 FROM zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2 FOR UPDATE`
				lockArgs = []any{args[0], args[3]}
			}
			state := "42501"
			if mode == "graph" {
				state = "55000"
			}
			if mode == "session-revoked" || mode == "expired" {
				state = "28000"
			}
			err := auditExportBlockedCall(t, ctx, f, auditPublicPageSQL, args, lock, lockArgs, func(tx pgx.Tx) error {
				var err error
				switch mode {
				case "graph":
					_, err = tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
				case "session-revoked":
					_, err = tx.Exec(ctx, `UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE token_digest=$1`, f.digest[:])
				case "expired":
					_, err = tx.Exec(ctx, `UPDATE zasp_product_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE token_digest=$1`, f.digest[:])
				case "membership-revoked":
					_, err = tx.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, args[0], args[3])
				case "permission-revoked":
					_, err = tx.Exec(ctx, `DELETE FROM zasp_authorized_scopes WHERE organization_id=$1 AND principal_id=$2`, args[0], args[3])
				case "group-revoked":
					_, err = tx.Exec(ctx, `DELETE FROM zasp_identity_member_groups WHERE organization_id=$1 AND principal_id=$2`, args[0], args[3])
				}
				return err
			})
			if auditExportSQLState(err) != state {
				t.Fatal("page accepted postwait authority loss", mode, err)
			}
			var untouched bool
			if err := f.admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_audit_export_jobs) AND NOT EXISTS(SELECT 1 FROM zasp_audit_export_outbox) AND NOT EXISTS(SELECT 1 FROM zasp_admin_audit)`).Scan(&untouched); err != nil || !untouched {
				t.Fatal("page mutated authority", err)
			}
		})
	}
}

func TestAuditExportPublicPageRegisteredFilters(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, identityIDs := auditExportRetainedIdentityFixture(t, ctx)
	policies := auditExportPublicPolicyMutations(t, ctx, f)
	tests := auditExportPublicTestMutations(t, ctx, f)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: f.api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	a := f.createArgs()
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) SELECT organization_id,workspace_id,id,environment_class,'metadata_only',30,true FROM zasp_environments WHERE (organization_id,workspace_id,id)=($1,$2,$3) ON CONFLICT DO NOTHING`, a[:3]...); err != nil {
		t.Fatal(err)
	}
	var version int64
	var environmentClass string
	if err := f.admin.QueryRow(ctx, `SELECT version,environment_class FROM zasp_data_controls WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, a[:3]...).Scan(&version, &environmentClass); err != nil {
		t.Fatal(err)
	}
	const configID = "pid_79840001-0000-4000-8000-000000000001"
	if _, err := repository.MutateAdministration(ctx, f.identity, administrationMutation{Operation: "updateDataControls", CollectionMode: "metadata_only", RetentionDays: 45, DeletionEnabled: true, ExpectedVersion: version, EnvironmentClass: environmentClass, AuditID: configID}); err != nil {
		t.Fatal("real data controls producer", err)
	}
	// Actual released cleanup may remove receipts without hiding retained policy
	// history. No production audit record is deleted by this setup.
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_workflow_receipts SET created_at=transaction_timestamp()-interval '8 days',expires_at=transaction_timestamp()-interval '1 day' WHERE resource_id='policy-public-history';SELECT zasp_workflow_receipt_cleanup(1000)`); err != nil {
		t.Fatal(err)
	}
	items, more, _ := auditPublicPageRead(t, ctx, f, `{}`, nil, nil, 100)
	if more || len(items) != 17 {
		t.Fatal("whole actual producer history missing", len(items))
	}
	seen := map[string]map[string]json.RawMessage{}
	for _, item := range items {
		var id string
		json.Unmarshal(item["id"], &id)
		if seen[id] != nil {
			t.Fatal("duplicate original ID")
		}
		seen[id] = item
	}
	for _, event := range append(policies, tests...) {
		item := seen[event.ID]
		if item == nil {
			t.Fatal("actual mutation ID omitted", event.ID)
		}
		for key, want := range map[string]string{"action": event.Action, "actor_id": event.ActorID, "target_id": event.TargetID, "occurred_at": event.OccurredAt, "workspace_id": event.WorkspaceID, "environment_id": event.EnvironmentID, "outcome": "succeeded"} {
			var got string
			if json.Unmarshal(item[key], &got) != nil || got != want {
				t.Fatal("producer projection changed", key, event.ID)
			}
		}
		metadata, _ := json.Marshal(event.Metadata)
		var got map[string]string
		if json.Unmarshal(item["metadata"], &got) != nil {
			t.Fatal("metadata")
		}
		actual, _ := json.Marshal(got)
		if string(actual) != string(metadata) {
			t.Fatal("summary provenance changed")
		}
	}
	for _, id := range append(identityIDs, configID) {
		if seen[id] == nil {
			t.Fatal("retained identity/config omitted")
		}
	}
	for _, action := range []string{"identity_provider.createSSOConnection", "identity_provider.deleteSSOConnection", "identity_provider.testSSOConnection", "identity_provider.createSCIMConnection", "identity_provider.deleteSCIMConnection", "data_controls.update"} {
		filter, _ := json.Marshal(map[string]string{"action": action})
		selected, more, _ := auditPublicPageRead(t, ctx, f, string(filter), nil, nil, 1)
		if len(selected) != 1 || more {
			t.Fatal("literal retained action filter", action)
		}
	}
	for _, tc := range []struct{ filter, action, id string }{
		{`{"action":"policy.create"}`, "policy.create", policies[0].ID},
		{`{"action":"test.create"}`, "test.create", ""},
		{`{"action":"identity_provider.createSSOConnection"}`, "identity_provider.createSSOConnection", ""},
	} {
		var raw []byte
		if err := f.api.QueryRow(ctx, auditPublicPageSQL, auditPublicPageArgs(f, tc.filter, nil, nil, 100)...).Scan(&raw); err != nil {
			t.Fatalf("registered public page must expose actual retained producers: SQLSTATE=%s: %v", auditExportSQLState(err), err)
		}
		var page struct {
			Items   []map[string]json.RawMessage `json:"items"`
			HasMore bool                         `json:"has_more"`
		}
		if err := json.Unmarshal(raw, &page); err != nil || len(page.Items) != 1 || page.HasMore {
			t.Fatalf("exact filtered source page: %s (%v)", raw, err)
		}
		var action, id string
		json.Unmarshal(page.Items[0]["action"], &action)
		json.Unmarshal(page.Items[0]["id"], &id)
		if action != tc.action || len(page.Items[0]) != 9 || tc.id != "" && id != tc.id {
			t.Fatal("public source identity/action/shape changed")
		}
		if tc.action == "test.create" {
			found := false
			for _, event := range tests {
				if event.ID == id && event.Action == tc.action {
					found = true
				}
			}
			if !found {
				t.Fatal("test page did not retain an actual producer ID")
			}
		}
		if tc.action == "identity_provider.createSSOConnection" {
			found := false
			for _, original := range identityIDs {
				if original == id {
					found = true
				}
			}
			if !found {
				t.Fatal("identity page did not retain schema19 producer ID")
			}
		}
	}
}
