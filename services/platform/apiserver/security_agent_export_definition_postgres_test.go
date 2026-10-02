package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
	"time"
)

// Prerequisites only: no export definition, history, control, run or plan is seeded.
func runExportDefinitionFixture(t *testing.T, exercise func(context.Context, *pgx.Conn, *pgx.Conn, string, string, string, string)) {
	t.Helper()
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, _, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
			t.Fatal(err)
		}
		applyExport58(t, ctx, owner)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($4,$1,'public-export-org','public-export-actor','security_admin',true);
   INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Public export','["view","manage_workflows","manage_identity","view_audit"]')`, pgx.QueryExecModeSimpleProtocol, o, w, e, actor); err != nil {
			t.Fatal(err)
		}
		exercise(ctx, owner, api, o, w, e, actor)
	})
}

// Empty bearer receipts must reach the predecessor's receiptless branch;
// browser identities still require a canonical receipt at the repository.
func TestSecurityAgentExportDefinitionReceiptPostgres(t *testing.T) {
	runExportDefinitionFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string) {
		driver := &exportDefinitionHTTPDriver{integrationPostgresDriver: &integrationPostgresDriver{connection: api}}
		native, err := NewPostgresJSONDatabase(driver)
		if err != nil {
			t.Fatal(err)
		}
		db := &exportDefinitionHTTPDatabase{PostgresJSONDatabase: native, workersReady: true, driver: driver}
		repo, err := NewSecurityAgentPostgresRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		parse := func(s string) domain.ProductID {
			v, err := domain.ParseProductID(s)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
		browser := fixtureRequestIdentity(t)
		browser.Scope, err = domain.NewScope(parse(o), parse(w), parse(e))
		if err != nil {
			t.Fatal(err)
		}
		browser.PrincipalID = parse(actor)
		bearer := browser
		bearer.CredentialKind = CredentialBearerToken
		id := "pid_efba0001-0000-4000-8000-000000000001"
		value := exportDefinitionTestBody(t, browser, id)
		marshal := func(v any) json.RawMessage {
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		checksum, fp := migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()
		t.Logf("release58 checksum=%s fingerprint=%s", checksum, fp)
		for i, action := range []string{"create", "update", "delete"} {
			body := marshal(value)
			resource, intentBody := id, map[string]any{}
			for k, v := range value {
				intentBody[k] = v
			}
			if action == "create" {
				resource = ""
				delete(intentBody, "id")
			}
			if action == "delete" {
				body = json.RawMessage(`{}`)
				intentBody = map[string]any{}
			}
			mutation := WorkflowMutation{Action: action, Kind: "security_agent", ID: id, Operation: map[string]string{"create": "createSecurityAgent", "update": "updateSecurityAgent", "delete": "deleteSecurityAgent"}[action], IdempotencyKey: "export-bearer-" + action + "-0001", ExpectedVersion: int64(i), Body: body, Intent: marshal(map[string]any{"resource_id": resource, "expected_version": i, "body": intentBody}), AuditID: fmt.Sprintf("pid_efba0002-0000-4000-8000-%012d", i+1), CorrelationID: fmt.Sprintf("pid_efba0003-0000-4000-8000-%012d", i+1)}
			for _, receipt := range []string{"", "not-a-product-id"} {
				bad := mutation
				bad.ReceiptID = receipt
				if _, err := repo.MutateWorkflow(ctx, browser, bad); !errors.Is(err, ErrRepositoryOperation) {
					t.Fatalf("browser %s receipt %q error=%v", action, receipt, err)
				}
			}
			// SQL cannot infer the credential type, but must reject null or
			// malformed nonempty receipts for every mutation before any write.
			for _, receipt := range []any{nil, "not-a-product-id"} {
				var raw []byte
				err := api.QueryRow(ctx, postgresExportDefinitionMutateSQL, action, id, o, w, e, actor, mutation.Operation, mutation.IdempotencyKey, mutation.ExpectedVersion, mutation.Intent, mutation.Body, mutation.AuditID, mutation.CorrelationID, receipt, checksum, fp).Scan(&raw)
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != "22023" {
					t.Fatalf("%s malformed receipt=%v error=%v", action, receipt, err)
				}
			}
			result, err := repo.MutateWorkflow(ctx, bearer, mutation)
			if err != nil {
				t.Fatalf("bearer %s failed: %v SQL=%v", action, err, driver.lastError)
			}
			if result.Version != int64(i+1) || result.ReceiptID != "" || result.Replayed || result.AuditID != mutation.AuditID {
				t.Fatalf("bearer %s result=%+v", action, result)
			}
			var legacyRaw []byte
			legacyErr := api.QueryRow(ctx, `SELECT zasp_security_agent_mutate_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, action, id, o, w, e, actor, mutation.Operation, mutation.IdempotencyKey, mutation.ExpectedVersion, mutation.Intent, mutation.Body, mutation.AuditID, mutation.CorrelationID, "").Scan(&legacyRaw)
			var legacyPG *pgconn.PgError
			if !errors.As(legacyErr, &legacyPG) || legacyPG.Code != "55000" {
				t.Fatalf("receiptless legacy %s bypass=%v", action, legacyErr)
			}
			replay, found, err := repo.ReplayWorkflow(ctx, bearer, mutation.Operation, mutation.IdempotencyKey, mutation.Intent)
			if err != nil || !found || !replay.Replayed || replay.Version != result.Version || replay.AuditID != result.AuditID || replay.CorrelationID != result.CorrelationID || replay.ReceiptID != "" || string(replay.Body) != string(result.Body) {
				t.Fatalf("bearer %s replay=%+v found=%v error=%v", action, replay, found, err)
			}
			if _, _, err = repo.ReplayWorkflow(ctx, browser, mutation.Operation, mutation.IdempotencyKey, mutation.Intent); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("browser borrowed bearer receipt: %v", err)
			}
			changed := marshal(map[string]any{"resource_id": resource, "expected_version": 99, "body": intentBody})
			if _, _, err = repo.ReplayWorkflow(ctx, bearer, mutation.Operation, mutation.IdempotencyKey, changed); !errors.Is(err, ErrRepositoryConflict) {
				t.Fatalf("changed bearer replay=%v", err)
			}
			var marked bool
			if err = owner.QueryRow(ctx, `SELECT receipt_semantics='receiptless_incompatible' AND NOT response ? 'receipt_id' AND NOT EXISTS(SELECT 1 FROM zasp_workflow_receipts WHERE idempotency_key=$2) FROM zasp_workflow_idempotency WHERE organization_id=$1 AND idempotency_key=$2`, o, mutation.IdempotencyKey).Scan(&marked); err != nil || !marked {
				t.Fatalf("receiptless provenance=%v error=%v", marked, err)
			}
			if _, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, o, actor); err != nil {
				t.Fatal(err)
			}
			if _, _, err = repo.ReplayWorkflow(ctx, bearer, mutation.Operation, mutation.IdempotencyKey, mutation.Intent); !errors.Is(err, ErrRepositoryAuthorization) {
				t.Fatalf("revoked bearer replay=%v", err)
			}
			if _, err = repo.MutateWorkflow(ctx, bearer, mutation); !errors.Is(err, ErrRepositoryAuthorization) {
				t.Fatalf("revoked bearer mutation=%v", err)
			}
			if _, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE organization_id=$1 AND principal_id=$2`, o, actor); err != nil {
				t.Fatal(err)
			}
			if action != "delete" {
				stale := mutation
				stale.Action = "update"
				stale.Operation = "updateSecurityAgent"
				stale.IdempotencyKey = "export-bearer-stale-" + action
				stale.ExpectedVersion = 99
				stale.Intent = marshal(map[string]any{"resource_id": id, "expected_version": 99, "body": value})
				if _, err = repo.MutateWorkflow(ctx, bearer, stale); !errors.Is(err, ErrRepositoryConflict) {
					t.Fatalf("bearer stale CAS=%v", err)
				}
			}
		}
	})
}

func TestSecurityAgentExportDefinitionPublicLifecyclePostgres(t *testing.T) {
	runExportDefinitionFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string) {
		var ready bool
		if err := api.QueryRow(ctx, `SELECT zasp_sa_export_workflow_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatalf("public admission readiness=%v error=%v", ready, err)
		}
		checksum, fp := migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()
		t.Logf("release58 checksum=%s fingerprint=%s", checksum, fp)
		id := "pid_ef000001-0000-4000-8000-000000000001"
		body := map[string]any{"id": id, "name": "Public export", "trigger_kind": "finding", "trigger_source": "credential", "environment_ids": []string{e}, "autonomy": "supervised", "max_steps": 1, "max_duration_seconds": 300, "temporary_policy_seconds": 600, "ai_token_budget": 1000, "max_ai_cost_nano_credits": 1000000, "concurrency_limit": 2, "allowed_actions": []string{"create_evidence_export"}, "verification_kind": "export", "definition_version": 1, "enabled": false}
		next := 0
		ids := func() []any {
			next++
			return []any{fmt.Sprintf("pid_ef000002-0000-4000-8000-%012d", next), fmt.Sprintf("pid_ef000003-0000-4000-8000-%012d", next), fmt.Sprintf("pid_ef000004-0000-4000-8000-%012d", next)}
		}
		read := func(sql string, args ...any) map[string]any {
			t.Helper()
			var raw []byte
			if err := api.QueryRow(ctx, sql, args...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var out map[string]any
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			return out
		}
		denied := func(sql string, args ...any) {
			t.Helper()
			var raw []byte
			err := api.QueryRow(ctx, sql, args...).Scan(&raw)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || (pg.Code != "22023" && pg.Code != "42501" && pg.Code != "40001" && pg.Code != "23505" && pg.Code != "55000") {
				t.Fatalf("invalid authority accepted or wrong refusal: %v", err)
			}
		}
		controls := read(`SELECT zasp_sa_export_controls($1,$2,$3,$4,$5,$6)`, o, w, e, actor, checksum, fp)
		actions := controls["actions"].([]any)
		if len(actions) != 8 || actions[0].(map[string]any)["action_key"] != "create_evidence_export" || actions[0].(map[string]any)["enabled"] != false || actions[0].(map[string]any)["version"] != float64(0) {
			t.Fatalf("controls=%v", controls)
		}
		const mutate = `SELECT zasp_sa_export_mutate_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`
		mutationArgs := func(kind, key string, version int64, value map[string]any) []any {
			intentBody := map[string]any{}
			for k, v := range value {
				intentBody[k] = v
			}
			resource := id
			if kind == "create" {
				delete(intentBody, "id")
				resource = ""
			}
			op := map[string]string{"create": "createSecurityAgent", "update": "updateSecurityAgent", "delete": "deleteSecurityAgent"}[kind]
			args := []any{kind, id, o, w, e, actor, op, key, version, map[string]any{"resource_id": resource, "expected_version": version, "body": intentBody}, value}
			args = append(args, ids()...)
			return append(args, checksum, fp)
		}
		createArgs := mutationArgs("create", "public-export-create-0001", 0, body)
		for _, field := range []string{"unexpected", "existing_test", "max_ai_cost_nano_credits", "max_steps", "environment_ids", "enabled"} {
			bad := map[string]any{}
			for k, v := range body {
				bad[k] = v
			}
			switch field {
			case "max_ai_cost_nano_credits":
				bad[field] = 0
			case "max_steps":
				bad[field] = 2
			case "environment_ids":
				bad[field] = []string{w}
			case "enabled":
				bad[field] = true
			default:
				bad[field] = map[string]any{}
			}
			denied(mutate, mutationArgs("create", "public-export-invalid-"+field, 0, bad)...)
		}
		wrongPins := append([]any(nil), createArgs...)
		wrongPins[15] = "wrong"
		denied(mutate, wrongPins...)
		foreign := append([]any(nil), createArgs...)
		foreign[4] = w
		denied(mutate, foreign...)
		created := read(mutate, createArgs...)
		if created["version"] != float64(1) {
			t.Fatalf("created=%v", created)
		}
		denied(`SELECT zasp_security_agent_replay_definition($1,$2,$3,$4,$5,$6,$7)`, o, w, e, actor, "createSecurityAgent", "public-export-create-0001", createArgs[9])
		for _, name := range []string{"value", "detail"} {
			t.Run("legacy_"+name, func(t *testing.T) {
				var raw []byte
				err := api.QueryRow(ctx, `SELECT zasp_security_agent_definition_`+name+`($1,$2,$3,$4)`, o, w, e, id).Scan(&raw)
				if !errors.Is(err, pgx.ErrNoRows) {
					t.Fatalf("legacy export reader not fenced: %v", err)
				}
			})
		}
		t.Run("legacy_page", func(t *testing.T) {
			var raw []byte
			if err := api.QueryRow(ctx, `SELECT zasp_security_agent_definition_page($1,$2,$3,'',100)`, o, w, e).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var page struct {
				Items []struct {
					ID string `json:"id"`
				}
			}
			if err := json.Unmarshal(raw, &page); err != nil {
				t.Fatal(err)
			}
			for _, item := range page.Items {
				if item.ID == id {
					t.Fatal("legacy page exposed export")
				}
			}
		})
		// Public definition/detail/list routes require view, not write authority.
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		read(`SELECT zasp_sa_export_definition_value($1,$2,$3,$4,$5,$6,$7)`, o, w, e, id, actor, checksum, fp)
		read(`SELECT zasp_sa_export_definition_detail($1,$2,$3,$4,$5,$6,$7)`, o, w, e, id, actor, checksum, fp)
		read(`SELECT zasp_sa_export_definition_page($1,$2,$3,$4,'',50,$5,$6)`, o, w, e, actor, checksum, fp)
		denied(mutate, createArgs...)
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='security_admin' WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		replayed := read(mutate, createArgs...)
		if replayed["replayed"] != true || replayed["receipt_id"] != created["receipt_id"] {
			t.Fatalf("replay=%v", replayed)
		}
		var provenance bool
		if err := owner.QueryRow(ctx, `SELECT h.actor_id=$5 AND h.definition=d.body AND h.definition_digest=digest(convert_to(d.body::text,'UTF8'),'sha256') FROM zasp_security_agent_definitions d JOIN zasp_security_agent_definition_versions h USING(organization_id,workspace_id,environment_id,definition_id,version) WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=($1,$2,$3,$4)`, o, w, e, id, actor).Scan(&provenance); err != nil || !provenance {
			t.Fatalf("original provenance=%v %v", provenance, err)
		}
		read(`SELECT zasp_sa_export_definition_value($1,$2,$3,$4,$5,$6,$7)`, o, w, e, id, actor, checksum, fp)
		denied(`SELECT zasp_security_agent_mutate_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, createArgs[:14]...)
		body["name"] = "Updated public export"
		updateArgs := mutationArgs("update", "public-export-update-0001", 1, body)
		updated := read(mutate, updateArgs...)
		if updated["version"] != float64(2) {
			t.Fatalf("updated=%v", updated)
		}
		denied(mutate, mutationArgs("update", "public-export-stale-0001", 1, body)...)
		conflict := append([]any(nil), createArgs...)
		conflict[9] = map[string]any{"resource_id": "", "expected_version": 0, "body": map[string]any{}}
		denied(mutate, conflict...)
		body["allowed_actions"] = []string{"run_test"}
		denied(mutate, mutationArgs("update", "public-export-convert-001", 2, body)...)
		body["allowed_actions"] = []string{"create_evidence_export"}
		setControl := func(target, action string, enabled bool, version int64) map[string]any {
			args := []any{o, w, e, actor, fmt.Sprintf("public-export-control-%04d", next), target, action, enabled, version, time.Now().Add(4 * time.Minute)}
			args = append(args, ids()...)
			args = append(args, checksum, fp)
			return read(`SELECT zasp_sa_export_set_control($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, args...)
		}
		environment := controls["environment"].(map[string]any)
		setControl("environment", "*", true, int64(environment["version"].(float64)))
		setControl("action", "create_evidence_export", true, 0)
		denied(`SELECT zasp_sa_export_set_control($1,$2,$3,$4,$5,'global','*',false,1,$6,$7,$8,$9,$10,$11)`, append(append([]any{o, w, e, actor, "public-export-global-0001", time.Now().Add(4 * time.Minute)}, ids()...), checksum, fp)...)
		activate := func(target string, version int64) []any {
			args := []any{o, w, e, id, actor, fmt.Sprintf("public-export-activate-%04d", next), version, target, time.Now().Add(4 * time.Minute)}
			args = append(args, ids()...)
			return append(args, checksum, fp)
		}
		const activation = `SELECT zasp_sa_export_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
		expired := activate("validated", 2)
		expired[8] = time.Now().Add(-time.Second)
		denied(activation, expired...)
		validated := read(activation, activate("validated", 2)...)
		if validated["version"] != float64(3) {
			t.Fatalf("validated=%v", validated)
		}
		activeArgs := activate("supervised", 3)
		active := read(activation, activeArgs...)
		if active["enabled"] != true || active["version"] != float64(4) {
			t.Fatalf("active=%v", active)
		}
		denied(`SELECT zasp_production_security_agent_existing_tests_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), activeArgs[:12]...), migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())...)
		if read(activation, activeArgs...)["replayed"] != true {
			t.Fatal("activation replay lost")
		}
		denied(`SELECT zasp_security_agent_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, activeArgs[:12]...)
		runArgs := []any{o, w, e, id, actor, "public-export-manual-001", int64(4), "pid_ef000005-0000-4000-8000-000000000001"}
		runArgs = append(runArgs, ids()...)
		runArgs = append(runArgs, checksum, fp)
		manual := read(`SELECT zasp_sa_manual_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, runArgs...)
		if manual["manual_trigger"] == nil {
			t.Fatalf("manual=%v", manual)
		}
		disabled := setControl("action", "create_evidence_export", false, 1)
		if disabled["enabled"] != false {
			t.Fatal(disabled)
		}
		withdrawArgs := activate("validated", 4)
		withdrawn := read(activation, withdrawArgs...)
		if withdrawn["version"] != float64(5) || withdrawn["enabled"] != false || withdrawn["activation"] != "validated" {
			t.Fatalf("withdrawal=%v", withdrawn)
		}
		if replay := read(activation, withdrawArgs...); replay["replayed"] != true || replay["receipt_id"] != withdrawn["receipt_id"] {
			t.Fatalf("withdrawal replay=%v", replay)
		}
		denied(activation, activate("validated", 4)...)
		denied(activation, activate("draft", 5)...)
		denied(activation, activate("supervised", 5)...)
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		denied(activation, withdrawArgs...)
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		reset := read(mutate, mutationArgs("update", "public-export-reset-draft-01", 5, body)...)
		if reset["version"] != float64(6) {
			t.Fatalf("reset draft=%v", reset)
		}
		denied(activation, activeArgs...)
		deletedArgs := mutationArgs("delete", "public-export-delete-0001", 6, map[string]any{})
		deleted := read(mutate, deletedArgs...)
		replay := read(`SELECT zasp_sa_export_replay_definition($1,$2,$3,$4,$5,$6,$7,$8,$9)`, o, w, e, actor, "deleteSecurityAgent", "public-export-delete-0001", deletedArgs[9], checksum, fp)
		if replay["found"] != true || replay["result"].(map[string]any)["receipt_id"] != deleted["receipt_id"] || replay["result"].(map[string]any)["replayed"] != true {
			t.Fatalf("delete replay=%v", replay)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		denied(`SELECT zasp_sa_export_controls($1,$2,$3,$4,$5,$6)`, o, w, e, actor, checksum, fp)
		denied(`SELECT zasp_sa_export_replay_definition($1,$2,$3,$4,$5,$6,$7,$8,$9)`, o, w, e, actor, "deleteSecurityAgent", "public-export-delete-0001", deletedArgs[9], checksum, fp)
		if err := precisionMigrationRunner(t, owner).DownProductionSecurityAgentExports(ctx); err == nil {
			t.Fatal("retained public export definition history downgraded")
		}
	})
}

// A scope mapping can change while a writer waits after its initial check.
// Assert the effective grant before/after, not merely a fixture row deletion.
func TestSecurityAgentExportDefinitionAuthorityWaitPostgres(t *testing.T) {
	runExportDefinitionFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string) {
		checksum, fp := migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE (organization_id,principal_id)=($1,$4);
 INSERT INTO zasp_group_mappings(organization_id,workspace_id,environment_id,group_reference,role) VALUES($1,$2,$3,'scim-group-test-public-export-authority','security_admin');
 INSERT INTO zasp_identity_member_groups(organization_id,principal_id,group_reference) VALUES($1,$4,'scim-group-test-public-export-authority')`, pgx.QueryExecModeSimpleProtocol, o, w, e, actor); err != nil {
			t.Fatal(err)
		}
		permitted := func() bool {
			var result bool
			if err := owner.QueryRow(ctx, `SELECT COALESCE(bool_or(permissions ? 'manage_workflows'),false) FROM zasp_identity_admin_effective_scopes($4,$1) WHERE workspace_id=$2 AND environment_id=$3`, o, w, e, actor).Scan(&result); err != nil {
				t.Fatal(err)
			}
			return result
		}
		if !permitted() {
			t.Fatal("initial effective group authority absent")
		}
		const id = "pid_ef000006-0000-4000-8000-000000000001"
		body := map[string]any{"id": id, "name": "Waited draft", "trigger_kind": "finding", "trigger_source": "credential", "environment_ids": []string{e}, "autonomy": "autonomous", "max_steps": 1, "max_duration_seconds": 300, "temporary_policy_seconds": 600, "ai_token_budget": 1000, "max_ai_cost_nano_credits": 1000000, "concurrency_limit": 1, "allowed_actions": []string{"create_evidence_export"}, "verification_kind": "export", "definition_version": 1, "enabled": false}
		intentBody := map[string]any{}
		for k, v := range body {
			if k != "id" {
				intentBody[k] = v
			}
		}
		invoke := func() error {
			var result []byte
			return api.QueryRow(ctx, `SELECT zasp_sa_export_mutate_definition('create',$1,$2,$3,$4,$5,'createSecurityAgent','public-export-waited-0001',0,$6,$7,'pid_ef000007-0000-4000-8000-000000000001','pid_ef000008-0000-4000-8000-000000000001','pid_ef000009-0000-4000-8000-000000000001',$8,$9)`, id, o, w, e, actor, map[string]any{"resource_id": "", "expected_version": 0, "body": intentBody}, body, checksum, fp).Scan(&result)
		}
		blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Close(context.Background())
		if _, err := blocker.Exec(ctx, `BEGIN; LOCK TABLE zasp_workflow_records IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- invoke() }()
		joined := false
		defer func() {
			blocker.Exec(context.Background(), `ROLLBACK`)
			if !joined {
				<-done
			}
		}()
		wait := func() {
			t.Helper()
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				var waiting bool
				if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, api.PgConn().PID()).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("API did not reach owned lock barrier")
		}
		wait()
		if _, err := owner.Exec(ctx, `DELETE FROM zasp_group_mappings WHERE organization_id=$1 AND group_reference='scim-group-test-public-export-authority'`, o); err != nil {
			t.Fatal(err)
		}
		if permitted() {
			t.Fatal("effective group authority not revoked")
		}
		if _, err := blocker.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		err = <-done
		joined = true
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatalf("postwait permission refusal=%v", err)
		}
		var writes int
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_definitions WHERE definition_id=$1)+(SELECT count(*) FROM zasp_security_agent_definition_versions WHERE definition_id=$1)+(SELECT count(*) FROM zasp_workflow_receipts WHERE resource_id=$1)+(SELECT count(*) FROM zasp_workflow_idempotency WHERE idempotency_key='public-export-waited-0001')`, id).Scan(&writes); err != nil || writes != 0 {
			t.Fatalf("denied write leaked %d %v", writes, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='security_admin' WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		if err := invoke(); err != nil {
			t.Fatalf("current direct authority retry=%v", err)
		}
		if _, err := blocker.Exec(ctx, `BEGIN; LOCK TABLE zasp_security_agent_definitions IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		joined = false
		go func() {
			var result []byte
			done <- api.QueryRow(ctx, `SELECT zasp_sa_export_definition_value($1,$2,$3,$4,$5,$6,$7)`, o, w, e, id, actor, checksum, fp).Scan(&result)
		}()
		wait()
		if _, err := owner.Exec(ctx, `DELETE FROM zasp_authorized_scopes WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)`, o, w, e, actor); err != nil {
			t.Fatal(err)
		}
		if permitted() {
			t.Fatal("direct authority not revoked")
		}
		if _, err := blocker.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		err = <-done
		joined = true
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatalf("read returned after permission loss: %v", err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_authorized_scopes(organization_id,workspace_id,environment_id,principal_id,label,permissions) VALUES($1,$2,$3,$4,'Restored public export','["view","manage_workflows","manage_identity","view_audit"]')`, o, w, e, actor); err != nil {
			t.Fatal(err)
		}
		if _, err := blocker.Exec(ctx, `BEGIN; SELECT 1 FROM zasp_security_agent_kill_switches WHERE organization_id='*' FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		fresh := time.Now().Add(time.Second)
		joined = false
		go func() {
			var result []byte
			done <- api.QueryRow(ctx, `SELECT zasp_sa_export_set_control($1,$2,$3,$4,'public-export-expired-001','action','create_evidence_export',false,0,$5,'pid_ef000017-0000-4000-8000-000000000001','pid_ef000018-0000-4000-8000-000000000001','pid_ef000019-0000-4000-8000-000000000001',$6,$7)`, o, w, e, actor, fresh, checksum, fp).Scan(&result)
		}()
		wait()
		if _, err := owner.Exec(ctx, `SELECT pg_sleep(1.1)`); err != nil {
			t.Fatal(err)
		}
		if _, err := blocker.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		err = <-done
		joined = true
		if !errors.As(err, &pg) || (pg.Code != "22023" && pg.Code != "40001") {
			t.Fatalf("postwait fresh-auth refusal=%v", err)
		}
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,'create_evidence_export')`, o, w, e).Scan(&writes); err != nil || writes != 0 {
			t.Fatalf("expired control leaked %d %v", writes, err)
		}
		// An autonomous draft traverses the existing staged activation sequence;
		// only its final autonomous version is eligible for source-free admission.
		var control []byte
		if err := api.QueryRow(ctx, `SELECT zasp_sa_export_set_control($1,$2,$3,$4,'public-export-auto-control','action','create_evidence_export',true,0,clock_timestamp()+interval '4 minutes','pid_ef000027-0000-4000-8000-000000000001','pid_ef000028-0000-4000-8000-000000000001','pid_ef000029-0000-4000-8000-000000000001',$5,$6)`, o, w, e, actor, checksum, fp).Scan(&control); err != nil {
			t.Fatal(err)
		}
		for i, state := range []string{"validated", "supervised", "autonomous"} {
			var raw []byte
			if err := api.QueryRow(ctx, `SELECT zasp_sa_export_activate($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp()+interval '4 minutes',$9,$10,$11,$12,$13)`, o, w, e, id, actor, fmt.Sprintf("public-export-auto-state-%d", i), int64(i+1), state, fmt.Sprintf("pid_ef000037-0000-4000-8000-%012d", i+1), fmt.Sprintf("pid_ef000038-0000-4000-8000-%012d", i+1), fmt.Sprintf("pid_ef000039-0000-4000-8000-%012d", i+1), checksum, fp).Scan(&raw); err != nil {
				t.Fatalf("autonomous stage %s: %v", state, err)
			}
		}
		var manual []byte
		if err := api.QueryRow(ctx, `SELECT zasp_sa_manual_run($1,$2,$3,$4,$5,'public-export-auto-manual',4,'pid_ef000040-0000-4000-8000-000000000001','pid_ef000041-0000-4000-8000-000000000001','pid_ef000042-0000-4000-8000-000000000001','pid_ef000043-0000-4000-8000-000000000001',$6,$7)`, o, w, e, id, actor, checksum, fp).Scan(&manual); err != nil {
			t.Fatalf("autonomous public manual: %v", err)
		}
		var withdrawal []byte
		if err := api.QueryRow(ctx, `SELECT zasp_sa_export_activate($1,$2,$3,$4,$5,'public-export-auto-withdraw',4,'validated',clock_timestamp()+interval '4 minutes','pid_ef000047-0000-4000-8000-000000000001','pid_ef000048-0000-4000-8000-000000000001','pid_ef000049-0000-4000-8000-000000000001',$6,$7)`, o, w, e, id, actor, checksum, fp).Scan(&withdrawal); err != nil {
			t.Fatalf("autonomous withdrawal: %v", err)
		}
	})
}

func TestSecurityAgentExportDefinitionPredecessorsPostgres(t *testing.T) {
	runExportDefinitionFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string) {
		const testID = "pid_89000012-0000-4000-8000-000000000002"
		exerciseSecurityAgentExistingTestDefinition(t, ctx, owner, api, o, w, e, testID, actor, true)
		exerciseAttackLabDefinitionWithoutSource(t, ctx, owner, api, o, w, e, testID, actor)
		var raw []byte
		if err := api.QueryRow(ctx, postgresExistingTestSetControlSQL, existingTestReadPins([]any{o, w, e, actor, "predecessor-attack-control", "action", "start_attack_lab", true, int64(0), time.Now().Add(time.Minute), "pid_ef000057-0000-4000-8000-000000000001", "pid_ef000058-0000-4000-8000-000000000001", "pid_ef000059-0000-4000-8000-000000000001"})...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		args := []any{o, w, e, "pid_8a200001-0000-4000-8000-000000000001", actor, "predecessor-attack-activate", int64(2), "supervised", time.Now().Add(time.Minute), "pid_ef000067-0000-4000-8000-000000000001", "pid_ef000068-0000-4000-8000-000000000001", "pid_ef000069-0000-4000-8000-000000000001", migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
		if err := api.QueryRow(ctx, existingTestActivateSQL, args...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		args[5], args[6], args[7] = "predecessor-no-withdrawal", int64(3), "validated"
		err := api.QueryRow(ctx, existingTestActivateSQL, args...).Scan(&raw)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "40001" {
			t.Fatalf("export withdrawal changed predecessor transition: %v", err)
		}
	})
}
