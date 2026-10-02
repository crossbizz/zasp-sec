package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestP7WebhookDigestConsumerPrerequisitePostgres(t *testing.T) {
	f := newIntegrationClientFixture(t)
	f.exec(`CREATE ROLE fix1_webhook_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`)
	f.exec(`CREATE ROLE fix1_webhook_worker LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`)
	f.exec(`SELECT public.zasp_security_agent_register_principals(session_user,'fix1_webhook_api','fix1_webhook_worker')`)
	var principal string
	if err := f.owner.QueryRow(f.ctx, `SELECT principal_name FROM zasp_security_agent_principal_bindings WHERE authority_role='zasp_security_agent_worker'`).Scan(&principal); err != nil {
		t.Fatal("registered worker inventory", err)
	}
	worker := connectRuntimeDataPlanePrincipal(t, f.ctx, f.dsn, principal)
	defer worker.Close(context.Background())
	var ready bool
	if err := f.owner.QueryRow(f.ctx, `SELECT public.zasp_sa_webhook_guard()`).Scan(&ready); err != nil {
		t.Fatal(err)
	}
	i := f.browser
	o, w, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
	var raw []byte
	err := worker.QueryRow(f.ctx, `SELECT public.zasp_accept_security_agent_webhook_plan($1,$2,$3,$4,'webhook-planning-worker','webhook-planning-lease-0001',1,$4,1,decode(repeat('a',64),'hex'),decode(repeat('b',64),'hex'),'fixture-model','planner-policy-v1','Approved response handoff','send_response_webhook',$4,$4,clock_timestamp()+interval '5 minutes',$4,$4,'webhook-fix1-prerequisite',$4,'[]'::jsonb)`, o, w, e, integrationClientExisting).Scan(&raw)
	var native *pgconn.PgError
	if ready || !errors.As(err, &native) || native.Code != "42501" || native.Message != "webhook planning authority unavailable" {
		t.Fatalf("current worker prerequisite changed: guard=%t %v", ready, err)
	}
	t.Logf("OPEN current80 worker gate: registered worker=%s guard=%t native=%v; placeholders not reached; not a prepared planner proof", principal, ready, err)
}

func TestP7WebhookSigningVersionPostgres(t *testing.T) {
	f := newIntegrationClientFixture(t)
	i := f.browser
	o, w, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
	schema := func() string {
		var v string
		err := f.owner.QueryRow(f.ctx, `SELECT jsonb_build_array(pg_get_functiondef('public.zasp_reference_only(jsonb)'::regprocedure),(SELECT jsonb_agg(pg_get_constraintdef(oid) ORDER BY conname) FROM pg_constraint WHERE conrelid='public.zasp_integrations'::regclass))::text`).Scan(&v)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	originalSchema := schema()
	config := func(version string) string {
		suffix := ""
		if version != "" {
			suffix = fmt.Sprintf(`,"signing_secret_version":%q`, version)
		}
		return `{"destination_url":"https://hooks.example.test/receive","signing_secret_reference":"secret_ref_customer"` + suffix + `}`
	}
	body := func(version string, create bool) string {
		prefix := ""
		if create {
			prefix = `"connector_key":"generic-webhook",`
		}
		return `{` + prefix + `"name":"Versioned webhook","configuration":` + config(version) + `}`
	}
	created := f.invoke(i, "createIntegration", "", "webhook-version-create", body(strings.Repeat("a", 32), true), 0)
	if created.Code != 201 {
		t.Fatalf("versioned create=%d %s", created.Code, created.Body)
	}
	var value struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(created.Body.Bytes(), &value)
	id := value.ID
	assertProjection := func(version string, want int64) {
		t.Helper()
		var good bool
		err := f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM zasp_workflow_records r JOIN zasp_integrations i ON(i.organization_id,i.workspace_id,i.environment_id,i.id)=(r.organization_id,r.workspace_id,r.environment_id,r.id) WHERE r.id=$1 AND r.version=$2 AND i.version=$2 AND r.body->'configuration'=$3::jsonb AND i.configuration=$3::jsonb-'signing_secret_version')`, id, want, config(version)).Scan(&good)
		if err != nil || !good {
			t.Fatalf("full/typed projection W/T%d exact=%t %v", want, good, err)
		}
	}
	assertProjection(strings.Repeat("a", 32), 1)
	f.reconcile()
	// The actual source59 private destination consumer reads the full checked-
	// created workflow. This owner read is not a checked worker/dispatch claim.
	destination := func(v int64) (json.RawMessage, error) {
		var raw []byte
		err := f.owner.QueryRow(f.ctx, `SELECT jsonb_build_object('body',d.body,'version',d.version,'configuration_text',(d.body->'configuration')::text) FROM public.zasp_sa_webhook_destination($1,$2,$3,jsonb_build_object('integration_id',$4::text,'integration_version',$5::bigint)) d`, o, w, e, id, v).Scan(&raw)
		return raw, err
	}
	assertDestination := func(raw json.RawMessage, wantVersion int64, wantMetadata string) webhookDestinationSnapshot {
		t.Helper()
		var value webhookDestinationSnapshot
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		var actual struct {
			ID            string            `json:"id"`
			Configuration map[string]string `json:"configuration"`
		}
		if err := json.Unmarshal(value.Body, &actual); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"destination_url": "https://hooks.example.test/receive", "signing_secret_reference": "secret_ref_customer", "signing_secret_version": wantMetadata}
		if actual.ID != id || value.Version != wantVersion || !reflect.DeepEqual(actual.Configuration, want) {
			t.Fatalf("exact consumer body/version=%s wantW%d config%v", raw, wantVersion, want)
		}
		return value
	}
	resolved, err := destination(1)
	if err != nil {
		t.Fatalf("native source59 destination=%s %v", resolved, err)
	}
	firstDestination := assertDestination(resolved, 1, strings.Repeat("a", 32))
	var editedDestination webhookDestinationSnapshot
	for index, version := range []string{strings.Repeat("b", 64), "", strings.Repeat("c", 32)} {
		expected := int64(index + 1)
		key := fmt.Sprintf("webhook-version-edit-%d", index)
		response := f.invoke(i, "updateIntegration", id, key, body(version, false), expected)
		if response.Code != 200 || response.Header().Get("ETag") != fmt.Sprintf(`"%d"`, expected+1) {
			t.Fatalf("version-only/removal update=%d %s", response.Code, response.Body)
		}
		assertProjection(version, expected+1)
		if expected == 1 {
			raw, err := destination(2)
			if err != nil {
				t.Fatal(err)
			}
			editedDestination = assertDestination(raw, 2, strings.Repeat("b", 64))
		}
		f.reconcile()
		before := f.effects(t)
		replay := f.invoke(i, "updateIntegration", id, key, body(version, false), expected)
		if replay.Code != 200 || replay.Body.String() != response.Body.String() || f.effects(t) != before {
			t.Fatalf("versioned replay=%d %s", replay.Code, replay.Body)
		}
		_, err := destination(expected)
		var p *pgconn.PgError
		if !errors.As(err, &p) || p.Code != "42501" {
			t.Fatalf("source59 old binding version%d=%v", expected, err)
		}
	}
	got := f.invoke(i, "getIntegration", id, "", "", 0)
	if got.Code != 200 || !strings.Contains(got.Body.String(), strings.Repeat("c", 32)) {
		t.Fatalf("public metadata GET=%d %s", got.Code, got.Body)
	}
	grant, err := f.authorizer.Authorize(f.ctx, i, i.credentialBinding, RoutedOperation{OperationID: "listIntegrations"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.repo.ListWorkflowPage(context.WithValue(f.ctx, requestAuthorizationContextKey{}, grant), i.Scope, "integration", "", 20)
	rawPage, _ := json.Marshal(page)
	if err != nil || !strings.Contains(string(rawPage), strings.Repeat("c", 32)) {
		t.Fatalf("checked list metadata missing: %v %s", err, rawPage)
	}
	grant, err = f.authorizer.Authorize(f.ctx, i, i.credentialBinding, RoutedOperation{OperationID: "listWorkflowMutationReceipts"})
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := f.repo.ListWorkflowMutationReceipts(context.WithValue(f.ctx, requestAuthorizationContextKey{}, grant), i, 20)
	if err != nil || len(receipts) != 4 {
		t.Fatalf("actual checked receipt decoder count=%d %v", len(receipts), err)
	}
	seen := map[int64]bool{}
	for _, r := range receipts {
		if r.ResourceID != id {
			t.Fatalf("unexpected receipt %+v", r)
		}
		seen[r.ResourceVersion] = true
		var result struct {
			Configuration map[string]string `json:"configuration"`
		}
		_ = json.Unmarshal(r.Result, &result)
		want := map[int64]string{1: strings.Repeat("a", 32), 2: strings.Repeat("b", 64), 3: "", 4: strings.Repeat("c", 32)}[r.ResourceVersion]
		if result.Configuration["signing_secret_version"] != want || want != "" && !strings.Contains(string(r.Intent), want) {
			t.Fatalf("receipt lost metadata at W%d", r.ResourceVersion)
		}
	}
	if len(seen) != 4 {
		t.Fatal("missing receipt versions")
	}
	resolved, err = destination(4)
	if err != nil {
		t.Fatalf("current native source59 binding=%s %v", resolved, err)
	}
	assertDestination(resolved, 4, strings.Repeat("c", 32))
	t.Run("invalid_native_metadata_never_projects_away_invalid_input", func(t *testing.T) {
		g, err := f.authorizer.Authorize(f.ctx, i, i.credentialBinding, RoutedOperation{OperationID: "createIntegration"})
		if err != nil {
			t.Fatal(err)
		}
		proof, _ := authorizationProofJSON(g)
		invalid := []string{`7`, `null`, `{}`, `[]`, `"short"`, `"` + strings.Repeat("z", 65) + `"`, `"` + strings.Repeat("z", 31) + `!"`}
		for _, field := range []string{"secret_version", "Signing_Secret_Version", "secret", "password", "token", "credential_value", "nested"} {
			invalid = append(invalid, "field:"+field)
		}
		for _, bad := range invalid {
			var configuration map[string]any
			_ = json.Unmarshal([]byte(config("")), &configuration)
			var v any
			if strings.HasPrefix(bad, "field:") {
				configuration["signing_secret_version"] = strings.Repeat("x", 32)
				field := strings.TrimPrefix(bad, "field:")
				if field == "nested" {
					configuration[field] = map[string]any{"password": "raw"}
				} else {
					configuration[field] = "raw"
				}
			} else {
				_ = json.Unmarshal([]byte(bad), &v)
				configuration["signing_secret_version"] = v
			}
			input := map[string]any{"connector_key": "generic-webhook", "name": "Webhook", "configuration": configuration}
			intent, _ := json.Marshal(map[string]any{"resource_id": "", "expected_version": 0, "body": input})
			args := f.nativeArgs("webhook-native-invalid", "pid_78200095-0000-4000-8000-000000000095", "create", 0)
			args[10] = json.RawMessage(intent)
			prepared, _ := json.Marshal(map[string]any{"id": args[2], "connector_key": "generic-webhook", "name": "Webhook", "configuration": configuration, "status": "configured", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"})
			args[11] = json.RawMessage(prepared)
			before := f.effects(t)
			tx, err := f.api.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(f.ctx, `SELECT zasp_authorization80.fence($1)`, string(proof))
			var raw []byte
			if err == nil {
				err = tx.QueryRow(f.ctx, postgresCurrentIntegrationMutateSQL, args...).Scan(&raw)
			}
			_ = tx.Rollback(f.ctx)
			var p *pgconn.PgError
			if !errors.As(err, &p) || p.Code != "22023" || f.effects(t) != before {
				t.Fatalf("native metadata %s=%v", bad, err)
			}
		}
	})
	t.Run("mismatched_old_typed_representation_is_not_repaired", func(t *testing.T) {
		t.Cleanup(func() { f.exec(`UPDATE zasp_integrations SET configuration=$2::jsonb WHERE id=$1`, id, config("")) })
		f.exec(`UPDATE zasp_integrations SET configuration=jsonb_set(configuration,'{destination_url}','"https://different.example.test/"') WHERE id=$1`, id)
		before := f.effects(t)
		r := f.invoke(i, "updateIntegration", id, "webhook-representation-mismatch", body(strings.Repeat("d", 32), false), 4)
		if r.Code != 400 || f.effects(t) != before {
			t.Fatalf("mismatched old representation=%d %s", r.Code, r.Body)
		}
	})
	t.Run("projected_mutation_fault_rolls_back_full_and_typed_effects", func(t *testing.T) {
		before := f.effects(t)
		f.driver.mode = "error-after-mutation"
		t.Cleanup(func() { f.driver.mode = "" })
		r := f.invoke(i, "updateIntegration", id, "webhook-projection-rollback", body(strings.Repeat("d", 32), false), 4)
		f.driver.mode = ""
		if r.Code != 503 || f.effects(t) != before {
			t.Fatalf("projection rollback=%d %s", r.Code, r.Body)
		}
	})
	if schema() != originalSchema {
		t.Fatal("historical helper/CHECK changed")
	}
	if f.providerCalls.Load() != 0 {
		t.Fatal("configuration save made provider I/O")
	}
	assertP7StoredWebhookDigest(t, firstDestination, editedDestination)
}

type webhookDestinationSnapshot struct {
	Body              json.RawMessage `json:"body"`
	Version           int64           `json:"version"`
	ConfigurationText string          `json:"configuration_text"`
}

// Split-profile data compatibility only. The source80 consumer output is copied
// exactly into an owned supported59 fixture; the real unchanged planner writes
// the digest. No readiness override or fabricated delivery digest is installed.
func assertP7StoredWebhookDigest(t *testing.T, first, edited webhookDestinationSnapshot) {
	t.Helper()
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		var ready bool
		if err := owner.QueryRow(ctx, `SELECT public.zasp_sa_webhook_guard()`).Scan(&ready); err != nil || !ready {
			t.Fatalf("supported59 guard=%t %v", ready, err)
		}
		read := func(c *pgx.Conn, q string, args ...any) json.RawMessage {
			t.Helper()
			var raw json.RawMessage
			if err := c.QueryRow(ctx, q, args...).Scan(&raw); err != nil {
				t.Fatalf("actual59 consumer query %s: %v", q, err)
			}
			return raw
		}
		exec := func(q string, args ...any) {
			t.Helper()
			if _, err := owner.Exec(ctx, q, args...); err != nil {
				t.Fatal(err)
			}
		}
		seq := 0
		id := func() string { seq++; return fmt.Sprintf("pid_78205901-0000-4000-8000-%012d", seq) }
		exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($2,$1,'webhook-fix1',$2,'security_admin',true)`, o, actor)
		exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Source59 compatibility','["view","manage_integrations","manage_workflows","manage_identity","view_audit"]')`, o, w, e, actor)
		checksum, fp := migrations.ProductionSecurityAgentWebhooks().Checksum(), migrations.SecurityAgentWebhooksFingerprint()
		for _, action := range []string{"*", "send_response_webhook"} {
			var version int64
			if err := owner.QueryRow(ctx, `SELECT COALESCE((SELECT version FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,$4)),0)`, o, w, e, action).Scan(&version); err != nil {
				t.Fatal(err)
			}
			target := "action"
			if action == "*" {
				target = "environment"
			}
			read(api, `SELECT public.zasp_sa_webhook_set_control($1,$2,$3,$4,$5,$6,$7,true,$8,$9,$10,$11,$12,$13,$14)`, o, w, e, actor, "webhook-fix1-control-"+target, target, action, version, time.Now().Add(4*time.Minute), id(), id(), id(), checksum, fp)
		}
		cfg := api.Config().Copy()
		cfg.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		var previousDigest []byte
		for index, snapshot := range []webhookDestinationSnapshot{first, edited} {
			var body struct {
				ID            string            `json:"id"`
				Configuration map[string]string `json:"configuration"`
			}
			if err := json.Unmarshal(snapshot.Body, &body); err != nil {
				t.Fatal(err)
			}
			if index == 0 {
				exec(`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,version,body) VALUES($1,$2,$3,'integration',$4,$5,$6)`, o, w, e, body.ID, snapshot.Version, snapshot.Body)
			} else {
				exec(`UPDATE zasp_workflow_records SET body=$5,version=$6 WHERE (organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'integration',$4)`, o, w, e, body.ID, snapshot.Body, snapshot.Version)
				var raw []byte
				err := owner.QueryRow(ctx, `SELECT (public.zasp_sa_webhook_destination($1,$2,$3,jsonb_build_object('integration_id',$4::text,'integration_version',1))).body`, o, w, e, body.ID).Scan(&raw)
				var native *pgconn.PgError
				if !errors.As(err, &native) || native.Code != "42501" {
					t.Fatalf("old supported59 binding accepted=%v", err)
				}
			}
			var equal bool
			if err := owner.QueryRow(ctx, `SELECT d.body=$6::jsonb AND d.version=$5 AND (d.body->'configuration')::text=$7 FROM public.zasp_sa_webhook_destination($1,$2,$3,jsonb_build_object('integration_id',$4::text,'integration_version',$5::bigint)) d`, o, w, e, body.ID, snapshot.Version, snapshot.Body, snapshot.ConfigurationText).Scan(&equal); err != nil || !equal {
				t.Fatalf("exact cross-profile destination input=%t %v", equal, err)
			}
			agent, run, approval := id(), id(), id()
			definition := map[string]any{"id": agent, "name": "Response compatibility", "trigger_kind": "finding", "trigger_source": "credential", "environment_ids": []string{e}, "autonomy": "supervised", "max_steps": 1, "max_duration_seconds": 300, "temporary_policy_seconds": 600, "ai_token_budget": 1000, "max_ai_cost_nano_credits": 1000000, "concurrency_limit": 10, "allowed_actions": []string{"send_response_webhook"}, "verification_kind": "signed_delivery", "definition_version": 1, "enabled": false, "response_webhook_destination": map[string]any{"integration_id": body.ID, "integration_version": snapshot.Version}}
			intentBody := map[string]any{}
			for k, v := range definition {
				if k != "id" {
					intentBody[k] = v
				}
			}
			read(api, `SELECT public.zasp_sa_webhook_mutate_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, "create", agent, o, w, e, actor, "createSecurityAgent", "webhook-fix1-definition-"+agent, int64(0), map[string]any{"resource_id": "", "expected_version": 0, "body": intentBody}, definition, id(), id(), id(), checksum, fp)
			for n, state := range []string{"validated", "supervised"} {
				read(api, `SELECT public.zasp_sa_webhook_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, o, w, e, agent, actor, "webhook-fix1-activation-"+state+agent, int64(n+1), state, time.Now().Add(4*time.Minute), id(), id(), id(), checksum, fp)
			}
			read(api, `SELECT public.zasp_sa_manual_run($1,$2,$3,$4,$5,$6,3,$7,$8,$9,$10,$11,$12)`, o, w, e, agent, actor, "webhook-fix1-run-"+run, run, id(), id(), id(), migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint())
			const workerID = "webhook-fix1-worker"
			lease := "webhook-fix1-lease-" + run
			read(worker, postgresSecurityAgentClaimRunsV24SQL, workerID, lease, 120, 1)
			raw := read(worker, `SELECT public.zasp_sa_webhook_planner_context($1,$2,$3,$4,$5,$6)`, o, w, e, run, workerID, lease)
			var input struct {
				InputDigest string `json:"input_digest"`
				Context     struct {
					Selection json.RawMessage `json:"export_selection"`
				} `json:"context"`
			}
			if json.Unmarshal(raw, &input) != nil || input.InputDigest == "" {
				t.Fatalf("actual planner context=%s", raw)
			}
			read(worker, `SELECT public.zasp_sa_webhook_reserve_planner($1,$2,$3,$4,$5,$6,1,'webhook-fix1-reservation',decode($7,'hex'),'fixture-model','fixture-price-policy','openrouter_credit',50,100)`, o, w, e, run, workerID, lease, strings.TrimPrefix(input.InputDigest, "sha256:"))
			output := strings.Repeat("ab", 32)
			read(worker, `SELECT public.zasp_security_agent_budget_settle_planner($1,$2,$3,$4,$5,$6,1,'webhook-fix1-reservation',decode($7,'hex'),10,10,20,20)`, o, w, e, run, workerID, lease, output)
			read(worker, `SELECT public.zasp_accept_security_agent_webhook_plan($1,$2,$3,$4,$5,$6,1,$7,3,decode($8,'hex'),decode($9,'hex'),'fixture-model','planner-policy-v1','Approved response handoff','send_response_webhook',$10,$11,$12,$13,$14,$15,$10,$16)`, o, w, e, run, workerID, lease, agent, strings.TrimPrefix(input.InputDigest, "sha256:"), output, body.ID, approval, time.Now().Add(5*time.Minute), id(), id(), "webhook-fix1-accept-"+run, input.Context.Selection)
			var actualDigest []byte
			var actualW int64
			var url, reference, signing string
			if err := owner.QueryRow(ctx, `SELECT configuration_digest,integration_version,destination_url,secret_reference,signing_version FROM zasp_security_agent_webhook_deliveries WHERE run_id=$1`, run).Scan(&actualDigest, &actualW, &url, &reference, &signing); err != nil {
				t.Fatal(err)
			}
			expected := sha256.Sum256([]byte(snapshot.ConfigurationText))
			if !bytes.Equal(actualDigest, expected[:]) || actualW != snapshot.Version || url != body.Configuration["destination_url"] || reference != body.Configuration["signing_secret_reference"] || signing != body.Configuration["signing_secret_version"] {
				t.Fatalf("actual stored consumer digest/W/config differs: W%d signing%s digest%x", actualW, signing, actualDigest)
			}
			if index == 1 && bytes.Equal(actualDigest, previousDigest) {
				t.Fatal("metadata-only edit did not change consumer digest")
			}
			previousDigest = append([]byte(nil), actualDigest...)
			t.Logf("supported59 actual planner persisted checked-output W%d signing=%s full-configuration digest=%x", actualW, signing, actualDigest)
		}
	}, func(t *testing.T) string { return startDisposablePostgresAs(t, "zasp_e2e") })
}
