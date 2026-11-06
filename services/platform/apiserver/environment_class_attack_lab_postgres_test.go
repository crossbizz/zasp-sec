package apiserver

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
)

// Controlled original source/target rows and sandbox reference exercise native
// consumer boundaries. This does not assert any provider sandbox was deployed.
func exerciseEnvironmentClassAttackLabConsumer(t *testing.T, f environmentClassNativeFixture, change func(string)) {
	t.Helper()
	ctx := f.ctx
	i := f.identity
	o, w, e, a := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const target = "pid_f0820001-0000-4000-8000-000000000001"
	const definition = "pid_f0820002-0000-4000-8000-000000000002"
	const source = "pid_f0820003-0000-4000-8000-000000000003"
	const binding = "pid_f0820004-0000-4000-8000-000000000004"
	const queued = "pid_f0820005-0000-4000-8000-000000000005"
	const running = "pid_f0820006-0000-4000-8000-000000000006"
	const refused = "pid_f0820007-0000-4000-8000-000000000007"
	const correlation = "pid_f0820008-0000-4000-8000-000000000008"
	const destination = "adapter.customer.example"
	stateCode := func(err error) string {
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) && len(pgerr.Code) == 5 {
			return pgerr.Code
		}
		return "unknown"
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := f.owner.Exec(ctx, query, args...); err != nil {
			t.Fatalf("controlled consumer seed refused SQLSTATE=%s", stateCode(err))
		}
	}
	exec(`INSERT INTO public.zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,state,first_seen_at,last_seen_at,version,product_kind,confidence_basis_points,observed_at,fresh_until,winning_attributes) VALUES($1,$2,$3,$4,'agent','Class-sensitive target','{}','active',clock_timestamp(),clock_timestamp(),1,'agent',9500,clock_timestamp(),clock_timestamp()+interval '1 hour','{"red_team":{"enabled":true,"endpoint":"https://adapter.customer.example/v1/evaluate","credential_reference":"ref:red-team/classification_target_0001","target_kinds":["agent_endpoint"]}}')`, o, w, e, target)
	exec(`INSERT INTO public.zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by) VALUES($1,$2,$3,$4,'Class-sensitive controlled definition',$5,'agent_endpoint','["prompt_injection"]','{"environment":"development","credential_class":"read_only","expected_side_effects":["bounded evaluation"]}',$6)`, o, w, e, definition, target, a)
	exec(`INSERT INTO public.zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,state,attempt,input_digest,verdict,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at) VALUES($1,$2,$3,$4,$5,1,$6,'complete',1,digest('controlled-class-input','sha256'),'fail','s3://fixture-bucket/classification/source','classification/source','controlled-version',digest('controlled-class-evidence','sha256'),100,clock_timestamp())`, o, w, e, source, definition, a)
	exec(`INSERT INTO public.zasp_red_team_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,objective,behavior,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at) SELECT organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,'Controlled criterion','Controlled unsafe outcome','[]',evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at FROM public.zasp_red_team_runs WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND run_id=$4`, o, w, e, source)
	exec(`INSERT INTO public.zasp_attack_lab_credential_bindings(organization_id,workspace_id,environment_id,binding_id,target_id,credential_reference,credential_class,version,reference_digest,state,valid_until) VALUES($1,$2,$3,$4,$5,'ref:red-team/classification_target_0001','read_only',1,digest('controlled-class-binding','sha256'),'active',clock_timestamp()+interval '1 hour')`, o, w, e, binding, target)
	connect := func(table, role string) *pgx.Conn {
		t.Helper()
		var name string
		// Tables and roles are fixed below, not caller-supplied SQL.
		if err := f.bootstrap.QueryRow(ctx, `SELECT principal_name FROM public.`+table+` WHERE authority_role=$1`, role).Scan(&name); err != nil {
			t.Fatal("registered consumer principal unavailable")
		}
		conn := connectRuntimeDataPlanePrincipal(t, ctx, f.configDSN, name)
		t.Cleanup(func() { _ = conn.Close(context.Background()) })
		return conn
	}
	api := connect("zasp_security_agent_principal_bindings", "zasp_security_agent_api")
	controller := connect("zasp_attack_lab_principal_bindings", "zasp_attack_lab_controller")
	proxy := connect("zasp_attack_lab_principal_bindings", "zasp_attack_lab_proxy")
	var raw json.RawMessage
	if err := api.QueryRow(ctx, `SELECT public.zasp_attack_lab_preflight($1,$2,$3,$4)`, o, w, e, source).Scan(&raw); err != nil {
		t.Fatalf("original consumer positive preflight refused SQLSTATE=%s", stateCode(err))
	}
	var preflight struct {
		Environment string `json:"environment"`
		Digest      string `json:"decision_digest"`
	}
	if json.Unmarshal(raw, &preflight) != nil || preflight.Environment != "development" {
		t.Fatal("original positive preflight binding invalid")
	}
	digest, err := hex.DecodeString(preflight.Digest)
	if err != nil || len(digest) != 32 {
		t.Fatal("original positive decision digest invalid")
	}
	create := func(run, key string) error {
		return api.QueryRow(ctx, `SELECT public.zasp_attack_lab_create_run($1,$2,$3,$4,$5,$6,$7,$8,$9)`, o, w, e, a, key, run, source, digest, correlation).Scan(&raw)
	}
	for _, run := range []string{queued, running} {
		if err := create(run, "class-consumer-create-"+run); err != nil {
			t.Fatalf("original positive consumer create refused SQLSTATE=%s", stateCode(err))
		}
	}
	// A private controlled lease is never included in failure output or artifacts.
	lease := bytes.Repeat([]byte{0x9d}, 32)
	defer func() { clear(lease) }()
	if err := controller.QueryRow(ctx, `SELECT public.zasp_attack_lab_claim_run($1,$2,$3,$4,$5,$6,$7)`, o, w, e, running, "class-consumer-controller", lease, 60).Scan(&raw); err != nil {
		t.Fatalf("original positive consumer claim refused SQLSTATE=%s", stateCode(err))
	}
	var claimed struct {
		Disposition string `json:"disposition"`
		Input       string `json:"input_digest"`
	}
	if json.Unmarshal(raw, &claimed) != nil || claimed.Disposition != "claimed" {
		t.Fatal("positive consumer claim not confirmed")
	}
	input, err := hex.DecodeString(claimed.Input)
	if err != nil || len(input) != 32 {
		t.Fatal("positive consumer input digest invalid")
	}
	if err := controller.QueryRow(ctx, `SELECT public.zasp_attack_lab_begin_provisioning($1,$2,$3,$4,$5,$6,$7)`, o, w, e, running, "class-consumer-controller", lease, input).Scan(&raw); err != nil {
		t.Fatalf("controlled provisioning intent refused SQLSTATE=%s", stateCode(err))
	}
	var sandboxName string
	if err := f.owner.QueryRow(ctx, `SELECT sandbox_name FROM public.zasp_attack_lab_runs WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND run_id=$4`, o, w, e, running).Scan(&sandboxName); err != nil {
		t.Fatal("controlled sandbox identity unavailable")
	}
	sandbox := "k8s://attack-lab/jobs/" + sandboxName + "@f0820000-0000-4000-8000-000000000001"
	if err := controller.QueryRow(ctx, `SELECT public.zasp_attack_lab_mark_running($1,$2,$3,$4,$5,$6,$7,$8)`, o, w, e, running, "class-consumer-controller", lease, input, sandbox).Scan(&raw); err != nil {
		t.Fatalf("controlled running transition refused SQLSTATE=%s", stateCode(err))
	}
	egress := func() error {
		return proxy.QueryRow(ctx, `SELECT public.zasp_attack_lab_resolve_egress($1,$2,$3,$4,$5)`, o, w, e, running, destination).Scan(&raw)
	}
	if err := egress(); err != nil {
		t.Fatalf("original positive consumer egress refused SQLSTATE=%s", stateCode(err))
	}
	snapshot := func() string {
		var result string
		if err := f.owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT count(*) FROM public.zasp_attack_lab_runs),(SELECT count(*) FROM public.zasp_attack_lab_request_receipts),(SELECT version FROM public.zasp_attack_lab_runs WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND run_id=$4),(SELECT version FROM public.zasp_attack_lab_runs WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND run_id=$5))::text`, o, w, e, queued, running).Scan(&result); err != nil {
			t.Fatal("consumer effect snapshot unavailable")
		}
		return result
	}
	for _, class := range []string{"staging", "production"} {
		change(class)
		before := snapshot()
		if code := stateCode(create(refused, "class-consumer-refused-"+class)); code != "22023" {
			t.Fatalf("class drift create refusal SQLSTATE=%s", code)
		}
		err := controller.QueryRow(ctx, `SELECT public.zasp_attack_lab_claim_run($1,$2,$3,$4,$5,$6,$7)`, o, w, e, queued, "class-consumer-controller", lease, 60).Scan(&raw)
		if code := stateCode(err); code != "40001" {
			t.Fatalf("class drift claim refusal SQLSTATE=%s", code)
		}
		if code := stateCode(egress()); code != "P0002" {
			t.Fatalf("class drift egress refusal SQLSTATE=%s", code)
		}
		if after := snapshot(); before != after {
			t.Fatal("class-sensitive consumer refusal left partial effects")
		}
	}
	change("development")
}
