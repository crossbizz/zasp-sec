package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam/probes"
)

const postgresRedTeamFireSchedulesSQL = `SELECT zasp_red_team_fire_due_schedules($1,$2)`

// RedTeamScheduleSweep is what the scheduler worker reads from one sweep.
type RedTeamScheduleSweep struct {
	Examined int `json:"examined"`
	Queued   int `json:"queued"`
}

// TestRedTeamProbeLibraryCompletionPostgres applies completion.sql sections
// WS2a, WS2b and WS2c to a database migrated through the red team invocation
// release and exercises the result with the worker, adapter, API and
// scheduler principals.
func TestRedTeamProbeLibraryCompletionPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	connection, runner, adapter, worker := redTeamInvocationFixture(t, ctx)
	if err := runner.UpProductionRedTeamInvocation(ctx); err != nil {
		t.Fatal(err)
	}
	scope := fixtureRequestIdentity(t).Scope
	principal := fixtureRequestIdentity(t).PrincipalID.String()
	org, workspace, environment := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	token := []byte(strings.Repeat("a", 32))
	exec := func(statement string, arguments ...any) {
		t.Helper()
		if _, err := connection.Exec(ctx, statement, arguments...); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	connect := func(name string) *pgx.Conn {
		t.Helper()
		config := connection.Config().Copy()
		config.User = name
		value, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { value.Close(context.Background()) })
		return value
	}

	// Before the sections: a definition with an agentic category is refused
	// and the resolver does not know the category.
	const insertDefinition = `INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by) VALUES($1,$2,$3,$4,$5,$6,'agent_endpoint',$7::jsonb,'{"environment":"staging","credential_class":"read_only","expected_side_effects":["bounded evaluation"]}',$8)`
	const agentic = `["indirect_injection","poisoned_resource","cross_agent_delegation","tool_abuse"]`
	var valid bool
	const validSQL = `SELECT zasp_red_team_definition_valid('Agentic',$1,'agent_endpoint',$2::jsonb,'{"environment":"staging","credential_class":"read_only","expected_side_effects":["bounded evaluation"]}'::jsonb)`
	if err := connection.QueryRow(ctx, validSQL, invocationTarget, agentic).Scan(&valid); err != nil || valid {
		t.Fatalf("agentic categories valid before the section: %t %v", valid, err)
	}
	var before json.RawMessage
	if err := connection.QueryRow(ctx, `SELECT to_jsonb(d) FROM zasp_red_team_definitions d WHERE definition_id=$1`, invocationDefinition).Scan(&before); err != nil {
		t.Fatal(err)
	}

	for pass := 0; pass < 2; pass++ { // every section is a no-op the second time
		for _, tag := range []string{"ws2_red_team_probe_categories", "ws2_red_team_probe_results", "ws2_red_team_schedules"} {
			applyCompletionBlock(t, ctx, connection, tag)
		}
	}

	// WS2a: the nine categories are accepted, others and production are not,
	// and the row that existed before is unchanged and still valid.
	for categories, want := range map[string]bool{agentic: true, `["prompt_injection"]`: true, `["tool_misuse"]`: false, `["indirect_injection","indirect_injection"]`: false} {
		if err := connection.QueryRow(ctx, validSQL, invocationTarget, categories).Scan(&valid); err != nil || valid != want {
			t.Fatalf("categories %s valid=%t err=%v", categories, valid, err)
		}
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_red_team_definition_valid('Production',$1,'agent_endpoint',$2::jsonb,'{"environment":"production","credential_class":"read_only","expected_side_effects":["bounded evaluation"]}'::jsonb)`, invocationTarget, agentic).Scan(&valid); err != nil || valid {
		t.Fatalf("production environment accepted: %t %v", valid, err)
	}
	var after json.RawMessage
	if err := connection.QueryRow(ctx, `SELECT to_jsonb(d) FROM zasp_red_team_definitions d WHERE definition_id=$1 AND zasp_red_team_definition_valid(name,target_id,target_kind,categories,safety)`, invocationDefinition).Scan(&after); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("existing definition changed or became invalid: %v", err)
	}
	const agenticDefinition, agenticRun = "pid_95100002-0000-4000-8000-000000000002", "pid_95100003-0000-4000-8000-000000000003"
	exec(insertDefinition, org, workspace, environment, agenticDefinition, "Agentic probes", invocationTarget, agentic, principal)
	exec(`INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,state,attempt,worker_id,lease_token,lease_expires_at,input_digest) VALUES($1,$2,$3,$4,$5,1,$6,'leased',1,'invocation-worker',$7,transaction_timestamp()+interval '1 hour',decode(repeat('cd',32),'hex'))`, org, workspace, environment, agenticRun, agenticDefinition, principal, token)
	const resolveSQL = `SELECT zasp_red_team_resolve_invocation($1,$2,$3,$4,'agent_endpoint',$5,$6,$7)`
	var body json.RawMessage
	for _, category := range []string{"indirect_injection", "poisoned_resource", "cross_agent_delegation", "tool_abuse"} {
		if err := adapter.QueryRow(ctx, resolveSQL, org, workspace, environment, invocationTarget, agenticRun, strings.Repeat("a", 32), category).Scan(&body); err != nil || !bytes.Contains(body, []byte(invocationTarget)) {
			t.Fatalf("resolve %s: %s %v", category, body, err)
		}
	}
	for name, arguments := range map[string][]any{
		"category outside the definition": {org, workspace, environment, invocationTarget, agenticRun, strings.Repeat("a", 32), "prompt_injection"},
		"unknown category":                {org, workspace, environment, invocationTarget, agenticRun, strings.Repeat("a", 32), "tool_misuse"},
		"wrong lease":                     {org, workspace, environment, invocationTarget, agenticRun, strings.Repeat("b", 32), "indirect_injection"},
	} {
		if err := adapter.QueryRow(ctx, resolveSQL, arguments...).Scan(&body); err == nil {
			t.Fatalf("%s resolved a target", name)
		}
	}

	exec(`CREATE ROLE ws2_api LOGIN INHERIT; CREATE ROLE ws2_agent_worker LOGIN INHERIT; SELECT zasp_security_agent_register_principals(session_user,'ws2_api','ws2_agent_worker')`)
	api := connect("ws2_api")

	// WS2b: the worker records the probes it ran under its lease.
	results := []RedTeamProbeResult{}
	for _, category := range []string{"indirect_injection", "poisoned_resource", "cross_agent_delegation", "tool_abuse"} {
		for index, probe := range probes.Sample(category, agenticRun, 20) {
			outcome := "protected"
			if category == "poisoned_resource" && index == 4 {
				outcome = "unsafe"
			}
			results = append(results, RedTeamProbeResult{ProbeID: probe.ID, Category: probe.Category, Outcome: outcome})
		}
	}
	encoded, _ := json.Marshal(results)
	const recordSQL = `SELECT zasp_red_team_record_probe_results($1,$2,$3,$4,$5,$6,$7::jsonb)`
	record := func(session *pgx.Conn, run, workerID string, lease []byte, payload []byte) (string, error) {
		var raw json.RawMessage
		err := session.QueryRow(ctx, recordSQL, org, workspace, environment, run, workerID, lease, payload).Scan(&raw)
		return string(raw), err
	}
	for pass := 0; pass < 2; pass++ { // a repeated record replaces, never duplicates
		if raw, err := record(worker, agenticRun, "invocation-worker", token, encoded); err != nil || !strings.Contains(raw, `"recorded": 80`) {
			t.Fatalf("record: %s %v", raw, err)
		}
	}
	mutate := func(change func([]RedTeamProbeResult)) []byte {
		copyOf := append([]RedTeamProbeResult(nil), results...)
		change(copyOf)
		value, _ := json.Marshal(copyOf)
		return value
	}
	for name, attempt := range map[string]func() (string, error){
		"adapter principal":   func() (string, error) { return record(adapter, agenticRun, "invocation-worker", token, encoded) },
		"migration principal": func() (string, error) { return record(connection, agenticRun, "invocation-worker", token, encoded) },
		"wrong lease": func() (string, error) {
			return record(worker, agenticRun, "invocation-worker", []byte(strings.Repeat("b", 32)), encoded)
		},
		"wrong worker": func() (string, error) { return record(worker, agenticRun, "other-worker", token, encoded) },
		"category not in the definition": func() (string, error) {
			probe := probes.Sample("prompt_injection", agenticRun, 1)[0]
			return record(worker, agenticRun, "invocation-worker", token, mutate(func(v []RedTeamProbeResult) { v[0] = RedTeamProbeResult{probe.ID, probe.Category, "protected"} }))
		},
		"probe of another category": func() (string, error) {
			return record(worker, agenticRun, "invocation-worker", token, mutate(func(v []RedTeamProbeResult) { v[0].Category = "tool_abuse" }))
		},
		"repeated probe": func() (string, error) {
			return record(worker, agenticRun, "invocation-worker", token, mutate(func(v []RedTeamProbeResult) { v[1] = v[0] }))
		},
		"unknown outcome": func() (string, error) {
			return record(worker, agenticRun, "invocation-worker", token, mutate(func(v []RedTeamProbeResult) { v[0].Outcome = "skipped" }))
		},
		"extra member": func() (string, error) {
			return record(worker, agenticRun, "invocation-worker", token, []byte(`[{"probe_id":"`+results[0].ProbeID+`","category":"indirect_injection","outcome":"protected","answer":"leak"}]`))
		},
		"empty": func() (string, error) { return record(worker, agenticRun, "invocation-worker", token, []byte(`[]`)) },
	} {
		if raw, err := attempt(); err == nil {
			t.Fatalf("%s recorded probe results: %s", name, raw)
		}
	}
	var stored, unsafe int
	if err := connection.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE outcome='unsafe') FROM zasp_red_team_probe_results WHERE run_id=$1 AND attempt=1`, agenticRun).Scan(&stored, &unsafe); err != nil || stored != 80 || unsafe != 1 {
		t.Fatalf("stored=%d unsafe=%d err=%v", stored, unsafe, err)
	}
	if _, err := worker.Exec(ctx, `SELECT count(*) FROM zasp_red_team_probe_results`); err == nil {
		t.Fatal("the worker reads probe results directly")
	}
	// The run detail lists the probes of an attempt; an attempt recorded
	// before this section (no probe rows) lists none and stays readable.
	exec(`INSERT INTO zasp_red_team_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,objective,behavior,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size)
 SELECT organization_id,workspace_id,environment_id,run_id,1,input_digest,'pass','Evaluate curated categories: prompt_injection','1 of 1 curated security checks passed; 0 exposed unsafe behavior.','["prompt_injection: protected"]','s3://zasp-evidence/'||run_id,run_id,'v1',decode(repeat('ef',32),'hex'),10 FROM zasp_red_team_runs WHERE run_id IN($1,$2)`, invocationRun, agenticRun)
	detail := func(run string) struct {
		Attempts []struct {
			Attempt      int                  `json:"attempt"`
			ProbeResults []RedTeamProbeResult `json:"probe_results"`
		} `json:"attempts"`
	} {
		t.Helper()
		var raw json.RawMessage
		var decoded struct {
			Attempts []struct {
				Attempt      int                  `json:"attempt"`
				ProbeResults []RedTeamProbeResult `json:"probe_results"`
			} `json:"attempts"`
		}
		// The real run detail, read by a registered API principal.
		if err := api.QueryRow(ctx, postgresRedTeamGetRunSQL, org, workspace, environment, run).Scan(&raw); err != nil || json.Unmarshal(raw, &decoded) != nil {
			t.Fatalf("detail: %s %v", raw, err)
		}
		return decoded
	}
	if got := detail(agenticRun); len(got.Attempts) != 1 || len(got.Attempts[0].ProbeResults) != 80 || got.Attempts[0].ProbeResults[0] != results[0] || got.Attempts[0].ProbeResults[79] != results[79] || !validRedTeamProbeResults(got.Attempts[0].ProbeResults) {
		t.Fatalf("probe run detail = %d attempts", len(got.Attempts))
	}
	if got := detail(invocationRun); len(got.Attempts) != 1 || len(got.Attempts[0].ProbeResults) != 0 {
		t.Fatal("an attempt recorded before the section gained probe results")
	}
	var definition string
	if err := connection.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_red_team_get_run(text,text,text,text)'::regprocedure)`).Scan(&definition); err != nil || strings.Count(definition, "'probe_results'") != 1 || !strings.Contains(definition, "zasp_red_team_probe_results probe_row") {
		t.Fatalf("zasp_red_team_get_run does not return probe results: %v", err)
	}

	// WS2c: the schedule API.
	exec(`CREATE ROLE ws2_scheduler LOGIN INHERIT IN ROLE zasp_discovery_scheduler`)
	scheduler := connect("ws2_scheduler")
	type schedule struct {
		Version        int64   `json:"version"`
		Enabled        bool    `json:"enabled"`
		CadenceSeconds *int    `json:"cadence_seconds"`
		OnTargetChange bool    `json:"on_target_change"`
		NextRunAt      *string `json:"next_run_at"`
		LastRunID      *string `json:"last_run_id"`
		LastTrigger    *string `json:"last_trigger"`
		LastOutcome    *string `json:"last_outcome"`
	}
	get := func(definition string) (schedule, []byte) {
		t.Helper()
		var raw json.RawMessage
		var value schedule
		if err := api.QueryRow(ctx, postgresRedTeamGetScheduleSQL, org, workspace, environment, definition).Scan(&raw); err != nil || json.Unmarshal(raw, &value) != nil {
			t.Fatalf("get schedule: %s %v", raw, err)
		}
		if _, err := decodeRedTeamSchedule(raw, definition); err != nil {
			t.Fatalf("the API decoder rejects the stored schedule %s", raw)
		}
		return value, raw
	}
	put := func(session *pgx.Conn, definition string, expected int64, enabled bool, cadence any, onChange bool) error {
		var raw json.RawMessage
		return session.QueryRow(ctx, postgresRedTeamPutScheduleSQL, org, workspace, environment, principal, definition, expected, enabled, cadence, onChange).Scan(&raw)
	}
	if value, _ := get(agenticDefinition); value.Version != 0 || value.Enabled || value.NextRunAt != nil {
		t.Fatalf("unsaved schedule = %+v", value)
	}
	for name, attempt := range map[string]func() error{
		"worker principal":        func() error { return put(worker, agenticDefinition, 0, true, 3600, false) },
		"stale version":           func() error { return put(api, agenticDefinition, 3, true, 3600, false) },
		"cadence under one hour":  func() error { return put(api, agenticDefinition, 0, true, 600, false) },
		"enabled without trigger": func() error { return put(api, agenticDefinition, 0, true, nil, false) },
		"unknown definition":      func() error { return put(api, "pid_95ffffff-0000-4000-8000-00000000000a", 0, true, 3600, false) },
	} {
		if err := attempt(); err == nil {
			t.Fatalf("%s saved a schedule", name)
		}
	}
	if err := put(api, agenticDefinition, 0, true, 3600, true); err != nil {
		t.Fatal(err)
	}
	if value, _ := get(agenticDefinition); value.Version != 1 || !value.Enabled || value.CadenceSeconds == nil || *value.CadenceSeconds != 3600 || !value.OnTargetChange || value.NextRunAt == nil || value.LastRunID != nil {
		t.Fatalf("saved schedule = %+v", value)
	}
	if err := put(api, agenticDefinition, 0, true, 7200, true); err == nil {
		t.Fatal("a second writer replaced the schedule with a stale version")
	}

	// The scheduler: nothing is due yet; an unauthorized principal is refused.
	fire := func(session *pgx.Conn) (RedTeamScheduleSweep, error) {
		var raw json.RawMessage
		var sweep RedTeamScheduleSweep
		if err := session.QueryRow(ctx, postgresRedTeamFireSchedulesSQL, "scheduler-1", 10).Scan(&raw); err != nil {
			return sweep, err
		}
		return sweep, json.Unmarshal(raw, &sweep)
	}
	for name, session := range map[string]*pgx.Conn{"api": api, "worker": worker, "adapter": adapter} {
		if _, err := fire(session); err == nil {
			t.Fatalf("%s principal fired schedules", name)
		}
	}
	runs := func(definition string) (count int, newest, requestedBy, state string) {
		t.Helper()
		if err := connection.QueryRow(ctx, `SELECT count(*),COALESCE((array_agg(run_id ORDER BY queued_at DESC,run_id))[1],''),COALESCE(max(requested_by),''),COALESCE((array_agg(state ORDER BY queued_at DESC,run_id))[1],'') FROM zasp_red_team_runs WHERE definition_id=$1`, definition).Scan(&count, &newest, &requestedBy, &state); err != nil {
			t.Fatal(err)
		}
		return
	}
	// The leased run of the definition is still active: a target change is
	// kept pending and nothing is queued.
	exec(`UPDATE zasp_inventory_entities SET winning_attributes=winning_attributes||'{"model":"model-b"}'::jsonb WHERE id=$1`, invocationTarget)
	if sweep, err := fire(scheduler); err != nil || sweep.Examined != 1 || sweep.Queued != 0 {
		t.Fatalf("sweep with an active run = %+v %v", sweep, err)
	}
	if count, _, _, _ := runs(agenticDefinition); count != 1 {
		t.Fatalf("a run was queued beside an active run: %d", count)
	}
	// Once the active run ends, the changed target is re-tested without a
	// person: one queued run, its outbox row and its audit event.
	exec(`UPDATE zasp_red_team_runs SET state='failed',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,error_code='exhausted',completed_at=transaction_timestamp() WHERE run_id=$1`, agenticRun)
	if sweep, err := fire(scheduler); err != nil || sweep.Examined != 1 || sweep.Queued != 1 {
		t.Fatalf("sweep after a target change = %+v %v", sweep, err)
	}
	count, scheduledRun, requestedBy, state := runs(agenticDefinition)
	value, _ := get(agenticDefinition)
	if count != 2 || state != "queued" || requestedBy != principal || value.LastRunID == nil || *value.LastRunID != scheduledRun || value.LastTrigger == nil || *value.LastTrigger != "target_change" || value.LastOutcome == nil || *value.LastOutcome != "queued" || value.Version != 1 {
		t.Fatalf("scheduled run count=%d state=%s by=%s schedule=%+v", count, state, requestedBy, value)
	}
	var outbox, audit int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_red_team_outbox WHERE deterministic_key='test-jobs:'||$1 AND payload->>'run_id'=$1 AND payload->>'definition_id'=$2),(SELECT count(*) FROM zasp_red_team_audit WHERE resource_id=$1 AND event_kind='red_team_run_queued' AND actor_id=$3)`, scheduledRun, agenticDefinition, principal).Scan(&outbox, &audit); err != nil || outbox != 1 || audit != 1 {
		t.Fatalf("outbox=%d audit=%d err=%v", outbox, audit, err)
	}
	// No further change and no due cadence: nothing happens.
	if sweep, err := fire(scheduler); err != nil || sweep.Examined != 0 || sweep.Queued != 0 {
		t.Fatalf("idle sweep = %+v %v", sweep, err)
	}
	// A due cadence while that run is still queued is skipped, not stacked.
	exec(`UPDATE zasp_red_team_schedules SET next_run_at=transaction_timestamp()-interval '1 minute' WHERE definition_id=$1`, agenticDefinition)
	if sweep, err := fire(scheduler); err != nil || sweep.Examined != 1 || sweep.Queued != 0 {
		t.Fatalf("cadence sweep with a queued run = %+v %v", sweep, err)
	}
	if value, _ := get(agenticDefinition); value.LastOutcome == nil || *value.LastOutcome != "skipped_active" || value.NextRunAt == nil {
		t.Fatalf("skipped schedule = %+v", value)
	}
	// A due cadence with no active run queues the next run.
	exec(`UPDATE zasp_red_team_runs SET state='cancelled',error_code='cancelled',completed_at=transaction_timestamp() WHERE run_id=$1`, scheduledRun)
	exec(`UPDATE zasp_red_team_schedules SET next_run_at=transaction_timestamp()-interval '1 minute' WHERE definition_id=$1`, agenticDefinition)
	if sweep, err := fire(scheduler); err != nil || sweep.Queued != 1 {
		t.Fatalf("cadence sweep = %+v %v", sweep, err)
	}
	count, cadenceRun, _, _ := runs(agenticDefinition)
	if value, _ := get(agenticDefinition); count != 3 || cadenceRun == scheduledRun || value.LastTrigger == nil || *value.LastTrigger != "cadence" || value.LastRunID == nil || *value.LastRunID != cadenceRun {
		t.Fatalf("cadence run count=%d schedule=%+v", count, value)
	}
	// The non-production rule is unchanged: when the environment is production
	// the due schedule queues nothing and records the refusal, and a schedule
	// cannot be enabled.
	exec(`UPDATE zasp_red_team_runs SET state='cancelled',error_code='cancelled',completed_at=transaction_timestamp() WHERE run_id=$1`, cadenceRun)
	exec(`UPDATE zasp_environments SET environment_class='production' WHERE (organization_id,workspace_id,id)=($1,$2,$3)`, org, workspace, environment)
	exec(`UPDATE zasp_red_team_schedules SET next_run_at=transaction_timestamp()-interval '1 minute' WHERE definition_id=$1`, agenticDefinition)
	if sweep, err := fire(scheduler); err != nil || sweep.Examined != 1 || sweep.Queued != 0 {
		t.Fatalf("production sweep = %+v %v", sweep, err)
	}
	if count, _, _, _ := runs(agenticDefinition); count != 3 {
		t.Fatalf("a scheduled run was queued in a production environment: %d", count)
	}
	if value, _ := get(agenticDefinition); value.LastOutcome == nil || *value.LastOutcome != "rejected" {
		t.Fatalf("production schedule = %+v", value)
	}
	if err := put(api, agenticDefinition, 1, true, 3600, false); err == nil {
		t.Fatal("a schedule was enabled in a production environment")
	}
	if err := put(api, agenticDefinition, 1, false, nil, false); err != nil {
		t.Fatalf("a schedule could not be disabled: %v", err)
	}
	if value, _ := get(agenticDefinition); value.Version != 2 || value.Enabled || value.NextRunAt != nil {
		t.Fatalf("disabled schedule = %+v", value)
	}
	if sweep, err := fire(scheduler); err != nil || sweep.Examined != 0 {
		t.Fatalf("a disabled schedule was examined: %+v %v", sweep, err)
	}
}
