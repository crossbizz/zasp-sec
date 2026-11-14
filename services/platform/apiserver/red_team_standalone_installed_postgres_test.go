package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam/probes"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

// TestRedTeamStandaloneRunOnInstalledBaselinePostgres needs
// ZASP_BASELINE_RELEASE_TEST_DSN: a superuser connection to a database on
// which the baseline is installed (the same database the baseline package's
// completion tests use). The service logins of the baseline must be able to
// connect with the same host and port.
//
// It applies the sections and refreshes the baseline seal, so it changes that
// database; every row it writes belongs to a tenant of its own.
//
// It establishes what happens there to a red team run that is not a Security
// Agent test step (a person pressed Run on the Red Team page, or a schedule
// fired), where the linked test authority zasp_temporal71 is installed:
//
//   - before completion.sql section WS2d the red team worker cannot classify
//     the run (zasp_temporal71.op01 refuses a run without a parent) and so
//     never claims it;
//   - with sections WS2a to WS2e the run is classified as standalone, claimed
//     by the worker login, its target is resolved by the adapter login for the
//     probe categories, its probe results are recorded and it is finished;
//   - the installed linked authority stays ready, a linked run is refused by
//     the standalone path, and saving a schedule writes an audit row.
//
// The test, the run and the schedule are created, read and saved by the API
// login inside a checked request (the transaction-local context the API
// server sets), through the same functions the HTTP handlers call.
func TestRedTeamStandaloneRunOnInstalledBaselinePostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_BASELINE_RELEASE_TEST_DSN")
	if dsn == "" {
		t.Skip("ZASP_BASELINE_RELEASE_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	login := func(name string) *pgx.Conn {
		t.Helper()
		config := admin.Config().Copy()
		config.User = name
		connection, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Cleanup(func() { connection.Close(context.Background()) })
		return connection
	}
	worker, adapter, api, scheduler := login("zasp_svc_red_team_worker"), login("zasp_svc_red_team_adapter"), login("zasp_svc_security_agent_api"), login("zasp_svc_scheduler")
	var installed, sectionsBefore bool
	if err := admin.QueryRow(ctx, `SELECT to_regnamespace('zasp_temporal71') IS NOT NULL AND zasp_baseline.intact(),to_regprocedure('public.zasp_red_team_standalone_protocol(text,text,text,text)') IS NOT NULL`).Scan(&installed, &sectionsBefore); err != nil || !installed {
		t.Fatalf("baseline with the linked authority installed=%t err=%v", installed, err)
	}
	id := func() string {
		t.Helper()
		value, err := domain.NewProductID()
		if err != nil {
			t.Fatal(err)
		}
		return value.String()
	}
	o, w, e, actor, integration, syncID, snapshot, target, evidenceID, definition := id(), id(), id(), id(), id(), id(), id(), id(), id(), id()
	credential := "ref:red-team/probe_" + strings.ReplaceAll(target[4:], "-", "")[:16]
	const safety = `{"environment":"staging","credential_class":"read_only","expected_side_effects":["bounded evaluation"]}`
	seed, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Rollback(context.Background())
	for _, statement := range []struct {
		sql       string
		arguments []any
	}{
		{`SET LOCAL session_replication_role=replica`, nil},
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Probe tenant',$2)`, []any{o, "probe-" + o[4:12] + ".invalid"}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Probe workspace')`, []any{w, o}},
		{`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Probe staging','staging')`, []any{o, w, e}},
		{`INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,apply_result,complete,is_last_good,collected_at,committed_at) VALUES($1,$2,$3,$4,$5,$6,1,'kubernetes','s3://zasp-evidence/probe/manifest.json',decode(repeat('ab',32),'hex'),'complete',decode(repeat('ab',32),'hex'),'{}',true,true,now()-interval '1 minute',now()-interval '1 minute')`, []any{o, w, e, snapshot, integration, syncID}},
		{`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,state,first_seen_at,last_seen_at,version,product_kind,confidence_basis_points,winning_evidence_id,winning_snapshot_id,winning_generation,observed_at,fresh_until,projection_version,winning_integration_id,winning_provider,winning_source,winning_source_native_id,winning_identity_rule,winning_source_projection,winning_attributes)
 VALUES($1,$2,$3,$4,'agent','Probe target','{}','active',now()-interval '1 minute',now()-interval '1 minute',1,'agent',9500,$5,$6,1,now()-interval '1 minute',now()+interval '1 hour',1,$7,'kubernetes','kubernetes','probe-agent',1,1,jsonb_build_object('red_team',jsonb_build_object('enabled',true,'endpoint','https://adapter.customer.example/v1/evaluate','credential_reference',$8::text,'target_kinds',jsonb_build_array('agent_endpoint'))))`, []any{o, w, e, target, evidenceID, snapshot, integration, credential}},
		{`INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,source,generation,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version)
 VALUES($1,$2,$3,$4,$5,$6,$7,'s3://zasp-evidence/probe/page.json',decode(repeat('ab',32),'hex'),'application/json','raw_v1','parser_v1',now()-interval '1 minute','kubernetes',1,$8,'probe/page.json','version-1',128,'tool_v1')`, []any{o, w, e, evidenceID, integration, snapshot, target, id()}},
		{`INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,identity_rule_version,identity_priority,source_projection_version)
 VALUES($1,$2,$3,$4,'kubernetes',$5,'probe-agent',$6,'present','{}',now()-interval '1 minute',now()-interval '1 minute','kubernetes','kubernetes_agent','Probe target','{}','kubernetes_agent','agent',1,decode(repeat('ab',32),'hex'),$7,9500,now()-interval '1 minute',now()+interval '1 hour',1,80,1)`, []any{o, w, e, integration, target, snapshot, evidenceID}},
		{`SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,$4,$5,$6,'read_only',1,decode(repeat('ab',32),'hex'),transaction_timestamp()+interval '1 hour')`, []any{o, w, e, id(), target, credential}},
		{`INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by) VALUES($1,$2,$3,$4,'Curated proof',$5,'agent_endpoint','["prompt_injection","tool_abuse"]',$6::jsonb,$7)`, []any{o, w, e, definition, target, safety, actor}},
	} {
		if _, err := seed.Exec(ctx, statement.sql, statement.arguments...); err != nil {
			t.Fatalf("seed %.60s: %v", statement.sql, err)
		}
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	organization, _ := domain.ParseProductID(o)
	workspace, _ := domain.ParseProductID(w)
	environment, _ := domain.ParseProductID(e)
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	// checked runs one statement as the API login inside a checked request of
	// the actor: the transaction-local authorization context the API server
	// sets for every request, sealed with the installation's verifier key.
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_authorization80.verifier(version,key) VALUES(repeat('a',64),decode(repeat('5a',32),'hex')) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	checked := func(statement string, arguments ...any) (json.RawMessage, error) {
		t.Helper()
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		var xid, version, seal string
		if err := tx.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid); err != nil {
			t.Fatal(err)
		}
		if err := admin.QueryRow(ctx, `SELECT version FROM zasp_authorization80.verifier`).Scan(&version); err != nil {
			t.Fatal(err)
		}
		proof, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "principal_id": actor, "key_version": version, "expires_at": time.Now().Add(time.Minute).UnixMilli()})
		if err := admin.QueryRow(ctx, `SELECT encode(public.hmac(convert_to(jsonb_build_array('zasp-authorization-context-v1','zasp_svc_security_agent_api',$1::text,$2::jsonb)::text,'UTF8'),key,'sha256'),'hex') FROM zasp_authorization80.verifier`, xid, string(proof)).Scan(&seal); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('zasp.authorization80',$1,true),set_config('zasp.authorization80_seal',$2,true)`, string(proof), seal); err != nil {
			t.Fatal(err)
		}
		var raw json.RawMessage
		if err := tx.QueryRow(ctx, statement, arguments...).Scan(&raw); err != nil {
			return nil, err
		}
		return raw, tx.Commit(ctx)
	}
	// A person presses Run: the API login calls zasp_red_team_run_test inside
	// a checked request, exactly as the POST does.
	press := func(definitionID string) string {
		t.Helper()
		run := id()
		if raw, err := api.Query(ctx, postgresRedTeamRunTestSQL, o, w, e, actor, "pressed-"+run[4:], definitionID, int64(1), run, id()); err == nil {
			raw.Close()
			if raw.Err() == nil {
				t.Fatal("the API login queued a run outside a checked request")
			}
		}
		raw, err := checked(postgresRedTeamRunTestSQL, o, w, e, actor, "pressed-"+run[4:], definitionID, int64(1), run, id())
		if err != nil || !bytes.Contains(raw, []byte(`"status": "queued"`)) {
			t.Fatalf("queue run: %s %v", raw, err)
		}
		var links, outbox int
		if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_test_links WHERE test_run_id=$1),(SELECT count(*) FROM zasp_red_team_outbox WHERE payload->>'run_id'=$1)`, run).Scan(&links, &outbox); err != nil || links != 0 || outbox != 1 {
			t.Fatalf("pressed run links=%d outbox=%d err=%v", links, outbox, err)
		}
		return run
	}
	workerDB, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	if available, err := workerDB.LegacyTestsAvailable(ctx, "zasp_red_team_worker"); err != nil || !available {
		t.Fatalf("the worker does not see the installed linked authority: %t %v", available, err)
	}
	linked, err := NewLinkedRedTeamExecutionRepository(workerDB)
	if err != nil {
		t.Fatal("installed linked repository", err)
	}
	curatedRun := press(definition)

	// The outbox login publishes the queued run: its repository is ready on
	// the baseline and claims the run's outbox event.
	outboxDB, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: login("zasp_svc_red_team_outbox")})
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := NewRedTeamExecutionRepository(outboxDB, RedTeamExecutionAuthorityOutbox)
	if err != nil {
		t.Fatal("red team outbox repository on the baseline", err)
	}
	events, err := outbox.ClaimRedTeamOutbox(ctx, "probe-outbox", strings.Repeat("f", 32), 60, 100)
	claimedEvents, _ := json.Marshal(events)
	if err != nil || !bytes.Contains(claimedEvents, []byte(curatedRun)) {
		t.Fatalf("the pressed run's outbox event was not claimed: %s %v", claimedEvents, err)
	}

	// The installed protocol refuses the unlinked run: with only the linked
	// authority the worker never claims a run started from the Red Team page.
	if protocol, err := linked.RunProtocol(ctx, scope, curatedRun); err == nil {
		t.Fatalf("the installed linked protocol classified a standalone run as %q", protocol)
	}
	if !sectionsBefore {
		if _, err := NewInstalledStandaloneRedTeamExecutionRepository(workerDB); err == nil {
			t.Fatal("standalone authority available before its section")
		}
	}
	for pass := 0; pass < 2; pass++ {
		for _, tag := range []string{"ws2_red_team_probe_categories", "ws2_red_team_probe_results", "ws2_red_team_schedules", "ws2_red_team_standalone_protocol", "ws2_red_team_schedule_audit", "ws2_red_team_api_functions"} {
			applyCompletionBlock(t, ctx, admin, tag)
		}
	}
	// The baseline seals its whole catalog, so a section applied to an
	// installed database breaks the seal by design. The sections reach a real
	// installation inside a rebuilt baseline, which is sealed with them; the
	// seal is refreshed here the same way, with the superuser's rights, to
	// stand for that rebuild. With it the installed authority is ready again.
	if _, err := admin.Exec(ctx, `UPDATE zasp_baseline.seal SET content=zasp_baseline.content(),marker=zasp_baseline.marker()`); err != nil {
		t.Fatal(err)
	}
	var intact bool
	if err := admin.QueryRow(ctx, `SELECT zasp_baseline.intact() AND zasp_temporal71.current_ready()`).Scan(&intact); err != nil || !intact || linked.Ready(ctx) != nil {
		t.Fatalf("the sections broke the installed authority: intact=%t err=%v linked=%v", intact, err, linked.Ready(ctx))
	}
	standalone, err := NewInstalledStandaloneRedTeamExecutionRepository(workerDB)
	if err != nil {
		t.Fatal("standalone authority", err)
	}
	for name, session := range map[string]*pgx.Conn{"adapter": adapter, "api": api, "scheduler": scheduler} {
		var raw json.RawMessage
		if err := session.QueryRow(ctx, postgresRedTeamStandaloneProtocolSQL, o, w, e, curatedRun).Scan(&raw); err == nil {
			t.Fatalf("%s login classified a run: %s", name, raw)
		}
	}
	agenticCategories := []string{"indirect_injection", "poisoned_resource", "cross_agent_delegation"}
	agenticDefinition := id()
	// A person creates a test with the agentic categories and opens it.
	if raw, err := checked(postgresRedTeamCreateDefinitionSQL, o, w, e, actor, "create-"+agenticDefinition[4:], agenticDefinition, "Agentic probes", target, "agent_endpoint", `["indirect_injection","poisoned_resource","cross_agent_delegation"]`, safety, id()); err != nil || !bytes.Contains(raw, []byte(`"cross_agent_delegation"`)) {
		t.Fatalf("a definition with the agentic categories was refused: %s %v", raw, err)
	}
	if _, err := checked(postgresRedTeamCreateDefinitionSQL, o, w, e, actor, "create-"+id()[4:], id(), "Production", target, "agent_endpoint", `["indirect_injection"]`, strings.Replace(safety, "staging", "production", 1), id()); err == nil {
		t.Fatal("a definition for a production environment was created")
	}
	if raw, err := checked(postgresRedTeamGetDefinitionSQL, o, w, e, agenticDefinition); err != nil || !bytes.Contains(raw, []byte(agenticDefinition)) {
		t.Fatalf("open test: %s %v", raw, err)
	}
	for name, statement := range map[string]string{"test": postgresRedTeamGetDefinitionSQL, "run": postgresRedTeamGetRunSQL} {
		var raw json.RawMessage
		subject := agenticDefinition
		if name == "run" {
			subject = curatedRun
		}
		if err := api.QueryRow(ctx, statement, o, w, e, subject).Scan(&raw); err == nil {
			t.Fatalf("the API login read a %s outside a checked request", name)
		}
	}
	adapterDB, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: adapter})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := redteamadapter.NewTemporalPostgresJournal(adapterDB, migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint())
	if err != nil || journal.Ready(ctx) != nil {
		t.Fatalf("adapter journal after the sections: %v", err)
	}

	execute := func(run string, categories []string) {
		t.Helper()
		if protocol, err := standalone.StandaloneRunProtocol(ctx, scope, run); err != nil || protocol != "standalone" {
			t.Fatalf("run protocol=%q err=%v", protocol, err)
		}
		token := strings.Repeat("c", 32)
		claim, err := standalone.ClaimRedTeamRun(ctx, scope, run, "probe-worker", token, 60)
		if err != nil || claim.Disposition != "claimed" || claim.EvidenceVersion != "" || claim.Run.ID != run || strings.Join(claim.Definition.Categories, ",") != strings.Join(categories, ",") {
			t.Fatalf("claim: %+v %v", claim, err)
		}
		if beat, err := standalone.HeartbeatRedTeamRun(ctx, scope, run, "probe-worker", token, 60); err != nil || !beat.Renewed {
			t.Fatalf("heartbeat: %+v %v", beat, err)
		}
		results := []RedTeamProbeResult{}
		for _, category := range categories {
			binding, err := journal.StandaloneResolver().ResolveTarget(ctx, redteamadapter.TargetResolution{Scope: scope, RunID: run, LeaseToken: token, TargetID: target, TargetKind: "agent_endpoint", Category: category})
			if err != nil || binding.TargetID != target || binding.CredentialReference != credential {
				t.Fatalf("resolve %s: %+v %v", category, binding, err)
			}
			for index, probe := range probes.Sample(category, run, 5) {
				outcome := "protected"
				if index == 2 && category == categories[0] {
					outcome = "unsafe"
				}
				results = append(results, RedTeamProbeResult{ProbeID: probe.ID, Category: category, Outcome: outcome})
			}
		}
		for name, resolution := range map[string]redteamadapter.TargetResolution{
			"category outside the definition": {Scope: scope, RunID: run, LeaseToken: token, TargetID: target, TargetKind: "agent_endpoint", Category: "sensitive_information"},
			"wrong lease":                     {Scope: scope, RunID: run, LeaseToken: strings.Repeat("d", 32), TargetID: target, TargetKind: "agent_endpoint", Category: categories[0]},
			"unknown category":                {Scope: scope, RunID: run, LeaseToken: token, TargetID: target, TargetKind: "agent_endpoint", Category: "tool_misuse"},
		} {
			if _, err := journal.StandaloneResolver().ResolveTarget(ctx, resolution); err == nil {
				t.Fatalf("%s resolved a target", name)
			}
		}
		key := "organizations/" + o + "/workspaces/" + w + "/environments/" + e + "/artifacts/" + run
		checksum := sha256.Sum256([]byte("evidence " + run))
		evidence := make([]string, len(categories))
		for index, category := range categories {
			evidence[index] = category + ": protected"
		}
		evidence[0] = categories[0] + ": unsafe behavior observed"
		completion := RedTeamRunCompletion{RunID: run, Worker: "probe-worker", LeaseToken: token, InputDigest: claim.InputDigest, Verdict: "fail", Objective: "Evaluate curated categories: " + strings.Join(categories, ", "), Behavior: "probes exposed unsafe behavior.", Evidence: evidence, ProbeResults: results,
			EvidenceReference: "s3://zasp-evidence/" + key, EvidenceKey: key, EvidenceVersionID: "evidence-version-1", EvidenceChecksum: checksum[:], EvidenceSizeBytes: 2048,
			InputArtifact: &RedTeamArtifactReference{Reference: "s3://zasp-evidence/" + strings.TrimSuffix(key, run) + id(), VersionID: "input-version-1", SHA256: strings.Repeat("b", 64), SizeBytes: 512}}
		stolen := completion
		stolen.LeaseToken = strings.Repeat("d", 32)
		if _, err := standalone.FinishRedTeamRun(ctx, scope, stolen); err == nil {
			t.Fatal("a run was finished under another lease")
		}
		// recordRedTeamProbeResults and the finish, through the repository.
		finished, err := standalone.FinishRedTeamRun(ctx, scope, completion)
		if err != nil || finished.Status != "complete" || finished.Verdict != "fail" || finished.ID != run {
			t.Fatalf("finish: %+v %v", finished, err)
		}
		var detail RedTeamRunDetail
		raw, err := checked(postgresRedTeamGetRunSQL, o, w, e, run)
		if err != nil || decodeStrictDiscovery(raw, &detail) != nil || len(detail.Attempts) != 1 || len(detail.Attempts[0].ProbeResults) != len(results) || detail.Attempts[0].ProbeResults[2] != results[2] || detail.Attempts[0].ProbeResults[2].Outcome != "unsafe" || !validRedTeamProbeResults(detail.Attempts[0].ProbeResults) {
			t.Fatalf("run detail: %s %v", raw, err)
		}
	}
	execute(press(agenticDefinition), agenticCategories)
	execute(curatedRun, []string{"prompt_injection", "tool_abuse"})

	// A schedule. The API login reaches the schedule functions only inside a
	// checked request.
	var raw json.RawMessage
	if err := api.QueryRow(ctx, postgresRedTeamPutScheduleSQL, o, w, e, actor, agenticDefinition, int64(0), true, 3600, true).Scan(&raw); err == nil {
		t.Fatal("the API login saved a schedule outside a checked request")
	}
	if err := api.QueryRow(ctx, postgresRedTeamGetScheduleSQL, o, w, e, agenticDefinition).Scan(&raw); err == nil {
		t.Fatal("the API login read a schedule outside a checked request")
	}
	if raw, err = checked(postgresRedTeamPutScheduleSQL, o, w, e, actor, agenticDefinition, int64(0), true, 3600, true); err != nil {
		t.Fatalf("save schedule: %v", err)
	}
	if _, err := decodeRedTeamSchedule(raw, agenticDefinition); err != nil {
		t.Fatalf("saved schedule %s", raw)
	}
	if raw, err = checked(postgresRedTeamGetScheduleSQL, o, w, e, agenticDefinition); err != nil || !bytes.Contains(raw, []byte(`"version": 1`)) {
		t.Fatalf("read schedule: %s %v", raw, err)
	}
	var audits int
	var auditBody json.RawMessage
	if err := admin.QueryRow(ctx, `SELECT count(*),(array_agg(body))[1] FROM zasp_red_team_audit WHERE resource_id=$1 AND actor_id=$2 AND event_kind='red_team_definition_updated' AND body ? 'schedule'`, agenticDefinition, actor).Scan(&audits, &auditBody); err != nil || audits != 1 || !bytes.Contains(auditBody, []byte(`"cadence_seconds": 3600`)) || !bytes.Contains(auditBody, []byte(`"enabled": true`)) {
		t.Fatalf("schedule audit rows=%d body=%s err=%v", audits, auditBody, err)
	}
	var published int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_audit_export_public_source_v1 WHERE target_id=$1 AND actor_id=$2 AND source_kind='red_team_mutation' AND source_valid AND action='test.update'`, agenticDefinition, actor).Scan(&published); err != nil || published != 1 {
		t.Fatalf("the schedule save is not in the public audit source: %d %v", published, err)
	}
	// The scheduler login queues the due run; it is standalone and executes.
	if _, err := admin.Exec(ctx, `UPDATE zasp_red_team_schedules SET next_run_at=transaction_timestamp()-interval '1 minute' WHERE definition_id=$1`, agenticDefinition); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, postgresRedTeamFireSchedulesSQL, "discovery-scheduler", 50).Scan(&raw); err == nil {
		t.Fatal("the worker login fired schedules")
	}
	if err := scheduler.QueryRow(ctx, postgresRedTeamFireSchedulesSQL, "discovery-scheduler", 50).Scan(&raw); err != nil {
		t.Fatalf("scheduled sweep: %v", err)
	}
	var scheduledRun, trigger, requestedBy string
	if err := admin.QueryRow(ctx, `SELECT s.last_run_id,s.last_trigger,r.requested_by FROM zasp_red_team_schedules s JOIN zasp_red_team_runs r ON r.run_id=s.last_run_id WHERE s.definition_id=$1 AND s.last_outcome='queued' AND r.state='queued'`, agenticDefinition).Scan(&scheduledRun, &trigger, &requestedBy); err != nil || trigger != "cadence" || requestedBy != actor {
		t.Fatalf("scheduled run trigger=%q by=%q err=%v", trigger, requestedBy, err)
	}
	execute(scheduledRun, agenticCategories)
	if _, err := checked(postgresRedTeamPutScheduleSQL, o, w, e, actor, agenticDefinition, int64(1), false, nil, false); err != nil {
		t.Fatalf("disable schedule: %v", err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_red_team_audit WHERE resource_id=$1 AND body ? 'schedule'`, agenticDefinition).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("schedule audit rows after the second save=%d err=%v", audits, err)
	}

	// Fail closed: a run that is a Security Agent test step is classified as
	// linked and the standalone functions refuse it; the journaled categories
	// of that protocol are still the six.
	linkedRun := press(definition)
	link, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer link.Rollback(context.Background())
	if _, err := link.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := link.Exec(ctx, `INSERT INTO zasp_security_agent_test_links(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,test_definition_id,test_definition_version,test_run_id,target_id,target_kind,test_categories,result) VALUES($1,$2,$3,$4,$5,'run_test',decode(repeat('ab',32),'hex'),$6,1,$7,$8,'agent_endpoint','["prompt_injection","tool_abuse"]','{}')`, o, w, e, id(), id(), definition, linkedRun, target); err != nil {
		t.Fatalf("link: %v", err)
	}
	if err := link.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if protocol, err := standalone.StandaloneRunProtocol(ctx, scope, linkedRun); err != nil || protocol != "linked" {
		t.Fatalf("linked run protocol=%q err=%v", protocol, err)
	}
	if claim, err := standalone.ClaimRedTeamRun(ctx, scope, linkedRun, "probe-worker", strings.Repeat("c", 32), 60); err == nil {
		t.Fatalf("the standalone path claimed a linked run: %+v", claim)
	}
	var journalCategories string
	if err := admin.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='zasp_security_agent_test_invocations_category_check' LIMIT 1`).Scan(&journalCategories); err != nil || strings.Contains(journalCategories, "indirect_injection") || !strings.Contains(journalCategories, "prompt_injection") {
		t.Fatalf("the journaled test step categories changed: %s %v", journalCategories, err)
	}
}
