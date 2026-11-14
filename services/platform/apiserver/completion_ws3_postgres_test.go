package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/compliancemap"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations/baseline"
)

const (
	ws3Organization = "pid_6a000001-0000-4000-8000-000000000001"
	ws3Workspace    = "pid_6a000002-0000-4000-8000-000000000002"
	ws3Environment  = "pid_6a000003-0000-4000-8000-000000000003"
	ws3Principal    = "pid_6a000004-0000-4000-8000-000000000004"
)

// startBaselineDatabase installs the embedded baseline (the catalog a new
// installation has) in a disposable PostgreSQL and returns a superuser
// connection to it. The completion sections under test are then applied on
// top, the way generate.sh applies completion.sql.
func startBaselineDatabase(t *testing.T) (context.Context, *pgx.Conn) {
	t.Helper()
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(ctx) }()
	for _, statement := range []string{`CREATE ROLE zasp_operator LOGIN SUPERUSER`, `CREATE DATABASE zasp_baseline OWNER zasp_operator`} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	operator := strings.Replace(strings.Replace(dsn, "zasp_test@", "zasp_operator@", 1), "/postgres?", "/zasp_baseline?", 1)
	connection, err := pgx.Connect(ctx, operator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	if err := baseline.Install(ctx, connection); err != nil {
		t.Fatalf("baseline install: %v", err)
	}
	return ctx, connection
}

// standIn replaces the body of an installed function, keeping its signature,
// owner and settings. The tests use it for the gates a request passes before
// a statement runs (catalog readiness, the browser session, the request
// proof, the OpenFGA resolver), which need services these tests do not start.
// The statement under test keeps its installed body.
func standIn(t *testing.T, ctx context.Context, connection *pgx.Conn, signature, language, body string) {
	t.Helper()
	if _, err := connection.Exec(ctx, `DO $standin$
DECLARE d text:=pg_get_functiondef('`+signature+`'::regprocedure);
BEGIN
 d:=regexp_replace(d,'LANGUAGE \w+','LANGUAGE `+language+`');
 EXECUTE regexp_replace(d,'AS \$function\$.*\$function\$','AS $function$ `+strings.ReplaceAll(body, "'", "''")+` $function$');
END $standin$`, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("stand-in %s: %v", signature, err)
	}
}

func functionDefinition(t *testing.T, ctx context.Context, connection *pgx.Conn, signature string) string {
	t.Helper()
	var definition string
	if err := connection.QueryRow(ctx, `SELECT pg_get_functiondef($1::regprocedure)`, signature).Scan(&definition); err != nil {
		t.Fatalf("%s: %v", signature, err)
	}
	return definition
}

func ws3ID(prefix string, ordinal int) string {
	return fmt.Sprintf("pid_%s%06x-0000-4000-8000-%012x", prefix, ordinal, ordinal)
}

func ws3Finding(t *testing.T, ctx context.Context, connection *pgx.Conn, ordinal int, source string, rule any, agent any) string {
	t.Helper()
	id := ws3ID("6b", ordinal)
	if _, err := connection.Exec(ctx, `INSERT INTO public.zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status,agent_id) VALUES($1,$2,$3,$4,$5,$6,$7,'high','open',$8)`,
		ws3Organization, ws3Workspace, ws3Environment, id, source, rule, fmt.Sprintf("Finding %d", ordinal), agent); err != nil {
		t.Fatalf("finding %d: %v", ordinal, err)
	}
	return id
}

// The AI frameworks on the compliance reads and the export job, on the
// baseline catalog (completion.sql sections ai_framework_data and
// ai_framework_compliance).
func TestCompletionAIFrameworkCompliancePostgres(t *testing.T) {
	ctx, connection := startBaselineDatabase(t)
	signatures := []string{
		"public.zasp_compliance_mappings()",
		"public.zasp_compliance_read(text,text,text,text,bytea,text,jsonb,text,text)",
		"zasp_authorization80.compliance_read(text,text,text,text,bytea,text,jsonb,text,text)",
		"public.zasp_compliance_export_create(text,text,text,text,bytea,text,jsonb,text,text)",
		"public.zasp_compliance_export_capture(text,text,text,text,text,text,bigint,jsonb,text,text)",
	}
	applyCompletionBlock(t, ctx, connection, "ai_framework_data")
	applyCompletionBlock(t, ctx, connection, "ai_framework_compliance")
	patched := map[string]string{}
	for _, signature := range signatures {
		patched[signature] = functionDefinition(t, ctx, connection, signature)
		if signature != signatures[0] && signature != signatures[3] && !strings.Contains(patched[signature], "zasp_compliance_ai_controls()") {
			t.Fatalf("%s does not name the AI controls", signature)
		}
	}
	applyCompletionBlock(t, ctx, connection, "ai_framework_data")
	applyCompletionBlock(t, ctx, connection, "ai_framework_compliance")
	for _, signature := range signatures {
		if functionDefinition(t, ctx, connection, signature) != patched[signature] {
			t.Fatalf("re-running the section changed %s", signature)
		}
	}
	// A changed predecessor is refused, not patched blindly.
	if _, err := connection.Exec(ctx, `BEGIN`); err != nil {
		t.Fatal(err)
	}
	standIn(t, ctx, connection, signatures[0], "sql", `SELECT NULL::text,NULL::text,NULL::text,NULL::text[],NULL::integer WHERE false`)
	if _, err := connection.Exec(ctx, completionBlock(t, "ai_framework_compliance"), pgx.QueryExecModeSimpleProtocol); err == nil || !strings.Contains(err.Error(), "compliance mappings predecessor changed") {
		t.Fatalf("a changed mapping function was accepted: %v", err)
	}
	if _, err := connection.Exec(ctx, `ROLLBACK`); err != nil {
		t.Fatal(err)
	}

	// The SQL data is the Go map.
	var controls, mappings []string
	rows, err := connection.Query(ctx, `SELECT framework||'|'||control_id||'|'||label FROM public.zasp_compliance_ai_controls() ORDER BY framework COLLATE "C",control_id COLLATE "C"`)
	if err != nil {
		t.Fatal(err)
	}
	if controls, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		t.Fatal(err)
	}
	rows, err = connection.Query(ctx, `SELECT rule||'|'||framework||'|'||control_id FROM public.zasp_compliance_ai_rule_controls() ORDER BY rule COLLATE "C",framework COLLATE "C",control_id COLLATE "C"`)
	if err != nil {
		t.Fatal(err)
	}
	if mappings, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		t.Fatal(err)
	}
	var wantControls, wantMappings []string
	for _, control := range compliancemap.Controls() {
		wantControls = append(wantControls, control.Framework+"|"+control.Control+"|"+control.Title)
	}
	for _, mapping := range compliancemap.Mappings() {
		wantMappings = append(wantMappings, mapping.Rule+"|"+mapping.Framework+"|"+mapping.Control)
	}
	if !slices.Equal(controls, wantControls) || !slices.Equal(mappings, wantMappings) {
		t.Fatalf("the SQL mapping differs from compliancemap:\ncontrols %v\nwant     %v\nmappings %v\nwant     %v", controls, wantControls, mappings, wantMappings)
	}

	// The request gates are stood in; the resolver's decision per source is a
	// table the test controls.
	if _, err := connection.Exec(ctx, `CREATE TABLE public.ws3_denied(id text PRIMARY KEY);GRANT SELECT ON public.ws3_denied TO PUBLIC`, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	standIn(t, ctx, connection, "zasp_authorization80.source_ready(integer,text,text)", "sql", `SELECT true`)
	standIn(t, ctx, connection, "public.zasp_discovery_principal_ready(text)", "sql", `SELECT true`)
	standIn(t, ctx, connection, "zasp_authorization79.reader()", "sql", `SELECT true`)
	standIn(t, ctx, connection, "zasp_authorization80.ready(text)", "sql", `SELECT true`)
	standIn(t, ctx, connection, "zasp_authorization80.checked_browser(text,text,text,text,bytea,text,boolean)", "plpgsql", `BEGIN RETURN; END`)
	standIn(t, ctx, connection, "zasp_authorization80.require_read(text,text,text,text[],text,boolean,text)", "plpgsql", `BEGIN RETURN; END`)
	standIn(t, ctx, connection, "zasp_authorization80.parent_allowed_inner(text,text,text,text,text,text)", "sql", `SELECT NOT EXISTS(SELECT 1 FROM public.ws3_denied x WHERE x.id=$5)`)

	findings := map[string]string{} // finding identifier -> rule
	for ordinal, rule := range []string{"ownerless_agent", "shell_credential", "", "ownerless_agent", "agent_guardrail_missing", "unmapped_rule"} {
		var value any
		source := "prowler"
		if rule != "" {
			value, source = rule, "posture"
		}
		findings[ws3Finding(t, ctx, connection, ordinal+1, source, value, nil)] = rule
	}
	type control struct {
		Framework    string   `json:"framework"`
		ControlID    string   `json:"control_id"`
		Freshness    string   `json:"freshness"`
		FindingIDs   []string `json:"finding_ids"`
		FindingCount *int     `json:"finding_count"`
	}
	read := func(operation string, parameters map[string]any) json.RawMessage {
		t.Helper()
		body, _ := json.Marshal(parameters)
		var result []byte
		if err := connection.QueryRow(ctx, `SELECT zasp_authorization80.compliance_read($1,$2,$3,$4,decode(repeat('11',32),'hex'),$5,$6::jsonb,'c','f')`, ws3Organization, ws3Workspace, ws3Environment, ws3Principal, operation, string(body)).Scan(&result); err != nil {
			t.Fatalf("%s %s: %v", operation, body, err)
		}
		return result
	}
	listControls := func(parameters map[string]any) []control {
		t.Helper()
		var page struct {
			Items []control `json:"items"`
		}
		if err := json.Unmarshal(read("listControls", parameters), &page); err != nil {
			t.Fatal(err)
		}
		return page.Items
	}
	evidenceIDs := func(parameters map[string]any) []string {
		t.Helper()
		var page struct {
			Items []struct {
				ID     string `json:"id"`
				Source string `json:"source"`
			} `json:"items"`
		}
		if err := json.Unmarshal(read("listEvidence", parameters), &page); err != nil {
			t.Fatal(err)
		}
		ids := []string{}
		for _, item := range page.Items {
			if item.Source != "finding" {
				t.Fatalf("evidence %s is a %s", item.ID, item.Source)
			}
			ids = append(ids, item.ID)
		}
		return ids
	}
	// wantFindings is what the Go map says: the findings, among the readable
	// ones, whose rule is evidence for the control.
	wantFindings := func(controlID string, denied ...string) []string {
		ids := []string{}
		for id, rule := range findings {
			if slices.Contains(denied, id) {
				continue
			}
			for _, reference := range compliancemap.References(rule) {
				if reference.Control == controlID {
					ids = append(ids, id)
				}
			}
		}
		slices.Sort(ids)
		return ids
	}
	checkControls := func(denied ...string) {
		t.Helper()
		all := listControls(map[string]any{})
		if len(all) != 10+len(compliancemap.Controls()) {
			t.Fatalf("controls = %d, want the ten product controls and %d AI controls", len(all), len(compliancemap.Controls()))
		}
		withFindings := 0
		for _, item := range all {
			if !compliancemap.IsFramework(item.Framework) {
				if item.FindingIDs != nil || item.FindingCount != nil {
					t.Fatalf("product control %s carries findings", item.ControlID)
				}
				continue
			}
			want := wantFindings(item.ControlID, denied...)
			if item.FindingCount == nil || *item.FindingCount != len(want) || !slices.Equal(item.FindingIDs, want) || (item.Freshness == "missing") != (len(want) == 0) {
				t.Fatalf("control %s = %v (%v, %s), want %v", item.ControlID, item.FindingIDs, item.FindingCount, item.Freshness, want)
			}
			if got := evidenceIDs(map[string]any{"control_id": item.ControlID}); !slices.Equal(got, want) {
				t.Fatalf("evidence of %s = %v, want %v", item.ControlID, got, want)
			}
			if len(want) > 0 {
				withFindings++
			}
		}
		if len(denied) == 0 && withFindings == 0 {
			t.Fatal("no AI control has a finding: the fixture proves nothing")
		}
	}
	checkControls()
	// One framework, in control order; a framework filter is any framework of
	// the mapping and nothing else.
	agentic := listControls(map[string]any{"framework": compliancemap.OWASPAgentic})
	var agenticIDs []string
	for _, item := range agentic {
		agenticIDs = append(agenticIDs, item.ControlID)
	}
	if !slices.Equal(agenticIDs, []string{"ASI02", "ASI03", "ASI04", "ASI05", "ASI10"}) {
		t.Fatalf("OWASP agentic controls = %v", agenticIDs)
	}
	var first string
	for id, rule := range findings {
		if rule == "ownerless_agent" && (first == "" || id < first) {
			first = id
		}
	}
	if got := wantFindings("ASI10"); len(got) != 2 || got[0] != first {
		t.Fatalf("fixture: ASI10 = %v", got)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_authorization80.compliance_read($1,$2,$3,$4,decode(repeat('11',32),'hex'),'listControls','{"framework":"unknown_framework"}'::jsonb,'c','f')`, ws3Organization, ws3Workspace, ws3Environment, ws3Principal); err == nil || !strings.Contains(err.Error(), "compliance filter rejected") {
		t.Fatalf("an unknown framework was accepted: %v", err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_authorization80.compliance_read($1,$2,$3,$4,decode(repeat('11',32),'hex'),'listControls','{"framework":"hipaa","control_id":"ASI03"}'::jsonb,'c','f')`, ws3Organization, ws3Workspace, ws3Environment, ws3Principal); err == nil || !strings.Contains(err.Error(), "compliance filter rejected") {
		t.Fatalf("a control of another framework was accepted: %v", err)
	}
	// A framework without a control: every finding mapped to one of its controls.
	var euWant []string
	for id, rule := range findings {
		for _, reference := range compliancemap.References(rule) {
			if reference.Framework == compliancemap.EUAIAct && !slices.Contains(euWant, id) {
				euWant = append(euWant, id)
			}
		}
	}
	slices.Sort(euWant)
	if got := evidenceIDs(map[string]any{"framework": compliancemap.EUAIAct}); !slices.Equal(got, euWant) || len(euWant) == 0 {
		t.Fatalf("EU AI Act evidence = %v, want %v", got, euWant)
	}
	// The product controls keep every source of their family.
	if got := evidenceIDs(map[string]any{"control_id": "hipaa-findings"}); len(got) != len(findings) {
		t.Fatalf("hipaa-findings evidence = %d findings, want %d", len(got), len(findings))
	}
	// Paging the controls crosses from the product into the AI frameworks.
	var page struct {
		Items      []control       `json:"items"`
		NextCursor json.RawMessage `json:"next_cursor"`
	}
	seen := 0
	parameters := map[string]any{"limit": 7}
	for range 10 {
		if err := json.Unmarshal(read("listControls", parameters), &page); err != nil {
			t.Fatal(err)
		}
		seen += len(page.Items)
		if string(page.NextCursor) == "null" || len(page.NextCursor) == 0 {
			break
		}
		parameters["cursor"] = page.NextCursor
	}
	if seen != 10+len(compliancemap.Controls()) {
		t.Fatalf("paged controls = %d", seen)
	}

	// A caller that may not read a finding does not see it, and it is not
	// counted: first two findings, then every finding.
	if _, err := connection.Exec(ctx, `INSERT INTO public.ws3_denied SELECT id FROM public.zasp_risk_findings WHERE rule='ownerless_agent'`); err != nil {
		t.Fatal(err)
	}
	var denied []string
	for id, rule := range findings {
		if rule == "ownerless_agent" {
			denied = append(denied, id)
		}
	}
	checkControls(denied...)
	for _, item := range listControls(map[string]any{"control_id": "ASI10"}) {
		if *item.FindingCount != 0 || item.Freshness != "missing" {
			t.Fatalf("ASI10 for a caller without access = %#v", item)
		}
	}
	if _, err := connection.Exec(ctx, `INSERT INTO public.ws3_denied SELECT id FROM public.zasp_risk_findings ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	for _, item := range listControls(map[string]any{}) {
		if item.FindingCount != nil && (*item.FindingCount != 0 || len(item.FindingIDs) != 0) {
			t.Fatalf("a caller without access sees findings of %s: %v", item.ControlID, item.FindingIDs)
		}
	}
	if got := evidenceIDs(map[string]any{"control_id": "ASI10"}); len(got) != 0 {
		t.Fatalf("a caller without access reads evidence: %v", got)
	}

	// The export job: the request accepts an AI framework, and the captured
	// snapshot records, per AI control, the findings mapped to it. The job's
	// own gates (release readiness, the worker binding, the requester's
	// session) are stood in; the capture statement is the installed one.
	standIn(t, ctx, connection, "public.zasp_compliance_require(text,text,text)", "plpgsql", `BEGIN RETURN; END`)
	standIn(t, ctx, connection, "public.zasp_compliance_authorize(text,text,text,text,bytea)", "plpgsql", `BEGIN RETURN; END`)
	export := ws3ID("6c", 1)
	if _, err := connection.Exec(ctx, `INSERT INTO public.zasp_compliance_export_scopes(organization_id,workspace_id,environment_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, ws3Organization, ws3Workspace, ws3Environment); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO public.zasp_compliance_export_jobs(organization_id,workspace_id,environment_id,export_id,principal_id,session_digest,idempotency_key,request,request_digest,policy_revision,phase,generation,attempt,worker_id,lease_digest,lease_expires_at,lane)
VALUES($1,$2,$3,$4,$5,decode(repeat('11',32),'hex'),'ws3-export',$6::jsonb,digest(convert_to($6::text,'UTF8'),'sha256'),'compliance-limits-v1','collecting',1,1,'worker-1',digest('token','sha256'),clock_timestamp()+interval '5 minutes','execute')`,
		ws3Organization, ws3Workspace, ws3Environment, export, ws3Principal, `{"framework":"owasp_agentic_top10_2026"}`); err != nil {
		t.Fatalf("export job: %v", err)
	}
	var captured []byte
	if err := connection.QueryRow(ctx, `SELECT public.zasp_compliance_export_capture($1,$2,$3,$4,'worker-1','token',1,'{}'::jsonb,'c','f')`, ws3Organization, ws3Workspace, ws3Environment, export).Scan(&captured); err != nil {
		t.Fatalf("capture: %v", err)
	}
	var snapshot struct {
		Snapshot struct {
			Controls []struct {
				Framework string `json:"framework"`
				ControlID string `json:"control_id"`
				Records   []struct {
					Kind string `json:"source_kind"`
					ID   string `json:"source_id"`
				} `json:"records"`
			} `json:"controls"`
		} `json:"snapshot"`
	}
	if err := json.Unmarshal(captured, &snapshot); err != nil || len(snapshot.Snapshot.Controls) != 5 {
		t.Fatalf("snapshot controls = %d / %v", len(snapshot.Snapshot.Controls), err)
	}
	for _, item := range snapshot.Snapshot.Controls {
		ids := []string{}
		for _, record := range item.Records {
			if record.Kind != "finding" {
				t.Fatalf("snapshot record of %s is a %s", item.ControlID, record.Kind)
			}
			ids = append(ids, record.ID)
		}
		slices.Sort(ids)
		if want := wantFindings(item.ControlID); item.Framework != compliancemap.OWASPAgentic || !slices.Equal(ids, want) {
			t.Fatalf("snapshot %s/%s = %v, want %v", item.Framework, item.ControlID, ids, want)
		}
	}
	// The create statement validates the framework against the mapping.
	if definition := functionDefinition(t, ctx, connection, signatures[3]); strings.Contains(definition, "NOT IN('soc2_security','hipaa')") || !strings.Contains(definition, "zasp_compliance_mappings() m WHERE m.framework=request_value->>'framework'") {
		t.Fatal("the export request still accepts only the product frameworks")
	}
}

// The agent activity helper and the summary functions that call it, on the
// baseline catalog and its real runtime events table (completion.sql section
// inventory_agent_activity).
func TestCompletionAgentActivityPostgres(t *testing.T) {
	ctx, connection := startBaselineDatabase(t)
	signatures := []string{"public.zasp_inventory_detail(text,text,text,text,text)", "public.zasp_inventory_page(text,text,text,text,text,integer)"}
	applyCompletionBlock(t, ctx, connection, "inventory_agent_activity")
	patched := map[string]string{}
	for _, signature := range signatures {
		patched[signature] = functionDefinition(t, ctx, connection, signature)
		if strings.Count(patched[signature], "public.zasp_inventory_agent_activity(") != 1 || !strings.Contains(patched[signature], "'management_state'") {
			t.Fatalf("%s does not add the activity members to the summary section X5 leaves", signature)
		}
	}
	applyCompletionBlock(t, ctx, connection, "inventory_agent_activity")
	for _, signature := range signatures {
		if functionDefinition(t, ctx, connection, signature) != patched[signature] {
			t.Fatalf("re-running the section changed %s", signature)
		}
	}
	// The index of the section is plain DDL outside the block.
	if _, err := connection.Exec(ctx, `CREATE INDEX IF NOT EXISTS zasp_runtime_session_events_agent_activity_idx ON public.zasp_runtime_session_events(organization_id,workspace_id,environment_id,agent_id,event_time DESC) WHERE agent_id IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	activity := func(agent, kind, attributes string, observed time.Time) (string, string) {
		t.Helper()
		var state string
		var last *string
		if err := connection.QueryRow(ctx, `SELECT a->>'activity_state',a->>'last_activity_at' FROM public.zasp_inventory_agent_activity($1,$2,$3,$4,$5,$6::jsonb,$7) a`, ws3Organization, ws3Workspace, ws3Environment, agent, kind, attributes, observed).Scan(&state, &last); err != nil {
			t.Fatalf("activity of %s: %v", agent, err)
		}
		if last == nil {
			return state, ""
		}
		return state, *last
	}
	now := time.Now().UTC().Truncate(time.Second)
	stamp := func(at time.Time) string { return at.Format("2006-01-02T15:04:05Z") }
	event := func(ordinal int, agent string, at time.Time, scope ...string) {
		t.Helper()
		environment := ws3Environment
		if len(scope) == 1 {
			environment = scope[0]
		}
		if _, err := connection.Exec(ctx, `INSERT INTO public.zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time) VALUES($1,$2,$3,$4,$5,$6,'exact','otlp','tool','invoke','Tool call',$7,$8)`,
			ws3Organization, ws3Workspace, environment, ws3ID("7a", ordinal), ws3ID("7b", ordinal), agent, ws3ID("7c", ordinal), at); err != nil {
			t.Fatalf("runtime event %d: %v", ordinal, err)
		}
	}
	plain := `{"discovery":{"method":"provider_api","platform":"bedrock_agent","signals":[]}}`
	invoked := `{"discovery":{"method":"provider_api","platform":"bedrock_agent","signals":["iam:bedrock_invoke_model","invoke:bedrock_model"]}}`
	egress := `{"discovery":{"method":"inferred","platform":"kubernetes_workload","signals":["egress:openai","image:langgraph"]}}`
	static := `{"discovery":{"method":"inferred","platform":"kubernetes_workload","signals":["env:openai","image:langgraph"]}}`
	recentAgent, oldAgent, otherAgent, unusedAgent, resolvedAgent, quietAgent := ws3ID("7d", 1), ws3ID("7d", 2), ws3ID("7d", 3), ws3ID("7d", 4), ws3ID("7d", 5), ws3ID("7d", 6)
	recent, old := now.Add(-29*24*time.Hour), now.Add(-31*24*time.Hour)
	event(1, recentAgent, old)
	event(2, recentAgent, recent)
	event(3, oldAgent, old)
	// An event of the same agent identifier in another Environment is not
	// this agent's activity.
	event(4, otherAgent, recent, ws3ID("7e", 1))
	ws3Finding(t, ctx, connection, 101, "posture", "agent_role_unused_90_days", unusedAgent)
	resolved := ws3Finding(t, ctx, connection, 102, "posture", "agent_role_unused_90_days", resolvedAgent)
	if _, err := connection.Exec(ctx, `UPDATE public.zasp_risk_findings SET status='resolved' WHERE id=$1`, resolved); err != nil {
		t.Fatal(err)
	}
	ws3Finding(t, ctx, connection, 103, "posture", "ownerless_agent", quietAgent)
	collected := now.Add(-time.Hour)
	stale := now.Add(-40 * 24 * time.Hour)
	for name, item := range map[string]struct {
		agent, kind, attributes string
		observed                time.Time
		state, last             string
	}{
		"a runtime event 29 days ago":                 {recentAgent, "agent", plain, collected, "active", stamp(recent)},
		"the newest runtime event 31 days ago":        {oldAgent, "agent", plain, collected, "inactive", stamp(old)},
		"an event in another Environment":             {otherAgent, "agent", plain, collected, "unknown", ""},
		"the provider's logs showed an invocation":    {quietAgent, "agent", invoked, collected, "active", stamp(collected)},
		"network logs showed egress to an AI API":     {quietAgent, "agent", egress, collected, "active", stamp(collected)},
		"an invocation seen by a collection long ago": {quietAgent, "agent", invoked, stale, "inactive", stamp(stale)},
		"a newer runtime event than the collection":   {recentAgent, "agent", invoked, stale, "active", stamp(recent)},
		"static signals are not activity":             {quietAgent, "agent", static, collected, "unknown", ""},
		"the role is reported unused for 90 days":     {unusedAgent, "agent", plain, collected, "inactive", ""},
		"a resolved unused-role finding":              {resolvedAgent, "agent", plain, collected, "unknown", ""},
		"no activity source":                          {quietAgent, "agent", plain, collected, "unknown", ""},
		"a declared agent without attributes":         {quietAgent, "agent", `{}`, collected, "unknown", ""},
		"an identity":                                 {recentAgent, "identity", plain, collected, "not_applicable", ""},
	} {
		if state, last := activity(item.agent, item.kind, item.attributes, item.observed); state != item.state || last != item.last {
			t.Errorf("%s: activity = %q / %q, want %q / %q", name, state, last, item.state, item.last)
		}
	}
}
