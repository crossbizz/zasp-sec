package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/compliancemap"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/evidencepack"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// complianceMemoryDriver is the object store of this test: the export store
// interface over a map. No S3 is available here; the worker's store, key
// layout, checksum and receipt logic above the driver are the real ones.
type complianceMemoryDriver struct {
	mu      sync.Mutex
	objects map[string]artifactstore.DriverObject
}

func (d *complianceMemoryDriver) Put(_ context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	object.Body = bytes.Clone(object.Body)
	object.VersionID = "memory-version-" + hex.EncodeToString(object.SHA256[:4])
	d.objects[object.Key] = object
	return object, nil
}
func (d *complianceMemoryDriver) Get(_ context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	object, found := d.objects[locator.Key]
	if !found {
		return artifactstore.DriverObject{}, errors.New("object not found")
	}
	return object, nil
}
func (d *complianceMemoryDriver) Delete(_ context.Context, locator artifactstore.DriverLocator) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.objects, locator.Key)
	return nil
}

func installedCompletionBlock(t *testing.T, tag string) string {
	t.Helper()
	completion, err := os.ReadFile(filepath.Join("..", "migrations", "baseline", "completion.sql"))
	if err != nil {
		t.Fatal(err)
	}
	opening, closing := "DO $"+tag+"$", "END $"+tag+"$;"
	start, end := strings.Index(string(completion), opening), strings.Index(string(completion), closing)
	if start < 0 || end < start || strings.Count(string(completion), opening) != 1 {
		t.Fatalf("completion.sql does not hold exactly one %s section", tag)
	}
	return string(completion[start : end+len(closing)])
}

// TestComplianceExportOnInstalledBaselinePostgres needs
// ZASP_BASELINE_RELEASE_TEST_DSN: a superuser connection to a database on
// which the baseline is installed (agentsec-migrate install-baseline). The
// service logins must be able to connect with the same host and port.
//
// It applies the compliance sections of completion.sql (twice) and refreshes
// the baseline seal, as a rebuilt baseline is sealed with them, so it changes
// that database; every row it writes belongs to a tenant of its own.
//
// It proves, on that catalog:
//   - before section WS3-C1 the export release is not ready there;
//   - the API login creates an export for an AI framework only inside a
//     checked request, and reads its status and download grant the same way;
//   - the compliance worker login finds, claims and captures the job, the
//     worker's Go renderer renders it, the package is stored and the job is
//     finished, with the findings mapped to each control;
//   - an export that names one agent retains that agent's evidence pack;
//   - readiness is false for a wrong release identity and for a catalog that
//     is no longer the sealed one.
//
// The object store is an in-memory driver behind the real export store.
func TestComplianceExportOnInstalledBaselinePostgres(t *testing.T) {
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
	checksum, fingerprint := migrations.ComplianceChecksum(), migrations.ComplianceFingerprint()
	var installed, sectionsBefore, readyBefore bool
	if err := admin.QueryRow(ctx, `SELECT zasp_baseline.intact(),position('source_ready(56' in pg_get_functiondef('public.zasp_compliance_readiness(text,text)'::regprocedure))>0,public.zasp_compliance_readiness($1,$2)`, checksum, fingerprint).Scan(&installed, &sectionsBefore, &readyBefore); err != nil || !installed {
		t.Fatalf("installed baseline intact=%t err=%v", installed, err)
	}
	if !sectionsBefore && readyBefore {
		t.Fatal("the export release was ready on the baseline before its section")
	}
	sections := []string{"ai_framework_data", "ai_framework_compliance", "inventory_agent_activity", "ws3_compliance_export_baseline", "ws3_agent_evidence_pack_export"}
	definitions := func() string {
		t.Helper()
		var text string
		if err := admin.QueryRow(ctx, `SELECT string_agg(pg_get_functiondef(p.oid),chr(10) ORDER BY p.oid::regprocedure::text) FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND starts_with(p.proname,'zasp_compliance_')`).Scan(&text); err != nil {
			t.Fatal(err)
		}
		return text
	}
	var first string
	for pass := 0; pass < 2; pass++ {
		for _, tag := range sections {
			if _, err := admin.Exec(ctx, installedCompletionBlock(t, tag), pgx.QueryExecModeSimpleProtocol); err != nil {
				t.Fatalf("%s: %v", tag, err)
			}
		}
		if pass == 0 {
			first = definitions()
		} else if definitions() != first {
			t.Fatal("re-running the sections changed a compliance function")
		}
	}
	// The baseline seals its whole catalog, so a section applied to an
	// installed database breaks the seal by design; a rebuilt baseline is
	// sealed with the sections. The refresh stands for that rebuild.
	var readyUnsealed bool
	if err := admin.QueryRow(ctx, `SELECT public.zasp_compliance_readiness($1,$2)`, checksum, fingerprint).Scan(&readyUnsealed); err != nil {
		t.Fatal(err)
	}
	if !sectionsBefore && readyUnsealed {
		t.Fatal("the export release is ready on a catalog that is not the sealed one")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_baseline.seal SET content=zasp_baseline.content(),marker=zasp_baseline.marker()`); err != nil {
		t.Fatal(err)
	}
	var ready, wrongIdentity, workerSecurity bool
	var bindings int
	if err := admin.QueryRow(ctx, `SELECT public.zasp_compliance_readiness($1,$2),public.zasp_compliance_readiness($2,$1),public.zasp_compliance_worker_security_ready(),(SELECT count(*) FROM public.zasp_compliance_worker_bindings WHERE (principal_name,authority_role) IN(('zasp_svc_compliance_worker','zasp_compliance_worker'),('zasp_svc_compliance_cleanup','zasp_compliance_cleanup')))`, checksum, fingerprint).Scan(&ready, &wrongIdentity, &workerSecurity, &bindings); err != nil || !ready || wrongIdentity || !workerSecurity || bindings != 2 {
		t.Fatalf("after the sections: ready=%t wrong identity ready=%t worker security=%t bindings=%d err=%v", ready, wrongIdentity, workerSecurity, bindings, err)
	}
	// A catalog that is no longer the sealed one is not ready.
	broken, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var brokenReady bool
	if _, err := broken.Exec(ctx, `CREATE FUNCTION public.zasp_compliance_ws3_drift() RETURNS integer LANGUAGE sql AS 'SELECT 1'`); err != nil {
		t.Fatal(err)
	}
	if err := broken.QueryRow(ctx, `SELECT public.zasp_compliance_readiness($1,$2)`, checksum, fingerprint).Scan(&brokenReady); err != nil || brokenReady {
		t.Fatalf("a drifted catalog is ready: %t %v", brokenReady, err)
	}
	if err := broken.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

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
	api := login("zasp_svc_api")
	id := func() string {
		t.Helper()
		value, err := domain.NewProductID()
		if err != nil {
			t.Fatal(err)
		}
		return value.String()
	}
	o, w, e, actor, integration, snapshot, agent, evidenceID, definition, testRun := id(), id(), id(), id(), id(), id(), id(), id(), id(), id()
	session := sha256.Sum256([]byte("ws3 compliance session " + actor))
	findings := map[string]string{id(): "ownerless_agent", id(): "shell_credential", id(): "agent_guardrail_missing"}
	otherFinding := id()
	seed, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Rollback(context.Background())
	type statement struct {
		sql       string
		arguments []any
	}
	statements := []statement{
		{`SET LOCAL session_replication_role=replica`, nil},
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Export tenant',$2)`, []any{o, "export-" + o[4:12] + ".invalid"}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Export workspace')`, []any{w, o}},
		{`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Export staging','staging')`, []any{o, w, e}},
		{`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($1,$2,$3,$4,'compliance_viewer')`, []any{actor, o, "export-" + o[4:], "reviewer-" + actor[4:]}},
		{`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($1,$2,$3,$4,'Export','["view","view_audit","view_compliance"]')`, []any{actor, o, w, e}},
		{`INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($1,$2,$3,$4,$5,'["view","view_audit","view_compliance"]',repeat('c',32),clock_timestamp()+interval '1 hour',clock_timestamp())`, []any{session[:], actor, o, w, e}},
		{`INSERT INTO zasp_inventory_cutover_state(organization_id,workspace_id,environment_id,phase,rule_catalog_digest,legacy_digest,typed_digest,expanded_at,backfilled_at,equivalent_at,cutover_at)
 SELECT $1,$2,$3,'cutover',substring(pg_get_constraintdef(oid) from '([a-f0-9]{64})'),decode(repeat('ab',32),'hex'),decode(repeat('ab',32),'hex'),now(),now(),now(),now() FROM pg_constraint WHERE conname='zasp_inventory_cutover_state_rule_catalog_digest_check'`, []any{o, w, e}},
		{`INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,apply_result,complete,is_last_good,collected_at,committed_at) VALUES($1,$2,$3,$4,$5,$6,1,'aws','s3://zasp-evidence/export/manifest.json',decode(repeat('ab',32),'hex'),'complete',decode(repeat('ab',32),'hex'),'{}',true,true,now()-interval '1 minute',now()-interval '1 minute')`, []any{o, w, e, snapshot, integration, id()}},
		{`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,state,first_seen_at,last_seen_at,version,product_kind,confidence_basis_points,winning_evidence_id,winning_snapshot_id,winning_generation,observed_at,fresh_until,projection_version,winning_integration_id,winning_provider,winning_source,winning_source_native_id,winning_identity_rule,winning_source_projection,winning_attributes)
 VALUES($1,$2,$3,$4,'agent','Export agent','{}','active',now()-interval '1 minute',now()-interval '1 minute',1,'agent',9500,$5,$6,1,now()-interval '1 minute',now()+interval '1 hour',1,$7,'aws','aws','export-agent',1,1,'{"discovery":{"method":"provider_api","platform":"bedrock_agent","signals":["invoke:bedrock_model"]}}')`, []any{o, w, e, agent, evidenceID, snapshot, integration}},
		{`INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,source,generation,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version)
 VALUES($1,$2,$3,$4,$5,$6,$7,'s3://zasp-evidence/export/page.json',decode(repeat('ab',32),'hex'),'application/json','raw_v1','parser_v1',now()-interval '1 minute','aws',1,$8,'export/page.json','version-1',128,'tool_v1')`, []any{o, w, e, evidenceID, integration, snapshot, agent, id()}},
		{`INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,identity_rule_version,identity_priority,source_projection_version)
 VALUES($1,$2,$3,$4,'aws',$5,'export-agent',$6,'present','{}',now()-interval '1 minute',now()-interval '1 minute','aws','aws_bedrock_agent','Export agent','{}','aws_bedrock_agent','agent',1,decode(repeat('ab',32),'hex'),$7,9500,now()-interval '1 minute',now()+interval '1 hour',1,80,1)`, []any{o, w, e, integration, agent, snapshot, evidenceID}},
		{`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'prowler',NULL,'Unrelated cloud record','low','open')`, []any{o, w, e, otherFinding}},
		{`INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by) VALUES($1,$2,$3,$4,'Export probe',$5,'agent_endpoint','["prompt_injection"]','{"environment":"staging","credential_class":"read_only","expected_side_effects":[]}',$6)`, []any{o, w, e, definition, agent, actor}},
		{`INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,state,attempt,input_digest) VALUES($1,$2,$3,$4,$5,1,$6,'queued',0,digest('input','sha256'))`, []any{o, w, e, testRun, definition, actor}},
	}
	for finding, rule := range findings {
		statements = append(statements, statement{`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status,agent_id) VALUES($1,$2,$3,$4,'posture',$5,'Finding on the export agent','high','open',$6)`, []any{o, w, e, finding, rule, agent}})
	}
	for _, item := range statements {
		if _, err := seed.Exec(ctx, item.sql, item.arguments...); err != nil {
			t.Fatalf("seed %.70s: %v", item.sql, err)
		}
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// checked runs one statement as the API login inside a checked request of
	// the actor: the transaction-local authorization context the API server
	// sets for every request, sealed with the installation's verifier key.
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_authorization80.verifier(version,key) VALUES(repeat('a',64),decode(repeat('5a',32),'hex')) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	checkedAs := func(principal, statement string, arguments ...any) (json.RawMessage, error) {
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
		proof, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "principal_id": principal, "key_version": version, "expires_at": time.Now().Add(time.Minute).UnixMilli()})
		if err := admin.QueryRow(ctx, `SELECT encode(public.hmac(convert_to(jsonb_build_array('zasp-authorization-context-v1','zasp_svc_api',$1::text,$2::jsonb)::text,'UTF8'),key,'sha256'),'hex') FROM zasp_authorization80.verifier`, xid, string(proof)).Scan(&seal); err != nil {
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
	checked := func(statement string, arguments ...any) (json.RawMessage, error) {
		return checkedAs(actor, statement, arguments...)
	}
	const createSQL = `SELECT public.zasp_compliance_export_create($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	const getSQL = `SELECT public.zasp_compliance_export_get($1,$2,$3,$4,$5,$6,$7,$8)`
	const grantSQL = `SELECT public.zasp_compliance_export_grant($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	create := func(key, request string) string {
		t.Helper()
		// Outside a checked request the API login is refused.
		var refused json.RawMessage
		if err := api.QueryRow(ctx, createSQL, o, w, e, actor, session[:], key, request, checksum, fingerprint).Scan(&refused); err == nil {
			t.Fatalf("the API login created an export outside a checked request: %s", refused)
		}
		raw, err := checked(createSQL, o, w, e, actor, session[:], key, request, checksum, fingerprint)
		if err != nil {
			t.Fatalf("create export %s: %v", request, err)
		}
		var job struct {
			ExportID        string `json:"export_id"`
			State           string `json:"state"`
			Phase           string `json:"phase"`
			MappingRevision string `json:"mapping_revision"`
		}
		if json.Unmarshal(raw, &job) != nil || job.State != "pending" || job.Phase != "queued" || job.MappingRevision != "product-evidence-v1" {
			t.Fatalf("created export = %s", raw)
		}
		// The same key and request replay the same job.
		replay, err := checked(createSQL, o, w, e, actor, session[:], key, request, checksum, fingerprint)
		if err != nil || !bytes.Contains(replay, []byte(job.ExportID)) {
			t.Fatalf("replayed create = %s %v", replay, err)
		}
		return job.ExportID
	}
	// A checked request of another principal cannot use this session.
	if _, err := checkedAs(id(), createSQL, o, w, e, actor, session[:], "ws3-other", `{"framework":"hipaa"}`, checksum, fingerprint); err == nil {
		t.Fatal("a checked request of another principal created an export")
	}
	for name, request := range map[string]string{
		"an unknown framework":            `{"framework":"iso_27001"}`,
		"a control of another framework":  `{"framework":"hipaa","control_id":"ASI03"}`,
		"an agent with a framework":       `{"framework":"hipaa","agent_id":"` + agent + `"}`,
		"an agent that does not exist":    `{"agent_id":"` + id() + `"}`,
		"an agent identifier of no shape": `{"agent_id":"agent"}`,
	} {
		if raw, err := checked(createSQL, o, w, e, actor, session[:], "ws3-refused-"+id()[4:12], request, checksum, fingerprint); err == nil {
			t.Fatalf("%s was accepted: %s", name, raw)
		}
	}

	driver := &complianceMemoryDriver{objects: map[string]artifactstore.DriverObject{}}
	store, err := artifactstore.NewExport(driver, artifactstore.Config{OperationTimeout: 10 * time.Second, MaximumBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = "zasp_svc_compliance_worker"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	workerDB, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	authority := newPostgresComplianceExportAuthority(workerDB)
	if err := authority.Ready(ctx, "execute"); err != nil {
		t.Fatalf("the compliance worker login is not ready on the baseline: %v", err)
	}
	// The API login is not a worker.
	var notWorker json.RawMessage
	if err := api.QueryRow(ctx, complianceCandidatesSQL, "execute", 10, checksum, fingerprint).Scan(&notWorker); err == nil {
		t.Fatalf("the API login listed export candidates: %s", notWorker)
	}
	processor := &complianceExportProcessor{authority: authority, store: store, worker: "ws3-export-worker", batch: 50, timeout: 20 * time.Second, heartbeat: 10 * time.Second}
	type envelope struct {
		Version int             `json:"version"`
		ID      string          `json:"id"`
		JSON    json.RawMessage `json:"json"`
		CSV     string          `json:"csv"`
		Human   string          `json:"human"`
	}
	// run processes the queued job with the worker and returns the stored
	// package, located through a download grant the API login issues.
	run := func(export string) envelope {
		t.Helper()
		if err := processor.RunOnce(ctx); err != nil {
			var state, phase string
			var failure *string
			_ = admin.QueryRow(ctx, `SELECT state,phase,failure_code FROM zasp_compliance_export_jobs WHERE export_id=$1`, export).Scan(&state, &phase, &failure)
			t.Fatalf("worker run: %v (job state=%s phase=%s failure=%v)", err, state, phase, failure)
		}
		status, err := checked(getSQL, o, w, e, actor, session[:], export, checksum, fingerprint)
		if err != nil || !bytes.Contains(status, []byte(`"state": "completed"`)) || !bytes.Contains(status, []byte(`"phase": "terminal"`)) {
			t.Fatalf("export status = %s %v", status, err)
		}
		var outside json.RawMessage
		if err := api.QueryRow(ctx, getSQL, o, w, e, actor, session[:], export, checksum, fingerprint).Scan(&outside); err == nil {
			t.Fatal("the API login read an export outside a checked request")
		}
		token := strings.Repeat("d", 32) + hex.EncodeToString([]byte(export[4:20]))
		if _, err := checked(grantSQL, o, w, e, actor, session[:], export, token, "json", "issue", checksum, fingerprint); err != nil {
			t.Fatalf("issue download grant: %v", err)
		}
		receipt, err := checked(grantSQL, o, w, e, actor, session[:], export, token, "json", "read", checksum, fingerprint)
		if err != nil {
			t.Fatalf("read download grant: %v", err)
		}
		var pin struct {
			Reference string `json:"reference"`
			Version   string `json:"version"`
			Size      int64  `json:"size"`
			SHA256    string `json:"sha256"`
		}
		if json.Unmarshal(receipt, &pin) != nil || pin.Reference != export {
			t.Fatalf("download receipt = %s", receipt)
		}
		var stored *artifactstore.DriverObject
		for key, object := range driver.objects {
			if strings.Contains(key, export) {
				object := object
				stored = &object
			}
		}
		if stored == nil || stored.VersionID != pin.Version || int64(len(stored.Body)) != pin.Size || hex.EncodeToString(stored.SHA256[:]) != pin.SHA256 {
			t.Fatalf("the stored package does not match the receipt %s", receipt)
		}
		if _, err := checked(grantSQL, o, w, e, actor, session[:], export, token, "json", "consume", checksum, fingerprint); err != nil {
			t.Fatalf("consume download grant: %v", err)
		}
		var value envelope
		if json.Unmarshal(stored.Body, &value) != nil || value.Version != 1 || value.ID != export || value.CSV == "" || value.Human == "" {
			t.Fatalf("stored package = %.300s", stored.Body)
		}
		return value
	}

	// 1. An export for an AI framework.
	frameworkExport := create("ws3-framework", `{"framework":"owasp_agentic_top10_2026"}`)
	rendered := run(frameworkExport)
	var entries []struct {
		Control struct {
			ID          string   `json:"id"`
			Framework   string   `json:"framework"`
			EvidenceIDs []string `json:"evidence_ids"`
		} `json:"control"`
		Freshness string `json:"freshness"`
	}
	if err := json.Unmarshal(rendered.JSON, &entries); err != nil || len(entries) != 5 {
		t.Fatalf("framework export entries = %d %v: %.400s", len(entries), err, rendered.JSON)
	}
	withFindings := 0
	for _, entry := range entries {
		want := []string{}
		for finding, rule := range findings {
			for _, reference := range compliancemap.References(rule) {
				if reference.Control == entry.Control.ID {
					want = append(want, finding)
				}
			}
		}
		got := map[string]bool{}
		for _, evidence := range entry.Control.EvidenceIDs {
			got[evidence] = true
		}
		if entry.Control.Framework != compliancemap.OWASPAgentic || len(got) != len(want) || got[otherFinding] || (entry.Freshness == "missing") != (len(want) == 0) {
			t.Fatalf("control %s holds %v, want %v (%s)", entry.Control.ID, entry.Control.EvidenceIDs, want, entry.Freshness)
		}
		for _, finding := range want {
			if !got[finding] {
				t.Fatalf("control %s lacks finding %s", entry.Control.ID, finding)
			}
		}
		if len(want) > 0 {
			withFindings++
		}
	}
	if withFindings < 2 || !strings.Contains(rendered.CSV, "ASI10") || !strings.Contains(rendered.Human, "ASI03") {
		t.Fatalf("the framework export holds findings for %d controls", withFindings)
	}

	// 2. The retained evidence pack of one agent.
	packExport := create("ws3-pack", `{"agent_id":"`+agent+`"}`)
	retained := run(packExport)
	pack, err := evidencepack.Decode(retained.JSON)
	if err != nil {
		t.Fatalf("retained pack: %v: %.600s", err, retained.JSON)
	}
	if pack.Agent.Summary.ID != agent || pack.Agent.Summary.Name != "Export agent" || pack.Agent.Summary.Discovery.Method != "provider_api" || len(pack.Agent.Summary.Discovery.Signals) != 1 || pack.Agent.Summary.ActivityState != "active" || len(pack.Agent.Sources) != 1 || pack.Agent.Evidence[0].ID != evidenceID {
		t.Fatalf("pack agent = %#v", pack.Agent)
	}
	if pack.FindingsStatus != "complete" || len(pack.Findings) != len(findings) {
		t.Fatalf("pack findings = %#v", pack.Findings)
	}
	for _, finding := range pack.Findings {
		rule, own := findings[finding.ID]
		references := compliancemap.References(rule)
		if !own || finding.Rule != rule || len(finding.Frameworks) != len(references) || len(references) == 0 {
			t.Fatalf("pack finding %#v, want rule %q with %d references", finding, rule, len(references))
		}
		for _, reference := range references {
			found := false
			for _, got := range finding.Frameworks {
				found = found || got.Framework == reference.Framework && got.Control == reference.Control && got.Title == reference.Title
			}
			if !found {
				t.Fatalf("pack finding %s lacks %s %s", finding.ID, reference.Framework, reference.Control)
			}
		}
	}
	if pack.RunsStatus != "partial" || len(pack.RedTeamTests) != 1 || pack.RedTeamTests[0].ID != definition || len(pack.RedTeamRuns) != 1 || pack.RedTeamRuns[0].ID != testRun || pack.RedTeamRuns[0].Status != "queued" {
		t.Fatalf("pack runs=%s tests=%#v test runs=%#v", pack.RunsStatus, pack.RedTeamTests, pack.RedTeamRuns)
	}
	for _, want := range []string{"# Agent evidence pack: Export agent", "## Findings", "owasp\\_agentic\\_top10\\_2026 ASI10: Rogue Agents", "## Security Agent actions and approvals", "Runs owned by the Temporal executor are not in a retained pack", "| `" + definition + "` | Export probe |", "| `" + testRun + "` | Export probe | queued |"} {
		if !strings.Contains(retained.Human, want) {
			t.Errorf("the retained rendering lacks %q:\n%s", want, retained.Human)
		}
	}
	if !strings.Contains(retained.CSV, "finding,") || !strings.Contains(retained.CSV, "red_team_run,"+testRun) {
		t.Fatalf("retained CSV = %s", retained.CSV)
	}
	// Both jobs are retained with their snapshot and receipt.
	var retainedJobs int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_compliance_export_jobs WHERE export_id IN($1,$2) AND state='completed' AND storage_state='verified' AND snapshot IS NOT NULL AND receipt_version IS NOT NULL AND retrieval_expires_at>clock_timestamp()`, frameworkExport, packExport).Scan(&retainedJobs); err != nil || retainedJobs != 2 {
		t.Fatalf("retained jobs = %d %v", retainedJobs, err)
	}
	// A requester whose membership ended cannot read the export any more.
	if _, err := admin.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
		t.Fatal(err)
	}
	if status, err := checked(getSQL, o, w, e, actor, session[:], packExport, checksum, fingerprint); err == nil {
		t.Fatalf("a requester without a membership read an export: %s", status)
	}
}
