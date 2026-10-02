package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/exportfixture"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type publicExportRestartParent struct {
	t                       *testing.T
	ctx                     context.Context
	owner                   *pgx.Conn
	directory, workerBinary string
	request                 publicExportAPIRequest
	sequence                int
	children                []map[string]any
}

func (p *publicExportRestartParent) read(name string, target any) {
	p.t.Helper()
	b, err := os.ReadFile(filepath.Join(p.directory, name))
	if err != nil || json.Unmarshal(b, target) != nil {
		p.t.Fatalf("owned %s missing/invalid: %v", name, err)
	}
}
func (p *publicExportRestartParent) json(query string, args ...any) string {
	p.t.Helper()
	var raw string
	if err := p.owner.QueryRow(p.ctx, query, args...).Scan(&raw); err != nil {
		p.t.Fatalf("registered readback failed: %v", err)
	}
	return raw
}
func (p *publicExportRestartParent) expect(query string, args ...any) {
	p.t.Helper()
	var ok bool
	if err := p.owner.QueryRow(p.ctx, query, args...).Scan(&ok); err != nil || !ok {
		p.t.Fatalf("durable restart invariant false: %s error=%v", query, err)
	}
}

// Every started command gets a cleanup owner before Start. Only its own PID is
// signalled; Wait runs exactly once, including assertion failure paths.
func (p *publicExportRestartParent) start(binary, entry, phase string, env []string, crash bool) func() {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(p.ctx, 80*time.Second)
	cmd := exec.CommandContext(ctx, binary, "-test.run=^"+entry+"$", "-test.v", "-test.timeout=75s")
	cmd.Env = append(os.Environ(), env...)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Second
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	done := make(chan struct{})
	var waitErr error
	p.t.Cleanup(func() {
		cancel()
		if cmd.Process != nil {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		}
	})
	if err := cmd.Start(); err != nil {
		cancel()
		p.t.Fatal("owned child start failed", err)
	}
	go func() { waitErr = cmd.Wait(); close(done) }()
	return func() {
		p.t.Helper()
		<-done
		cancel()
		status := cmd.ProcessState.ExitCode()
		want := 0
		if crash {
			want = 86
		}
		marker := "PUBLIC_EXPORT_JOINED " + phase
		if entry == "TestSecurityAgentExportPublicAPIProcess" {
			marker = "PUBLIC_EXPORT_RESPONSE "
		}
		if crash {
			marker = "PUBLIC_EXPORT_CHECKPOINT " + phase
		}
		p.children = append(p.children, map[string]any{"phase": phase, "pid": cmd.Process.Pid, "exit_code": status, "abrupt_post_commit": crash, "output_sha256": fmt.Sprintf("%x", sha256.Sum256(output.Bytes()))})
		if status != want || !strings.Contains(output.String(), marker) || strings.Contains(output.String(), "--- SKIP:") {
			p.t.Fatalf("child %s exit=%d want=%d err=%v: %s", phase, status, want, waitErr, output.String())
		}
		p.t.Logf("joined %s pid=%d exit=%d abrupt_post_commit=%t", phase, cmd.Process.Pid, status, crash)
	}
}

func (p *publicExportRestartParent) api(method, path, body, version, key, checkpoint string) publicExportAPIResponse {
	p.t.Helper()
	p.sequence++
	in := p.request
	in.Method, in.Path, in.Body, in.Version, in.Key, in.Checkpoint = method, path, body, version, key, checkpoint
	in.Correlation = fmt.Sprintf("pid_8ed00000-0000-4000-8000-%012d", p.sequence)
	raw, _ := json.Marshal(in)
	name := filepath.Join(p.directory, "request.json")
	if err := os.WriteFile(name, raw, 0600); err != nil {
		p.t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(p.directory, "response.json"))
	_ = os.Remove(filepath.Join(p.directory, "checkpoint.json"))
	p.start(os.Args[0], "TestSecurityAgentExportPublicAPIProcess", checkpoint, []string{"ZASP_PUBLIC_EXPORT_API_REQUEST=" + name}, checkpoint != "")()
	if checkpoint != "" {
		if _, err := os.Stat(filepath.Join(p.directory, "response.json")); err == nil {
			p.t.Fatal("post-commit exit delivered HTTP response")
		}
		return publicExportAPIResponse{}
	}
	var response publicExportAPIResponse
	p.read("response.json", &response)
	return response
}
func (p *publicExportRestartParent) must(response publicExportAPIResponse, status int) publicExportAPIResponse {
	p.t.Helper()
	if response.Status != status {
		p.t.Fatalf("public response status=%d want=%d body=%s", response.Status, status, response.Body)
	}
	return response
}
func (p *publicExportRestartParent) worker(phase string, crash bool) func() {
	p.t.Helper()
	config := p.owner.Config().Copy()
	config.User = "security_agent_v33_worker_login"
	if strings.HasPrefix(phase, "E-") {
		config.User = "compliance_executor"
	}
	_ = os.Remove(filepath.Join(p.directory, "checkpoint.json"))
	dsn := fmt.Sprintf("postgres://%s@127.0.0.1:%d/postgres?sslmode=disable", config.User, config.Port)
	return p.start(p.workerBinary, "TestSecurityAgentExportPublicWorkerProcess", phase, []string{"ZASP_PUBLIC_EXPORT_DIRECTORY=" + p.directory, "ZASP_PUBLIC_EXPORT_PHASE=" + phase, "ZASP_PUBLIC_EXPORT_WORKER_DSN=" + dsn}, crash)
}
func (p *publicExportRestartParent) waitUntil(at time.Time) {
	p.t.Helper()
	d := time.Until(at)
	if d < 0 {
		return
	}
	if d > 35*time.Second {
		p.t.Fatalf("unexpected retry/lease deadline %s", d)
	}
	timer := time.NewTimer(d + 50*time.Millisecond)
	defer timer.Stop()
	select {
	case <-p.ctx.Done():
		p.t.Fatal("parent deadline waiting for real lease/retry")
	case <-timer.C:
	}
}
func (p *publicExportRestartParent) plannerCalls() int {
	p.t.Helper()
	b, err := os.ReadFile(filepath.Join(p.directory, "planner-calls.jsonl"))
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		p.t.Fatal(err)
	}
	return bytes.Count(b, []byte("\n"))
}

// One public-created run crosses A-H. Identity/model/storage transports are
// controlled; registered SQL, worker compositions and OS process exits are real.
func TestSecurityAgentExportPublicRestartPostgres(t *testing.T) {
	if _, err := os.Stat("/compliance-worker.test"); err != nil {
		t.Fatal("owned registered worker binary required; missing binary is not restart evidence")
	}
	runExportDefinitionFixture(t, func(_ context.Context, owner, api *pgx.Conn, o, w, e, actor string) {
		ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
		defer cancel()
		directory, err := os.MkdirTemp("/tmp", "zasp-public-export-restart-")
		if err != nil {
			t.Fatal(err)
		}
		// Registered first: later child cleanup callbacks run before directory removal.
		t.Cleanup(func() {
			if err := os.RemoveAll(directory); err != nil {
				t.Error(err)
			}
		})
		config := owner.Config().Copy()
		config.User = "security_agent_v33_api_login"
		dsn := fmt.Sprintf("postgres://%s@127.0.0.1:%d/postgres?sslmode=disable", config.User, config.Port)
		p := &publicExportRestartParent{t: t, ctx: ctx, owner: owner, directory: directory, workerBinary: "/compliance-worker.test", request: publicExportAPIRequest{DSN: dsn, Directory: directory, Organization: o, Workspace: w, Environment: e, Actor: actor}}
		p.expect(`SELECT (SELECT count(*) FROM zasp_security_agent_definitions WHERE body->'allowed_actions' ? 'create_evidence_export')=0 AND (SELECT count(*) FROM zasp_security_agent_definition_versions WHERE definition->'allowed_actions' ? 'create_evidence_export')=0 AND (SELECT count(*) FROM zasp_security_agent_kill_switches WHERE action_key='create_evidence_export')=0 AND (SELECT count(*) FROM zasp_security_agent_runs)=0 AND (SELECT count(*) FROM zasp_security_agent_plans)=0 AND (SELECT count(*) FROM zasp_security_agent_steps)=0 AND (SELECT count(*) FROM zasp_security_agent_approvals)=0 AND (SELECT count(*) FROM zasp_sa_export_links)=0 AND (SELECT count(*) FROM zasp_compliance_export_jobs)=0`)
		if _, err := owner.Exec(ctx, `CREATE ROLE compliance_executor LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;CREATE ROLE compliance_cleanup LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
		if err := precisionMigrationRunner(t, owner).RegisterComplianceWorkers(ctx, "compliance_executor", "compliance_cleanup"); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($4,$1,'public-restart-org','public-restart-approver','security_admin',true);INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Independent approver','["view","manage_workflows","manage_identity","view_audit"]')`, pgx.QueryExecModeSimpleProtocol, o, w, e, exportApproverID); err != nil {
			t.Fatal(err)
		}
		for _, principal := range []string{actor, exportApproverID} {
			digest := sha256.Sum256([]byte(publicExportSession(principal)))
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($5,$4,$1,$2,$3,'["view","manage_workflows","manage_identity","view_audit"]',$6,clock_timestamp()+interval '1 hour',clock_timestamp())`, o, w, e, principal, digest[:], strings.Repeat("c", 32)); err != nil {
				t.Fatal(err)
			}
		}
		store, err := exportfixture.Create(exportfixture.Config{Directory: filepath.Join(directory, "export-store"), Bucket: "zasp-compliance-exports", Owner: "123456789012", KMSKey: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 8 << 20})
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		checksum, fp := migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()
		p.expect(`SELECT zasp_sa_export_readiness($1,$2)`, checksum, fp)
		t.Logf("public restart compiled/installed58 checksum=%s fingerprint=%s", checksum, fp)
		marshal := func(v any) string {
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
		body := exportDefinitionTestBody(t, fixtureRequestIdentity(t), "")
		body["environment_ids"] = []string{e}
		body["trigger_kind"] = "finding"
		body["trigger_source"] = "credential"
		body["max_duration_seconds"] = 900
		createBody := marshal(body)
		created := p.must(p.api("POST", "/api/v1/security-agents", createBody, "", "restart-create-0001", ""), 201)
		var definition map[string]any
		if json.Unmarshal(created.Body, &definition) != nil {
			t.Fatal("definition response")
		}
		id, _ := definition["id"].(string)
		if !validProductID(id) {
			t.Fatal("public definition ID")
		}
		path := "/api/v1/security-agents/" + id
		body["id"], body["name"] = id, "Public restart evidence"
		updateBody := marshal(body)
		updated := p.must(p.api("PATCH", path, updateBody, `"1"`, "restart-update-0001", ""), 200)
		controlBody := `{"target":"action","action_key":"create_evidence_export","enabled":true}`
		control := p.must(p.api("PUT", "/api/v1/security-agent-execution-controls", controlBody, `"0"`, "restart-control-0001", ""), 200)
		p.must(p.api("POST", path+"/activation", `{"activation":"validated"}`, `"2"`, "restart-validate-0001", ""), 200)
		activated := p.must(p.api("POST", path+"/activation", `{"activation":"supervised"}`, `"3"`, "restart-activate-0001", ""), 200)
		manualBody := marshal(map[string]string{"environment_id": e})
		p.api("POST", path+"/runs", manualBody, `"4"`, "restart-manual-0001", "A")
		var committed SecurityAgentRunResult
		p.read("checkpoint.json", &committed)
		started := p.must(p.api("POST", path+"/runs", manualBody, `"4"`, "restart-manual-0001", ""), 202)
		var run SecurityAgentRun
		if json.Unmarshal(started.Body, &run) != nil || run.ID != committed.ID || run.ManualTrigger == nil || started.Header.Get("X-Mutation-Receipt-ID") != committed.ReceiptID || started.Header.Get("X-Audit-ID") != committed.AuditID {
			t.Fatal("A manual committed receipt changed")
		}
		for _, retry := range []struct {
			method, path, body, version, key string
			original                         publicExportAPIResponse
		}{{"POST", "/api/v1/security-agents", createBody, "", "restart-create-0001", created}, {"PATCH", path, updateBody, `"1"`, "restart-update-0001", updated}, {"PUT", "/api/v1/security-agent-execution-controls", controlBody, `"0"`, "restart-control-0001", control}, {"POST", path + "/activation", `{"activation":"supervised"}`, `"3"`, "restart-activate-0001", activated}} {
			got := p.must(p.api(retry.method, retry.path, retry.body, retry.version, retry.key, ""), retry.original.Status)
			var originalBody, replayedBody map[string]any
			if json.Unmarshal(retry.original.Body, &originalBody) != nil || json.Unmarshal(got.Body, &replayedBody) != nil {
				t.Fatal("A invalid replay body")
			}
			if before, exists := originalBody["replayed"]; exists {
				if before != false || replayedBody["replayed"] != true {
					t.Fatal("A replay provenance absent")
				}
				delete(originalBody, "replayed")
				delete(replayedBody, "replayed")
			}
			if !reflect.DeepEqual(originalBody, replayedBody) {
				t.Fatalf("A retained public result changed: %s %s", retry.method, retry.path)
			}
			for _, header := range []string{"ETag", "X-Audit-ID", "X-Mutation-Receipt-ID"} {
				if got.Header.Get(header) != retry.original.Header.Get(header) {
					t.Fatalf("A %s changed", header)
				}
			}
		}
		p.must(p.api("GET", path, "", "", "", ""), 200)
		// Intermediate activation replay must not roll current authority backwards.
		p.must(p.api("POST", path+"/activation", `{"activation":"validated"}`, `"2"`, "restart-validate-0001", ""), 409)
		p.expect(`SELECT count(*)=1 AND bool_and(r.run_id=$1 AND t.trigger_kind='manual') FROM zasp_security_agent_runs r JOIN zasp_security_agent_trigger_receipts t USING(organization_id,workspace_id,environment_id,run_id)`, run.ID)
		t.Log("checkpoint A: public setup/manual receipts survive new API processes")

		p.worker("B", true)()
		planSnapshot := p.json(`SELECT jsonb_build_object('plan',to_jsonb(p),'input',to_jsonb(i),'usage',(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_security_agent_provider_reservations x WHERE x.run_id=p.run_id))::text FROM zasp_security_agent_plans p JOIN zasp_sa_export_planner_inputs i USING(organization_id,workspace_id,environment_id,run_id) WHERE p.run_id=$1`, run.ID)
		var step, approval string
		if err := owner.QueryRow(ctx, `SELECT step_id,approval_id FROM zasp_security_agent_approvals WHERE run_id=$1`, run.ID).Scan(&step, &approval); err != nil {
			t.Fatal(err)
		}
		p.worker("B-wait", false)()
		if p.plannerCalls() != 1 || p.json(`SELECT jsonb_build_object('plan',to_jsonb(p),'input',to_jsonb(i),'usage',(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_security_agent_provider_reservations x WHERE x.run_id=p.run_id))::text FROM zasp_security_agent_plans p JOIN zasp_sa_export_planner_inputs i USING(organization_id,workspace_id,environment_id,run_id) WHERE p.run_id=$1`, run.ID) != planSnapshot {
			t.Fatal("B accepted plan/accounting changed or provider repeated")
		}
		p.expect(`SELECT (SELECT count(*) FROM zasp_security_agent_plans)=1 AND (SELECT count(*) FROM zasp_security_agent_steps)=1 AND (SELECT count(*) FROM zasp_security_agent_approvals WHERE state='pending')=1 AND (SELECT count(*) FROM zasp_security_agent_provider_reservations WHERE settled_at IS NOT NULL)=1`)
		p.must(p.api("GET", "/api/v1/security-agent-runs/"+run.ID, "", "", "", ""), 200)
		p.must(p.api("GET", "/api/v1/security-agent-approvals/"+approval, "", "", "", ""), 200)
		t.Log("checkpoint B: accepted plan retained; exactly one controlled model request and settled reservation")

		p.request.Actor = exportApproverID
		p.api("POST", "/api/v1/security-agent-approvals/"+approval+"/decision", `{"decision":"approved"}`, `"1"`, "restart-approve-0001", "C")
		var decision SecurityAgentApprovalResult
		p.read("checkpoint.json", &decision)
		approved := p.must(p.api("POST", "/api/v1/security-agent-approvals/"+approval+"/decision", `{"decision":"approved"}`, `"1"`, "restart-approve-0001", ""), 200)
		if approved.Header.Get("X-Audit-ID") != decision.AuditID || approved.Header.Get("X-Mutation-Receipt-ID") != decision.ReceiptID {
			t.Fatal("C approval replay changed decision receipt")
		}
		p.request.Actor = actor
		p.worker("D", true)()
		var exportID string
		if err := owner.QueryRow(ctx, `SELECT export_id FROM zasp_sa_export_links WHERE run_id=$1`, run.ID).Scan(&exportID); err != nil {
			t.Fatal(err)
		}
		dispatchSnapshot := p.json(`SELECT jsonb_build_object('link',to_jsonb(l),'run',to_jsonb(r),'usage',(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_security_agent_provider_reservations x WHERE x.run_id=r.run_id))::text FROM zasp_sa_export_links l JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run.ID)
		p.worker("D-pending", false)()
		if p.json(`SELECT jsonb_build_object('link',to_jsonb(l),'run',to_jsonb(r),'usage',(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_security_agent_provider_reservations x WHERE x.run_id=r.run_id))::text FROM zasp_sa_export_links l JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run.ID) != dispatchSnapshot || p.plannerCalls() != 1 {
			t.Fatal("D pending child churned link/parent/accounting")
		}
		p.expect(`SELECT (SELECT count(*) FROM zasp_sa_export_links)=1 AND (SELECT count(*) FROM zasp_compliance_export_jobs)=1 AND (SELECT count(*) FROM zasp_security_agent_effects)=1 AND (SELECT state='verifying' FROM zasp_security_agent_runs WHERE run_id=$1)`, run.ID)
		t.Log("checkpoints C/D: original independent decision, one dispatch, pending settlement no-op")

		p.worker("E-interrupt", false)()
		var frozen []byte
		var retryAt time.Time
		if err := owner.QueryRow(ctx, `SELECT package,next_attempt_at FROM zasp_compliance_export_jobs WHERE export_id=$1`, exportID).Scan(&frozen, &retryAt); err != nil {
			t.Fatal(err)
		}
		p.expect(`SELECT state='pending' AND storage_state='unknown' AND receipt_version IS NULL AND generation=1 AND attempt=1 AND renderer_revision='security-agent-evidence-envelope-v1' AND snapshot IS NOT NULL AND retained_bytes>0 FROM zasp_compliance_export_jobs WHERE export_id=$1`, exportID)
		preparedQuery := `SELECT jsonb_build_object('snapshot',snapshot,'snapshot_digest',encode(snapshot_digest,'hex'),'snapshot_at',snapshot_at,'revision',renderer_revision,'reference',artifact_reference,'size',artifact_size,'digest',encode(artifact_digest,'hex'),'formats',format_sizes,'retained_bytes',retained_bytes)::text FROM zasp_compliance_export_jobs WHERE export_id=$1`
		preparedSnapshot := p.json(preparedQuery, exportID)
		objects, err := store.Objects(ctx)
		if err != nil || len(objects) != 1 {
			t.Fatal("E first PUT did not create exactly one object", err)
		}
		originalObject := objects[0]
		p.waitUntil(retryAt)
		p.worker("E-resume", false)()
		var resumed []byte
		if err := owner.QueryRow(ctx, `SELECT package FROM zasp_compliance_export_jobs WHERE export_id=$1`, exportID).Scan(&resumed); err != nil || !bytes.Equal(frozen, resumed) {
			t.Fatal("E prepared package changed", err)
		}
		p.expect(`SELECT state='completed' AND storage_state='verified' AND generation=2 AND attempt=2 AND receipt_version IS NOT NULL FROM zasp_compliance_export_jobs WHERE export_id=$1`, exportID)
		if p.json(preparedQuery, exportID) != preparedSnapshot {
			t.Fatal("E retained snapshot/package metadata changed")
		}
		objects, err = store.Objects(ctx)
		if err != nil || len(objects) != 1 || !reflect.DeepEqual(objects[0], originalObject) {
			t.Fatal("E replay created/changed object version", err)
		}
		var resumeQueries []string
		p.read("E-resume-queries.json", &resumeQueries)
		loads := 0
		for _, query := range resumeQueries {
			if query == "zasp_compliance_export_load_prepared" {
				loads++
			}
			if query == "zasp_compliance_export_capture" || query == "zasp_compliance_export_prepare_artifact" {
				t.Fatal("E prepared replay recaptured or rerendered")
			}
		}
		if loads != 1 {
			t.Fatalf("E prepared load calls=%d want1", loads)
		}
		var firstClaim struct {
			Args   []any
			Result struct {
				Generation int64 `json:"generation"`
			}
		}
		p.read("E-interrupt-claim.json", &firstClaim)
		workerConfig := owner.Config().Copy()
		workerConfig.User = "compliance_executor"
		executor, err := pgx.ConnectConfig(ctx, workerConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(context.Background())
		var refused json.RawMessage
		if len(firstClaim.Args) != 9 || firstClaim.Result.Generation != 1 {
			t.Fatal("E original claim not retained")
		}
		oldArgs := append(append([]any{}, firstClaim.Args[:6]...), int64(1), json.RawMessage(`{}`), firstClaim.Args[7], firstClaim.Args[8])
		var staleError *pgconn.PgError
		if err := executor.QueryRow(ctx, `SELECT public.zasp_compliance_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, oldArgs...).Scan(&refused); !errors.As(err, &staleError) || staleError.Code != "40001" || staleError.Message != "compliance lease rejected" {
			t.Fatal("E stale generation/token did not hit lease fence", err)
		}
		t.Log("checkpoint E: SIGTERM unknown write; real retry deadline; generation2 prepared replay; one immutable object")

		var beforeSettlementVersion int64
		if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_runs WHERE run_id=$1`, run.ID).Scan(&beforeSettlementVersion); err != nil {
			t.Fatal(err)
		}
		p.worker("F", true)()
		var oldSettlement struct{ Args []any }
		p.read("checkpoint.json", &oldSettlement)
		leaseSnapshot := p.json(`SELECT jsonb_build_object('worker',settlement_worker,'token_digest',encode(settlement_token_digest,'hex'),'expiry',settlement_lease_expires_at)::text FROM zasp_sa_export_links WHERE run_id=$1`, run.ID)
		var expires time.Time
		if err := owner.QueryRow(ctx, `SELECT settlement_lease_expires_at FROM zasp_sa_export_links WHERE run_id=$1`, run.ID).Scan(&expires); err != nil {
			t.Fatal(err)
		}
		p.worker("F-held", false)()
		if p.json(`SELECT jsonb_build_object('worker',settlement_worker,'token_digest',encode(settlement_token_digest,'hex'),'expiry',settlement_lease_expires_at)::text FROM zasp_sa_export_links WHERE run_id=$1`, run.ID) != leaseSnapshot {
			t.Fatal("F replacement stole unexpired link lease")
		}
		p.waitUntil(expires)
		joinG := p.worker("G", true)
		wait := time.NewTimer(4 * time.Second)
		defer wait.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
	claimWait:
		for {
			if _, err := os.Stat(filepath.Join(directory, "G-claim.json")); err == nil {
				break
			}
			select {
			case <-wait.C:
				t.Fatal("G committed claim checkpoint missing")
			case <-tick.C:
				continue claimWait
			}
		}
		newLease := p.json(`SELECT jsonb_build_object('worker',settlement_worker,'token_digest',encode(settlement_token_digest,'hex'),'expiry',settlement_lease_expires_at)::text FROM zasp_sa_export_links WHERE run_id=$1`, run.ID)
		if newLease == leaseSnapshot || len(oldSettlement.Args) != 6 {
			t.Fatal("F expired dedicated lease was not reclaimed")
		}
		workerConfig.User = "security_agent_v33_worker_login"
		settler, err := pgx.ConnectConfig(ctx, workerConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer settler.Close(context.Background())
		if err := settler.QueryRow(ctx, `SELECT public.zasp_sa_export_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, o, w, e, run.ID, oldSettlement.Args[0], oldSettlement.Args[1], "pid_8ed00001-0000-4000-8000-000000000001", "pid_8ed00002-0000-4000-8000-000000000001", checksum, fp).Scan(&refused); !errors.As(err, &staleError) || staleError.Code != "40001" || staleError.Message != "export settlement lease rejected" {
			t.Fatal("F stale settlement token did not hit lease fence", err)
		}
		if p.json(`SELECT jsonb_build_object('worker',settlement_worker,'token_digest',encode(settlement_token_digest,'hex'),'expiry',settlement_lease_expires_at)::text FROM zasp_sa_export_links WHERE run_id=$1`, run.ID) != newLease {
			t.Fatal("F stale token mutated replacement lease")
		}
		if err := os.WriteFile(filepath.Join(directory, "G-release"), []byte("continue"), 0600); err != nil {
			t.Fatal(err)
		}
		joinG()
		settledSnapshot := p.json(`SELECT jsonb_build_object('link',to_jsonb(l),'run',to_jsonb(r),'usage',(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_security_agent_provider_reservations x WHERE x.run_id=r.run_id))::text FROM zasp_sa_export_links l JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run.ID)
		p.worker("G-done", false)()
		if p.json(`SELECT jsonb_build_object('link',to_jsonb(l),'run',to_jsonb(r),'usage',(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_security_agent_provider_reservations x WHERE x.run_id=r.run_id))::text FROM zasp_sa_export_links l JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run.ID) != settledSnapshot || p.plannerCalls() != 1 {
			t.Fatal("G committed settlement replay changed facts/accounting")
		}
		p.expect(`SELECT r.state='needs_human' AND r.last_error_code='export_available' AND l.settled_at IS NOT NULL AND (SELECT count(*) FROM zasp_security_agent_audit a WHERE a.run_id=r.run_id AND a.event_kind='export_settled')=1 FROM zasp_security_agent_runs r JOIN zasp_sa_export_links l USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run.ID)
		p.expect(`SELECT r.version=$2+1 AND s.state='succeeded' AND f.state='succeeded' FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_effects f USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE r.run_id=$1`, run.ID, beforeSettlementVersion)
		t.Log("checkpoints F/G: dedicated30s lease survives loss, no theft, stale token refused, one runtime settlement")

		exportPath := "/api/v1/security-agent-runs/" + run.ID + "/steps/" + step + "/export"
		p.must(p.api("GET", exportPath, "", "", "", ""), 200)
		grant := func() string {
			response := p.must(p.api("POST", exportPath+"/download-grants", `{"format":"json"}`, "", "", ""), 201)
			var body struct {
				Token string `json:"token"`
			}
			if json.Unmarshal(response.Body, &body) != nil || len(body.Token) != 64 {
				t.Fatal("H grant response absent")
			}
			return body.Token
		}
		download := func(token, checkpoint string) publicExportAPIResponse {
			return p.api("POST", exportPath+"/download", marshal(map[string]string{"format": "json", "token": token}), "", "", checkpoint)
		}
		// The plaintext token is received before the first API exits. Only its
		// digest survives in PostgreSQL, so a pre-response issue crash is not replayable.
		first := p.must(download(grant(), ""), http.StatusOK)
		var envelope map[string]json.RawMessage
		if json.Unmarshal(frozen, &envelope) != nil || !bytes.Equal(first.Body, envelope["json"]) {
			t.Fatal("H download changed frozen requested format")
		}
		var manifest struct {
			Records []SecurityAgentExportSelection `json:"records"`
		}
		if json.Unmarshal(first.Body, &manifest) != nil || len(manifest.Records) != 1 || manifest.Records[0].Kind != "manual" || "sha256:"+manifest.Records[0].ID != run.ManualTrigger.IntentDigest || manifest.Records[0].Version != 1 {
			t.Fatal("H manual selected tuple changed")
		}
		var retainedSelection []SecurityAgentExportSelection
		if json.Unmarshal([]byte(p.json(`SELECT selection::text FROM zasp_sa_export_links WHERE run_id=$1`, run.ID)), &retainedSelection) != nil || !reflect.DeepEqual(manifest.Records, retainedSelection) {
			t.Fatal("H downloaded association differs from retained selected tuple")
		}
		lost := grant()
		download(lost, "H-consume")
		var consumeWrites map[string]int
		p.read("H-consume-writes.json", &consumeWrites)
		if len(consumeWrites) != 3 || consumeWrites["header_writes"] != 0 || consumeWrites["body_writes"] != 0 || consumeWrites["body_bytes"] != 0 {
			t.Fatal("H consume checkpoint emitted HTTP output", consumeWrites)
		}
		if response := download(lost, ""); response.Status < 400 || len(response.Body) == 0 {
			t.Fatal("H consumed grant was reused")
		}
		recovered := p.must(download(grant(), ""), 200)
		if !bytes.Equal(recovered.Body, first.Body) {
			t.Fatal("H fresh grant changed recovered bytes")
		}
		objects, err = store.Objects(ctx)
		if err != nil || len(objects) != 1 || !reflect.DeepEqual(objects[0], originalObject) {
			t.Fatal("H download recreated artifact", err)
		}
		requests, err := store.Requests(ctx)
		if err != nil {
			t.Fatal(err)
		}
		puts := 0
		for _, r := range requests {
			if r.Method == "PUT" && r.Stage == "stored" {
				puts++
			}
		}
		if puts != 2 {
			t.Fatalf("PUT attempts=%d want2; creations=1", puts)
		}
		p.expect(`SELECT (SELECT count(*) FROM zasp_security_agent_runs)=1 AND (SELECT count(*) FROM zasp_sa_export_links)=1 AND (SELECT count(*) FROM zasp_compliance_export_jobs)=1`)
		summary := map[string]any{"checkpoints": []string{"A", "B", "C", "D", "E", "F", "G", "H"}, "checksum": checksum, "fingerprint": fp, "definition_id": id, "run_id": run.ID, "step_id": step, "export_id": exportID, "model_calls": p.plannerCalls(), "put_attempts": puts, "object_creations": len(objects), "object_version": originalObject.VersionID, "package_sha256": fmt.Sprintf("%x", sha256.Sum256(frozen)), "download_sha256": fmt.Sprintf("%x", sha256.Sum256(first.Body)), "children": p.children, "old_settlement_lease": json.RawMessage(leaseSnapshot), "new_settlement_lease": json.RawMessage(newLease), "controlled_providers": true, "browser_native_save": false}
		summary["consume_checkpoint_writes"] = consumeWrites
		if evidence := os.Getenv("ZASP_PUBLIC_EXPORT_EVIDENCE"); evidence != "" {
			if evidence != "/evidence" {
				t.Fatal("evidence mount refused")
			}
			raw, _ := json.MarshalIndent(summary, "", "  ")
			if os.WriteFile(filepath.Join(evidence, "summary.json"), raw, 0600) != nil || os.WriteFile(filepath.Join(evidence, "download.json"), first.Body, 0600) != nil {
				t.Fatal("evidence persistence failed")
			}
		}
		t.Logf("checkpoint H: mounted download bytes=%d sha256=%s; issue/restart and consume/lost-response/fresh-grant recovery", len(first.Body), hex.EncodeToString(sha256Sum(first.Body)))
	})
}

func sha256Sum(raw []byte) []byte { hash := sha256.Sum256(raw); return hash[:] }
