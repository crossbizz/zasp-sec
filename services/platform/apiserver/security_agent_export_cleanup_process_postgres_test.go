package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/exportfixture"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type cleanupPublicArtifact struct {
	Organization, Workspace, Environment, Actor, Approver, Run, Step, Export string
	Object                                                                   exportfixture.Object
	Download                                                                 []byte
}

func cleanupProcessRun(p *publicExportRestartParent, phase string, crash bool) {
	p.t.Helper()
	login := "compliance_cleanup"
	if phase == "publish" {
		login = "compliance_executor"
	}
	dsn := fmt.Sprintf("postgres://%s@127.0.0.1:%d/postgres?sslmode=disable", login, p.owner.Config().Port)
	p.start(p.workerBinary, "TestSecurityAgentExportCleanupWorkerProcess", phase, []string{"ZASP_CLEANUP_DIRECTORY=" + p.directory, "ZASP_CLEANUP_PHASE=" + phase, "ZASP_CLEANUP_DSN=" + dsn}, crash)()
	if !crash {
		var trace struct{ Claims, Retries, Confirmations int }
		p.read("cleanup-"+phase+".json", &trace)
		claims, retries, confirmations := 0, 0, 0
		switch phase {
		case "publish":
			claims = 1
		case "denied", "generic404":
			claims, retries = 1, 1
		case "absent":
			claims, confirmations = 1, 1
		}
		if trace.Claims != claims || trace.Retries != retries || trace.Confirmations != confirmations {
			p.t.Fatalf("cleanup %s query outcomes=%+v want claims=%d retries=%d confirmations=%d", phase, trace, claims, retries, confirmations)
		}
	}
}

func cleanupWait(p *publicExportRestartParent, at time.Time) {
	p.t.Helper()
	delay := time.Until(at) + 50*time.Millisecond
	if delay <= 0 {
		return
	}
	if delay > 65*time.Second {
		p.t.Fatal("unexpected cleanup lease/retry deadline", delay)
	}
	p.t.Logf("waiting real cleanup deadline %s", delay.Round(time.Millisecond))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-p.ctx.Done():
		p.t.Fatal("cleanup parent deadline")
	}
}

// Removing read-lease gating, conflating404 with typed absence, clearing quota
// after DELETE alone, or deleting a sibling/version must fail this process test.
func TestSecurityAgentExportCleanupProcessPostgres(t *testing.T) {
	if _, err := os.Stat("/compliance-worker.test"); err != nil {
		t.Fatal("owned worker binary required")
	}
	runExportDefinitionFixture(t, func(_ context.Context, owner, api *pgx.Conn, o, w, e, actor string) {
		ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
		defer cancel()
		directory, err := os.MkdirTemp("/tmp", "zasp-public-export-restart-cleanup-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(directory); err != nil {
				t.Error(err)
			}
		})
		p := &publicExportRestartParent{t: t, ctx: ctx, owner: owner, directory: directory, workerBinary: "/compliance-worker.test", request: publicExportAPIRequest{DSN: fmt.Sprintf("postgres://security_agent_v33_api_login@127.0.0.1:%d/postgres?sslmode=disable", owner.Config().Port), Directory: directory}}
		p.expect(`SELECT (SELECT count(*) FROM zasp_compliance_export_jobs)=0 AND (SELECT count(*) FROM zasp_sa_export_links)=0 AND (SELECT count(*) FROM zasp_security_agent_runs)=0 AND (SELECT count(*) FROM zasp_security_agent_plans)=0 AND (SELECT count(*) FROM zasp_security_agent_definitions WHERE body->'allowed_actions' ? 'create_evidence_export')=0`)
		if _, err := owner.Exec(ctx, `CREATE ROLE compliance_executor LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;CREATE ROLE compliance_cleanup LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
		if err := precisionMigrationRunner(t, owner).RegisterComplianceWorkers(ctx, "compliance_executor", "compliance_cleanup"); err != nil {
			t.Fatal(err)
		}
		const o2 = "pid_8ec00001-0000-4000-8000-000000000001"
		const w2 = "pid_8ec00002-0000-4000-8000-000000000002"
		const e2 = "pid_8ec00003-0000-4000-8000-000000000003"
		const a2 = "pid_8ec00004-0000-4000-8000-000000000004"
		const approver2 = "pid_8ec00005-0000-4000-8000-000000000005"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Cleanup second organization','cleanup-second.invalid');INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($2,$1,'Second workspace');INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($3,$1,$2,'Second environment','staging')`, pgx.QueryExecModeSimpleProtocol, o2, w2, e2); err != nil {
			t.Fatal(err)
		}
		artifacts := []cleanupPublicArtifact{{Organization: o, Workspace: w, Environment: e, Actor: actor, Approver: exportApproverID}, {Organization: o2, Workspace: w2, Environment: e2, Actor: a2, Approver: approver2}, {Organization: o, Workspace: w, Environment: e, Actor: actor, Approver: exportApproverID}}
		// Only organizations, scoped identities, sessions and registered logins are
		// fixture prerequisites. All three export definitions/runs/plans are public.
		for _, a := range artifacts[:2] {
			for _, principal := range []string{a.Actor, a.Approver} {
				if principal != actor {
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($4,$1,$1,$4,'security_admin',true);INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Cleanup scoped actor','["view","manage_workflows","manage_identity","view_audit"]')`, pgx.QueryExecModeSimpleProtocol, a.Organization, a.Workspace, a.Environment, principal); err != nil {
						t.Fatal(err)
					}
				}
				digest := sha256.Sum256([]byte(publicExportSession(principal)))
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($5,$4,$1,$2,$3,'["view","manage_workflows","manage_identity","view_audit"]',$6,clock_timestamp()+interval '1 hour',clock_timestamp())`, a.Organization, a.Workspace, a.Environment, principal, digest[:], strings.Repeat("c", 32)); err != nil {
					t.Fatal(err)
				}
			}
		}
		store, err := exportfixture.Create(exportfixture.Config{Directory: filepath.Join(directory, "export-store"), Bucket: "zasp-compliance-exports", Owner: "123456789012", KMSKey: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 8 << 20})
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		checksum, fp := migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()
		p.expect(`SELECT zasp_sa_export_readiness($1,$2)`, checksum, fp)
		t.Logf("cleanup compiled/installed58 checksum=%s fingerprint=%s", checksum, fp)
		encode := func(v any) string {
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
		selectScope := func(a cleanupPublicArtifact) {
			p.request.Organization, p.request.Workspace, p.request.Environment, p.request.Actor = a.Organization, a.Workspace, a.Environment, a.Actor
		}
		grant := func(a cleanupPublicArtifact) string {
			selectScope(a)
			response := p.must(p.api("POST", "/api/v1/security-agent-runs/"+a.Run+"/steps/"+a.Step+"/export/download-grants", `{"format":"json"}`, "", "", ""), 201)
			var g struct{ Token string }
			if json.Unmarshal(response.Body, &g) != nil || len(g.Token) != 64 {
				t.Fatal("grant unavailable")
			}
			return g.Token
		}
		download := func(a cleanupPublicArtifact) []byte {
			token := grant(a)
			return p.must(p.api("POST", "/api/v1/security-agent-runs/"+a.Run+"/steps/"+a.Step+"/export/download", encode(map[string]string{"format": "json", "token": token}), "", "", ""), 200).Body
		}
		for i := range artifacts {
			a := &artifacts[i]
			selectScope(*a)
			key := fmt.Sprintf("cleanup-setup-%d-", i)
			if i == 1 {
				p.must(p.api("PUT", "/api/v1/security-agent-execution-controls", `{"target":"environment","action_key":"*","enabled":true}`, `"0"`, key+"environment", ""), 200)
			}
			if i < 2 {
				p.must(p.api("PUT", "/api/v1/security-agent-execution-controls", `{"target":"action","action_key":"create_evidence_export","enabled":true}`, `"0"`, key+"control", ""), 200)
			}
			body := exportDefinitionTestBody(t, fixtureRequestIdentity(t), "")
			body["environment_ids"] = []string{a.Environment}
			body["trigger_kind"] = "finding"
			body["trigger_source"] = "credential"
			body["max_duration_seconds"] = 900
			created := p.must(p.api("POST", "/api/v1/security-agents", encode(body), "", key+"create", ""), 201)
			var def struct{ ID string }
			if json.Unmarshal(created.Body, &def) != nil || !validProductID(def.ID) {
				t.Fatal("definition response")
			}
			path := "/api/v1/security-agents/" + def.ID
			p.must(p.api("POST", path+"/activation", `{"activation":"validated"}`, `"1"`, key+"validated", ""), 200)
			p.must(p.api("POST", path+"/activation", `{"activation":"supervised"}`, `"2"`, key+"supervised", ""), 200)
			response := p.must(p.api("POST", path+"/runs", encode(map[string]string{"environment_id": a.Environment}), `"3"`, key+"manual", ""), 202)
			var run SecurityAgentRun
			if json.Unmarshal(response.Body, &run) != nil || !validProductID(run.ID) {
				t.Fatal("manual response")
			}
			a.Run = run.ID
			p.worker("B", true)()
			var approval string
			if err := owner.QueryRow(ctx, `SELECT step_id,approval_id FROM zasp_security_agent_approvals WHERE run_id=$1`, a.Run).Scan(&a.Step, &approval); err != nil {
				t.Fatal(err)
			}
			p.request.Actor = a.Approver
			p.must(p.api("POST", "/api/v1/security-agent-approvals/"+approval+"/decision", `{"decision":"approved"}`, `"1"`, key+"approve", ""), 200)
			p.request.Actor = a.Actor
			p.worker("D", true)()
			if err := owner.QueryRow(ctx, `SELECT export_id FROM zasp_sa_export_links WHERE run_id=$1`, a.Run).Scan(&a.Export); err != nil {
				t.Fatal(err)
			}
			cleanupProcessRun(p, "publish", false)
			p.expect(`SELECT state='completed' AND storage_state='verified' AND retained_bytes>0 AND receipt_version IS NOT NULL FROM zasp_compliance_export_jobs WHERE export_id=$1`, a.Export)
			objects, err := store.Objects(ctx)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, object := range objects {
				if strings.Contains(object.Key, a.Export) {
					a.Object = object
					found = true
				}
			}
			if !found {
				t.Fatal("stored scoped artifact absent")
			}
			a.Download = download(*a)
			var envelope map[string]json.RawMessage
			if json.Unmarshal(a.Object.Body, &envelope) != nil || !bytes.Equal(envelope["json"], a.Download) {
				t.Fatal("successful mounted artifact bytes changed")
			}
			t.Logf("public artifact%d org=%s run=%s export=%s version=%s bytes=%d", i, a.Organization, a.Run, a.Export, a.Object.VersionID, len(a.Object.Body))
		}
		target := artifacts[2]
		beforeForeignProbe, err := store.Requests(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, pair := range [][2]int{{2, 1}, {1, 2}} {
			selectScope(artifacts[pair[0]])
			foreign := artifacts[pair[1]]
			response := p.api("GET", "/api/v1/security-agent-runs/"+foreign.Run+"/steps/"+foreign.Step+"/export", "", "", "", "")
			if response.Status != 403 && response.Status != 404 {
				t.Fatal("cross-organization artifact disclosed", response.Status)
			}
			if bytes.Contains(response.Body, []byte(foreign.Export)) || bytes.Contains(response.Body, foreign.Download) {
				t.Fatal("foreign response leaked stored artifact")
			}
		}
		afterForeignProbe, err := store.Requests(ctx)
		if err != nil || len(afterForeignProbe) != len(beforeForeignProbe) {
			t.Fatal("foreign API probe reached artifact provider", err)
		}
		p.expect(`SELECT count(*)=3 AND count(DISTINCT organization_id)=2 FROM zasp_compliance_export_jobs`)
		if p.plannerCalls() != 3 {
			t.Fatal("unexpected provider calls")
		}
		protected := func(a cleanupPublicArtifact) string {
			return p.json(`SELECT jsonb_build_object('job',to_jsonb(j),'link',to_jsonb(l),'run',to_jsonb(r),'plan',to_jsonb(p),'usage',(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_security_agent_provider_reservations x WHERE x.run_id=r.run_id))::text FROM zasp_compliance_export_jobs j JOIN zasp_sa_export_links l USING(organization_id,workspace_id,environment_id,export_id) JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE j.export_id=$1`, a.Export)
		}
		siblingBefore, foreignBefore := protected(artifacts[0]), protected(artifacts[1])
		token := grant(target)
		digest := sha256.Sum256([]byte(publicExportSession(target.Actor)))
		var lease struct {
			Expires time.Time `json:"read_expires_at"`
		}
		var raw []byte
		if err := api.QueryRow(ctx, `SELECT zasp_sa_export_grant($1,$2,$3,$4,$5,$6,$7,$8,$9,'json','read',$10,$11)`, target.Organization, target.Workspace, target.Environment, target.Run, target.Step, target.Actor, digest[:], strings.Repeat("c", 32), token, checksum, fp).Scan(&raw); err != nil || json.Unmarshal(raw, &lease) != nil || !lease.Expires.After(time.Now()) {
			t.Fatal("real read lease unavailable", err)
		}
		selectScope(target)
		var version int64
		if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_runs WHERE run_id=$1`, target.Run).Scan(&version); err != nil {
			t.Fatal(err)
		}
		p.must(p.api("POST", "/api/v1/security-agent-runs/"+target.Run+"/cancel", "", fmt.Sprintf(`"%d"`, version), "cleanup-target-cancel", ""), 200)
		accountingQuery := `SELECT jsonb_build_object('package',encode(package,'hex'),'snapshot',snapshot,'digest',encode(artifact_digest,'hex'),'size',artifact_size,'reference',artifact_reference,'version',receipt_version,'retained_bytes',retained_bytes)::text FROM zasp_compliance_export_jobs WHERE export_id=$1`
		accounting := p.json(accountingQuery, target.Export)
		var targetRetained, totalRetained int64
		if err := owner.QueryRow(ctx, `SELECT retained_bytes,(SELECT sum(retained_bytes) FROM zasp_compliance_export_jobs) FROM zasp_compliance_export_jobs WHERE export_id=$1`, target.Export).Scan(&targetRetained, &totalRetained); err != nil {
			t.Fatal(err)
		}
		requests, err := store.Requests(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cleanupStart := len(requests)
		cleanupProcessRun(p, "blocked", false)
		var blocked map[string]any
		p.read("cleanup-blocked.json", &blocked)
		if blocked["claims"] != float64(0) {
			t.Fatal("live read lease allowed cleanup claim")
		}
		requests, _ = store.Requests(ctx)
		if len(requests) != cleanupStart {
			t.Fatal("live read lease reached provider")
		}
		cleanupWait(p, lease.Expires)
		cleanupProcessRun(p, "delete-loss", true)
		var deleted exportfixture.Request
		p.read("cleanup-delete-checkpoint.json", &deleted)
		if deleted.Key != target.Object.Key || deleted.VersionID != target.Object.VersionID || deleted.Status != 204 {
			t.Fatal("DELETE checkpoint was not exact target")
		}
		var expiry time.Time
		if err := owner.QueryRow(ctx, `SELECT lease_expires_at FROM zasp_compliance_export_jobs WHERE export_id=$1`, target.Export).Scan(&expiry); err != nil {
			t.Fatal(err)
		}
		p.expect(`SELECT storage_state='delete_pending' AND retained_bytes>0 AND package IS NOT NULL AND deletion_audit_id IS NULL FROM zasp_compliance_export_jobs WHERE export_id=$1`, target.Export)
		afterLoss := p.json(`SELECT to_jsonb(j)::text FROM zasp_compliance_export_jobs j WHERE export_id=$1`, target.Export)
		cleanupProcessRun(p, "held", false)
		if p.json(`SELECT to_jsonb(j)::text FROM zasp_compliance_export_jobs j WHERE export_id=$1`, target.Export) != afterLoss {
			t.Fatal("replacement stole unexpired cleanup lease")
		}
		cleanupWait(p, expiry)
		for _, phase := range []string{"denied", "generic404"} {
			cleanupProcessRun(p, phase, false)
			if p.json(accountingQuery, target.Export) != accounting {
				t.Fatal("uncertain response released accounting", phase)
			}
			p.expect(`SELECT storage_state='delete_pending' AND deletion_audit_id IS NULL AND lease_expires_at IS NULL FROM zasp_compliance_export_jobs WHERE export_id=$1`, target.Export)
			var at time.Time
			if err := owner.QueryRow(ctx, `SELECT next_attempt_at FROM zasp_compliance_export_jobs WHERE export_id=$1`, target.Export).Scan(&at); err != nil {
				t.Fatal(err)
			}
			cleanupWait(p, at)
		}
		cleanupProcessRun(p, "absent", false)
		p.expect(`SELECT storage_state='deleted' AND retained_bytes=0 AND package IS NULL AND snapshot IS NULL AND deleted_at IS NOT NULL AND deletion_audit_id IS NOT NULL AND (SELECT count(*) FROM zasp_admin_audit a WHERE a.target_id=j.export_id AND a.action='compliance.export.deleted')=1 FROM zasp_compliance_export_jobs j WHERE export_id=$1`, target.Export)
		p.expect(`SELECT sum(retained_bytes)=$1 FROM zasp_compliance_export_jobs`, totalRetained-targetRetained)
		finished := p.json(`SELECT to_jsonb(j)::text FROM zasp_compliance_export_jobs j WHERE export_id=$1`, target.Export)
		cleanupProcessRun(p, "done", false)
		if p.json(`SELECT to_jsonb(j)::text FROM zasp_compliance_export_jobs j WHERE export_id=$1`, target.Export) != finished {
			t.Fatal("cleanup cleared target more than once")
		}
		if protected(artifacts[0]) != siblingBefore || protected(artifacts[1]) != foreignBefore {
			t.Fatal("cleanup mutated sibling/second-org durable rows")
		}
		objects, err := store.Objects(ctx)
		if err != nil || len(objects) != 3 {
			t.Fatal("stored identities changed", err)
		}
		for _, a := range artifacts {
			found := false
			for _, object := range objects {
				if object.Key == a.Object.Key {
					found = true
					if a.Export == target.Export {
						if !object.Deleted || len(object.Body) != 0 || object.VersionID != a.Object.VersionID {
							t.Fatal("target tombstone changed")
						}
					} else if !reflect.DeepEqual(object, a.Object) {
						t.Fatal("cleanup altered protected artifact")
					}
				}
			}
			if !found {
				t.Fatal("object identity missing")
			}
		}
		requests, err = store.Requests(ctx)
		if err != nil {
			t.Fatal(err)
		}
		puts, deletes, missing := 0, 0, 0
		for _, r := range requests[cleanupStart:] {
			if r.Method == "PUT" {
				puts++
			}
			if r.Key != target.Object.Key || r.VersionID != target.Object.VersionID {
				t.Fatal("cleanup touched a sibling/foreign key or version")
			}
			if r.Stage == "stored" && r.Method == "DELETE" && r.Status == 204 {
				deletes++
			}
			if r.Stage == "response" && r.Method == "GET" && r.Code == "NoSuchVersion" {
				missing++
			}
		}
		if puts != 0 || deletes != 1 || missing != 1 {
			t.Fatalf("cleanup PUT=%d actual DELETE=%d typed missing=%d", puts, deletes, missing)
		}
		artifactEvidence := make([]map[string]any, 0, len(artifacts))
		for _, a := range artifacts {
			if a.Export != target.Export && !bytes.Equal(download(a), a.Download) {
				t.Fatal("protected artifact cannot be downloaded unchanged after cleanup")
			}
			artifactEvidence = append(artifactEvidence, map[string]any{"organization": a.Organization, "workspace": a.Workspace, "environment": a.Environment, "run": a.Run, "export": a.Export, "key": a.Object.Key, "version": a.Object.VersionID, "package_sha256": fmt.Sprintf("%x", sha256.Sum256(a.Object.Body)), "download_sha256": fmt.Sprintf("%x", sha256.Sum256(a.Download))})
		}
		summary := map[string]any{"checksum": checksum, "fingerprint": fp, "public_artifacts": 3, "organizations": 2, "model_calls": p.plannerCalls(), "cleanup_puts": puts, "physical_deletions": deletes, "typed_absence_confirmations": missing, "children": p.children, "target_export": target.Export, "sibling_export": artifacts[0].Export, "second_org_export": artifacts[1].Export, "cleanup_requests": requests[cleanupStart:], "read_lease_expires_at": lease.Expires, "lost_delete_lease_expires_at": expiry}
		summary["artifacts"] = artifactEvidence
		summary["retained_bytes_before"] = totalRetained
		summary["retained_bytes_after"] = totalRetained - targetRetained
		summary["sibling_rows_sha256"] = fmt.Sprintf("%x", sha256.Sum256([]byte(siblingBefore)))
		summary["second_org_rows_sha256"] = fmt.Sprintf("%x", sha256.Sum256([]byte(foreignBefore)))
		if evidence := os.Getenv("ZASP_PUBLIC_EXPORT_EVIDENCE"); evidence != "" {
			if evidence != "/evidence" {
				t.Fatal("evidence mount refused")
			}
			data, _ := json.MarshalIndent(summary, "", "  ")
			if err := os.WriteFile(filepath.Join(evidence, "cleanup-summary.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		t.Log("cleanup proof: three public artifacts/two organizations; live read blocked; exact DELETE lost response; real lease/retry deadlines;403/generic404 retain; typed NoSuchVersion clears once; siblings unchanged; zero PUTs")
	})
}
