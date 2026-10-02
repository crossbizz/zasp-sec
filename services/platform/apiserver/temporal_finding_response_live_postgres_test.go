package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Borrows the separately verified pinned server, owns its namespace/database
// and child process. HTTP identities/provider/storage/FGA are controlled inputs.
func TestTemporalFindingResponseNativePostgres(t *testing.T) {
	runFindingResponseNative(t, "")
}

func TestTemporalFindingResponseNativeApprovalPostgres(t *testing.T) {
	runFindingResponseNative(t, "approved")
}
func TestTemporalFindingResponseNativeCancelPostgres(t *testing.T) {
	runFindingResponseNative(t, "cancelled")
}

func runFindingResponseNative(t *testing.T, decision string) {
	runFindingResponseNativeOrigin(t, decision, false, "")
}

func runFindingResponseNativeOrigin(t *testing.T, decision string, human bool, workerBinary string) {
	runFindingResponseFixtureOptions(t, func(ctx context.Context, f findingResponseFixture) {
		cfg := f.owner.Config().Copy()
		cfg.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(context.Background())
		policy := orderedPricingAdminRequest(f.o, f.w, f.e, f.actor)
		bindTemporalTestPlannerPricing(policy)
		pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
		if err != nil {
			t.Fatal(err)
		}
		selection := orderedPricingLookupRequest(f.o, f.w, f.e, policy["policy"].(map[string]any), pricing)
		binding := map[string]any{}
		for _, key := range []string{"organization_id", "workspace_id", "environment_id", "account_profile", "credential_reference", "policy_id", "policy_version", "policy_digest", "account_id", "account_version"} {
			binding[key] = selection[key]
		}
		encoded, _ := json.Marshal(binding)
		finding := f.next()
		severity := "high"
		decisionIdentity := f.identity
		if human {
			// The source remains captured, but is below the configured automatic
			// threshold. Only an actual human request can admit this run.
			severity = "low"
			decisionIdentity = findingNativeDistinctApprover(t, ctx, f)
		}
		// Existing source rows and unrelated definitions are fixture prerequisites.
		// Only the selected finding definition may run in this owned namespace.
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','false') WHERE definition_id<>$1;UPDATE zasp_risk_findings SET severity='low';INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($2,$3,$4,$5,'posture','credential','Native finding prerequisite',$7,'under_review');INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES($2,$3,$4,$5,1,$6)`, pgx.QueryExecModeSimpleProtocol, f.definition, f.o, f.w, f.e, finding, f.next(), severity); err != nil {
			t.Fatal(err)
		}
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: admin})
		if err != nil {
			t.Fatal(err)
		}
		risk, err := newRiskHTTPHandler(&PostgresRepository{database: db}, securityAgentTestSigningKey, time.Now, &findingTicketCreatorStub{})
		if err != nil {
			t.Fatal(err)
		}
		request := workflowRequest(t, f.identity, testCorrelationID, "updateFinding", map[string]string{"id": finding}, http.MethodPatch, "/api/v1/findings/"+finding, `{"status":"open"}`)
		request.Header.Set("If-Match", `"1"`)
		request.Header.Set("Idempotency-Key", "finding78-native-source-open")
		response := httptest.NewRecorder()
		risk.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatal("actual finding HTTP source", response.Code)
		}
		var event, parent string
		version := 4
		if decision != "" {
			version = 3
		}
		if human {
			parent = findingNativeHumanAdmission(t, ctx, f, finding)
		} else if err := f.owner.QueryRow(ctx, `SELECT event_id,zasp_discovery_canonical_id($1,$2,$3,'security_agent_run',concat_ws(chr(31),$4::text,$6::int,'finding',$5::text,2)) FROM zasp_temporal77.source_events WHERE(organization_id,workspace_id,environment_id,source_kind,source_id,source_version)=($1,$2,$3,'finding',$5,2)`, f.o, f.w, f.e, f.definition, finding, version).Scan(&event, &parent); err != nil {
			t.Fatal(err)
		}
		namespace := fmt.Sprintf("finding-response78-%d", time.Now().UnixNano())
		nc, err := client.NewNamespaceClient(client.Options{HostPort: "127.0.0.1:7233"})
		if err != nil {
			t.Fatal(err)
		}
		err = nc.Register(ctx, &workflowservice.RegisterNamespaceRequest{Namespace: namespace, WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour)})
		nc.Close()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, "go", "test", "./agentsec-worker", "-run", "^TestFindingResponseNativeWorker$", "-count=1", "-v")
		if human {
			if workerBinary == "" {
				t.Fatal("human fixture requires prebuilt owned worker")
			}
			command = exec.CommandContext(ctx, workerBinary, "-test.run=^TestFindingResponseNativeWorker$", "-test.count=1", "-test.v")
		}
		command.Dir = ".."
		command.WaitDelay = 5 * time.Second
		command.Env = append(os.Environ(), "ZASP_FINDING78_OWNER_DSN="+f.owner.Config().ConnString(), "ZASP_FINDING78_BINDING="+string(encoded), "ZASP_FINDING78_NAMESPACE="+namespace, "ZASP_FINDING78_ADDRESS=127.0.0.1:7233", "ZASP_FINDING78_RUN="+parent, "ZASP_FINDING78_FINDING="+finding, "ZASP_FINDING78_DEFINITION="+f.definition, "ZASP_FINDING78_EVENT="+event, "ZASP_FINDING78_ACTOR="+f.actor)
		command.Env = append(command.Env, "ZASP_FINDING78_DECISION="+decision)
		if human {
			command.Env = append(command.Env, "ZASP_FINDING78_HUMAN=true")
		}
		var buffer bytes.Buffer
		command.Stdout = &buffer
		command.Stderr = &buffer
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		joined := false
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		defer func() {
			if !joined {
				_ = command.Process.Kill()
				<-done
				t.Log("joined owned finding child after fixture failure", buffer.String())
			}
		}()
		if decision != "" {
			var approval string
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for approval == "" {
				if err := f.owner.QueryRow(ctx, `SELECT COALESCE((SELECT ap.approval_id FROM zasp_security_agent_approvals ap JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE ap.run_id=$1 AND ap.state='pending' AND r.state='waiting_approval'),'')`, parent).Scan(&approval); err != nil {
					t.Fatal(err)
				}
				if approval != "" {
					break
				}
				select {
				case err := <-done:
					joined = true
					t.Log(buffer.String())
					t.Fatal("owned worker ended before approval", err)
				case <-ctx.Done():
					t.Fatal("native approval deadline")
				case <-ticker.C:
				}
			}
			read := workflowRequest(t, decisionIdentity, testCorrelationID, "getSecurityAgentApproval", map[string]string{"id": approval}, http.MethodGet, "/api/v1/security-agent-approvals/"+approval, "")
			res := httptest.NewRecorder()
			f.handler.ServeHTTP(res, read)
			var proposal SecurityAgentApproval
			if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &proposal) != nil || !requiredFindingApprovalContext(proposal) || proposal.Context.FindingResponse.TargetID != finding || proposal.Context.FindingResponse.AssigneeID != f.actor || proposal.Context.FindingResponse.ExpectedVersion != 2 {
				t.Fatal("native concrete approval", res.Code)
			}
			if human && (proposal.Context.FindingResponse.TargetStatus != "under_review" || proposal.Context.FindingResponse.ResponseStatus != "investigating" || proposal.Context.FindingResponse.Note != "Investigate the credential exposure") {
				t.Fatal("human approver did not receive the exact proposed changes")
			}
			if human {
				var unapplied bool
				if err := f.owner.QueryRow(ctx, `SELECT status='open' AND version=2 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$2) AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE run_id=$2) FROM zasp_risk_findings WHERE id=$1`, finding, parent).Scan(&unapplied); err != nil || !unapplied {
					t.Fatal("human finding changed before distinct approval", unapplied, err)
				}
			}
			op, id, path, body, expected := "decideSecurityAgentApproval", approval, "/api/v1/security-agent-approvals/"+approval+"/decision", `{"decision":"approved"}`, `"1"`
			if decision == "cancelled" {
				op, id, path, body, expected = "cancelSecurityAgentRun", parent, "/api/v1/security-agent-runs/"+parent+"/cancel", "", `"3"`
			}
			req := workflowRequest(t, decisionIdentity, testCorrelationID, op, map[string]string{"id": id}, http.MethodPost, path, body)
			req.Header.Set("If-Match", expected)
			req.Header.Set("Idempotency-Key", "finding78-native-"+decision)
			req.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
			res = httptest.NewRecorder()
			f.handler.ServeHTTP(res, req)
			if res.Code != 200 {
				t.Fatal("native finding decision", decision, res.Code)
			}
			if human {
				replay := workflowRequest(t, decisionIdentity, testCorrelationID, op, map[string]string{"id": id}, http.MethodPost, path, body)
				replay.Header.Set("If-Match", expected)
				replay.Header.Set("Idempotency-Key", "finding78-native-"+decision)
				replay.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
				replayed := httptest.NewRecorder()
				f.handler.ServeHTTP(replayed, replay)
				if replayed.Code != 200 {
					t.Fatal("human distinct approval replay", replayed.Code)
				}
				assertAutomaticRuleJSON(t, "human approval exact response replay", res.Body.Bytes(), replayed.Body.Bytes())
			}
		}
		err = <-done
		joined = true
		output := buffer.Bytes()
		t.Log(string(output))
		if err != nil || !strings.Contains(string(output), "--- PASS: TestFindingResponseNativeWorker") || strings.Contains(string(output), "--- SKIP:") {
			t.Fatal("owned finding worker", err)
		}
		read := workflowRequest(t, f.identity, testCorrelationID, "getSecurityAgentRun", map[string]string{"id": parent}, http.MethodGet, "/api/v1/security-agent-runs/"+parent, "")
		read.Header.Set("X-Zasp-Action-Details", "v1")
		result := httptest.NewRecorder()
		f.handler.ServeHTTP(result, read)
		if result.Code != http.StatusOK {
			t.Fatal("native finding public readback", result.Code)
		}
		var detail SecurityAgentRunDetail
		wantState := "remediated"
		if decision == "cancelled" {
			wantState = "cancelled"
		}
		if json.Unmarshal(result.Body.Bytes(), &detail) != nil || detail.Run.ID != parent || detail.Run.State != wantState || len(detail.ActionDetails) != 1 {
			t.Fatal("native finding public result identity")
		}
		a := detail.ActionDetails[0]
		if decision == "cancelled" {
			var untouched bool
			if a.Result != nil || f.owner.QueryRow(ctx, `SELECT status='open' AND version=2 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$2) AND EXISTS(SELECT 1 FROM zasp_temporal78.control_deliveries d JOIN zasp_temporal78.control_intents c USING(organization_id,workspace_id,environment_id,control_id) WHERE c.run_id=$2 AND c.kind='cancel' AND d.accepted_at IS NOT NULL) AND EXISTS(SELECT 1 FROM zasp_temporal78.stops WHERE run_id=$2) FROM zasp_risk_findings WHERE id=$1`, finding, parent).Scan(&untouched) != nil || !untouched {
				t.Fatal("native cancellation applied finding or lost cleanup/control proof")
			}
			return
		}
		if a.Action != "update_finding_response" || a.Arguments == nil || a.Arguments.TargetID != finding || a.Arguments.ExpectedVersion != 2 || a.Arguments.AssigneeID != f.actor || a.Arguments.ResponseStatus != "investigating" || a.Arguments.TargetStatus != "under_review" || a.Arguments.Note != "Investigate the credential exposure" || a.Result == nil || a.Result.State != "verified" || a.Verification.State != "verified" || a.ExistingTest != nil {
			t.Fatal("native finding public metadata/effect projection")
		}
		if human {
			assertFindingNativeHumanProof(t, ctx, f, parent, finding, decisionIdentity.PrincipalID.String())
			return
		}
		var proof bool
		if err := f.owner.QueryRow(ctx, `SELECT f.status='under_review' AND f.version=3 AND m.expected_version=2 AND m.result_version=3 AND m.assignee_id=$3 AND m.note='Investigate the credential exposure' AND r.state='remediated' AND x.source_kind='automatic77' AND r.requested_by=public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_definition_service',x.definition_id) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.run_owners WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_security_agent_effects WHERE run_id=$1) FROM zasp_temporal78.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal78.response_metadata m USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_risk_findings f ON(f.organization_id,f.workspace_id,f.environment_id,f.id)=(x.organization_id,x.workspace_id,x.environment_id,x.trigger_id) WHERE x.run_id=$1 AND f.id=$2`, parent, finding, f.actor).Scan(&proof); err != nil || !proof {
			t.Fatal("native finding committed proof", proof, err)
		}
	}, nil, decision != "")
}
