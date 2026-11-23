package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

type advisoryTestModel struct {
	calls  atomic.Int32
	target string
}

func (m *advisoryTestModel) Evaluate(_ context.Context, p aigateway.Purpose, input json.RawMessage) (json.RawMessage, error) {
	m.calls.Add(1)
	out, _ := json.Marshal(map[string]any{"steps": []studioCandidate{{Action: "isolate_session", Target: m.target, Rollback: "ttl_release"}}})
	if p != aigateway.PurposeRemediate || !aigateway.ValidateRemediationProposal(input, out) {
		return nil, ErrRepositoryOperation
	}
	return out, nil
}

func exerciseStudioAdvisory(t *testing.T, b *installedBaseline, h *discoveryWorkflowSurface, admin installedPrincipal, cfg aigateway.BedrockBinding, thread analystThread, handoff studioHandoff) {
	t.Helper()
	session := thread.Session
	run, step, approval, definition := b.id(), b.id(), b.id(), b.id()
	plan, _ := json.Marshal(map[string]any{"steps": []map[string]any{{"action": "isolate_session", "target_id": session, "session_id": session, "scope": b.e, "step_id": step, "authorization": "approval_required", "ttl_seconds": 300}}})
	b.seed(func() {
		b.exec(`INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,$4,'supervised',1,1,'{}','security-agent-actions-v1')`, b.o, b.w, b.e, definition)
		b.exec(`INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,plan_hash) VALUES($1,$2,$3,$4,$5,1,$6,$7,'waiting_approval',digest(convert_to($8::jsonb::text,'UTF8'),'sha256'))`, b.o, b.w, b.e, run, definition, session, admin.identity.PrincipalID.String(), plan)
		b.exec(`INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id) VALUES($1,$2,$3,$4,$5,'runtime_decision',1,decode(repeat('bb',32),'hex'),$6)`, b.o, b.w, b.e, definition, session, run)
		b.exec(`INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at) VALUES($1,$2,$3,$4,$5,1,decode(repeat('bb',32),'hex'),'security-agent-actions-v1',$6,digest(convert_to($6::jsonb::text,'UTF8'),'sha256'),now()+interval '1 hour')`, b.o, b.w, b.e, run, definition, plan)
		b.exec(`INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state) VALUES($1,$2,$3,$4,$5,0,'isolate_session',digest(convert_to(($6::jsonb#>'{steps,0}')::text,'UTF8'),'sha256'),'approval_required','waiting_approval')`, b.o, b.w, b.e, run, step, plan)
		b.exec(`INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,digest(convert_to($8::jsonb::text,'UTF8'),'sha256'),'pending',$7,now()+interval '1 hour')`, b.o, b.w, b.e, approval, run, step, admin.identity.PrincipalID.String(), plan)
	})
	cfg.Cost = 5
	cfg.DeploymentDigest = "sha256:" + strings.Repeat("d", 64)
	model := &advisoryTestModel{target: session}
	h.advisory = &analystChat{driver: model, binding: cfg}
	call := func(method string, code int, expected string) {
		t.Helper()
		path := "/api/v1/security-agents/chat/threads/" + thread.ID + "/advisory?session_id=" + session + "&approval_id=" + approval + "&message_id=" + handoff.MessageID
		op, body := "getStudioRemediationAdvisory", ""
		if method == "POST" {
			op, body = "requestStudioRemediationAdvisory", "{}"
		}
		out := b.serve(h, admin, op, method, path, map[string]string{"id": thread.ID}, body, nil)
		var v advisoryRecord
		if out.Code != code || code < 300 && (json.Unmarshal(out.Body.Bytes(), &v) != nil || v.State != expected || v.Lease != "" || v.Input != nil || v.Message != handoff.MessageID || v.Session != session || v.Approval != approval || (expected == "reviewed") != (v.Candidate != nil)) {
			t.Fatalf("advisory %s want %d/%s: %d %s", method, code, expected, out.Code, out.Body)
		}
	}
	call("GET", 200, "unavailable")
	b.seed(func() {
		b.exec(`INSERT INTO model_qualifications(organization_id,workspace_id,environment_id,provider,model,purpose,qualified,deployment_digest,evidence_digest,expires_at) VALUES($1,$2,$3,'privatelink_bedrock',$4,'security_agent_remediate',true,$5,$5,now()+interval '1 hour')`, b.o, b.w, b.e, cfg.Model, cfg.DeploymentDigest)
	})
	call("GET", 200, "available")
	call("POST", 202, "pending")
	deadline := time.Now().Add(20 * time.Second)
	for len(studioAdvisorySlots) > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	call("GET", 200, "reviewed")
	call("POST", 200, "reviewed")
	if model.calls.Load() != 1 || b.text(`SELECT state FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,approval_id)=($1,$2,$3,$4)`, b.o, b.w, b.e, approval) != "pending" {
		t.Fatal("advisory changed the approval or dispatched twice")
	}
	b.seed(func() {
		b.exec(`UPDATE public.zasp_security_agent_approvals SET expires_at=now()-interval '1 second' WHERE approval_id=$1`, approval)
	})
	call("GET", 404, "")
}
