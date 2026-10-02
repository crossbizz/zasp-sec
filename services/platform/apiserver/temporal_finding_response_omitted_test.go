package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func TestTemporalFindingResponseOmittedRulesPostgres(t *testing.T) {
	runFindingResponseFixture(t, func(ctx context.Context, f findingResponseFixture) {
		var body map[string]any
		var raw json.RawMessage
		if err := f.owner.QueryRow(ctx, `SELECT body-'id'-'trigger_rules' FROM zasp_security_agent_definitions WHERE definition_id=$1`, f.definition).Scan(&raw); err != nil || json.Unmarshal(raw, &body) != nil {
			t.Fatal("omitted finding body", err)
		}
		body["enabled"], body["autonomy"] = false, "supervised"
		raw, _ = json.Marshal(body)
		r := workflowRequest(t, f.identity, testCorrelationID, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", string(raw))
		r.Header.Set("Idempotency-Key", "finding78-omitted-create")
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		var created map[string]json.RawMessage
		var definition string
		if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &created) != nil || json.Unmarshal(created["id"], &definition) != nil || created["trigger_rules"] != nil {
			t.Fatal("omitted public finding create", w.Code)
		}
		for i, target := range []string{"validated", "supervised", "autonomous"} {
			_, err := f.repository.ActivateSecurityAgent(ctx, f.identity, SecurityAgentActivation{DefinitionID: definition, ExpectedVersion: int64(i + 1), TargetActivation: target, FreshAuthExpiresAt: f.identity.FreshAuthExpiresAt, IdempotencyKey: "finding78-omitted-" + target, AuditID: f.next(), CorrelationID: f.next(), ReceiptID: f.next()})
			if err != nil {
				t.Fatal("omitted activation", target, err)
			}
		}
		ref := map[string]any{"organization_id": f.o, "workspace_id": f.w, "environment_id": f.e, "definition_id": definition}
		encoded, _ := json.Marshal(ref)
		var desired orchestration.TestSelectorDesired
		if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal77.desired($1::jsonb)`, encoded).Scan(&raw); err != nil || json.Unmarshal(raw, &desired) != nil || !desired.Enabled || !desired.Automatic {
			t.Fatal("omitted finding must select native catch-up", desired.Enabled, desired.Automatic, err)
		}
		finding := f.next()
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_risk_findings SET status='under_review';INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Omitted low severity source','low','open')`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e, finding); err != nil {
			t.Fatal(err)
		}
		var event string
		if err := f.owner.QueryRow(ctx, `SELECT event_id FROM zasp_temporal77.source_events WHERE(organization_id,workspace_id,environment_id,source_id,source_version)=($1,$2,$3,$4,1)`, f.o, f.w, f.e, finding).Scan(&event); err != nil {
			t.Fatal(err)
		}
		page, _ := json.Marshal(map[string]any{"organization_id": f.o, "workspace_id": f.w, "environment_id": f.e, "event_id": event, "after": ""})
		if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal77.dispatch_page($1::jsonb)`, page).Scan(&raw); err != nil {
			t.Fatal("omitted event delivery", err)
		}
		var proof bool
		if err := f.owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(x.trigger_id=$2 AND x.trigger_version=1 AND x.source_kind='automatic77') FROM zasp_temporal78.run_owners x WHERE x.definition_id=$1`, definition, finding).Scan(&proof); err != nil || !proof {
			t.Fatal("omitted finding event admission", proof, err)
		}
		after, visited, complete := "", 0, false
		for i := 0; i < 20; i++ {
			catchup, _ := json.Marshal(map[string]any{"ref": ref, "revision": 1, "after": after})
			if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal77.catchup_definition($1::jsonb)`, catchup).Scan(&raw); err != nil {
				t.Fatal("omitted catch-up replay", err)
			}
			var result orchestration.AutomaticPage
			if json.Unmarshal(raw, &result) != nil || !result.Valid(after) || result.Retry || result.Admitted != 0 {
				t.Fatal("omitted catch-up duplicated admission or lost progress", string(raw))
			}
			after, visited = result.After, visited+result.Scanned
			if !result.More {
				complete = true
				break
			}
		}
		if !complete || visited < 1 {
			t.Fatal("omitted catch-up did not complete current-source traversal", complete, visited)
		}
		if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal77.dispatch_page($1::jsonb)`, page).Scan(&raw); err != nil {
			t.Fatal("omitted event replay", err)
		}
		if err := f.owner.QueryRow(ctx, `SELECT NOT d.body?'trigger_rules' AND NOT h.definition?'trigger_rules' AND (SELECT count(*)=1 FROM zasp_temporal78.run_owners WHERE definition_id=$1) AND (SELECT count(*)=1 FROM zasp_temporal77.occurrences WHERE definition_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal77.cooldowns WHERE definition_id=$1) FROM zasp_security_agent_definitions d JOIN zasp_security_agent_definition_versions h ON(h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version) WHERE d.definition_id=$1`, definition).Scan(&proof); err != nil || !proof {
			t.Fatal("omitted intent or occurrence rewritten", proof, err)
		}
	})
}
