package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTemporalFindingResponseHumanDecisionsPostgres(t *testing.T) {
	runFindingResponseFixture(t, func(ctx context.Context, f findingResponseFixture) {
		run := assertFindingHumanAdmission(t, ctx, f.owner, f.handler, f.identity, f.o, f.w, f.e, f.definition, f.actor, f.next)
		// Source-less requests must not synthesize a finding or automatic provenance.
		manual := workflowRequest(t, f.identity, testCorrelationID, "runSecurityAgent", map[string]string{"id": f.definition}, http.MethodPost, "/api/v1/security-agents/"+f.definition+"/runs", `{"environment_id":"`+f.e+`","trigger_kind":"manual"}`)
		manual.Header.Set("If-Match", `"4"`)
		manual.Header.Set("Idempotency-Key", "finding78-sourceless-human")
		rejected := httptest.NewRecorder()
		f.handler.ServeHTTP(rejected, manual)
		if rejected.Code != http.StatusBadRequest {
			t.Fatal("source-less finding status", rejected.Code)
		}
		call := func() *httptest.ResponseRecorder {
			req := workflowRequest(t, f.identity, testCorrelationID, "cancelSecurityAgentRun", map[string]string{"id": run}, http.MethodPost, "/api/v1/security-agent-runs/"+run+"/cancel", "")
			req.Header.Set("Idempotency-Key", "finding78-human-cancel")
			req.Header.Set("If-Match", `"1"`)
			res := httptest.NewRecorder()
			f.handler.ServeHTTP(res, req)
			return res
		}
		if _, err := f.api.Exec(ctx, `BEGIN`); err != nil {
			t.Fatal(err)
		}
		rolled := call()
		_, captureErr := f.api.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
		_, rollbackErr := f.api.Exec(ctx, `ROLLBACK`)
		if rolled.Code != http.StatusOK || captureErr != nil || rollbackErr != nil {
			t.Fatal("finding cancellation rollback fixture", rolled.Code, captureErr, rollbackErr)
		}
		var unchanged bool
		if err := f.owner.QueryRow(ctx, `SELECT state='queued' AND version=1 AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.control_intents WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_request_receipts WHERE operation='cancelSecurityAgentRun' AND resource_id=$1) FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("rollback persisted decision", unchanged, err)
		}
		response := call()
		if response.Code != http.StatusOK {
			t.Fatal("human finding cancellation status", response.Code)
		}
		var cancelled SecurityAgentRun
		if json.Unmarshal(response.Body.Bytes(), &cancelled) != nil || cancelled.ID != run || cancelled.State != "cancelled" || cancelled.Version != 2 {
			t.Fatal("finding cancellation projection")
		}
		replay := call()
		if replay.Code != http.StatusOK {
			t.Fatal("finding cancellation replay", replay.Code)
		}
		assertAutomaticRuleJSON(t, "finding cancellation exact replay", response.Body.Bytes(), replay.Body.Bytes())
		var proof bool
		if err := f.owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_temporal78.control_intents WHERE run_id=$1 AND kind='cancel' AND actor_id=$2`, run, f.actor).Scan(&proof); err != nil || !proof {
			t.Fatal("finding cancellation durable intent", proof, err)
		}
		assertFindingControlJournal(t, ctx, f, run)
	})
}

func assertFindingControlJournal(t *testing.T, ctx context.Context, f findingResponseFixture, run string) {
	t.Helper()
	var pending, start json.RawMessage
	if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal78.pending_controls()`).Scan(&pending); err != nil || string(pending) != "[]" {
		t.Fatal("decision delivered before accepted start", err)
	}
	if err := f.owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest) FROM zasp_temporal78.run_owners WHERE run_id=$1`, run).Scan(&start); err != nil {
		t.Fatal(err)
	}
	var ignored json.RawMessage
	if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal78.accept_start($1::jsonb)`, start).Scan(&ignored); err != nil {
		t.Fatal(err)
	}
	read := func(terminal bool) string {
		if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal78.pending_controls()`).Scan(&pending); err != nil {
			t.Fatal(err)
		}
		var items []struct {
			ID       string `json:"control_id"`
			Kind     string `json:"kind"`
			Terminal bool   `json:"terminal"`
			Start    struct {
				Ref struct {
					Run string `json:"run_id"`
				} `json:"ref"`
			} `json:"start"`
		}
		if json.Unmarshal(pending, &items) != nil || len(items) != 1 || items[0].ID == "" || items[0].Kind != "cancel" || items[0].Terminal != terminal || items[0].Start.Ref.Run != run {
			t.Fatal("finding decision projection")
		}
		return items[0].ID
	}
	id := read(false)
	if replay := read(false); replay != id {
		t.Fatal("notification retry changed identity")
	}
	if _, err := f.owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, f.actor); err != nil {
		t.Fatal(err)
	}
	if replay := read(false); replay != id {
		t.Fatal("initiator revoke blocked committed cancel delivery")
	}
	var ack map[string]any
	_ = json.Unmarshal(start, &ack)
	ack["control_id"] = id
	q, _ := json.Marshal(ack)
	wrong := map[string]any{}
	_ = json.Unmarshal(q, &wrong)
	wrong["definition_version"] = 5
	bad, _ := json.Marshal(wrong)
	if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal78.accept_control($1::jsonb)`, bad).Scan(&ignored); err == nil {
		t.Fatal("wrong control generation accepted")
	}
	if err := f.api.QueryRow(ctx, `SELECT zasp_temporal78.accept_control($1::jsonb)`, q).Scan(&ignored); err == nil {
		t.Fatal("API acknowledged executor control")
	}
	if _, err := f.executor.Exec(ctx, `BEGIN`); err != nil {
		t.Fatal(err)
	}
	err := f.executor.QueryRow(ctx, `SELECT zasp_temporal78.accept_control($1::jsonb)`, q).Scan(&ignored)
	_, rollbackErr := f.executor.Exec(ctx, `ROLLBACK`)
	if err != nil || rollbackErr != nil {
		t.Fatal("ACK rollback", err, rollbackErr)
	}
	if replay := read(false); replay != id {
		t.Fatal("rolled ACK consumed decision")
	}
	var first, second json.RawMessage
	if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal78.accept_control($1::jsonb)`, q).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal78.accept_control($1::jsonb)`, q).Scan(&second); err != nil {
		t.Fatal(err)
	}
	assertAutomaticRuleJSON(t, "control ACK exact replay", first, second)
	if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal78.pending_controls()`).Scan(&pending); err != nil || string(pending) != "[]" {
		t.Fatal("acknowledged finding control still pending", err)
	}
}
