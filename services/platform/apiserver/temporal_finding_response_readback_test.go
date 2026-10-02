package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func assertFindingPublicMetadata(t *testing.T, handler http.Handler, identity RequestIdentity, run, finding, assignee string, applied bool) {
	t.Helper()
	r := workflowRequest(t, identity, testCorrelationID, "getSecurityAgentRun", map[string]string{"id": run}, http.MethodGet, "/api/v1/security-agent-runs/"+run, "")
	r.Header.Set("X-Zasp-Action-Details", "v1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("finding public read status=%d applied=%t", w.Code, applied)
		return
	}
	var value SecurityAgentRunDetail
	if json.Unmarshal(w.Body.Bytes(), &value) != nil || value.Run.ID != run || len(value.ActionDetails) != 1 {
		t.Error("finding public read identity")
		return
	}
	a := value.ActionDetails[0]
	if a.Arguments == nil || a.Arguments.TargetID != finding || a.Arguments.ExpectedVersion != 1 || a.Arguments.AssigneeID != assignee || a.Arguments.ResponseStatus != "investigating" || a.Arguments.TargetStatus != "under_review" || a.Arguments.Note != "Investigate the credential exposure" || a.ExistingTest != nil {
		t.Errorf("finding public planned metadata absent/mismatched applied=%t", applied)
	}
	if applied {
		if value.Run.State != "remediated" || a.Result == nil || a.Result.State != "verified" || a.Verification.State != "verified" {
			t.Error("finding public verified effect absent")
		}
	} else if value.Run.State != "queued" || a.Result != nil || a.Verification.State != "unavailable" {
		t.Error("planned finding metadata asserted an applied effect")
	}
}
