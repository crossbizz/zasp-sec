package apiserver

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Missing operation admission leaves an otherwise valid operator request
// unreachable. This exercises the shipped registry, not a test registry.
func TestSingleTestRecoveryHTTPContracts(t *testing.T) {
	for _, id := range []string{"requestSingleTestCleanupRecovery", "getSingleTestCleanupRecovery"} {
		if _, err := authorization.LookupOperation(id); err != nil {
			t.Errorf("scoped recovery operation unavailable: %s: %v", id, err)
		}
		found := false
		for _, op := range coreOperations {
			if op.OperationID == id {
				found = true
			}
		}
		if !found {
			t.Errorf("recovery route not composed: %s", id)
		}
	}
	id := orderedPublicIdentity()
	run := public62Finding
	digest := strings.Repeat("a", 64)
	calls := 0
	for _, mode := range []string{"queued", "replay", "extra", "duplicate", "query", "stop_false", "missing_header", "get"} {
		t.Run(mode, func(t *testing.T) {
			calls = 0
			db := &orderedPublicDB{query: func(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
				calls++
				q := singleTestRecoveryWire{}
				if sql == singleTestRecoveryGetSQL {
					return json.Marshal(SingleTestRecoveryView{RunID: run, RequestIdentity: SingleTestRecoveryRequestIdentity{2, digest}, Status: "not_requested", Reason: "not_requested", ParentVersion: 3})
				}
				if sql == singleTestRecoveryPreflightSQL {
					if recoveryDecode(args[0].(json.RawMessage), 4096, &q) != nil {
						t.Fatal("bad preflight")
					}
				} else {
					var a singleTestRecoveryAdmission
					if recoveryDecode(args[0].(json.RawMessage), 8192, &a) != nil {
						t.Fatal("bad admission")
					}
					q = a.singleTestRecoveryWire
				}
				cid, _ := CanonicalDiscoveryID(id.Scope, "single_test_cleanup_recovery", run)
				stamp := time.Now().UTC().Format(time.RFC3339Nano)
				result := SingleTestRecoveryMutationResult{Body: SingleTestRecoveryView{RunID: run, RequestIdentity: SingleTestRecoveryRequestIdentity{2, digest}, Status: "queued", Reason: "queued", ParentVersion: 4, Command: &orchestration.SingleTestRecoveryRef{Start: q.start(), CommandID: cid, CommandDigest: strings.Repeat("b", 64)}, AcceptedAt: &stamp}, AuditID: q.AuditID, CorrelationID: q.CorrelationID, ReceiptID: q.ReceiptID, Replayed: mode == "replay"}
				if sql == singleTestRecoveryPreflightSQL {
					wid, _ := orchestration.SingleTestWorkflowID(q.start().Ref)
					p := singleTestRecoveryPreflight{Start: q.start(), RunVersion: 3, WorkflowID: wid}
					if mode == "replay" {
						p.Replay = &result
					}
					return json.Marshal(p)
				}
				return json.Marshal(result)
			}}
			repo, _ := NewSingleTestRecoveryRepository(db, recoveryObserverFunc(func(_ context.Context, q orchestration.StartRequest) (orchestration.SingleTestOriginalObservation, error) {
				wid, _ := orchestration.SingleTestWorkflowID(q.Ref)
				return orchestration.SingleTestOriginalObservation{WorkflowID: wid, Status: "absent", ObservedAt: time.Now().UTC()}, nil
			}))
			h, _ := NewSingleTestRecoveryHTTPHandler(repo)
			surface, _ := NewSingleTestRecoveryWorkflowSurface(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("fell through") }), h)
			body := `{"definition_version":2,"input_digest":"` + digest + `","diagnostic":"history_unavailable","stop_original":true}`
			switch mode {
			case "extra":
				body = strings.TrimSuffix(body, "}") + `,"observation":{}}`
			case "duplicate":
				body = strings.Replace(body, `"definition_version":2`, `"definition_version":2,"definition_version":2`, 1)
			case "stop_false":
				body = strings.Replace(body, "true", "false", 1)
			}
			method, op := http.MethodPost, "requestSingleTestCleanupRecovery"
			if mode == "get" {
				method, op, body = http.MethodGet, "getSingleTestCleanupRecovery", ""
			}
			url := "/api/v1/security-agent-runs/" + run + "/cleanup-recovery"
			if mode == "query" {
				url += "?x=1"
			}
			r := workflowRequest(t, id, testCorrelationID, op, map[string]string{"id": run}, method, url, body)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("If-Match", `"3"`)
			r.Header.Set("Idempotency-Key", "single-recovery-http-0001")
			if mode == "missing_header" {
				r.Header.Del("If-Match")
			}
			response := httptest.NewRecorder()
			surface.ServeHTTP(response, r)
			want := http.StatusBadRequest
			if mode == "queued" {
				want = http.StatusAccepted
			}
			if mode == "replay" || mode == "get" {
				want = http.StatusOK
			}
			if response.Code != want || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("HTTP", response.Code, want, response.Body.String())
			}
			if want == http.StatusBadRequest && calls != 0 {
				t.Fatal("malformed HTTP reached SQL")
			}
		})
	}
}
