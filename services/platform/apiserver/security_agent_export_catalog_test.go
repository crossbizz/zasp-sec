package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type exportCatalogRepository struct {
	*workflowRepositoryStub
	ready bool
	err   error
}

func (r *exportCatalogRepository) SecurityAgentExportsWorkflowAvailable(context.Context) (bool, error) {
	return r.ready, r.err
}

// Catch advertising export without its connected workflow capability, retaining
// a stale positive after withdrawal, or losing the action's read-only target.
func TestSecurityAgentExportCatalogRequiresConnectedReadiness(t *testing.T) {
	r := &exportCatalogRepository{workflowRepositoryStub: &workflowRepositoryStub{}}
	h, err := newWorkflowHTTPHandler(r, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	read := func() *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		h.ServeHTTP(response, workflowRequest(t, fixtureRequestIdentity(t), testCorrelationID, "listSecurityActions", nil, http.MethodGet, "/api/v1/security-actions", ""))
		return response
	}
	for _, ready := range []bool{false, true, false} {
		r.ready = ready
		response := read()
		var page struct {
			Items []struct {
				Key          string   `json:"key"`
				Targets      []string `json:"target_types"`
				Verification string   `json:"verification_kind"`
				Reversible   bool     `json:"reversible"`
			} `json:"items"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil {
			t.Fatalf("catalog: %d %s", response.Code, response.Body.String())
		}
		found := 0
		for _, item := range page.Items {
			if item.Key != "create_evidence_export" {
				continue
			}
			found++
			if item.Verification != "export" || !item.Reversible || len(item.Targets) != 1 || item.Targets[0] != "evidence" {
				t.Fatalf("export contract changed: %#v", item)
			}
		}
		if (found == 1) != ready || found > 1 {
			t.Fatalf("ready=%v exports=%d", ready, found)
		}
	}
	r.err = errors.New("installed workflow drift")
	if response := read(); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("drift catalog=%d", response.Code)
	}
}
