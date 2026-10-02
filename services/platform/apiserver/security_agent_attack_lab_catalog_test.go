package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type attackLabCatalogRepository struct {
	*workflowRepositoryStub
	ready bool
	err   error
}

func (r *attackLabCatalogRepository) SecurityAgentAttackLabWorkflowAvailable(context.Context) (bool, error) {
	return r.ready, r.err
}

func TestSecurityAgentAttackLabCatalogRequiresConnectedReadiness(t *testing.T) {
	r := &attackLabCatalogRepository{workflowRepositoryStub: &workflowRepositoryStub{}}
	h, err := newWorkflowHTTPHandler(r, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, ready := range []bool{false, true, false} {
		r.ready = ready
		for _, op := range []string{"listSecurityActions", "listSecurityAgentTemplates"} {
			response := httptest.NewRecorder()
			h.ServeHTTP(response, workflowRequest(t, fixtureRequestIdentity(t), testCorrelationID, op, nil, http.MethodGet, "/api/v1/security-actions", ""))
			if response.Code != 200 || strings.Contains(response.Body.String(), "start_attack_lab") != ready {
				t.Fatalf("runtime ready=%v op=%s response=%d %s", ready, op, response.Code, response.Body.String())
			}
			if ready && (!strings.Contains(response.Body.String(), "attack_lab_run") || op == "listSecurityActions" && !strings.Contains(response.Body.String(), `"approval_floor":"operator"`)) {
				t.Fatal("catalog lost mandatory verification or approval")
			}
			if ready && op == "listSecurityActions" {
				var page struct {
					Items []struct {
						Key        string `json:"key"`
						Reversible bool   `json:"reversible"`
						Approval   string `json:"approval_floor"`
					} `json:"items"`
				}
				if json.Unmarshal(response.Body.Bytes(), &page) != nil {
					t.Fatal("invalid action catalog")
				}
				for _, item := range page.Items {
					if item.Key == "start_attack_lab" && (item.Reversible || item.Approval != "operator") {
						t.Fatal("bounded reproduction cannot be undone; operator floor still required")
					}
				}
			}
			if op == "listSecurityAgentTemplates" {
				var page struct {
					Items []struct {
						ID string `json:"id"`
					} `json:"items"`
				}
				if json.Unmarshal(response.Body.Bytes(), &page) != nil {
					t.Fatal("invalid catalog JSON")
				}
				seen := map[string]bool{}
				for _, item := range page.Items {
					if !validProductID(item.ID) || seen[item.ID] {
						t.Fatalf("catalog supplied invalid product ID: %s", item.ID)
					}
					seen[item.ID] = true
				}
			}
		}
	}
	r.err = errors.New("corrupt57")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, workflowRequest(t, fixtureRequestIdentity(t), testCorrelationID, "listSecurityActions", nil, http.MethodGet, "/api/v1/security-actions", ""))
	if response.Code != 503 {
		t.Fatalf("corrupt capability did not fail closed: %d", response.Code)
	}
}

func TestSecurityAgentTemplateIdentifiersPreserveExistingBoundary(t *testing.T) {
	for index, expected := range []string{"pid_70000001-0000-4000-8000-000000000001", "pid_70000002-0000-4000-8000-000000000002", "pid_70000003-0000-4000-8000-000000000003", "pid_70000004-0000-4000-8000-000000000004", "pid_70000005-0000-4000-8000-000000000005", "pid_70000006-0000-4000-8000-000000000006", "pid_70000007-0000-4000-8000-000000000007", "pid_70000008-0000-4000-8000-000000000008", "pid_70000009-0000-4000-8000-000000000009", "pid_70000010-0000-4000-8000-000000000010"} {
		if got := deterministicProductID(index + 1); got != expected {
			t.Fatalf("template%d id=%s", index+1, got)
		}
	}
}
