package redteamadapter

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The same five negatives as the owned native route run, without a database
// fixture. Each must stop before resolver, journal, credential or target use.
func TestWorkerReceiptRouteRefusalStatusBeforeIO(t *testing.T) {
	h, calls, resolver := linkedHandlerFixture(t, &journalFixture{}, `{"output":"unused"}`)
	h.completedReader = &TemporalPostgresJournal{}
	q := CompletedReceiptRequest{OrganizationID: testOrganizationID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID, ParentRunID: "pid_7d000006-0000-4000-8000-000000000006", TestRunID: testRunID, StepID: "pid_7d000007-0000-4000-8000-000000000007", EffectKey: "5f54181176138a00efc787d94a0b807f276eb07c0000d3c40bd9d20a61219ef0", Generation: 1, Category: "prompt_injection", InputDigest: strings.Repeat("a", 64), RequestDigest: strings.Repeat("b", 64)}
	raw, _ := json.Marshal(q)
	for _, mode := range []string{"auth", "header", "duplicate", "extra", "null"} {
		body := bytes.Clone(raw)
		switch mode {
		case "duplicate":
			body = append([]byte(`{"generation":1,`), raw[1:]...)
		case "extra":
			body = append([]byte(`{"context":{},`), raw[1:]...)
		case "null":
			body = bytes.Replace(body, []byte(`"generation":1`), []byte(`"generation":null`), 1)
		}
		r := adapterRequest(t, testWorkerToken, string(body))
		r.URL.Path = "/v1/effects/completed-receipt"
		r.Header.Set("X-Zasp-Effect-Key", q.EffectKey)
		want := http.StatusBadRequest
		if mode == "auth" {
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("b", 64))
			want = http.StatusForbidden
		}
		if mode == "header" {
			r.Header.Set("X-Zasp-Effect-Key", strings.Repeat("0", 64))
		}
		res := httptest.NewRecorder()
		h.ServeHTTP(res, r)
		if res.Code != want {
			t.Fatal("retained route refusal changed", mode, res.Code, want)
		}
		if calls.Load() != 0 || resolver.calls != 0 {
			t.Fatal("refusal attempted forward IO", mode)
		}
	}
}
