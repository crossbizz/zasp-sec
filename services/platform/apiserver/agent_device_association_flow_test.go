package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const associationFlowAgentID = "pid_55555555-5555-4555-8555-555555555555"
const associationFlowDeviceID = "pid_44444444-4444-4444-8444-444444444444"
const associationFlowPairID = "pid_f3f29485-8121-4d74-80ac-797261970ce8"

func associationFlowIdentity(t *testing.T) RequestIdentity {
	i := fixtureRequestIdentity(t)
	o, e := domain.ParseProductID("pid_11111111-1111-4111-8111-111111111111")
	if e != nil {
		t.Fatal(e)
	}
	w, e := domain.ParseProductID("pid_22222222-2222-4222-8222-222222222222")
	if e != nil {
		t.Fatal(e)
	}
	v, e := domain.ParseProductID("pid_33333333-3333-4333-8333-333333333333")
	if e != nil {
		t.Fatal(e)
	}
	scope, e := domain.NewScope(o, w, v)
	if e != nil {
		t.Fatal(e)
	}
	i.Scope = scope
	i.FreshAuthExpiresAt = time.Date(2026, 10, 17, 12, 5, 0, 0, time.UTC)
	return i
}

// Closed new operations reuse the actual Agent target. The original owner ABI,
// updateAgent permission and PAT support must remain independent.
func TestAgentDeviceAssociationClosedOperationPermissionSurface(t *testing.T) {
	for _, op := range []string{"createAgentDeviceIntent", "activateAgentDeviceAssociation", "revokeAgentDeviceAssociation", "listAgentDeviceAssociations"} {
		t.Run(op, func(t *testing.T) {
			policy, e := authorization.LookupOperation(op)
			if e != nil {
				t.Fatal("actual closed association operation absent")
			}
			write := op != "listAgentDeviceAssociations"
			permission := "view"
			if write {
				permission = "manage_identity"
			}
			if policy.Permission != permission || policy.Relation != permission || policy.FreshAuth != write || write && !equalStrings(policy.Security, []string{"BrowserSession"}) {
				t.Fatal("association borrowed wrong permission/freshness/PAT policy")
			}
			target, e := authorizationTargetPolicy(op)
			if e != nil || target.Mode != "object" || target.Kind != "agent" || target.Parameter != "id" {
				t.Fatal("association borrowed environment/organization/collection target")
			}
			old, e := authorization.LookupOperation("updateAgent")
			if e != nil || old.Permission != "manage_workflows" || old.FreshAuth || !equalStrings(old.Security, []string{"BrowserSession", "ProductAPIToken"}) {
				t.Fatal("original ownership operation was widened or changed")
			}
		})
	}
}

type associationFlowAuthority struct {
	calls        []AgentDeviceAssociationMutation
	operation    string
	fail, replay bool
	response     json.RawMessage
}

func (a *associationFlowAuthority) MutateAssociation(_ context.Context, _ RequestIdentity, op string, in AgentDeviceAssociationMutation) (json.RawMessage, error) {
	a.calls = append(a.calls, in)
	a.operation = op
	if a.fail {
		return nil, ErrRepositoryUnavailable
	}
	return append(json.RawMessage(nil), a.response...), nil
}
func (a *associationFlowAuthority) ListAssociations(context.Context, RequestIdentity, string, string, int) (json.RawMessage, error) {
	return json.RawMessage(`{"items":[],"next_association_id":null}`), nil
}

// Mock repository responses are component boundaries, not Stytch, PostgreSQL,
// native Device possession or COMMIT proof. These grouped cases must reach the
// actual HTTP handler and never let nonce possession activate an association.
func TestAgentDeviceAssociationHumanFlowAndUnknownCommit(t *testing.T) {
	for _, mode := range []string{"fresh_intent", "historical_intent", "PAT_refused", "browser_not_fresh", "unknown_commit", "closed_body_refused", "revoke_whole_pair"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			op := "createAgentDeviceIntent"
			path := "/api/v1/agents/" + associationFlowAgentID + "/device-association-intents"
			params := map[string]string{"id": associationFlowAgentID}
			body := `{"device_id":"` + associationFlowDeviceID + `","expected_association_version":0,"ttl_seconds":300}`
			if mode == "closed_body_refused" {
				body = `{"device_id":"` + associationFlowDeviceID + `","expected_association_version":0,"ttl_seconds":300,"owner":"forbidden"}`
			}
			if mode == "revoke_whole_pair" {
				op = "revokeAgentDeviceAssociation"
				path = "/api/v1/agents/" + associationFlowAgentID + "/device-associations/" + associationFlowPairID + "/revoke"
				params["associationId"] = associationFlowPairID
				body = `{"expected_association_version":0}`
			}
			challengeID := `"pid_66666666-6666-4666-8666-666666666666"`
			if mode == "revoke_whole_pair" {
				challengeID = "null"
			}
			replay := mode == "historical_intent"
			recordedState := "intent_created"
			challenge := `{"schema":"agent-device-challenge-envelope-v1","challenge_wire":"eyJzY2hlbWEiOiJhZ2VudC1kZXZpY2UtaW50ZW50LXYxIiwiY2hhbGxlbmdlX2lkIjoicGlkXzY2NjY2NjY2LTY2NjYtNDY2Ni04NjY2LTY2NjY2NjY2NjY2NiIsImFzc29jaWF0aW9uX2lkIjoicGlkX2YzZjI5NDg1LTgxMjEtNGQ3NC04MGFjLTc5NzI2MTk3MGNlOCIsIm9yZ2FuaXphdGlvbl9pZCI6InBpZF8xMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEiLCJ3b3Jrc3BhY2VfaWQiOiJwaWRfMjIyMjIyMjItMjIyMi00MjIyLTgyMjItMjIyMjIyMjIyMjIyIiwiZW52aXJvbm1lbnRfaWQiOiJwaWRfMzMzMzMzMzMtMzMzMy00MzMzLTgzMzMtMzMzMzMzMzMzMzMzIiwiYWdlbnRfaWQiOiJwaWRfNTU1NTU1NTUtNTU1NS00NTU1LTg1NTUtNTU1NTU1NTU1NTU1IiwiYWdlbnRfc291cmNlX2RpZ2VzdCI6ImFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIiLCJkZXZpY2VfaWQiOiJwaWRfNDQ0NDQ0NDQtNDQ0NC00NDQ0LTg0NDQtNDQ0NDQ0NDQ0NDQ0IiwiZXhwZWN0ZWRfYXNzb2NpYXRpb25fdmVyc2lvbiI6MCwibm9uY2UiOiJBUUlEQkFVR0J3Z0pDZ3NNRFE0UEVCRVNFeFFWRmhjWUdSb2JIQjBlSHlBIiwiZXhwaXJlc19hdCI6IjIwMjYtMTAtMTdUMTI6MDU6MDBaIn0","challenge_sha256":"cb1633d5602b39af00efe5669100951e6431886515a905614bc02f5548ec150b"}`
			if mode == "revoke_whole_pair" {
				recordedState = "revoked"
				challenge = "null"
			}
			authority := &associationFlowAuthority{fail: mode == "unknown_commit", replay: replay}
			version := 0
			if mode == "revoke_whole_pair" {
				version = 1
			}
			authority.response = json.RawMessage(`{"receipt":{"operation":"` + op + `","association_id":"` + associationFlowPairID + `","challenge_id":` + challengeID + `,"version":` + map[int]string{0: "0", 1: "1"}[version] + `,"recorded_state":"` + recordedState + `","recorded_at":"2026-10-17T12:00:00Z"},"challenge":` + challenge + `,"replayed":` + map[bool]string{true: "true", false: "false"}[replay] + `,"new_mutation":` + map[bool]string{true: "false", false: "true"}[replay] + `}`)
			h, e := NewAgentDeviceAssociationHTTPHandler(authority, AgentDeviceAssociationHandlerConfig{NewProductID: func() (string, error) { return "pid_66666666-6666-4666-8666-666666666666", nil }, NewNonce: func() ([]byte, error) {
				nonce := make([]byte, 32)
				for n := range nonce {
					nonce[n] = byte(n + 1)
				}
				return nonce, nil
			}, Clock: func() time.Time { return now }, SigningKey: bytes.Repeat([]byte{3}, 32)})
			if e != nil {
				t.Fatal("actual association handler capability absent")
			}
			i := associationFlowIdentity(t)
			i.CredentialKind = CredentialBrowserSession
			i.FreshAuthenticated = true
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "association-human-idem-01")
			req.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
			if mode == "PAT_refused" {
				i.CredentialKind = CredentialBearerToken
				req.Header.Del("X-Zasp-Fresh-Auth")
			}
			if mode == "browser_not_fresh" {
				i.FreshAuthenticated = false
			}
			req = req.WithContext(context.WithValue(req.Context(), identityContextKey{}, i))
			req = req.WithContext(context.WithValue(req.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: op, PathParameters: params}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("association result lost no-store")
			}
			if mode == "fresh_intent" || mode == "historical_intent" || mode == "revoke_whole_pair" {
				want := 200
				if mode == "fresh_intent" {
					want = 201
				}
				var fields map[string]json.RawMessage
				if rec.Code != want || json.Unmarshal(rec.Body.Bytes(), &fields) != nil || len(fields) != 3 || fields["new_mutation"] != nil || fields["receipt"] == nil {
					t.Fatal("actual association handler lost closed fresh/replay/whole-revoke response")
				}
			} else if rec.Code < 400 {
				t.Fatal("unauthorized, malformed or unknown-commit association returned success")
			}
			if mode == "PAT_refused" || mode == "browser_not_fresh" || mode == "closed_body_refused" {
				if len(authority.calls) != 0 {
					t.Fatal("refused current human flow reached repository")
				}
			}
		})
	}
}
