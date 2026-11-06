package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Controlled application repository boundary. These tests do not authenticate
// Stytch, execute SQL/COMMIT or establish provider/native acceptance.
type gatewayBootstrapFlowAuthority struct {
	inputs       []GatewayBootstrapMutation
	replay, fail bool
	now          time.Time
}

func (a *gatewayBootstrapFlowAuthority) MutateGateway(_ context.Context, _ RequestIdentity, operation string, input GatewayBootstrapMutation) (GatewayBootstrapMutationResult, error) {
	a.inputs = append(a.inputs, input)
	if a.fail {
		return GatewayBootstrapMutationResult{}, ErrRepositoryUnavailable
	}
	device := GatewayDeviceRecord{ID: input.DeviceID, Name: "Production gateway", State: "pending", Version: 1, ReplayFloor: 0, CreatedAt: a.now}
	enrollment := &GatewayBootstrapEnrollment{ID: input.EnrollmentID, DeviceID: input.DeviceID, TokenGeneration: 1, DeviceVersion: 1, Audience: "runtime-gateway-enroll", IssuedAt: a.now, ExpiresAt: input.ExpiresAt}
	return GatewayBootstrapMutationResult{Operation: operation, Device: device, Enrollment: enrollment, CredentialGeneration: 1, Replayed: a.replay, NewMutation: !a.replay}, nil
}
func (a *gatewayBootstrapFlowAuthority) GetGateway(context.Context, domain.Scope, string) (GatewayBootstrapStatus, error) {
	return GatewayBootstrapStatus{Device: GatewayDeviceRecord{ID: testSensorID, Name: "Production gateway", State: "pending", Version: 1, CreatedAt: a.now}, NextCredentialGeneration: 1, IssuanceState: "available"}, nil
}
func TestGatewayBootstrapConnectedOneTimeDelivery(t *testing.T) {
	for _, mode := range []string{"fresh_browser", "fresh_PAT", "metadata_replay", "unknown_transaction", "browser_without_fresh", "duplicate_body_member", "changed_expected_version"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			authority := &gatewayBootstrapFlowAuthority{now: now, replay: mode == "metadata_replay", fail: mode == "unknown_transaction"}
			n := byte(1)
			handler, err := NewGatewayBootstrapHTTPHandler(authority, GatewayBootstrapHandlerConfig{
				NewProductID: func() (string, error) { return testTokenID, nil },
				NewEnrollmentMaterial: func() ([]byte, []byte, []byte, error) {
					n++
					return bytes.Repeat([]byte{n}, 16), bytes.Repeat([]byte{n + 1}, 32), bytes.Repeat([]byte{n + 2}, 32), nil
				},
				Clock: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal("connected gateway handler configuration refused")
			}
			identity := fixtureRequestIdentity(t)
			identity.CredentialKind = CredentialBrowserSession
			identity.FreshAuthenticated = true
			body := `{"expected_version":1,"ttl_seconds":600}`
			if mode == "duplicate_body_member" {
				body = `{"expected_version":1,"expected_version":1,"ttl_seconds":600}`
			}
			if mode == "changed_expected_version" {
				body = `{"expected_version":0,"ttl_seconds":600}`
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/gateways/"+testSensorID+"/enrollments", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "gateway-issue-idempotency-01")
			if mode == "fresh_PAT" {
				identity.CredentialKind = CredentialBearerToken
				identity.FreshAuthenticated = false
			} else if mode != "browser_without_fresh" {
				request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
			} else {
				identity.FreshAuthenticated = false
			}
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
			request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "issueGatewayEnrollment", PathParameters: map[string]string{"id": testSensorID}}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("one-time gateway response lost no-store")
			}
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(response.Body.Bytes(), &fields)
			switch mode {
			case "fresh_browser", "fresh_PAT":
				if response.Code != http.StatusCreated || len(fields) != 4 || fields["token_bundle"] == nil || !bytes.Equal(fields["replayed"], []byte("false")) {
					t.Fatal("confirmed fresh native token not delivered as exact fresh response")
				}
				var bundle map[string]json.RawMessage
				if json.Unmarshal(fields["token_bundle"], &bundle) != nil || len(bundle) != 11 || bundle["locator"] == nil || bundle["secret"] == nil || bundle["credential_generation"] == nil {
					t.Fatal("protected stdin bundle lost exact11 fields")
				}
			case "metadata_replay":
				if response.Code != http.StatusOK || len(fields) != 3 || fields["token_bundle"] != nil || !bytes.Equal(fields["replayed"], []byte("true")) {
					t.Fatal("metadata replay fabricated or redisclosed secret")
				}
			default:
				if response.Code < 400 || fields["token_bundle"] != nil {
					t.Fatal("refused or uncertain issue returned token success")
				}
				if mode != "unknown_transaction" && len(authority.inputs) != 0 {
					t.Fatal("closed header/body/freshness refusal reached mutation")
				}
			}
		})
	}
}
func TestGatewayBootstrapCanonicalIntentExcludesMintedRandomness(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	a := &gatewayBootstrapFlowAuthority{now: now}
	counter := byte(0)
	h, err := NewGatewayBootstrapHTTPHandler(a, GatewayBootstrapHandlerConfig{NewProductID: func() (string, error) {
		counter++
		if counter == 1 {
			return testTokenID, nil
		}
		return "pid_93000004-0000-4000-8000-000000000004", nil
	}, NewEnrollmentMaterial: func() ([]byte, []byte, []byte, error) {
		return bytes.Repeat([]byte{counter + 1}, 16), bytes.Repeat([]byte{counter + 2}, 32), bytes.Repeat([]byte{counter + 3}, 32), nil
	}, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		identity := fixtureRequestIdentity(t)
		identity.CredentialKind = CredentialBearerToken
		r := httptest.NewRequest(http.MethodPost, "/api/v1/gateways/"+testSensorID+"/enrollments", strings.NewReader(`{"expected_version":1,"ttl_seconds":600}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "gateway-issue-idempotency-02")
		r = r.WithContext(context.WithValue(r.Context(), identityContextKey{}, identity))
		r = r.WithContext(context.WithValue(r.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "issueGatewayEnrollment", PathParameters: map[string]string{"id": testSensorID}}))
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if len(a.inputs) != 2 || !reflect.DeepEqual(a.inputs[0].RequestDigest, a.inputs[1].RequestDigest) || reflect.DeepEqual(a.inputs[0].LocatorDigest, a.inputs[1].LocatorDigest) {
		t.Fatal("canonical intent either included minted randomness or reused token material")
	}
}
