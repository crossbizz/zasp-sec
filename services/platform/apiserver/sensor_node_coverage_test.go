package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Existing actual handler and repository interface only: unsupported opted-in
// observations must never silently return the legacy nine-field representation.
func TestSensorNodeCoverageRepresentationAdmission(t *testing.T) {
	for _, mode := range []string{"legacy_nine_fields_unchanged", "explicit_v2_default_off", "unknown_schema", "duplicate_schema"} {
		t.Run(mode, func(t *testing.T) {
			repository := &sensorPublicHandlerRepository{coverage: SensorCoverage{SensorID: testSensorID, Status: "unknown", Kernel: "unknown", Capabilities: []string{}}}
			handler, err := NewSensorPublicHTTPHandler(repository, bytes.Repeat([]byte{0x55}, 32))
			if err != nil {
				t.Fatal(err)
			}
			identity := fixtureRequestIdentity(t)
			request := httptest.NewRequest(http.MethodGet, "/api/v1/sensors/"+testSensorID+"/coverage", nil)
			switch mode {
			case "explicit_v2_default_off":
				request.Header.Set("X-Zasp-Schema-Version", "sensor-coverage-node-observation-v2")
			case "unknown_schema":
				request.Header.Set("X-Zasp-Schema-Version", "unknown-v99")
			case "duplicate_schema":
				request.Header.Add("X-Zasp-Schema-Version", "sensor-coverage-node-observation-v2")
				request.Header.Add("X-Zasp-Schema-Version", "sensor-coverage-node-observation-v2")
			}
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
			request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "getSensorCoverage", PathParameters: map[string]string{"id": testSensorID}}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if mode == "legacy_nine_fields_unchanged" {
				var fields map[string]json.RawMessage
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &fields) != nil || len(fields) != 9 || fields["node_observation"] != nil || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("legacy coverage representation changed")
				}
			} else if response.Code < 400 {
				t.Fatal("unsupported node observation schema silently fell back to legacy coverage")
			}
		})
	}
}

// Successor coverage authored after root initial dependency setup block; no
// claim that these new symbols were exercised by the initial attempt.
func TestSensorNodeCoverageCurrentRepositoryAndStatement(t *testing.T) {
	for _, mode := range []string{"normal", "audit", "no_profile", "no_proof", "foreign_scope", "wrong_target", "wrong_operation", "collection", "denied"} {
		t.Run(mode, func(t *testing.T) {
			g := agentCurrentReadGrant(t, "getAgent")
			g.OperationID = "getSensorCoverage"
			g.PathParameters = map[string]string{"id": testSensorID}
			g.Targets = []AuthorizationTarget{{Scope: g.Identity.Scope, Kind: "sensor", ID: testSensorID, SourceID: testSensorID, Version: 1}}
			g.Allowed = append([]AuthorizationTarget{}, g.Targets...)
			// Database transaction revalidates actual attested proof. This direct recorder
			// group separately checks the repository's fixed admission/SQL boundary.
			pin := migrations.SensorNodeCoverageProfileChecksum()
			if mode == "audit" {
				pin = migrations.SensorNodeCoverageAuditProfileChecksum()
			}
			db := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresSensorNodeCoverageSQL: nodeCoverageReadFixture(t, "unavailable")}}
			repo := &SensorPublicRepository{database: db}
			if mode != "no_profile" {
				if repo.RequireSensorNodeCoverageProfile(pin) != nil {
					t.Fatal("compiled profile refused")
				}
			}
			scope := g.Identity.Scope
			switch mode {
			case "wrong_target":
				g.Allowed = nil
			case "wrong_operation":
				g.OperationID = "getSensor"
			case "collection":
				g.Collection = true
			case "denied":
				g.Allowed = nil
			case "foreign_scope":
				foreign, parseErr := domain.ParseProductID(testTokenID)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				otherScope, scopeErr := domain.NewScope(scope.OrganizationID(), scope.WorkspaceID(), foreign)
				if scopeErr != nil {
					t.Fatal(scopeErr)
				}
				scope = otherScope
			}
			ctx := context.Background()
			if mode != "no_proof" {
				ctx = context.WithValue(ctx, requestAuthorizationContextKey{}, g)
			}
			v, err := repo.GetSensorNodeCoverage(ctx, scope, testSensorID)
			if mode == "normal" || mode == "audit" {
				if err != nil || v.SensorID != testSensorID || db.query != postgresSensorNodeCoverageSQL || !reflect.DeepEqual(db.args, []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), testSensorID}) {
					t.Fatal("current scoped four-argument read missing")
				}
			} else if err == nil || db.query != "" {
				t.Fatal("unsupported proof/profile escaped to SQL")
			}
			if authorizationStatementAllowed(g, postgresRuntimePublicSensorCoverageSQL, []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), testSensorID}) {
				t.Fatal("legacy coverage SQL admitted under current proof")
			}
		})
	}
}
func TestSensorNodeCoverageStrictReadDTO(t *testing.T) {
	for _, state := range []string{"unavailable", "source_current", "source_expired", "source_superseded", "enrollment_revoked"} {
		t.Run(state, func(t *testing.T) {
			raw := nodeCoverageReadFixture(t, state)
			v, ok := decodeSensorNodeCoverage(raw, testSensorID)
			if !ok || v.NodeObservation.State != state {
				t.Fatal("valid retained testimony refused")
			}
			if _, ok = decodeSensorNodeCoverage(raw, testTokenID); ok {
				t.Fatal("wrong returned sensor accepted")
			}
		})
	}
	for _, mode := range []string{"header_as_body_schema", "unknown_state", "missing_receipt", "null_envelope", "wrong_sequence", "wrong_expiry", "duplicate_nested", "unknown_envelope_field", "unknown_top_field"} {
		t.Run(mode, func(t *testing.T) {
			raw := string(nodeCoverageReadFixture(t, "source_current"))
			switch mode {
			case "header_as_body_schema":
				raw = strings.Replace(raw, nodecoveragewire.ObservationReadSchema, nodecoveragewire.ReadSchema, 1)
			case "unknown_state":
				raw = strings.Replace(raw, "source_current", "covered", 1)
			case "missing_receipt":
				var m map[string]any
				_ = json.Unmarshal([]byte(raw), &m)
				m["node_observation"].(map[string]any)["receipt"] = nil
				b, _ := json.Marshal(m)
				raw = string(b)
			case "null_envelope":
				var m map[string]any
				_ = json.Unmarshal([]byte(raw), &m)
				m["node_observation"].(map[string]any)["receipt"].(map[string]any)["observation"] = nil
				b, _ := json.Marshal(m)
				raw = string(b)
			case "wrong_sequence":
				raw = strings.Replace(raw, `"sequence":7`, `"sequence":8`, 1)
			case "wrong_expiry":
				raw = strings.Replace(raw, `"expires_at":"2026-10-17T00:00:30Z"`, `"expires_at":"2026-10-17T00:00:31Z"`, 1)
			case "duplicate_nested":
				raw = strings.Replace(raw, `"schema":"zasp-node-observation-read-v1"`, `"schema":"wrong","schema":"zasp-node-observation-read-v1"`, 1)
			case "unknown_envelope_field":
				raw = strings.Replace(raw, `"observation":{`, `"observation":{"secret":"forbidden",`, 1)
			case "unknown_top_field":
				raw = `{"secret":true,` + raw[1:]
			}
			if _, ok := decodeSensorNodeCoverage([]byte(raw), testSensorID); ok {
				t.Fatal("invalid nested observation was accepted")
			}
		})
	}
}
func TestSensorNodeCoverageMountedHandlerSelectsExactRead(t *testing.T) {
	for _, mode := range []string{"valid", "wrong_returned_id", "repository_error"} {
		t.Run(mode, func(t *testing.T) {
			raw := nodeCoverageReadFixture(t, "source_current")
			v, ok := decodeSensorNodeCoverage(raw, testSensorID)
			if !ok {
				t.Fatal("invalid controlled fixture")
			}
			repo := &nodeCoverageHandlerFixture{sensorPublicHandlerRepository: sensorPublicHandlerRepository{coverage: v.SensorCoverage}, value: v}
			if mode == "wrong_returned_id" {
				repo.value.SensorID = testTokenID
			}
			if mode == "repository_error" {
				repo.err = ErrRepositoryUnavailable
			}
			h, err := NewSensorPublicHTTPHandler(repo, bytes.Repeat([]byte{0x55}, 32))
			if err != nil {
				t.Fatal(err)
			}
			id := fixtureRequestIdentity(t)
			request := httptest.NewRequest(http.MethodGet, "/api/v1/sensors/"+testSensorID+"/coverage", nil)
			request.Header.Set("X-Zasp-Schema-Version", nodecoveragewire.ReadSchema)
			ctx := context.WithValue(request.Context(), identityContextKey{}, id)
			ctx = context.WithValue(ctx, routedOperationContextKey{}, RoutedOperation{OperationID: "getSensorCoverage", PathParameters: map[string]string{"id": testSensorID}})
			out := httptest.NewRecorder()
			h.ServeHTTP(out, request.WithContext(ctx))
			if mode == "valid" {
				if out.Code != 200 || repo.calls != 1 || !strings.Contains(out.Body.String(), nodecoveragewire.ObservationReadSchema) {
					t.Fatal("explicit retained read not mounted")
				}
			} else if out.Code < 400 {
				t.Fatal("bad provider result returned success")
			}
		})
	}
}

type nodeCoverageHandlerFixture struct {
	sensorPublicHandlerRepository
	value SensorNodeCoverage
	err   error
	calls int
}

func (r *nodeCoverageHandlerFixture) GetSensorNodeCoverage(context.Context, domain.Scope, string) (SensorNodeCoverage, error) {
	r.calls++
	return r.value, r.err
}
func nodeCoverageReadFixture(t *testing.T, state string) json.RawMessage {
	t.Helper()
	v := SensorNodeCoverage{SensorCoverage: SensorCoverage{SensorID: testSensorID, Status: "pending", Kernel: "unknown", Capabilities: []string{}}, NodeObservation: nodecoveragewire.ObservationRead{Schema: nodecoveragewire.ObservationReadSchema, State: state}}
	if state != "unavailable" {
		now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
		target := nodecoveragewire.CoverageTarget{Namespace: "sensor", Name: "agent", Release: "zasp", ReleaseNamespace: "sensor", Image: "example/sensor@sha256:" + strings.Repeat("b", 64), ServiceAccount: "agent", Container: "agent"}
		other := target
		other.Name = "tetragon"
		env := nodecoveragewire.Envelope{Heartbeat: nodecoveragewire.Heartbeat{Sequence: 7, Status: "degraded", Capabilities: []string{"process"}, Kernel: "unknown"}, CoverageSchema: nodecoveragewire.CoverageSchema, StateUID: "11111111-1111-4111-8111-111111111111", StorageEpoch: 1, Selection: nodecoveragewire.NodeCoverageSelection{SourceProfile: "tetragon-local-stream-v2", ClusterUID: "22222222-2222-4222-8222-222222222222", EnrollmentBinding: strings.Repeat("a", 64), MatchLabels: map[string]string{"group": "selected"}, Sensor: target, Tetragon: other}, TargetDigest: strings.Repeat("c", 64), InventoryObservedAt: now, SourceObservedAt: now, TTLSeconds: 30, SensorDaemonSetUID: "33333333-3333-4333-8333-333333333333", TetragonDaemonSetUID: "44444444-4444-4444-8444-444444444444", SelectedNodes: []nodecoveragewire.SelectedNode{{NodeName: "node-a", NodeUID: "55555555-5555-4555-8555-555555555555", BootID: "66666666-6666-4666-8666-666666666666"}}, Reports: []nodecoveragewire.NodeCoverageV2{}}
		v.NodeObservation.Receipt = &nodecoveragewire.AcceptedObservation{Sequence: 7, RequestDigest: strings.Repeat("d", 64), ReceivedAt: now, SourceObservedAt: now, ExpiresAt: now.Add(30 * time.Second), Observation: env}
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
