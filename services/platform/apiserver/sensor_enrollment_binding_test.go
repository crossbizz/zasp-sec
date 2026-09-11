package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func TestSensorEnrollmentBindingRepresentation(t *testing.T) {
	const header = "X-Zasp-Sensor-Enrollment-Schema"
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	for _, operation := range []string{"createSensorEnrollment", "rotateSensorToken"} {
		for _, profile := range []string{"legacy", "bound", "empty", "unknown", "duplicate", "alias"} {
			t.Run(operation+"/"+profile, func(t *testing.T) {
				repository := &sensorPublicHandlerRepository{authority: SensorTokenAuthority{Generation: 4, SensorVersion: 7}}
				handler, err := NewSensorPublicHTTPHandler(repository, bytes.Repeat([]byte{0x55}, 32))
				if err != nil {
					t.Fatal(err)
				}
				body, path, sensorID := `{"name":"runtime","kind":"tetragon","mode":"metadata_only"}`, "/api/v1/sensors", ""
				if operation == "rotateSensorToken" {
					body, sensorID, path = `{}`, testSensorID, "/api/v1/sensors/"+testSensorID+"/rotate-token"
				}
				request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Idempotency-Key", "sensor-binding-profile-0001")
				if sensorID != "" {
					request.Header.Set("If-Match", `"7"`)
				}
				if profile != "legacy" {
					request.Header.Set(header, "enrollment-binding-v1")
				}
				switch profile {
				case "empty":
					request.Header[header] = nil
				case "unknown":
					request.Header.Set(header, "future")
				case "duplicate":
					request.Header.Add(header, "enrollment-binding-v1")
				case "alias":
					request.Header[strings.ToLower(header)] = []string{"enrollment-binding-v1"}
				}
				request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
				request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": sensorID}}))
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if profile != "legacy" && profile != "bound" {
					if response.Code != http.StatusBadRequest || len(repository.createInputs) != 0 || repository.rotateInput.TokenGeneration != 0 || strings.Contains(response.Body.String(), "zasp_sensor_v1.") {
						t.Fatal("invalid representation performed a credential mutation", response.Code)
					}
					return
				}
				if response.Code != http.StatusCreated && response.Code != http.StatusOK {
					t.Fatal("enrollment failed", response.Code)
				}
				var result map[string]json.RawMessage
				if json.Unmarshal(response.Body.Bytes(), &result) != nil {
					t.Fatal("invalid response")
				}
				if profile == "legacy" {
					if _, exists := result["enrollment_binding"]; exists {
						t.Fatal("legacy closed response changed")
					}
					return
				}
				var id, binding string
				if json.Unmarshal(result["id"], &id) != nil || json.Unmarshal(result["enrollment_binding"], &binding) != nil {
					t.Fatal("bound response omitted installation identity")
				}
				parsed, err := domain.ParseProductID(id)
				if err != nil {
					t.Fatal(err)
				}
				want, err := sensor.EnrollmentBinding(identity.Scope, parsed)
				if err != nil || binding != want {
					t.Fatal("binding does not match authenticated scope and enrollment")
				}
			})
		}
	}
}

type bindingResponseDriftRepository struct{ *sensorPublicHandlerRepository }

func (repository *bindingResponseDriftRepository) CreateSensor(ctx context.Context, identity RequestIdentity, input SensorCreateMutation) (SensorMutationResult, error) {
	result, err := repository.sensorPublicHandlerRepository.CreateSensor(ctx, identity, input)
	result.Sensor.ID = "pid_78950009-0000-4000-8000-000000000009"
	return result, err
}

func (repository *bindingResponseDriftRepository) RotateSensorToken(ctx context.Context, identity RequestIdentity, input SensorRotateMutation) (SensorMutationResult, error) {
	result, err := repository.sensorPublicHandlerRepository.RotateSensorToken(ctx, identity, input)
	result.Sensor.ID = "pid_78950009-0000-4000-8000-000000000009"
	return result, err
}

func TestSensorEnrollmentBindingRejectsResponseIDDrift(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	for _, operation := range []string{"createSensorEnrollment", "rotateSensorToken"} {
		t.Run(operation, func(t *testing.T) {
			repository := &bindingResponseDriftRepository{&sensorPublicHandlerRepository{authority: SensorTokenAuthority{Generation: 4, SensorVersion: 7}}}
			handler, err := NewSensorPublicHTTPHandler(repository, bytes.Repeat([]byte{0x55}, 32))
			if err != nil {
				t.Fatal(err)
			}
			response := callBindingEnrollment(t, handler, identity, operation, testSensorID, true)
			if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "zasp_sensor_v1.") || strings.Contains(response.Body.String(), "enrollment_binding") {
				t.Fatal("mismatched response identity revealed an installation credential", response.Code)
			}
		})
	}
}

func TestSensorEnrollmentBindingStableAcrossRotationAndScopedAgainstReuse(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	repository := &sensorPublicHandlerRepository{authority: SensorTokenAuthority{Generation: 4, SensorVersion: 7}}
	handler, err := NewSensorPublicHTTPHandler(repository, bytes.Repeat([]byte{0x55}, 32))
	if err != nil {
		t.Fatal(err)
	}
	read := func(response *httptest.ResponseRecorder) sensorEnrollment {
		t.Helper()
		var value sensorEnrollment
		if response.Code != http.StatusCreated && response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &value) != nil || value.EnrollmentBinding == "" {
			t.Fatal("missing bound enrollment", response.Code)
		}
		return value
	}
	created := read(callBindingEnrollment(t, handler, identity, "createSensorEnrollment", "", true))
	rotated := read(callBindingEnrollment(t, handler, identity, "rotateSensorToken", created.ID, true))
	if created.EnrollmentBinding != rotated.EnrollmentBinding || created.Token == rotated.Token {
		t.Fatal("rotation changed enrollment or reused the credential")
	}
	otherEnvironment, _ := domain.ParseProductID("pid_78950008-0000-4000-8000-000000000008")
	otherIdentity := identity
	otherIdentity.Scope, err = domain.NewScope(identity.Scope.OrganizationID(), identity.Scope.WorkspaceID(), otherEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	foreign := read(callBindingEnrollment(t, handler, otherIdentity, "rotateSensorToken", created.ID, true))
	if foreign.EnrollmentBinding == created.EnrollmentBinding {
		t.Fatal("same sensor ID in another scope reused the binding")
	}
	// Representation changes aren't mutation intent. The existing one-time
	// replay refusal remains a conflict and returns no credential or binding.
	replay := callBindingEnrollment(t, handler, identity, "createSensorEnrollment", "", false)
	if replay.Code != http.StatusConflict || strings.Contains(replay.Body.String(), "zasp_sensor_v1.") || strings.Contains(replay.Body.String(), "enrollment_binding") || !bytes.Equal(repository.createInputs[0].RequestDigest, repository.createInputs[1].RequestDigest) {
		t.Fatal("representation changed receipt/replay semantics", replay.Code)
	}
}

func callBindingEnrollment(t *testing.T, handler http.Handler, identity RequestIdentity, operation, id string, bound bool) *httptest.ResponseRecorder {
	t.Helper()
	body, path := `{"name":"runtime","kind":"tetragon","mode":"metadata_only"}`, "/api/v1/sensors"
	if operation == "rotateSensorToken" {
		body, path = `{}`, path+"/"+id+"/rotate-token"
	}
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "sensor-binding-replay-0001")
	if operation == "rotateSensorToken" {
		request.Header.Set("If-Match", `"7"`)
	}
	if bound {
		request.Header.Set("X-Zasp-Sensor-Enrollment-Schema", "enrollment-binding-v1")
	}
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": id}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
