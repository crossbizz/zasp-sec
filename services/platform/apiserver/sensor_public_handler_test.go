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
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

type sensorPublicHandlerRepository struct {
	createInputs []SensorCreateMutation
	rotateInput  SensorRotateMutation
	authority    SensorTokenAuthority
	page         SensorPage
	coverage     SensorCoverage
}

func (repository *sensorPublicHandlerRepository) ListSensors(context.Context, domain.Scope, string, int) (SensorPage, error) {
	return repository.page, nil
}

func (repository *sensorPublicHandlerRepository) GetSensor(_ context.Context, _ domain.Scope, id string) (ProductSensor, error) {
	return publicHandlerSensor(id, 7), nil
}

func (repository *sensorPublicHandlerRepository) GetSensorCoverage(context.Context, domain.Scope, string) (SensorCoverage, error) {
	return repository.coverage, nil
}

func (repository *sensorPublicHandlerRepository) GetSensorTokenAuthority(context.Context, domain.Scope, string) (SensorTokenAuthority, error) {
	return repository.authority, nil
}

func (repository *sensorPublicHandlerRepository) CreateSensor(_ context.Context, _ RequestIdentity, input SensorCreateMutation) (SensorMutationResult, error) {
	repository.createInputs = append(repository.createInputs, input)
	if len(repository.createInputs) == 1 {
		value := publicHandlerSensor(input.SensorID, 1)
		value.Name, value.Kind, value.Mode, value.RuntimeSensorID = input.Name, input.Kind, input.Mode, input.RuntimeSensorID
		return SensorMutationResult{Sensor: value, TokenID: input.TokenID, TokenGeneration: 1, TokenExpiresAt: &input.TokenExpiresAt}, nil
	}
	prior := repository.createInputs[0]
	return SensorMutationResult{Sensor: publicHandlerSensor(prior.SensorID, 1), TokenID: prior.TokenID, TokenGeneration: 1, TokenExpiresAt: &prior.TokenExpiresAt, Replayed: true}, nil
}

func TestSensorPublicHTTPHandlerPairingIntentAndClosedBody(t *testing.T) {
	const anchor = "pid_93000006-0000-4000-8000-000000000006"
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	const legacy = `{"name":"Production runtime","kind":"otlp","mode":"metadata_only"}`
	paired := strings.TrimSuffix(legacy, "}") + `,"runtime_sensor_id":"` + anchor + `"}`
	var legacyDigest, pairedDigest []byte
	for _, test := range []struct {
		name, body, anchor string
		valid              bool
	}{
		{"legacy", legacy, "", true},
		{"paired", paired, anchor, true},
		{"reordered", `{"runtime_sensor_id":"` + anchor + `","mode":"metadata_only","kind":"otlp","name":"Production runtime"}`, anchor, true},
		{"null", strings.ReplaceAll(paired, `"`+anchor+`"`, `null`), "", false},
		{"empty", strings.ReplaceAll(paired, anchor, ""), "", false},
		{"name is not identity", strings.ReplaceAll(paired, anchor, "runtime-sensor"), "", false},
		{"wrong kind", strings.ReplaceAll(paired, `"otlp"`, `"tetragon"`), "", false},
		{"duplicate anchor", strings.TrimSuffix(paired, "}") + `,"runtime_sensor_id":"` + anchor + `"}`, "", false},
		{"duplicate kind", strings.TrimSuffix(paired, "}") + `,"kind":"otlp"}`, "", false},
		{"case variant", strings.ReplaceAll(paired, "runtime_sensor_id", "Runtime_Sensor_ID"), "", false},
		{"foreign scope field", strings.TrimSuffix(paired, "}") + `,"organization_id":"` + anchor + `"}`, "", false},
		{"trailing object", paired + `{}`, "", false},
		{"missing name", `{"kind":"otlp","mode":"metadata_only","runtime_sensor_id":"` + anchor + `"}`, "", false},
		{"oversize", strings.ReplaceAll(paired, "Production runtime", strings.Repeat("x", 16*1024)), "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &sensorPublicHandlerRepository{}
			generated := 0
			handler, err := NewSensorPublicHTTPHandler(repository, bytes.Repeat([]byte{0x55}, 32), SensorPublicHandlerConfig{
				NewProductID: func() (string, error) {
					generated++
					if generated == 1 {
						return "pid_93000001-0000-4000-8000-000000000001", nil
					}
					return "pid_93000002-0000-4000-8000-000000000002", nil
				},
				NewTokenCredential: func() (*sensor.TokenCredential, error) {
					return sensor.NewTokenCredential(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 32))
				},
				NewSalt: func() ([]byte, error) { return bytes.Repeat([]byte{0x33}, 32), nil },
				Clock:   func() time.Time { return time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC) }, TokenTTL: 30 * 24 * time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/sensors", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "sensor-pairing-idem-0001")
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
			request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "createSensorEnrollment", PathParameters: map[string]string{}}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if !test.valid {
				if response.Code != http.StatusBadRequest || len(repository.createInputs) != 0 || generated != 0 || strings.Contains(response.Body.String(), "zasp_sensor_v1.") {
					t.Fatalf("invalid input reached mutation: status=%d mutations=%d generated=%d", response.Code, len(repository.createInputs), generated)
				}
				return
			}
			if response.Code != http.StatusCreated || len(repository.createInputs) != 1 {
				t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
			}
			input := repository.createInputs[0]
			if input.RuntimeSensorID != test.anchor {
				t.Fatal("request pairing lost")
			}
			var output map[string]json.RawMessage
			if json.Unmarshal(response.Body.Bytes(), &output) != nil {
				t.Fatal("invalid response")
			}
			if test.anchor == "" {
				if output["runtime_sensor_id"] != nil {
					t.Fatal("legacy response changed")
				}
				legacyDigest = input.RequestDigest
				want, ok := sensorIntentDigest(identity, "createSensorEnrollment", "", 0, "sensor-pairing-idem-0001", map[string]any{"name": "Production runtime", "kind": "otlp", "mode": "metadata_only"})
				if !ok || !bytes.Equal(want, legacyDigest) {
					t.Fatal("legacy digest changed")
				}
			} else {
				if string(output["runtime_sensor_id"]) != `"`+anchor+`"` || bytes.Equal(input.RequestDigest, legacyDigest) {
					t.Fatal("pairing not bound to response and intent")
				}
				if pairedDigest != nil && !bytes.Equal(pairedDigest, input.RequestDigest) {
					t.Fatal("field ordering changed semantic intent")
				}
				pairedDigest = input.RequestDigest
			}
		})
	}
}

func (repository *sensorPublicHandlerRepository) UpdateSensor(_ context.Context, _ RequestIdentity, input SensorUpdateMutation) (SensorMutationResult, error) {
	value := publicHandlerSensor(input.SensorID, input.ExpectedVersion+1)
	value.Name = input.Name
	value.Mode = input.Mode
	return SensorMutationResult{Sensor: value}, nil
}

func (repository *sensorPublicHandlerRepository) DeleteSensor(_ context.Context, _ RequestIdentity, input SensorDeleteMutation) (SensorMutationResult, error) {
	value := publicHandlerSensor(input.SensorID, input.ExpectedVersion+1)
	value.State = "deleted"
	value.TokenExpiresAt = nil
	return SensorMutationResult{Sensor: value}, nil
}

func (repository *sensorPublicHandlerRepository) RotateSensorToken(_ context.Context, _ RequestIdentity, input SensorRotateMutation) (SensorMutationResult, error) {
	repository.rotateInput = input
	return SensorMutationResult{Sensor: publicHandlerSensor(input.SensorID, input.ExpectedVersion), TokenID: input.TokenID, TokenGeneration: input.TokenGeneration, TokenExpiresAt: &input.TokenExpiresAt}, nil
}

func publicHandlerSensor(id string, version int64) ProductSensor {
	expires := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	created := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	return ProductSensor{ID: id, Name: "Production runtime", Kind: "tetragon", Mode: "metadata_only", State: "pending", Version: version, TokenExpiresAt: &expires, CreatedAt: created, UpdatedAt: created}
}

func TestSensorPublicHTTPHandlerRevealsFreshCredentialOnceAndRejectsReplay(t *testing.T) {
	repository := &sensorPublicHandlerRepository{}
	ids := []string{
		"pid_93000001-0000-4000-8000-000000000001", "pid_93000002-0000-4000-8000-000000000002",
		"pid_93000003-0000-4000-8000-000000000003", "pid_93000004-0000-4000-8000-000000000004",
	}
	credentialCount := byte(1)
	handler, err := NewSensorPublicHTTPHandler(repository, bytes.Repeat([]byte{0x55}, 32), SensorPublicHandlerConfig{
		NewProductID: func() (string, error) { value := ids[0]; ids = ids[1:]; return value, nil },
		NewTokenCredential: func() (*sensor.TokenCredential, error) {
			value, err := sensor.NewTokenCredential(bytes.Repeat([]byte{credentialCount}, 16), bytes.Repeat([]byte{credentialCount + 16}, 32))
			credentialCount++
			return value, err
		},
		NewSalt: func() ([]byte, error) { return bytes.Repeat([]byte{0x44}, 32), nil },
		Clock:   func() time.Time { return time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC) }, TokenTTL: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	call := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/sensors", strings.NewReader(`{"name":"Production runtime","kind":"tetragon","mode":"metadata_only"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "sensor-create-idem-0001")
		request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
		request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "createSensorEnrollment", PathParameters: map[string]string{}}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	first := call()
	if first.Code != http.StatusCreated || first.Header().Get("Cache-Control") != "no-store" || first.Header().Get("Pragma") != "no-cache" || first.Header().Get("ETag") != `"1"` {
		t.Fatalf("first=%d headers=%v body=%s", first.Code, first.Header(), first.Body.String())
	}
	var enrollment map[string]any
	if json.Unmarshal(first.Body.Bytes(), &enrollment) != nil || !strings.HasPrefix(enrollment["token"].(string), "zasp_sensor_v1.") {
		t.Fatalf("enrollment=%s", first.Body.String())
	}
	second := call()
	if second.Code != http.StatusConflict || strings.Contains(second.Body.String(), "zasp_sensor_v1.") {
		t.Fatalf("replay=%d body=%s", second.Code, second.Body.String())
	}
	if len(repository.createInputs) != 2 || repository.createInputs[0].SensorID == repository.createInputs[1].SensorID || repository.createInputs[0].TokenID == repository.createInputs[1].TokenID || !reflect.DeepEqual(repository.createInputs[0].RequestDigest, repository.createInputs[1].RequestDigest) {
		t.Fatalf("create inputs=%#v", repository.createInputs)
	}
}

func TestSensorPublicHTTPHandlerBindsRotationToLiveGenerationAndAllowsPAT(t *testing.T) {
	repository := &sensorPublicHandlerRepository{authority: SensorTokenAuthority{Generation: 4, SensorVersion: 7}}
	ids := []string{"pid_93000005-0000-4000-8000-000000000005"}
	handler, err := NewSensorPublicHTTPHandler(repository, bytes.Repeat([]byte{0x66}, 32), SensorPublicHandlerConfig{
		NewProductID: func() (string, error) { return ids[0], nil },
		NewTokenCredential: func() (*sensor.TokenCredential, error) {
			return sensor.NewTokenCredential(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 32))
		},
		NewSalt: func() ([]byte, error) { return bytes.Repeat([]byte{0x33}, 32), nil },
		Clock:   func() time.Time { return time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC) }, TokenTTL: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sensors/"+testSensorID+"/rotate-token", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "sensor-rotate-idem-0001")
	request.Header.Set("If-Match", `"7"`)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "rotateSensorToken", PathParameters: map[string]string{"id": testSensorID}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || repository.rotateInput.TokenGeneration != 5 || repository.rotateInput.ExpectedVersion != 7 || len(repository.rotateInput.TokenHash) != 32 || !strings.Contains(response.Body.String(), "zasp_sensor_v1.") {
		t.Fatalf("response=%d %s input=%#v", response.Code, response.Body.String(), repository.rotateInput)
	}
}
