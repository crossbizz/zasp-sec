package apiserver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

// PostgreSQL stores timestamps at microsecond precision. The double preserves
// that boundary while allowing the returned authority to be deliberately damaged.
type sensorPrecisionRepository struct {
	sensorPublicHandlerRepository
	drift time.Duration
}

func (repository *sensorPrecisionRepository) persisted(result SensorMutationResult) SensorMutationResult {
	expires := result.TokenExpiresAt.Truncate(time.Microsecond).Add(repository.drift)
	result.TokenExpiresAt = &expires
	result.Sensor.TokenExpiresAt = &expires
	return result
}

func (repository *sensorPrecisionRepository) CreateSensor(ctx context.Context, identity RequestIdentity, input SensorCreateMutation) (SensorMutationResult, error) {
	result, err := repository.sensorPublicHandlerRepository.CreateSensor(ctx, identity, input)
	return repository.persisted(result), err
}

func (repository *sensorPrecisionRepository) RotateSensorToken(ctx context.Context, identity RequestIdentity, input SensorRotateMutation) (SensorMutationResult, error) {
	result, err := repository.sensorPublicHandlerRepository.RotateSensorToken(ctx, identity, input)
	return repository.persisted(result), err
}

func TestSensorPublicHTTPHandlerCanonicalizesExpiryBeforeMutation(t *testing.T) {
	for _, operation := range []string{"createSensorEnrollment", "rotateSensorToken"} {
		for _, nanos := range []int{0, 1, 999, 123456789, 999999999} {
			for _, drift := range []time.Duration{0, time.Nanosecond, time.Microsecond, -time.Nanosecond, -time.Microsecond} {
				t.Run(operation+"/"+time.Duration(nanos).String()+"/drift="+drift.String(), func(t *testing.T) {
					repository := &sensorPrecisionRepository{sensorPublicHandlerRepository: sensorPublicHandlerRepository{authority: SensorTokenAuthority{Generation: 4, SensorVersion: 7}}, drift: drift}
					now := time.Date(2026, 9, 11, 12, 0, 0, nanos, time.FixedZone("fixture", 3600))
					const ttl = 24*time.Hour + 321*time.Nanosecond
					ids := []string{"pid_93000001-0000-4000-8000-000000000001", "pid_93000002-0000-4000-8000-000000000002"}
					handler, err := NewSensorPublicHTTPHandler(repository, bytes.Repeat([]byte{0x55}, 32), SensorPublicHandlerConfig{
						NewProductID: func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil },
						NewTokenCredential: func() (*sensor.TokenCredential, error) {
							return sensor.NewTokenCredential(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 32))
						},
						NewSalt: func() ([]byte, error) { return bytes.Repeat([]byte{0x33}, 32), nil },
						Clock:   func() time.Time { return now }, TokenTTL: ttl,
					})
					if err != nil {
						t.Fatal(err)
					}
					path, body, status := "/api/v1/sensors", `{"name":"Precision sensor","kind":"tetragon","mode":"metadata_only"}`, http.StatusCreated
					parameters := map[string]string{}
					if operation == "rotateSensorToken" {
						path, body, status = path+"/"+testSensorID+"/rotate-token", `{}`, http.StatusOK
						parameters["id"] = testSensorID
					}
					identity := fixtureRequestIdentity(t)
					identity.CredentialKind = CredentialBearerToken
					request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
					request.Header.Set("Content-Type", "application/json")
					request.Header.Set("Idempotency-Key", "precision-mutation-0001")
					if operation == "rotateSensorToken" {
						request.Header.Set("If-Match", `"7"`)
					}
					request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
					request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: parameters}))
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					if drift != 0 {
						status = http.StatusServiceUnavailable
					}
					if response.Code != status {
						t.Fatalf("status=%d want=%d", response.Code, status)
					}
					expires := repository.rotateInput.TokenExpiresAt
					if operation == "createSensorEnrollment" {
						if len(repository.createInputs) != 1 {
							t.Fatal("missing mutation")
						}
						expires = repository.createInputs[0].TokenExpiresAt
					}
					if !expires.Equal(now.UTC().Add(ttl).Truncate(time.Microsecond)) || expires.Location() != time.UTC {
						t.Fatal("noncanonical expiry reached repository")
					}
					if drift != 0 && strings.Contains(response.Body.String(), "zasp_sensor_v1.") {
						t.Fatal("damaged authority revealed credential")
					}
				})
			}
		}
	}
}
