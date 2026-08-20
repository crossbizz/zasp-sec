package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

const (
	testSensorID = "pid_91000001-0000-4000-8000-000000000001"
	testTokenID  = "pid_91000002-0000-4000-8000-000000000002"
)

func sensorRecordJSON(id, state string, version int) string {
	return `{"id":"` + id + `","name":"Production runtime","kind":"tetragon","mode":"metadata_only","state":"` + state + `","version":` + string(rune('0'+version)) + `,"token_expires_at":"2026-09-19T00:00:00Z","last_heartbeat_at":null,"created_at":"2026-08-20T00:00:00Z","updated_at":"2026-08-20T00:00:00Z"}`
}

func newTestSensorPublicRepository(t *testing.T, database *discoveryCallDatabase) *SensorPublicRepository {
	t.Helper()
	database.schema = RuntimeDataPlaneSchemaVersion
	database.responses[postgresRuntimeDataPlaneReadinessSQL] = json.RawMessage(`true`)
	repository, err := NewSensorPublicRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func TestSensorPublicRepositoryStrictlyReadsScopedSensorsAndCoverage(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestSensorPublicRepository(t, database)
	database.responses[postgresRuntimePublicSensorPageSQL] = json.RawMessage(`{"items":[` + sensorRecordJSON(testSensorID, "active", 1) + `],"next_id":null}`)

	page, err := repository.ListSensors(context.Background(), identity.Scope, "", 50)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != testSensorID || page.NextID != "" {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	wantArgs := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), "", 50}
	if database.query != postgresRuntimePublicSensorPageSQL || !reflect.DeepEqual(database.args, wantArgs) {
		t.Fatalf("query/args=%q/%#v", database.query, database.args)
	}

	database.responses[postgresRuntimePublicSensorDetailSQL] = json.RawMessage(sensorRecordJSON(testSensorID, "active", 1))
	detail, err := repository.GetSensor(context.Background(), identity.Scope, testSensorID)
	if err != nil || detail.ID != testSensorID || detail.TokenExpiresAt == nil || detail.TokenExpiresAt.Location() != time.UTC {
		t.Fatalf("detail=%#v err=%v", detail, err)
	}

	database.responses[postgresRuntimePublicSensorCoverageSQL] = json.RawMessage(`{"sensor_id":"` + testSensorID + `","supported":true,"status":"healthy","last_heartbeat":"2026-08-20T00:00:00Z","kernel":"6.8.0","btf":true,"capabilities":["network","process"],"event_rate":12.5,"drops":0}`)
	coverage, err := repository.GetSensorCoverage(context.Background(), identity.Scope, testSensorID)
	if err != nil || coverage.SensorID != testSensorID || !coverage.Supported || coverage.LastHeartbeat == nil || len(coverage.Capabilities) != 2 {
		t.Fatalf("coverage=%#v err=%v", coverage, err)
	}
}

func TestSensorPublicRepositoryCreatesAndRotatesWithoutPersistingWireToken(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestSensorPublicRepository(t, database)
	digest := sha256.Sum256([]byte("sensor-create-intent"))
	locator := sha256.Sum256([]byte("locator"))
	salt := sha256.Sum256([]byte("salt"))
	tokenHash := sha256.Sum256([]byte("token"))
	expires := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	database.responses[postgresRuntimePublicCreateSensorSQL] = json.RawMessage(`{"body":` + sensorRecordJSON(testSensorID, "pending", 1) + `,"token_id":"` + testTokenID + `","token_generation":1,"token_expires_at":"2026-09-19T00:00:00Z","replayed":false}`)
	input := SensorCreateMutation{SensorID: testSensorID, Name: "Production runtime", Kind: "tetragon", Mode: "metadata_only", IdempotencyKey: "sensor-create-idem-0001", RequestDigest: digest[:], TokenID: testTokenID, TokenGeneration: 1, LocatorDigest: locator[:], Salt: salt[:], TokenHash: tokenHash[:], TokenExpiresAt: expires}
	result, err := repository.CreateSensor(context.Background(), identity, input)
	if err != nil || result.Sensor.ID != testSensorID || result.TokenID != testTokenID || result.TokenGeneration != 1 || result.Replayed {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	for _, argument := range database.args {
		if value, ok := argument.(string); ok && len(value) > 0 && value[:min(len(value), len("zasp_sensor_v1."))] == "zasp_sensor_v1." {
			t.Fatalf("wire token crossed repository boundary: %q", value)
		}
	}

	database.responses[postgresRuntimePublicRotateSensorSQL] = json.RawMessage(`{"body":` + sensorRecordJSON(testSensorID, "active", 1) + `,"token_id":"pid_91000003-0000-4000-8000-000000000003","token_generation":2,"token_expires_at":"2026-09-19T00:00:00Z","replayed":true}`)
	rotated, err := repository.RotateSensorToken(context.Background(), identity, SensorRotateMutation{SensorID: testSensorID, ExpectedVersion: 1, IdempotencyKey: "sensor-rotate-idem-001", RequestDigest: digest[:], TokenID: "pid_91000003-0000-4000-8000-000000000003", TokenGeneration: 2, LocatorDigest: locator[:], Salt: salt[:], TokenHash: tokenHash[:], TokenExpiresAt: expires})
	if err != nil || !rotated.Replayed || rotated.TokenGeneration != 2 {
		t.Fatalf("rotated=%#v err=%v", rotated, err)
	}
}

func TestSensorPublicRepositoryRejectsHostileAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestSensorPublicRepository(t, database)
	for name, payload := range map[string]string{
		"secret field":   `{"items":[` + sensorRecordJSON(testSensorID, "active", 1)[:len(sensorRecordJSON(testSensorID, "active", 1))-1] + `,"token":"secret"}],"next_id":null}`,
		"foreign cursor": `{"items":[` + sensorRecordJSON(testSensorID, "active", 1) + `],"next_id":"pid_91000009-0000-4000-8000-000000000009"}`,
		"invalid state":  `{"items":[` + sensorRecordJSON(testSensorID, "unknown", 1) + `],"next_id":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			database.responses[postgresRuntimePublicSensorPageSQL] = json.RawMessage(payload)
			if _, err := repository.ListSensors(context.Background(), identity.Scope, "", 50); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
