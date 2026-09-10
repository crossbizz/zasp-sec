package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const pairingContractAnchor = "pid_78200001-0000-4000-8000-000000000001"

func TestSensorRecordPreservesOnlyQualifiedEnrollmentPairing(t *testing.T) {
	legacy := sensorRecordJSON(testSensorID, "pending", 1)
	paired := strings.Replace(strings.TrimSuffix(legacy, "}")+`,"runtime_sensor_id":"`+pairingContractAnchor+`"}`, `"kind":"tetragon"`, `"kind":"otlp"`, 1)
	value, ok := decodeSensorRecord(json.RawMessage(paired))
	if !ok || value.RuntimeSensorID != pairingContractAnchor {
		t.Fatal("paired sensor response lost runtime enrollment")
	}
	value, ok = decodeSensorRecord(json.RawMessage(legacy))
	if !ok || value.RuntimeSensorID != "" {
		t.Fatal("legacy unpaired sensor response changed")
	}
	for _, body := range []string{
		strings.Replace(paired, pairingContractAnchor, testSensorID, 1),
		strings.Replace(paired, `"kind":"otlp"`, `"kind":"tetragon"`, 1),
		strings.Replace(paired, `"`+pairingContractAnchor+`"`, `null`, 1),
		strings.Replace(paired, pairingContractAnchor, "", 1),
		strings.TrimSuffix(paired, "}") + `,"runtime_sensor_id":"` + pairingContractAnchor + `"}`,
	} {
		if _, ok := decodeSensorRecord(json.RawMessage(body)); ok {
			t.Fatal("malformed enrollment pairing accepted")
		}
	}
}

func TestSensorRepositoryUsesExplicitPairingOverloadAndChecksResponse(t *testing.T) {
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{}}
	repository := newTestSensorPublicRepository(t, database)
	digest := sha256.Sum256([]byte("sensor-pairing-contract-fixture"))
	expires := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	input := SensorCreateMutation{SensorID: testSensorID, Name: "Production runtime", Kind: "otlp", Mode: "metadata_only", RuntimeSensorID: pairingContractAnchor, IdempotencyKey: "sensor-pairing-idem-0001", RequestDigest: digest[:], TokenID: testTokenID, TokenGeneration: 1, LocatorDigest: digest[:], Salt: digest[:], TokenHash: digest[:], TokenExpiresAt: expires}
	body := strings.Replace(strings.TrimSuffix(sensorRecordJSON(testSensorID, "pending", 1), "}")+`,"runtime_sensor_id":"`+pairingContractAnchor+`"}`, `"kind":"tetragon"`, `"kind":"otlp"`, 1)
	receipt := `{"body":` + body + `,"token_id":"` + testTokenID + `","token_generation":1,"token_expires_at":"2026-09-19T00:00:00Z","replayed":false}`
	database.responses[postgresRuntimePublicCreatePairedSensorSQL] = json.RawMessage(receipt)
	result, err := repository.CreateSensor(context.Background(), fixtureRequestIdentity(t), input)
	if err != nil || result.Sensor.RuntimeSensorID != pairingContractAnchor || database.query != postgresRuntimePublicCreatePairedSensorSQL || len(database.args) != 17 || database.args[16] != pairingContractAnchor {
		t.Fatalf("pairing repository did not bind exact overload: %v", err)
	}
	database.responses[postgresRuntimePublicCreatePairedSensorSQL] = json.RawMessage(strings.Replace(receipt, pairingContractAnchor, "pid_78200009-0000-4000-8000-000000000009", 1))
	if _, err := repository.CreateSensor(context.Background(), fixtureRequestIdentity(t), input); err == nil {
		t.Fatal("different pairing accepted from database response")
	}
}
