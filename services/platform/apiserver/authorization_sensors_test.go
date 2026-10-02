package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestP7SensorCheckedStatements(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	c := context.WithValue(context.Background(), requestAuthorizationContextKey{}, RequestAuthorization{})
	digest := sha256.Sum256([]byte("sensor-fixture"))
	create := SensorCreateMutation{SensorID: testSensorID, Name: "Runtime", Kind: "otlp", Mode: "metadata_only", IdempotencyKey: "sensor-authorization-01", RequestDigest: digest[:], TokenID: testTokenID, TokenGeneration: 1, LocatorDigest: digest[:], Salt: digest[:], TokenHash: digest[:], TokenExpiresAt: time.Now().UTC().Add(time.Hour)}
	for _, tc := range []struct {
		name, sql string
		call      func(*SensorPublicRepository)
	}{
		{"list", "SELECT zasp_authorization80.sensor_page($1,$2,$3,NULLIF($4,''),$5)", func(r *SensorPublicRepository) { _, _ = r.ListSensors(c, identity.Scope, "", 1) }},
		{"detail", "SELECT zasp_authorization80.sensor_detail($1,$2,$3,$4)", func(r *SensorPublicRepository) { _, _ = r.GetSensor(c, identity.Scope, testSensorID) }},
		{"coverage", "SELECT zasp_authorization80.sensor_coverage($1,$2,$3,$4)", func(r *SensorPublicRepository) { _, _ = r.GetSensorCoverage(c, identity.Scope, testSensorID) }},
		{"token authority", "SELECT zasp_authorization80.sensor_token_authority($1,$2,$3,$4)", func(r *SensorPublicRepository) { _, _ = r.GetSensorTokenAuthority(c, identity.Scope, testSensorID) }},
		{"create", "SELECT zasp_authorization80.create_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)", func(r *SensorPublicRepository) { _, _ = r.CreateSensor(c, identity, create) }},
		{"paired", "SELECT zasp_authorization80.create_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)", func(r *SensorPublicRepository) {
			paired := create
			paired.RuntimeSensorID = "pid_91000003-0000-4000-8000-000000000003"
			_, _ = r.CreateSensor(c, identity, paired)
		}},
		{"update", "SELECT zasp_authorization80.update_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", func(r *SensorPublicRepository) {
			_, _ = r.UpdateSensor(c, identity, SensorUpdateMutation{SensorID: testSensorID, Name: "Runtime", Mode: "metadata_only", ExpectedVersion: 1, IdempotencyKey: create.IdempotencyKey, RequestDigest: digest[:]})
		}},
		{"delete", "SELECT zasp_authorization80.delete_sensor($1,$2,$3,$4,$5,$6,$7,$8)", func(r *SensorPublicRepository) {
			_, _ = r.DeleteSensor(c, identity, SensorDeleteMutation{SensorID: testSensorID, ExpectedVersion: 1, IdempotencyKey: create.IdempotencyKey, RequestDigest: digest[:]})
		}},
		{"rotate", "SELECT zasp_authorization80.rotate_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)", func(r *SensorPublicRepository) {
			_, _ = r.RotateSensorToken(c, identity, SensorRotateMutation{SensorID: testSensorID, ExpectedVersion: 1, IdempotencyKey: create.IdempotencyKey, RequestDigest: digest[:], TokenID: testTokenID, TokenGeneration: 2, LocatorDigest: digest[:], Salt: digest[:], TokenHash: digest[:], TokenExpiresAt: create.TokenExpiresAt})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := &workflowCallDatabase{}
			tc.call(&SensorPublicRepository{database: database})
			if database.query != tc.sql {
				t.Fatalf("checked sensor statement=%q want%q", database.query, tc.sql)
			}
		})
	}
}

func TestP7SensorCursorIsRequestBound(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &sensorPublicHandlerRepository{page: SensorPage{Items: []ProductSensor{publicHandlerSensor(testSensorID, 1)}, NextID: testSensorID}}
	baseKey := bytes.Repeat([]byte{0x55}, 32)
	raw, err := NewSensorPublicHTTPHandler(repository, baseKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := raw.(*sensorPublicHTTPHandler)
	grant := RequestAuthorization{Identity: identity, OperationID: "listSensors", Collection: true, Credential: CredentialBinding{ID: "session-cursor-one"}}
	call := func(proof RequestAuthorization, cursor string) *httptest.ResponseRecorder {
		path := "/api/v1/sensors?limit=1"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		request := httptest.NewRequest(http.MethodGet, path, nil)
		c := context.WithValue(request.Context(), identityContextKey{}, identity)
		c = context.WithValue(c, routedOperationContextKey{}, RoutedOperation{OperationID: "listSensors", PathParameters: map[string]string{}})
		c = context.WithValue(c, requestAuthorizationContextKey{}, proof)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request.WithContext(c))
		return response
	}
	first := call(grant, "")
	if first.Code != http.StatusOK {
		t.Fatal(first.Code)
	}
	var page struct {
		PageInfo struct {
			Cursor string `json:"next_cursor"`
		} `json:"page_info"`
	}
	if json.Unmarshal(first.Body.Bytes(), &page) != nil || page.PageInfo.Cursor == "" {
		t.Fatal("cursor missing")
	}
	changed := grant
	changed.Credential.ID = "session-cursor-two"
	if response := call(changed, page.PageInfo.Cursor); response.Code != http.StatusNotFound {
		t.Fatalf("foreign credential cursor accepted: %d", response.Code)
	}
	changed = grant
	changed.Revision.Desired++
	if response := call(changed, page.PageInfo.Cursor); response.Code != http.StatusNotFound {
		t.Fatalf("stale revision cursor accepted: %d", response.Code)
	}
	if response := call(grant, page.PageInfo.Cursor); response.Code != http.StatusOK {
		t.Fatalf("same proof cursor rejected: %d", response.Code)
	}
	if !bytes.Equal(handler.signingKey, baseKey) {
		t.Fatal("shared handler key mutated")
	}
}
