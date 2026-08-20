package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestGatewayPostgresControlUsesExactV15ReadinessAndAuthority(t *testing.T) {
	authority := gatewayRuntimeAuthority()
	database := &gatewayDatabaseStub{responses: []any{
		true,
		json.RawMessage(`{"organization_id":"` + authority.OrganizationID + `","workspace_id":"` + authority.WorkspaceID + `","environment_id":"` + authority.EnvironmentID + `","device_id":"` + authority.DeviceID + `","device_version":3,"replay_floor":7,"credential_id":"` + authority.CredentialID + `","credential_generation":2,"key_id":"gateway-key-1","algorithm":"Ed25519","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","audience":"runtime-gateway","expires_at":"2026-08-21T12:00:00Z"}`),
	}}
	control, err := newGatewayPostgresControl(database, time.Second)
	if err != nil || control.Ready(context.Background()) != nil {
		t.Fatalf("control=%#v err=%v", control, err)
	}
	actual, err := control.Authority(context.Background(), authority.CredentialID)
	if err != nil || actual.ReplayFloor != 7 || !sameGatewayAuthority(actual, authority) {
		t.Fatalf("authority=%#v err=%v", actual, err)
	}
	metadata := migrations.ProductionRuntimeDataPlane()
	if !reflect.DeepEqual(database.calls[0].arguments, []any{metadata.Checksum(), migrations.ProductionRuntimeDataPlaneSemanticFingerprint()}) || database.calls[1].arguments[0] != authority.CredentialID {
		t.Fatalf("calls=%#v", database.calls)
	}
}

func TestGatewayPostgresControlStrictlyDecodesPolicyAndNoUpdate(t *testing.T) {
	authority := gatewayRuntimeAuthority()
	database := &gatewayDatabaseStub{responses: []any{
		nil,
		json.RawMessage(`{"contract_version":1,"key_id":"gateway-key-1","algorithm":"Ed25519","audience":"runtime-gateway-policy","organization_id":"` + authority.OrganizationID + `","workspace_id":"` + authority.WorkspaceID + `","environment_id":"` + authority.EnvironmentID + `","device_id":"` + authority.DeviceID + `","credential_id":"` + authority.CredentialID + `","sequence":3,"policy_version":2,"issued_at":"2026-08-20T11:00:00.000000Z","expires_at":"2026-08-20T13:00:00.000000Z","failure_mode":"closed","payload_digest":"` + strings.Repeat("a", 64) + `","policies":[],"signature":"` + strings.Repeat("A", 86) + `"}`),
	}}
	control, _ := newGatewayPostgresControl(database, time.Second)
	if envelope, err := control.Policy(context.Background(), authority.CredentialID, 2); err != nil || envelope != nil {
		t.Fatalf("no update envelope=%#v err=%v", envelope, err)
	}
	envelope, err := control.Policy(context.Background(), authority.CredentialID, 2)
	if err != nil || envelope == nil || envelope.Sequence != 3 || envelope.PolicyVersion != 2 {
		t.Fatalf("envelope=%#v err=%v", envelope, err)
	}
	if !reflect.DeepEqual(database.calls[0].arguments, []any{authority.CredentialID, uint64(2)}) {
		t.Fatalf("arguments=%#v", database.calls[0].arguments)
	}
}

func TestGatewayPostgresControlRecordsThroughServerCanonicalDigest(t *testing.T) {
	authority := gatewayRuntimeAuthority()
	event := gatewayDecisionEvent{CredentialID: authority.CredentialID, DeviceID: authority.DeviceID, EventID: gatewayRuntimeID(9), ExpectedFloor: 4, NextFloor: 5, PolicyVersion: 3, Decision: "monitor", ActionKind: "mcp", Classification: gatewayRuntimeClassification("monitored"), OccurredAt: gatewayRuntimeTime()}
	database := &gatewayDatabaseStub{responses: []any{json.RawMessage(`{"event_id":"` + event.EventID + `","device_id":"` + event.DeviceID + `","sequence":5,"recorded_at":"2026-08-20T12:00:01Z","replayed":false}`)}}
	control, _ := newGatewayPostgresControl(database, time.Second)
	if err := control.Record(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	call := database.calls[0]
	if !strings.Contains(call.statement, "digest(convert_to(jsonb_build_object") || strings.Contains(call.statement, "request_digest_value") || len(call.arguments) != 10 {
		t.Fatalf("call=%#v", call)
	}
	if call.arguments[0] != event.CredentialID || call.arguments[1] != event.EventID || call.arguments[2] != event.ExpectedFloor || call.arguments[3] != event.NextFloor {
		t.Fatalf("arguments=%#v", call.arguments)
	}
}

func TestGatewayPostgresControlRejectsHostileOutputs(t *testing.T) {
	authority := gatewayRuntimeAuthority()
	for _, response := range []any{
		json.RawMessage(`{"organization_id":"` + authority.OrganizationID + `","workspace_id":"` + authority.WorkspaceID + `","environment_id":"` + authority.EnvironmentID + `","device_id":"` + authority.DeviceID + `","device_version":3,"replay_floor":7,"credential_id":"` + authority.CredentialID + `","credential_generation":2,"key_id":"gateway-key-1","algorithm":"Ed25519","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","audience":"runtime-gateway","expires_at":"2026-08-21T12:00:00Z","secret":"leak"}`),
		json.RawMessage(`{"organization_id":"` + authority.OrganizationID + `","workspace_id":"` + authority.WorkspaceID + `","environment_id":"` + authority.EnvironmentID + `","device_id":"` + authority.DeviceID + `","device_version":3,"replay_floor":-1,"credential_id":"` + authority.CredentialID + `","credential_generation":2,"key_id":"gateway-key-1","algorithm":"Ed25519","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","audience":"runtime-gateway","expires_at":"2026-08-21T12:00:00Z"}`),
	} {
		control, _ := newGatewayPostgresControl(&gatewayDatabaseStub{responses: []any{response}}, time.Second)
		if result, err := control.Authority(context.Background(), authority.CredentialID); !errors.Is(err, errGatewayRepository) || result.CredentialID != "" {
			t.Fatalf("response=%s result=%#v err=%v", response, result, err)
		}
	}
}

type gatewayDatabaseCall struct {
	statement string
	arguments []any
}

type gatewayDatabaseStub struct {
	responses []any
	calls     []gatewayDatabaseCall
}

func (database *gatewayDatabaseStub) QueryRow(_ context.Context, statement string, arguments ...any) gatewayDatabaseRow {
	database.calls = append(database.calls, gatewayDatabaseCall{statement: statement, arguments: append([]any(nil), arguments...)})
	if len(database.responses) == 0 {
		return gatewayRowStub{err: errors.New("unexpected query")}
	}
	response := database.responses[0]
	database.responses = database.responses[1:]
	return gatewayRowStub{value: response}
}

type gatewayRowStub struct {
	value any
	err   error
}

func (row gatewayRowStub) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != 1 {
		return errors.New("unexpected destinations")
	}
	switch destination := destinations[0].(type) {
	case *bool:
		value, ok := row.value.(bool)
		if !ok {
			return errors.New("unexpected boolean")
		}
		*destination = value
	case *json.RawMessage:
		if row.value == nil {
			*destination = nil
			return nil
		}
		value, ok := row.value.(json.RawMessage)
		if !ok {
			return errors.New("unexpected json")
		}
		*destination = append((*destination)[:0], value...)
	default:
		return errors.New("unexpected destination")
	}
	return nil
}
