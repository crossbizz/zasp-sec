package apiserver

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestPreciseOutboxRequiresCompiledRelease51(t *testing.T) {
	const readySQL = `SELECT to_jsonb(zasp_production_runtime_precision_readiness($1,$2) AND zasp_discovery_principal_ready($3))`
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{readySQL: json.RawMessage(`true`)}}
	repository, err := NewPreciseRuntimeOutboxRepository(database)
	if err != nil || repository == nil {
		t.Fatal("explicit precision authority unavailable", err)
	}
	if err := repository.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []any{migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint(), "zasp_outbox_worker"}
	if calls := database.callsFor(readySQL); len(calls) != 2 || !reflect.DeepEqual(calls[0], want) {
		t.Fatal("precision readiness did not bind compiled release and principal", calls)
	}
}

func TestPreciseOutboxTransitionsRefuseDriftBeforeSQL(t *testing.T) {
	scope := fixtureRequestIdentity(t).Scope
	for _, response := range []string{`false`, `null`, `"true"`, `{"ready":false,"ready":true}`, `true false`} {
		for _, operation := range []string{"heartbeat", "ack", "retry"} {
			t.Run(operation+response, func(t *testing.T) {
				database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresPreciseRuntimeOutboxReadySQL: json.RawMessage(`true`)}}
				repository, err := NewPreciseRuntimeOutboxRepository(database)
				if err != nil {
					t.Fatal(err)
				}
				database.responses[postgresPreciseRuntimeOutboxReadySQL] = json.RawMessage(response)
				before := len(database.queries)
				switch operation {
				case "heartbeat":
					_, err = repository.HeartbeatOutboxTopic(context.Background(), "runtime-events", "runtime-outbox-01", "0123456789abcdef", 30, 1)
				case "ack":
					_, err = repository.AcknowledgeOutboxTopic(context.Background(), "runtime-events", scope, "pid_75000003-0000-4000-8000-000000000003", "runtime-outbox-01", "0123456789abcdef", "sha256:"+strings.Repeat("c", 64))
				case "retry":
					_, err = repository.RetryOutboxTopic(context.Background(), "runtime-events", scope, "pid_75000003-0000-4000-8000-000000000003", "runtime-outbox-01", "0123456789abcdef", 30, "queue_publish_unknown")
				}
				if err == nil || len(database.queries) != before+1 || database.queries[before] != postgresPreciseRuntimeOutboxReadySQL {
					t.Fatal("drifted transition reached operation SQL", database.queries, err)
				}
			})
		}
	}
}

func TestPreciseOutboxDoesNotFallBackToLegacyReadiness(t *testing.T) {
	for _, response := range []string{`false`, `null`, `"true"`, `{"ready":true}`, `true false`} {
		database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
			postgresPreciseRuntimeOutboxReadySQL: json.RawMessage(response), postgresProductionRecoveryRuntimeOutboxReadySQL: json.RawMessage(`{"ready":true}`),
		}}
		if repository, err := NewPreciseRuntimeOutboxRepository(database); err == nil || repository != nil || len(database.queries) != 1 {
			t.Fatal("precision fell back to legacy readiness", response, err)
		}
	}
	if repository, err := NewPreciseRuntimeOutboxRepository(nil); err == nil || repository != nil {
		t.Fatal("nil database accepted")
	}
}

func TestPreciseOutboxCapabilityRejectsLegacyRepository(t *testing.T) {
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresPreciseRuntimeOutboxReadySQL: json.RawMessage(`true`), postgresProductionRecoveryRuntimeOutboxReadySQL: json.RawMessage(`{"ready":true}`),
	}}
	for _, precise := range []bool{false, true} {
		constructor := NewRuntimeOutboxRepository
		if precise {
			constructor = NewPreciseRuntimeOutboxRepository
		}
		repository, err := constructor(database)
		if err != nil {
			t.Fatal(err)
		}
		capability, ok := any(repository).(interface{ ReadyPrecision(context.Context) error })
		if !ok {
			t.Fatal("outbox repository lacks precise capability")
		}
		if err := capability.ReadyPrecision(context.Background()); (err == nil) != precise {
			t.Fatal("legacy authority passed precise check", precise, err)
		}
		before := len(database.queries)
		if err := capability.ReadyPrecision(nil); err == nil || len(database.queries) != before {
			t.Fatal("nil context reached database", err)
		}
	}
}

func TestPreciseOutboxClaimsOnlyExplicitVersionedEntry(t *testing.T) {
	const claimSQL = `SELECT zasp_runtime_claim_outbox_v2($1,$2,$3,$4,$5)`
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresPreciseRuntimeOutboxReadySQL: json.RawMessage(`true`), claimSQL: json.RawMessage(`{"items":[]}`),
	}}
	repository, err := NewPreciseRuntimeOutboxRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if items, err := repository.ClaimOutboxTopic(context.Background(), "runtime-events", "runtime-outbox-01", "0123456789abcdef", 30, 10); err != nil || len(items) != 0 {
		t.Fatal("versioned claim failed", err)
	}
	if len(database.callsFor(postgresRuntimeClaimOutboxSQL)) != 0 || len(database.callsFor(claimSQL)) != 1 {
		t.Fatal("legacy claim selected")
	}
	if !reflect.DeepEqual(database.callsFor(claimSQL)[0], []any{"runtime-events", "runtime-outbox-01", "0123456789abcdef", 30, 10}) {
		t.Fatal("claim authority arguments changed")
	}
	database.responses[postgresPreciseRuntimeOutboxReadySQL] = json.RawMessage(`false`)
	if _, err := repository.ClaimOutboxTopic(context.Background(), "runtime-events", "runtime-outbox-01", "0123456789abcdef", 30, 10); err == nil || len(database.callsFor(claimSQL)) != 1 {
		t.Fatal("drifted claim reached SQL", err)
	}
}
