package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

const sandboxSearchReadySQL = `SELECT to_jsonb(zasp_production_runtime_sandbox_binding_readiness($1,$2) AND zasp_runtime_principal_ready('zasp_runtime_index_worker'))`

type sandboxSearchQuery struct {
	sql  string
	args []any
}

type sandboxSearchDatabase struct {
	readyWorkerDatabase
	queries []sandboxSearchQuery
	query   func(string, ...any) (json.RawMessage, error)
}

func (db *sandboxSearchDatabase) QueryJSON(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	db.queries = append(db.queries, sandboxSearchQuery{sql, args})
	if db.query != nil {
		return db.query(sql, args...)
	}
	return db.readyWorkerDatabase.QueryJSON(ctx, sql, args...)
}

func sandboxSearchStage() *productionRuntimeStageDependencies {
	return &productionRuntimeStageDependencies{
		Stage: runtimeevent.RuntimeStageIndex,
		Executor: runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
			return runtimeStageEffect{}, errRuntimeStageRetryable
		}),
		Sessions: sessionSearchExecuteFunc(func(context.Context, runtimeSessionSearchLease) ([]string, error) {
			return nil, errRuntimeStageRetryable
		}),
		SessionReady: func(context.Context) error { return nil },
		ready:        func(context.Context) error { return nil },
		close:        func() error { return nil },
	}
}

// Catches a factory that selects the v2 provider but retains the v1 queue authority.
func TestSandboxSearchFactoryPinsSelectedAuthorityAtStartup(t *testing.T) {
	config := validRuntimeIndexConfig()
	config.RuntimeSessionIndex = "zasp-runtime-sessions-v2"
	db := &sandboxSearchDatabase{}
	dependencies, err := composeRuntimeStageWorkerRuntime(config, db, sandboxSearchStage())
	if err != nil {
		t.Fatal(err)
	}
	if err := dependencies.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, query := range db.queries {
		if strings.Contains(query.sql, "session_search_readiness") {
			t.Fatalf("v2 startup used v1 readiness: %s", query.sql)
		}
		if query.sql == sandboxSearchReadySQL {
			found = true
			if !reflect.DeepEqual(query.args, []any{migrations.ProductionRuntimeSandboxBinding().Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()}) {
				t.Fatalf("startup readiness did not pin compiled release50: %v", query.args)
			}
		}
	}
	if !found {
		t.Fatal("v2 startup omitted release50 readiness")
	}
}

func configuredSearchAuthority(t *testing.T, name string, db *sandboxSearchDatabase) *postgresRuntimeSessionSearchAuthority {
	t.Helper()
	config := validRuntimeIndexConfig()
	config.RuntimeSessionIndex = name
	dependencies, err := composeRuntimeStageWorkerRuntime(config, db, sandboxSearchStage())
	if err != nil {
		t.Fatal(err)
	}
	return dependencies.Processor.(runtimeIndexAndSessionProcessor).sessions.(readinessGatedWorkerProcessor).delegate.(*runtimeSessionSearchProcessor).config.Authority.(*postgresRuntimeSessionSearchAuthority)
}

func sandboxSearchReply(t *testing.T, lease runtimeSessionSearchLease, operation string) json.RawMessage {
	t.Helper()
	if operation == "claim" {
		return sessionSearchLeaseJSON(t, lease)
	}
	var value any = map[string]any{"lease_until": time.Now().UTC().Add(30 * time.Second)}
	if operation == "finish" {
		value = map[string]any{"state": "indexed", "batch_id": lease.Binding.BatchID.String(), "generation": lease.Binding.Generation, "attempt": lease.Attempt, "receipt_digest": hex.EncodeToString(lease.Binding.ReceiptDigest[:]), "indexed_at": time.Now().UTC()}
	}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func callSandboxSearchOperation(authority *postgresRuntimeSessionSearchAuthority, lease runtimeSessionSearchLease, operation string) error {
	switch operation {
	case "claim":
		_, err := authority.Claim(context.Background(), "search-worker", "search-lease-token-0001", 30)
		return err
	case "heartbeat":
		_, err := authority.Heartbeat(context.Background(), lease, "search-worker", "search-lease-token-0001", 30)
		return err
	default:
		return authority.Finish(context.Background(), lease, "search-worker", "search-lease-token-0001", "indexed", lease.DocumentIDs, 0)
	}
}

func claimConfiguredSearchLease(t *testing.T, authority *postgresRuntimeSessionSearchAuthority, db *sandboxSearchDatabase, fixture runtimeSessionSearchLease) runtimeSessionSearchLease {
	t.Helper()
	db.query = func(sql string, _ ...any) (json.RawMessage, error) {
		if strings.Contains(sql, "readiness") {
			return json.RawMessage(`true`), nil
		}
		return sessionSearchLeaseJSON(t, fixture), nil
	}
	lease, err := authority.Claim(context.Background(), "search-worker", "search-lease-token-0001", 30)
	if err != nil || lease == nil {
		t.Fatalf("claim: %v %v", lease, err)
	}
	db.queries = nil
	return *lease
}

// Catches wrong SQL selection, unpinned readiness, and startup-only readiness caching.
func TestSandboxSearchEveryMutationChecksCompiled50ThenFixedSQL(t *testing.T) {
	for _, operation := range []string{"claim", "heartbeat", "finish"} {
		t.Run(operation, func(t *testing.T) {
			fixture, _, _ := sessionSearchWorkerFixture(t)
			db := &sandboxSearchDatabase{}
			authority := configuredSearchAuthority(t, "zasp-runtime-sessions-v2", db)
			lease := claimConfiguredSearchLease(t, authority, db, fixture)
			db.query = func(sql string, _ ...any) (json.RawMessage, error) {
				if sql == sandboxSearchReadySQL {
					return json.RawMessage(`true`), nil
				}
				return sandboxSearchReply(t, fixture, operation), nil
			}
			for range 2 {
				if err := callSandboxSearchOperation(authority, lease, operation); err != nil {
					t.Fatal(err)
				}
			}
			wantSQL := map[string]string{
				"claim":     `SELECT COALESCE(zasp_runtime_sandbox_search_claim($1,$2,$3),'null'::jsonb)`,
				"heartbeat": `SELECT zasp_runtime_sandbox_search_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
				"finish":    `SELECT zasp_runtime_sandbox_search_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			}[operation]
			if len(db.queries) != 4 {
				t.Fatalf("each mutation requires fresh readiness: queries=%v", db.queries)
			}
			for i, query := range db.queries {
				if i%2 == 0 {
					if query.sql != sandboxSearchReadySQL || !reflect.DeepEqual(query.args, []any{migrations.ProductionRuntimeSandboxBinding().Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()}) {
						t.Fatalf("wrong readiness: %v", query)
					}
				} else if query.sql != wantSQL {
					t.Fatalf("wrong mutation: %s", query.sql)
				}
			}
			args := db.queries[1].args
			wantArgs := []any{"search-worker", "search-lease-token-0001", 30}
			if operation != "claim" {
				wantArgs = []any{fixture.Binding.Scope.OrganizationID().String(), fixture.Binding.Scope.WorkspaceID().String(), fixture.Binding.Scope.EnvironmentID().String(), fixture.Binding.BatchID.String(), fixture.Binding.Generation, "search-worker", "search-lease-token-0001", fixture.Attempt}
				if operation == "heartbeat" {
					wantArgs = append(wantArgs, 30)
				} else {
					wantArgs = append(wantArgs, fixture.Binding.ReceiptDigest[:], "indexed", fixture.DocumentIDs, 0)
				}
			}
			if !reflect.DeepEqual(args, wantArgs) {
				t.Fatalf("lease arguments changed: %v", args)
			}
		})
	}
}

// Catches readiness failures that are cached, ignored, or retried through v1.
func TestSandboxSearchReadinessDriftBlocksEveryMutationWithoutFallback(t *testing.T) {
	for _, operation := range []string{"claim", "heartbeat", "finish"} {
		for _, fault := range []string{"false", "null", `"true"`, `{}`, `true false`, "missing function", "denied"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				fixture, _, _ := sessionSearchWorkerFixture(t)
				db := &sandboxSearchDatabase{}
				authority := configuredSearchAuthority(t, "zasp-runtime-sessions-v2", db)
				lease := claimConfiguredSearchLease(t, authority, db, fixture)
				if authority.Ready(context.Background()) != nil {
					t.Fatal("initial readiness")
				}
				db.queries = nil
				db.query = func(sql string, _ ...any) (json.RawMessage, error) {
					if sql != sandboxSearchReadySQL {
						return sandboxSearchReply(t, fixture, operation), nil
					}
					if fault == "missing function" || fault == "denied" {
						return nil, errors.New(fault)
					}
					return json.RawMessage(fault), nil
				}
				if callSandboxSearchOperation(authority, lease, operation) == nil {
					t.Fatal("mutation accepted after readiness drift")
				}
				if len(db.queries) != 1 || db.queries[0].sql != sandboxSearchReadySQL {
					t.Fatalf("failed readiness reached mutation/fallback: %v", db.queries)
				}
			})
		}
	}
}

func TestSandboxSearchMutationFailureNeverFallsBack(t *testing.T) {
	for _, operation := range []string{"claim", "heartbeat", "finish"} {
		for _, fault := range []string{"missing", "denied", "malformed"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				fixture, _, _ := sessionSearchWorkerFixture(t)
				db := &sandboxSearchDatabase{}
				authority := configuredSearchAuthority(t, "zasp-runtime-sessions-v2", db)
				lease := claimConfiguredSearchLease(t, authority, db, fixture)
				db.query = func(sql string, _ ...any) (json.RawMessage, error) {
					if sql == sandboxSearchReadySQL {
						return json.RawMessage(`true`), nil
					}
					if fault == "malformed" {
						return json.RawMessage(`{}`), nil
					}
					return nil, errors.New(fault)
				}
				if callSandboxSearchOperation(authority, lease, operation) == nil {
					t.Fatal("failed mutation accepted")
				}
				if len(db.queries) != 2 || !strings.Contains(db.queries[1].sql, "zasp_runtime_sandbox_search_"+operation) {
					t.Fatalf("unexpected fallback: %v", db.queries)
				}
			})
		}
	}
}

func TestSandboxSearchRejectsCrossTargetLeasesBeforeDatabase(t *testing.T) {
	for _, source := range []string{"", "zasp-runtime-sessions-v1", "zasp-runtime-sessions-v2"} {
		for _, target := range []string{"zasp-runtime-sessions-v1", "zasp-runtime-sessions-v2"} {
			if source == target || source == "" && target == "zasp-runtime-sessions-v1" {
				continue
			}
			t.Run(source+"/"+target, func(t *testing.T) {
				fixture, _, _ := sessionSearchWorkerFixture(t)
				sourceDB, targetDB := &sandboxSearchDatabase{}, &sandboxSearchDatabase{}
				lease := claimConfiguredSearchLease(t, configuredSearchAuthority(t, source, sourceDB), sourceDB, fixture)
				authority := configuredSearchAuthority(t, target, targetDB)
				for _, operation := range []string{"heartbeat", "finish"} {
					targetDB.query = func(string, ...any) (json.RawMessage, error) { return sandboxSearchReply(t, fixture, operation), nil }
					if callSandboxSearchOperation(authority, lease, operation) == nil {
						t.Fatal("cross-target lease accepted")
					}
				}
				if len(targetDB.queries) != 0 {
					t.Fatal("cross-target lease reached database")
				}
			})
		}
	}
}

func TestSandboxSearchLegacyAuthorityCallsRemainUnchanged(t *testing.T) {
	for _, name := range []string{"constructor", "", "zasp-runtime-sessions-v1"} {
		t.Run(name, func(t *testing.T) {
			fixture, _, _ := sessionSearchWorkerFixture(t)
			db := &sandboxSearchDatabase{}
			var authority *postgresRuntimeSessionSearchAuthority
			if name == "constructor" {
				authority, _ = newPostgresRuntimeSessionSearchAuthority(db)
			} else {
				authority = configuredSearchAuthority(t, name, db)
			}
			if authority.Ready(context.Background()) != nil {
				t.Fatal("v1 readiness")
			}
			if len(db.queries) != 1 || db.queries[0].sql != `SELECT to_jsonb(zasp_production_runtime_session_search_readiness($1,$2) AND zasp_runtime_session_search_worker_ready())` || !reflect.DeepEqual(db.queries[0].args, []any{migrations.ProductionRuntimeSessionSearch().Checksum(), migrations.ProductionRuntimeSessionSearchSemanticFingerprint()}) {
				t.Fatalf("legacy readiness changed: %v", db.queries)
			}
			for _, operation := range []string{"claim", "heartbeat", "finish"} {
				db.queries = nil
				db.query = func(string, ...any) (json.RawMessage, error) { return sandboxSearchReply(t, fixture, operation), nil }
				if callSandboxSearchOperation(authority, fixture, operation) != nil {
					t.Fatal("legacy mutation failed", operation)
				}
				if len(db.queries) != 1 || !strings.Contains(db.queries[0].sql, "zasp_runtime_session_search_"+operation) {
					t.Fatalf("v1 authority changed: %v", db.queries)
				}
			}
		})
	}
}

func TestSandboxSearchFactoryRejectsInvalidSelectionBeforeDatabase(t *testing.T) {
	for _, name := range []string{"zasp-runtime-sessions-v3", "*", "zasp-runtime-sessions-v2*", " Zasp-runtime-sessions-v2", "zasp-runtime-sessions-v2 ", "zasp-runtime-sessions-v2;SELECT 1"} {
		t.Run(name, func(t *testing.T) {
			config := validRuntimeIndexConfig()
			config.RuntimeSessionIndex = name
			db := &sandboxSearchDatabase{}
			if _, err := composeRuntimeStageWorkerRuntime(config, db, sandboxSearchStage()); err == nil {
				t.Fatal("invalid selector accepted")
			}
			if len(db.queries) != 0 {
				t.Fatal("invalid selector reached database")
			}
			if authority, err := newConfiguredPostgresRuntimeSessionSearchAuthority(db, name); err == nil || authority != nil {
				t.Fatal("authority constructor accepted invalid selector")
			}
			if len(db.queries) != 0 {
				t.Fatal("invalid authority constructor reached database")
			}
		})
	}
}

func TestSandboxSearchConstructorRejectsMissingDatabase(t *testing.T) {
	var typedNil *sandboxSearchDatabase
	for _, database := range []recoveryJSONDatabase{nil, typedNil} {
		for _, name := range []string{"", "zasp-runtime-sessions-v1", "zasp-runtime-sessions-v2"} {
			if authority, err := newConfiguredPostgresRuntimeSessionSearchAuthority(database, name); err == nil || authority != nil {
				t.Fatal("missing database accepted", name)
			}
		}
	}
}
