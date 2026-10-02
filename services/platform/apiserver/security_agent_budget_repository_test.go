package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type budgetRepositoryDatabase struct {
	securityAgentRepositoryDatabase
	releaseError  error
	releaseChecks int
	queryError    error
}

func (db *budgetRepositoryDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	if db.queryError != nil {
		return nil, db.queryError
	}
	return db.securityAgentRepositoryDatabase.QueryJSON(ctx, statement, args...)
}

func TestSecurityAgentBudgetRepositoryPreservesConflict(t *testing.T) {
	db := &budgetRepositoryDatabase{queryError: ErrRepositoryConflict}
	repository := &SecurityAgentWorkerRepository{database: db}
	claim := budgetRepositoryClaim()
	_, err := repository.ReserveSecurityAgentPlannerBudget(context.Background(), claim, "worker-1", "worker-lease-00000001", SecurityAgentBudgetReservation{ReservationID: "reservation-1", InputDigest: "sha256:" + strings.Repeat("1", 64)})
	if !errors.Is(err, ErrRepositoryConflict) {
		t.Errorf("reserve conflict lost: %v", err)
	}
	_, err = repository.SettleSecurityAgentPlannerBudget(context.Background(), claim, "worker-1", "worker-lease-00000001", SecurityAgentBudgetUsage{ReservationID: "reservation-1"})
	if !errors.Is(err, ErrRepositoryConflict) {
		t.Errorf("settle conflict lost: %v", err)
	}
}

func (db *budgetRepositoryDatabase) VerifySecurityAgentBudgetRelease(context.Context) error {
	db.releaseChecks++
	return db.releaseError
}

func budgetRepositoryClaim() SecurityAgentRunClaim {
	return SecurityAgentRunClaim{OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003", RunID: "pid_78000001-0000-4000-8000-000000000001", DefinitionID: "pid_78000002-0000-4000-8000-000000000002", DefinitionVersion: 3, TriggerID: "pid_78000003-0000-4000-8000-000000000003", State: "planning", Version: 2, Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}
}

func TestSecurityAgentBudgetRepositoryPermits(t *testing.T) {
	claim := budgetRepositoryClaim()
	request := SecurityAgentBudgetReservation{ReservationID: "reservation-1", InputDigest: "sha256:" + strings.Repeat("1", 64), Model: "fixture-model", CostPolicyVersion: "fixture-policy", CostUnit: "openrouter_credit", MaximumTokens: 100, MaximumCostNanoCredits: 200}
	for _, mode := range []string{"valid", "heartbeat", "foreign_org", "foreign_workspace", "foreign_environment", "foreign_run", "wrong_attempt", "stale_version", "huge_version", "wrong_reservation", "wrong_input", "wrong_model", "wrong_policy", "wrong_unit", "wrong_tokens", "null_cost", "expired", "distant_expiry", "extra", "duplicate", "stop", "heartbeat_stop", "wrong_stop", "release_drift"} {
		t.Run(mode, func(t *testing.T) {
			permit := map[string]any{"organization_id": claim.OrganizationID, "workspace_id": claim.WorkspaceID, "environment_id": claim.EnvironmentID, "run_id": claim.RunID, "attempt": 1, "version": 2, "reservation_id": "reservation-1", "input_digest": request.InputDigest, "model": "fixture-model", "cost_policy_version": "fixture-policy", "cost_unit": "openrouter_credit", "maximum_tokens": 100, "maximum_cost_nano_credits": 200, "expires_at": claim.LeaseExpiresAt.Format(time.RFC3339Nano)}
			envelope := map[string]any{"budget_permit": permit}
			switch mode {
			case "heartbeat":
				permit["version"] = 3
				permit["expires_at"] = claim.LeaseExpiresAt.Add(time.Minute).Format(time.RFC3339Nano)
			case "foreign_org":
				permit["organization_id"] = claim.RunID
			case "foreign_workspace":
				permit["workspace_id"] = claim.RunID
			case "foreign_environment":
				permit["environment_id"] = claim.RunID
			case "foreign_run":
				permit["run_id"] = claim.TriggerID
			case "wrong_attempt":
				permit["attempt"] = 2
			case "stale_version":
				permit["version"] = 1
			case "huge_version":
				permit["version"] = 1000001
			case "wrong_reservation":
				permit["reservation_id"] = "different"
			case "wrong_input":
				permit["input_digest"] = "sha256:" + strings.Repeat("2", 64)
			case "wrong_model":
				permit["model"] = "another-model"
			case "wrong_policy":
				permit["cost_policy_version"] = "another-policy"
			case "wrong_unit":
				permit["cost_unit"] = "USD"
			case "wrong_tokens":
				permit["maximum_tokens"] = 101
			case "null_cost":
				permit["maximum_cost_nano_credits"] = nil
			case "expired":
				permit["expires_at"] = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
			case "distant_expiry":
				permit["expires_at"] = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
			case "extra":
				permit["authorized"] = true
			case "stop", "heartbeat_stop", "wrong_stop":
				version := 3
				if mode == "heartbeat_stop" {
					version = 5
				}
				stop := map[string]any{"organization_id": claim.OrganizationID, "workspace_id": claim.WorkspaceID, "environment_id": claim.EnvironmentID, "run_id": claim.RunID, "attempt": 1, "version": version, "state": "needs_human", "reason": "budget_usage_unknown"}
				if mode == "wrong_stop" {
					stop["attempt"] = 2
				}
				envelope = map[string]any{"budget_stop": stop}
			}
			payload, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "duplicate" {
				payload = []byte(strings.Replace(string(payload), `"maximum_tokens":100`, `"maximum_tokens":1,"maximum_tokens":100`, 1))
			}
			db := &budgetRepositoryDatabase{securityAgentRepositoryDatabase: securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{reservePlannerBudgetTestSQL: payload}}}
			if mode == "release_drift" {
				db.releaseError = ErrRepositoryUnavailable
			}
			repository := &SecurityAgentWorkerRepository{database: db}
			result, err := repository.ReserveSecurityAgentPlannerBudget(context.Background(), claim, "worker-1", "worker-lease-00000001", request)
			if mode == "valid" || mode == "heartbeat" {
				if err != nil || result.Reservation != request || result.Version < claim.Version || result.ExpiresAt.IsZero() {
					t.Fatalf("permit rejected: %#v %v", result, err)
				}
			} else {
				want := ErrRepositoryUnavailable
				if mode == "stop" || mode == "heartbeat_stop" {
					want = ErrSecurityAgentBudgetStopped
				}
				if !errors.Is(err, want) || !reflect.DeepEqual(result, SecurityAgentBudgetPermit{}) {
					t.Fatalf("unsafe permit accepted: %#v %v", result, err)
				}
			}
			if db.releaseChecks != 1 {
				t.Fatalf("release checks=%d", db.releaseChecks)
			}
			if mode == "release_drift" {
				if len(db.statements) != 0 {
					t.Fatal("mutation attempted after release drift")
				}
				return
			}
			input, _ := decodeSecurityAgentDigest(request.InputDigest)
			wantArgs := []any{claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, "worker-1", "worker-lease-00000001", claim.Attempt, request.ReservationID, input, request.Model, request.CostPolicyVersion, request.CostUnit, request.MaximumTokens, request.MaximumCostNanoCredits}
			if len(db.statements) != 1 || db.statements[0] != reservePlannerBudgetTestSQL || !reflect.DeepEqual(db.arguments[0], wantArgs) {
				t.Fatalf("wrong scoped request: %#v %#v", db.statements, db.arguments)
			}
		})
	}
}

func TestSecurityAgentBudgetRepositorySettlements(t *testing.T) {
	claim := budgetRepositoryClaim()
	claim.LeaseExpiresAt = time.Now().UTC().Add(-time.Minute)
	for _, mode := range []string{"known_zero", "unknown", "late_stopped", "foreign_org", "wrong_attempt", "wrong_reservation", "null_known", "null_reason", "wrong_known", "unknown_reason", "extra", "duplicate", "release_drift"} {
		t.Run(mode, func(t *testing.T) {
			usage := SecurityAgentBudgetUsage{ReservationID: "reservation-1", OutputDigest: "sha256:" + strings.Repeat("3", 64), Known: mode != "unknown"}
			if mode == "unknown" {
				usage.OutputDigest = ""
			}
			settlement := map[string]any{"organization_id": claim.OrganizationID, "workspace_id": claim.WorkspaceID, "environment_id": claim.EnvironmentID, "run_id": claim.RunID, "attempt": 1, "reservation_id": "reservation-1", "known": usage.Known, "stop_reason": ""}
			if mode == "unknown" || mode == "late_stopped" {
				settlement["stop_reason"] = "budget_usage_unknown"
			}
			switch mode {
			case "foreign_org":
				settlement["organization_id"] = claim.RunID
			case "wrong_attempt":
				settlement["attempt"] = 2
			case "wrong_reservation":
				settlement["reservation_id"] = "different"
			case "null_known":
				settlement["known"] = nil
			case "null_reason":
				settlement["stop_reason"] = nil
			case "wrong_known":
				settlement["known"] = false
			case "unknown_reason":
				settlement["stop_reason"] = "success"
			case "extra":
				settlement["permit"] = true
			}
			payload, err := json.Marshal(map[string]any{"budget_settlement": settlement})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "duplicate" {
				payload = []byte(strings.Replace(string(payload), `"known":true`, `"known":false,"known":true`, 1))
			}
			db := &budgetRepositoryDatabase{securityAgentRepositoryDatabase: securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{settlePlannerBudgetTestSQL: payload}}}
			if mode == "release_drift" {
				db.releaseError = ErrRepositoryUnavailable
			}
			repository := &SecurityAgentWorkerRepository{database: db}
			result, err := repository.SettleSecurityAgentPlannerBudget(context.Background(), claim, "worker-1", "worker-lease-00000001", usage)
			valid := mode == "known_zero" || mode == "unknown" || mode == "late_stopped"
			if valid {
				if err != nil || result.ReservationID != usage.ReservationID || result.Known != usage.Known || result.StopReason != settlement["stop_reason"] {
					t.Fatalf("settlement rejected: %#v %v", result, err)
				}
			} else if !errors.Is(err, ErrRepositoryUnavailable) || !reflect.DeepEqual(result, SecurityAgentBudgetSettlement{}) {
				t.Fatalf("unsafe settlement accepted: %#v %v", result, err)
			}
			if db.releaseChecks != 1 {
				t.Fatalf("release checks=%d", db.releaseChecks)
			}
			if mode == "release_drift" {
				if len(db.statements) != 0 {
					t.Fatal("settlement attempted after release drift")
				}
				return
			}
			var output any
			var prompt, completion, total, cost any
			if usage.Known {
				output, _ = decodeSecurityAgentDigest(usage.OutputDigest)
				prompt, completion, total, cost = int64(0), int64(0), int64(0), int64(0)
			}
			want := []any{claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, "worker-1", "worker-lease-00000001", claim.Attempt, usage.ReservationID, output, prompt, completion, total, cost}
			if len(db.statements) != 1 || db.statements[0] != settlePlannerBudgetTestSQL || !reflect.DeepEqual(db.arguments[0], want) {
				t.Fatalf("unknown/zero or scope corrupted: %#v", db.arguments)
			}
		})
	}
}
