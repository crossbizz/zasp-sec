package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"reflect"
	"strings"
	"testing"
	"time"
)

type existingTestReadRouteDatabase struct {
	workflowCallDatabase
	available  bool
	releaseErr error
	scopeArgs  []any
	history    []string
	namespace  json.RawMessage
	probeErr   error
	ready      json.RawMessage
	definition json.RawMessage
}

func (d *existingTestReadRouteDatabase) SecurityAgentExistingTestDefinitionsAvailable(context.Context) (bool, error) {
	return d.available, d.releaseErr
}

// Historical release tests must model mandatory newer-family probes explicitly.
// Only the terminal operation receives the injected query failure.
func (d *existingTestReadRouteDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	d.history = append(d.history, query)
	switch query {
	case `SELECT to_jsonb(to_regnamespace('zasp_temporal78') IS NOT NULL)`:
		if len(args) != 0 {
			return nil, errors.New("namespace probe arguments drifted")
		}
		if d.probeErr != nil {
			return nil, d.probeErr
		}
		if d.namespace != nil {
			return d.namespace, nil
		}
		return json.RawMessage(`false`), nil
	case `SELECT to_jsonb(zasp_temporal78.api_ready($1,$2))`:
		if !reflect.DeepEqual(args, []any{migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint()}) {
			return nil, errors.New("readiness pins drifted")
		}
		return d.ready, nil
	case postgresSecurityAgentDefinitionValueSQL:
		if !reflect.DeepEqual(args, d.scopeArgs) {
			return nil, errors.New("definition scope drifted")
		}
		if d.definition != nil {
			return d.definition, nil
		}
		return json.RawMessage(`{"body":{"id":"` + args[3].(string) + `"},"version":1,"secret_generation":0}`), nil
	}
	return d.workflowCallDatabase.QueryJSON(ctx, query, args...)
}

func TestSecurityAgentExistingTestReadRouting(t *testing.T) {
	for _, operation := range []string{"run", "approval", "page", "decision", "activate", "simulate"} {
		t.Run(operation, func(t *testing.T) {
			failure := errors.New("query boundary")
			db := &existingTestReadRouteDatabase{workflowCallDatabase: workflowCallDatabase{err: failure}}
			repo := &PostgresRepository{database: db, securityAgentExecution: true, schema: SecurityAgentSessionIsolationSchemaVersion}
			identity := fixtureRequestIdentity(t)
			identity.FreshAuthenticated = true
			identity.FreshAuthExpiresAt = time.Now().UTC().Add(time.Minute)
			id := "pid_89c00300-0000-4000-8000-000000000003"
			db.scopeArgs = []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), id}
			invoke := func() error {
				switch operation {
				case "run":
					_, err := repo.GetSecurityAgentRun(context.Background(), identity, id)
					return err
				case "approval":
					_, err := repo.GetSecurityAgentApproval(context.Background(), identity, id)
					return err
				case "page":
					_, err := repo.ListSecurityAgentApprovals(context.Background(), identity, SecurityAgentApprovalPageRequest{Limit: 10})
					return err
				case "decision":
					_, err := repo.DecideSecurityAgentApproval(context.Background(), identity, SecurityAgentApprovalDecisionRequest{ApprovalID: id, IdempotencyKey: "existing-approval-routing-0001", ExpectedVersion: 1, Decision: "approved", FreshAuthAt: time.Now().UTC(), AuditID: id, CorrelationID: id, ReceiptID: id})
					return err
				case "activate":
					_, err := repo.ActivateSecurityAgent(context.Background(), identity, SecurityAgentActivation{DefinitionID: id, IdempotencyKey: "existing-activation-routing-0001", ExpectedVersion: 1, TargetActivation: "validated", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: id, CorrelationID: "pid_89c00300-0000-4000-8000-000000000004", ReceiptID: "pid_89c00300-0000-4000-8000-000000000005"})
					return err
				default:
					_, err := repo.SimulateSecurityAgent(context.Background(), identity, SecurityAgentSimulationRequest{DefinitionID: id, IdempotencyKey: "existing-simulation-routing-0001", ExpectedVersion: 1, RunID: id, Goal: "Verify pinned test", EvidenceIDs: []string{id}, ExpiresAt: time.Now().UTC().Add(time.Minute), AuditID: id, CorrelationID: id, ReceiptID: id})
					return err
				}
			}
			for _, available := range []bool{false, true, false, true} {
				db.available = available
				db.query = ""
				db.history = nil
				if err := invoke(); !errors.Is(err, failure) {
					t.Fatalf("operation refusal=%v", err)
				}
				wantHistory := []string{db.query}
				if operation != "simulate" {
					wantHistory = append([]string{`SELECT to_jsonb(to_regnamespace('zasp_temporal78') IS NOT NULL)`}, wantHistory...)
				}
				if operation == "activate" {
					wantHistory = append([]string{postgresSecurityAgentDefinitionValueSQL}, wantHistory...)
				}
				if !reflect.DeepEqual(db.history, wantHistory) {
					t.Fatalf("unexpected exact query history: got=%v want=%v", db.history, wantHistory)
				}
				if len(db.args) < 3 || !reflect.DeepEqual(db.args[:3], db.scopeArgs[:3]) {
					t.Fatalf("terminal tenant scope drifted: %v", db.args)
				}
				if !available {
					wantSQL := map[string]string{"run": postgresSecurityAgentRunDetailV24SQL, "approval": postgresSecurityAgentApprovalDetailV24SQL, "page": postgresSecurityAgentApprovalPageV24SQL, "decision": postgresSecurityAgentDecideApprovalV24SQL, "activate": postgresSecurityAgentActivateSQL, "simulate": postgresSecurityAgentSimulateSQL}[operation]
					if db.query != wantSQL {
						t.Fatalf("wrong historical operation SQL: got=%s want=%s", db.query, wantSQL)
					}
				}
				if strings.Contains(db.query, "zasp_production_security_agent_existing_tests_") != available {
					t.Fatalf("warm release %t query=%s", available, db.query)
				}
				if available {
					expectedSQL := map[string]string{"run": postgresExistingTestRunContextSQL, "approval": postgresExistingTestApprovalSQL, "page": postgresExistingTestApprovalPageSQL, "decision": postgresExistingTestApprovalDecisionSQL,
						"activate": `SELECT zasp_production_security_agent_existing_tests_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
						"simulate": `SELECT zasp_production_security_agent_existing_tests_simulate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15,$16)`}[operation]
					if db.query != expectedSQL {
						t.Fatalf("wrong operation SQL: %s", db.query)
					}
					want := 6
					if operation == "page" {
						want = 10
					}
					if operation == "decision" || operation == "activate" {
						want = 14
					}
					if operation == "simulate" {
						want = 16
					}
					if len(db.args) != want {
						t.Fatalf("unpinned query arguments=%d want=%d", len(db.args), want)
					}
					if db.args[want-2] != migrations.ProductionSecurityAgentExistingTests().Checksum() || db.args[want-1] != migrations.SecurityAgentExistingTestsFingerprint() {
						t.Fatal("uncompiled release pins")
					}
				}
			}
			db.query = ""
			db.history = nil
			db.releaseErr = errors.New("release drift")
			if err := invoke(); !errors.Is(err, ErrRepositoryUnavailable) || db.query != "" {
				t.Fatalf("drift reached SQL: %s %v", db.query, err)
			}
		})
	}
}

// Installed-but-unready or malformed current authority never falls back to a
// historical release. The test exercises the real repository preflight.
func TestSecurityAgentExistingTestReadRoutingRefusesUnreadyDispatch(t *testing.T) {
	for _, mode := range []string{"probe_error", "malformed_namespace", "null_namespace", "unready", "malformed_ready", "missing_ready", "foreign_definition", "malformed_definition"} {
		t.Run(mode, func(t *testing.T) {
			db := &existingTestReadRouteDatabase{available: true, workflowCallDatabase: workflowCallDatabase{err: errors.New("terminal must not execute")}}
			id := fixtureRequestIdentity(t)
			const definition = "pid_89c00300-0000-4000-8000-000000000003"
			db.scopeArgs = []any{id.Scope.OrganizationID().String(), id.Scope.WorkspaceID().String(), id.Scope.EnvironmentID().String(), definition}
			switch mode {
			case "probe_error":
				db.probeErr = errors.New("probe failed")
			case "malformed_namespace":
				db.namespace = json.RawMessage(`"false"`)
			case "null_namespace":
				db.namespace = json.RawMessage(`null`)
			case "unready":
				db.namespace = json.RawMessage(`true`)
				db.ready = json.RawMessage(`false`)
			case "malformed_ready":
				db.namespace = json.RawMessage(`true`)
				db.ready = json.RawMessage(`"true"`)
			case "missing_ready":
				db.namespace = json.RawMessage(`true`)
			case "foreign_definition":
				db.definition = json.RawMessage(`{"body":{"id":"pid_89c00300-0000-4000-8000-000000000099"},"version":1,"secret_generation":0}`)
			case "malformed_definition":
				db.definition = json.RawMessage(`null`)
			}
			repo := &PostgresRepository{database: db, securityAgentExecution: true, schema: SecurityAgentSessionIsolationSchemaVersion}
			var err error
			if strings.HasSuffix(mode, "definition") {
				err = requireAutomaticDefinitionActivation(context.Background(), db, id, definition)
			} else {
				_, err = repo.GetSecurityAgentRun(context.Background(), id, definition)
			}
			if !errors.Is(err, ErrRepositoryUnavailable) || db.query != "" {
				t.Fatalf("unsafe historical fallback: error=%v terminal=%s history=%v", err, db.query, db.history)
			}
			want := 1
			if strings.HasSuffix(mode, "ready") {
				want = 2
			}
			if len(db.history) != want {
				t.Fatalf("wrong fail-closed boundary: %v", db.history)
			}
		})
	}
}
