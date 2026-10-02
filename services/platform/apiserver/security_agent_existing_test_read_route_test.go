package apiserver

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"testing"
	"time"
)

type existingTestReadRouteDatabase struct {
	workflowCallDatabase
	available  bool
	releaseErr error
}

func (d *existingTestReadRouteDatabase) SecurityAgentExistingTestDefinitionsAvailable(context.Context) (bool, error) {
	return d.available, d.releaseErr
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
				if err := invoke(); !errors.Is(err, failure) {
					t.Fatalf("operation refusal=%v", err)
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
			db.releaseErr = errors.New("release drift")
			if err := invoke(); !errors.Is(err, ErrRepositoryUnavailable) || db.query != "" {
				t.Fatalf("drift reached SQL: %s %v", db.query, err)
			}
		})
	}
}
