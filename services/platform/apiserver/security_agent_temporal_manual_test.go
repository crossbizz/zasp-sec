package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type temporalManualDatabase struct {
	*manualStartDatabase
	temporal    bool
	temporalErr error
}

func (d *temporalManualDatabase) TemporalAdmissionAvailable(context.Context) (bool, error) {
	return d.temporal, d.temporalErr
}

// Catch fallback to public58 when66 exists but refuses readiness, and dropping
// the original manual provenance while selecting the new scoped facade.
func TestTemporalManualFacadeRouting(t *testing.T) {
	const query = `SELECT zasp_temporal66.manual_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	const run = "pid_78000001-0000-4000-8000-000000000001"
	const def = "pid_78000004-0000-4000-8000-000000000004"
	const audit = "pid_78000005-0000-4000-8000-000000000005"
	const receipt = "pid_78000007-0000-4000-8000-000000000007"
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	value := map[string]any{"id": run, "agent_id": def, "state": "queued", "definition_version": 1, "version": 1, "evidence_ids": []string{}, "manual_trigger": map[string]any{"kind": "manual", "intent_digest": "sha256:" + strings.Repeat("a", 64), "version": 1}, "audit_id": audit, "correlation_id": testCorrelationID, "receipt_id": receipt, "replayed": false}
	raw, _ := json.Marshal(value)
	db := &temporalManualDatabase{manualStartDatabase: &manualStartDatabase{securityAgentRepositoryDatabase: &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{query: raw}}}, temporal: true}
	repository := &PostgresRepository{database: db, securityAgentExecution: true}
	input := SecurityAgentRunRequest{DefinitionID: def, ExpectedVersion: 1, IdempotencyKey: "temporal-manual-0001", RunID: run, AuditID: audit, CorrelationID: testCorrelationID, ReceiptID: receipt, TriggerKind: "manual"}
	result, err := repository.runSecurityAgentManual(context.Background(), identity, input)
	if err != nil || result.ManualTrigger == nil || result.ID != run {
		t.Fatal("registered66 manual route unavailable", result, err)
	}
	db.temporalErr = ErrRepositoryUnavailable
	db.available = true
	if _, err := repository.runSecurityAgentManual(context.Background(), identity, input); err == nil {
		t.Fatal("broken66 fell back to58")
	}
}
