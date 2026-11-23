package apiserver

import (
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

const caseVerificationRead = `SELECT zasp_authorization80.case_verification($1,$2,$3,$4,$5,NULL,false)`
const caseVerificationWrite = `SELECT zasp_authorization80.case_verification($1,$2,$3,$4,$5,$6,$7)`

func init() {
	productStatementRules[caseVerificationRead] = productStatementRule{operations: []string{"getSecurityCaseVerification"}, arguments: 5, scope: 1, actor: 4, object: 5, kind: "security_agent_run", browserOnly: true}
	productStatementRules[caseVerificationWrite] = productStatementRule{operations: []string{"verifySecurityCase"}, arguments: 7, scope: 1, actor: 4, object: 5, kind: "security_agent_run", browserOnly: true, fresh: true}
}

type storedCaseEvidence struct {
	CaseID                     string                     `json:"case_id"`
	TargetID                   string                     `json:"target_id"`
	BusinessFixtureUnavailable bool                       `json:"business_fixture_unavailable"`
	RemediationVerified        bool                       `json:"remediation_verified"`
	FixtureRunID               *string                    `json:"fixture_run_id"`
	SubmittedAt                *time.Time                 `json:"submitted_at"`
	Bundle                     *redteam.TicketProofBundle `json:"bundle"`
}

type caseVerification struct {
	CaseID                string  `json:"case_id"`
	State                 string  `json:"state"`
	Reason                string  `json:"reason"`
	FixtureRunID          *string `json:"fixture_run_id"`
	SecurityCheckPassed   bool    `json:"security_check_passed"`
	BusinessTaskPreserved bool    `json:"business_task_preserved"`
	SecurityReceiptID     *string `json:"security_receipt_id"`
	BusinessReceiptID     *string `json:"business_receipt_id"`
}

// Tier: 4 | Purpose: verify the owner's protected and approved ticket tasks.
// Model: none. Authority: same-target, post-remediation signed fixture receipts.
// Fallback: keep the case open when either check lacks independent evidence.
func verifyCase(record storedCaseEvidence, scope redteam.TicketScope, qualify func(redteam.TicketProofBundle, time.Time) string) (caseVerification, error) {
	value := caseVerification{CaseID: record.CaseID, State: "open", Reason: "owner_fixture_required", FixtureRunID: record.FixtureRunID}
	if record.FixtureRunID == nil {
		if record.Bundle != nil || record.SubmittedAt != nil {
			return value, ErrRepositoryUnavailable
		}
		if !record.RemediationVerified {
			value.Reason = "remediation_pending"
		}
		return value, nil
	}
	b := record.Bundle
	if !validProductID(*record.FixtureRunID) || !record.RemediationVerified || b == nil || !b.Archivable() || record.SubmittedAt == nil || record.SubmittedAt.IsZero() || b.Scenario.Scope != scope || b.Scenario.TargetID != record.TargetID || b.Scenario.RunID != *record.FixtureRunID {
		return value, ErrRepositoryUnavailable
	}
	test, err := redteam.VerifyTicketProof(b.Scenario, b.Adapter, b.Recorder, *record.SubmittedAt)
	if err != nil {
		return value, ErrRepositoryUnavailable
	}
	value.Reason = test.Reason
	if test.ProtectedReceiptID != "" {
		value.SecurityReceiptID = &test.ProtectedReceiptID
	}
	if test.Verdict != "passed" {
		return value, nil
	}
	if qualify(*b, *record.SubmittedAt) != "verified_prevention" {
		value.Reason = "independent_attestations_required"
		return value, nil
	}
	if test.ProtectedDecisionID == "" || test.ControlReceiptID == "" {
		return value, ErrRepositoryUnavailable
	}
	value.SecurityCheckPassed, value.SecurityReceiptID = true, &test.ProtectedDecisionID
	if record.BusinessFixtureUnavailable {
		value.State, value.Reason = "closed_business_task_unverified", "owner_attested_no_business_fixture"
		return value, nil
	}
	value.BusinessTaskPreserved, value.BusinessReceiptID = true, &test.ControlReceiptID
	value.State = "verified_complete"
	return value, nil
}

func serveSecurityCaseVerification(db JSONDatabase, w http.ResponseWriter, r *http.Request, route RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	i, ok := IdentityFromRequest(r)
	if !ok || i.CredentialKind != CredentialBrowserSession {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	id := route.PathParameters["id"]
	if !validProductID(id) || r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	s := redteam.TicketScope{OrganizationID: i.Scope.OrganizationID().String(), WorkspaceID: i.Scope.WorkspaceID().String(), EnvironmentID: i.Scope.EnvironmentID().String()}
	args := []any{s.OrganizationID, s.WorkspaceID, s.EnvironmentID, i.PrincipalID.String(), id}
	query := caseVerificationRead
	if route.OperationID == "verifySecurityCase" {
		var body struct {
			Fixture                    string `json:"fixture_run_id"`
			BusinessFixtureUnavailable bool   `json:"business_fixture_unavailable"`
		}
		if !i.FreshAuthenticated {
			writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
			return
		}
		if r.Method != http.MethodPost || decodeProductionJSON(r, &body) != nil || !validProductID(body.Fixture) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		query, args = caseVerificationWrite, append(args, body.Fixture, body.BusinessFixtureUnavailable)
	} else if route.OperationID != "getSecurityCaseVerification" || r.Method != http.MethodGet {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	raw, err := db.QueryJSON(r.Context(), query, args...)
	if err != nil {
		writeProductionError(w, r, discoveryProviderError(err))
		return
	}
	switch string(raw) {
	case "null":
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	case `"owner_required"`:
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	case `"ineligible"`:
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	case `"remediation_pending"`, `"stale"`:
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	var stored storedCaseEvidence
	if decodeStrictDiscovery(raw, &stored) != nil || stored.CaseID != id || !validProductID(stored.TargetID) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	verified, err := verifyCase(stored, s, ticketProofQualification)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	writeJSONValue(w, r, 200, verified, nil)
}
