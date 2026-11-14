package apiserver

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestSecurityAgentRunInputTakesARemediationOnlyWithAFindingTrigger(t *testing.T) {
	const environment, finding = "pid_10000003-0000-4000-8000-000000000003", "pid_30000005-0000-4000-8000-000000000005"
	decode := func(body string) (securityAgentRunInput, error) {
		var input securityAgentRunInput
		err := json.Unmarshal([]byte(body), &input)
		return input, err
	}
	input, err := decode(`{"environment_id":"` + environment + `","trigger_kind":"finding","trigger_id":"` + finding + `","remediation":{"action":"attach_bedrock_guardrail","parameters":{"guardrail_identifier":"gr1abc","guardrail_version":"3"}}}`)
	if err != nil || input.Remediation == nil || input.Remediation.Action != "attach_bedrock_guardrail" || input.Remediation.Parameters["guardrail_version"] != "3" || input.TriggerKind != "finding" || input.TriggerID != finding {
		t.Fatalf("input=%#v err=%v", input, err)
	}
	// A run without a remediation decodes as before.
	plain, err := decode(`{"environment_id":"` + environment + `","trigger_kind":"finding","trigger_id":"` + finding + `"}`)
	if err != nil || plain.Remediation != nil {
		t.Fatalf("plain input=%#v err=%v", plain, err)
	}
	for name, body := range map[string]string{
		"a manual run":                 `{"environment_id":"` + environment + `","remediation":{"action":"attach_bedrock_guardrail","parameters":{"guardrail_identifier":"gr1abc","guardrail_version":"3"}}}`,
		"an attack path trigger":       `{"environment_id":"` + environment + `","trigger_kind":"attack_path","trigger_id":"` + finding + `","remediation":{"action":"attach_bedrock_guardrail","parameters":{"guardrail_identifier":"gr1abc","guardrail_version":"3"}}}`,
		"a named trigger version":      `{"environment_id":"` + environment + `","trigger_kind":"finding","trigger_id":"` + finding + `","trigger_version":2,"trigger_source":"agent_guardrail_missing","remediation":{"action":"attach_bedrock_guardrail","parameters":{"guardrail_identifier":"gr1abc","guardrail_version":"3"}}}`,
		"an action that is not listed": `{"environment_id":"` + environment + `","trigger_kind":"finding","trigger_id":"` + finding + `","remediation":{"action":"revoke_integration_connection","parameters":{"connection_id":"x"}}}`,
		"a missing parameter":          `{"environment_id":"` + environment + `","trigger_kind":"finding","trigger_id":"` + finding + `","remediation":{"action":"attach_bedrock_guardrail","parameters":{"guardrail_identifier":"gr1abc"}}}`,
		"an extra parameter":           `{"environment_id":"` + environment + `","trigger_kind":"finding","trigger_id":"` + finding + `","remediation":{"action":"detach_role_administrator_policy","parameters":{"policy_arn":"arn:aws:iam::aws:policy/AdministratorAccess","role_name":"other"}}}`,
		"an extra remediation member":  `{"environment_id":"` + environment + `","trigger_kind":"finding","trigger_id":"` + finding + `","remediation":{"action":"detach_role_administrator_policy","parameters":{"policy_arn":"arn:aws:iam::aws:policy/AdministratorAccess"},"role_arn":"arn:aws:iam::123456789012:role/x"}}`,
		"a non-string parameter":       `{"environment_id":"` + environment + `","trigger_kind":"finding","trigger_id":"` + finding + `","remediation":{"action":"attach_bedrock_guardrail","parameters":{"guardrail_identifier":"gr1abc","guardrail_version":3}}}`,
	} {
		if input, err := decode(body); err == nil {
			t.Fatalf("%s was accepted: %#v", name, input)
		}
	}
}

func TestSecurityAgentRemediationRunIsOneAttestedStatement(t *testing.T) {
	f := newSecondaryFixture(t)
	i := f.identity
	const agent, run, finding = "pid_20000001-0000-4000-8000-000000000001", "pid_30000004-0000-4000-8000-000000000004", "pid_30000005-0000-4000-8000-000000000005"
	const audit, correlation, receipt, approval = "pid_30000001-0000-4000-8000-000000000001", "pid_30000002-0000-4000-8000-000000000002", "pid_30000003-0000-4000-8000-000000000003", "pid_30000006-0000-4000-8000-000000000006"
	result := func(family, state string) string {
		return `{"family":"` + family + `","result":{"id":"` + run + `","agent_id":"` + agent + `","state":"` + state + `","evidence_ids":["` + finding + `"],"definition_version":3,"version":1,"audit_id":"` + audit + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}}`
	}
	request := SecurityAgentRunRequest{DefinitionID: agent, IdempotencyKey: "idempotency-key-0001", ExpectedVersion: 3, RunID: run, TriggerKind: "finding", TriggerID: finding, AuditID: audit, CorrelationID: correlation, ReceiptID: receipt,
		Remediation: &SecurityAgentRunRemediation{Action: "detach_role_administrator_policy", Parameters: map[string]string{"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}, ApprovalID: approval}}
	route := RoutedOperation{OperationID: "runSecurityAgent", PathParameters: map[string]string{"id": agent}}
	repository := func(payload string) (*PostgresRepository, *completionTxFixture) {
		database, tx, _ := f.database(t, payload)
		return &PostgresRepository{database: database, schema: ProductionRecoverySchemaVersion, securityAgentExecution: true, currentAuthorization: true}, tx
	}

	t.Run("admitted", func(t *testing.T) {
		repo, tx := repository(result("remediation", "waiting_approval"))
		value, err := repo.RunSecurityAgent(f.request(t, route), i, request)
		if err != nil || value.ID != run || value.State != "waiting_approval" {
			t.Fatalf("run=%#v err=%v", value, err)
		}
		if len(tx.statements) != 1 || tx.statements[0] != currentSecurityAgentRemediationRunSQL || len(tx.arguments[0]) != 7 {
			t.Fatalf("statements=%v", tx.statements)
		}
		var admission securityAgentRemediationAdmission
		raw, ok := tx.arguments[0][5].(json.RawMessage)
		if !ok || json.Unmarshal(raw, &admission) != nil || admission.Action != "detach_role_administrator_policy" || admission.Parameters["policy_arn"] != "arn:aws:iam::aws:policy/AdministratorAccess" || admission.ApprovalID != approval || admission.TriggerID != finding || admission.DefinitionID != agent || admission.ActorID != i.PrincipalID.String() {
			t.Fatalf("admission=%s", raw)
		}
		// The finding travels with the attestation of its own decision.
		envelope, ok := tx.arguments[0][6].(string)
		if !ok {
			t.Fatalf("finding attestation was %T", tx.arguments[0][6])
		}
		body, _ := json.Marshal(attestedBody(t, envelope))
		var attested struct {
			Operation string            `json:"operation_id"`
			Path      map[string]string `json:"path_parameters"`
		}
		if json.Unmarshal(body, &attested) != nil || attested.Operation != "getFinding" || attested.Path["id"] != finding {
			t.Fatalf("finding attestation names %s", body)
		}
	})
	t.Run("a finding the requester may not view", func(t *testing.T) {
		f.denied["finding"] = true
		defer delete(f.denied, "finding")
		repo, tx := repository(result("remediation", "waiting_approval"))
		if _, err := repo.RunSecurityAgent(f.request(t, route), i, request); !errors.Is(err, ErrRepositoryAuthorization) {
			t.Fatalf("err=%v", err)
		}
		if len(tx.statements) != 0 {
			t.Fatalf("a statement was sent: %v", tx.statements)
		}
	})
	t.Run("another family's answer", func(t *testing.T) {
		repo, _ := repository(result("legacy", "queued"))
		if _, err := repo.RunSecurityAgent(f.request(t, route), i, request); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("a run that is not waiting for approval", func(t *testing.T) {
		repo, _ := repository(result("remediation", "running"))
		if _, err := repo.RunSecurityAgent(f.request(t, route), i, request); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("err=%v", err)
		}
	})
	for name, change := range map[string]func(*SecurityAgentRunRequest){
		"without an approval ID": func(value *SecurityAgentRunRequest) {
			value.Remediation = &SecurityAgentRunRemediation{Action: "detach_role_administrator_policy", Parameters: map[string]string{"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}}
		},
		"with the run's ID as the approval ID": func(value *SecurityAgentRunRequest) {
			value.Remediation = &SecurityAgentRunRemediation{Action: "detach_role_administrator_policy", Parameters: map[string]string{"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}, ApprovalID: run}
		},
		"with a trigger version": func(value *SecurityAgentRunRequest) {
			version, source := int64(2), "agent_role_administrator_access"
			value.TriggerVersion, value.TriggerSource = &version, &source
		},
		"on an attack path": func(value *SecurityAgentRunRequest) { value.TriggerKind = "attack_path" },
		"with malformed parameters": func(value *SecurityAgentRunRequest) {
			value.Remediation = &SecurityAgentRunRemediation{Action: "detach_role_administrator_policy", Parameters: map[string]string{"policy_arn": "arn:aws:iam::123456789012:role/admin"}, ApprovalID: approval}
		},
	} {
		t.Run(name, func(t *testing.T) {
			repo, tx := repository(result("remediation", "waiting_approval"))
			changed := request
			change(&changed)
			if _, err := repo.RunSecurityAgent(f.request(t, route), i, changed); !errors.Is(err, ErrRepositoryOperation) {
				t.Fatalf("err=%v", err)
			}
			if len(tx.statements) != 0 {
				t.Fatalf("a statement was sent: %v", tx.statements)
			}
		})
	}
	t.Run("without a checked request", func(t *testing.T) {
		repo := &PostgresRepository{schema: ProductionRecoverySchemaVersion, securityAgentExecution: true}
		if _, err := repo.RunSecurityAgent(t.Context(), i, request); !errors.Is(err, ErrRepositoryOperation) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestSecurityAgentRemediationRefusalsAreNamed(t *testing.T) {
	for _, test := range []struct {
		code, message string
		want          error
		status        int
		api           string
	}{
		{"55000", "security agent remediation role not configured", ErrSecurityAgentRemediationRoleMissing, 409, "remediation_role_not_configured"},
		{"55000", "security agent remediation integration unavailable", ErrSecurityAgentRemediationIntegrationUnavailable, 409, "remediation_integration_unavailable"},
		{"23505", "security agent remediation already requested", ErrSecurityAgentRemediationAlreadyRequested, 409, "remediation_already_requested"},
		{"22023", "security agent remediation finding rule mismatch", ErrSecurityAgentRemediationRuleMismatch, 400, "remediation_rule_mismatch"},
		{"22023", "security agent remediation target unsupported", ErrSecurityAgentRemediationTargetUnsupported, 400, "remediation_target_unsupported"},
	} {
		err := discoveryProviderError(classifyPostgresError(&pgconn.PgError{Code: test.code, Message: test.message}))
		if !errors.Is(err, test.want) {
			t.Fatalf("%s %s classified as %v", test.code, test.message, err)
		}
		status, code, message, named := securityAgentRemediationErrorResponse(err)
		if !named || status != test.status || code != test.api || message == "" {
			t.Fatalf("%s: status=%d code=%q named=%t", test.message, status, code, named)
		}
	}
	// Any other refusal keeps its general class and is not named.
	other := classifyPostgresError(&pgconn.PgError{Code: "22023", Message: "security agent run definition rejected"})
	if _, _, _, named := securityAgentRemediationErrorResponse(other); named || !errors.Is(other, ErrRepositoryOperation) {
		t.Fatalf("an unrelated refusal was named: %v", other)
	}
}

func TestSecurityAgentExecutionControlsListTheRemediationActions(t *testing.T) {
	control := func(target, key string, version int64) SecurityAgentExecutionControl {
		return SecurityAgentExecutionControl{Target: target, ActionKey: key, Enabled: version > 0, Version: version}
	}
	value := SecurityAgentExecutionControls{Global: control("global", "*", 1), Environment: control("environment", "*", 1)}
	for _, key := range securityAgentExecutionControlActions {
		value.Actions = append(value.Actions, control("action", key, 0))
	}
	if len(value.Actions) != 10 || !validSecurityAgentExecutionControls(value) {
		t.Fatalf("the ten action switches were rejected: %#v", value)
	}
	value.Actions[0], value.Actions[1] = value.Actions[1], value.Actions[0]
	if validSecurityAgentExecutionControls(value) {
		t.Fatal("action switches in another order were accepted")
	}
}

// A decision reads the approval before it decides it. Under current
// authorization that read is a request of its own: it is made under a second
// decision for getSecurityAgentApproval, not under the decision's proof,
// which neither the statement gate nor PostgreSQL accepts for a read.
func TestApprovalDecisionReadsTheApprovalUnderItsOwnDecision(t *testing.T) {
	f := newSecondaryFixture(t)
	const approval, run, step, agent, finding = "pid_656ea599-55b3-4bd0-969d-af956edfe20f", "pid_abf53263-0b03-4d47-b1a4-e3c31fcc7517", "pid_3473f281-34c6-4899-8313-84d40748c57c", "pid_7b523400-2d8a-4eb5-88ac-fa181b1da365", "pid_8770c18a-59d6-429f-a8e0-810ae5c9003c"
	// The answer of zasp_authorization80.security_agent_approval for a
	// pending guardrail attachment, as an installed baseline produced it.
	payload := `{"family":"legacy","result":{"detail":{"id":"` + approval + `","state":"pending","run_id":"` + run + `","step_id":"` + step + `","version":1,"expires_at":"2026-11-15T08:18:01.175000Z","reversible":true,"ttl_seconds":0,"expected_effect":"Attach Bedrock guardrail","evidence_summary":["` + finding + `"]},
"context":{"action":"attach_bedrock_guardrail","run_id":"` + run + `","step_id":"` + step + `","agent_id":"` + agent + `","arguments":{"target_id":"pid_b2710f6d-2eed-49f9-a020-0c593881ced5","integration_id":"pid_8b960a0f-92fe-4094-a37b-b85193c905c0","guardrail_version":"1","guardrail_identifier":"gr1abc"},"plan_hash":"sha256:e884b65f52cd8244929ef6b1e7fdb23e35cda256cf85061350845aef17537d4f","approval_id":"` + approval + `","requester_id":"pid_d13ad76a-1b87-4311-83a4-735d72ffe2e1","authorization":"approval_required","catalog_version":"security-agent-actions-v1","planner_receipt":null,"approval_plan_hash":"sha256:e884b65f52cd8244929ef6b1e7fdb23e35cda256cf85061350845aef17537d4f"}}}`
	database, tx, _ := f.database(t, payload)
	repository := &PostgresRepository{database: database, schema: ProductionRecoverySchemaVersion, securityAgentExecution: true, currentAuthorization: true}
	deciding := f.request(t, RoutedOperation{OperationID: "decideSecurityAgentApproval", PathParameters: map[string]string{"id": approval}})
	f.resolved = nil
	value, err := repository.GetSecurityAgentApproval(deciding, f.identity, approval)
	if err != nil || value.ID != approval || value.ExpectedEffect != "Attach Bedrock guardrail" || value.Context == nil || value.Context.Action != "attach_bedrock_guardrail" {
		t.Fatalf("approval=%+v err=%v", value, err)
	}
	if len(tx.statements) != 1 || tx.statements[0] != currentSecurityAgentApprovalSQL {
		t.Fatalf("statements=%v", tx.statements)
	}
	if len(f.resolved) != 1 || !strings.HasSuffix(f.resolved[0], ":getSecurityAgentApproval") {
		t.Fatalf("second decision resolved=%v", f.resolved)
	}
	// The decision's own proof is not accepted for the read, for this
	// approval or another one.
	grant, _ := requestAuthorizationFromContext(deciding)
	arguments := []any{f.identity.Scope.OrganizationID().String(), f.identity.Scope.WorkspaceID().String(), f.identity.Scope.EnvironmentID().String(), approval, f.identity.PrincipalID.String()}
	if handled, allowed := securityAgentObjectStatementAllowed(grant, currentSecurityAgentApprovalSQL, arguments); !handled || allowed {
		t.Fatalf("the decision's proof was accepted for a read: handled=%t allowed=%t", handled, allowed)
	}
	// A member who may not read the approval does not read it by deciding.
	f.denied["security_agent_approval"] = true
	if _, err := repository.GetSecurityAgentApproval(deciding, f.identity, approval); err == nil {
		t.Fatal("an approval the member may not view was read under a decision")
	}
}
