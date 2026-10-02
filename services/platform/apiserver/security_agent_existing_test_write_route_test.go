package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Test-bearing writes must never use a legacy entrypoint after a55 rollback.
func TestSecurityAgentExistingTestWriteUsesVersionedAuthority(t *testing.T) {
	for _, test := range []struct {
		name, body          string
		versioned, rejected bool
	}{
		{"run", `{"allowed_actions":["run_test"]}`, true, false},
		{"rerun", `{"allowed_actions":["rerun_test"]}`, true, false},
		{"reference", `{"existing_test":{"definition_id":"pid_89000012-0000-4000-8000-000000000002","definition_version":1}}`, true, false},
		{"case_alias_cannot_hide_action", `{"allowed_actions":["run_test"],"Allowed_Actions":["update_finding_response"]}`, true, false},
		{"legacy", `{"allowed_actions":["update_finding_response"]}`, false, false},
		{"null_reference", `{"existing_test":null}`, false, true},
		{"duplicate_actions", `{"allowed_actions":["run_test"],"allowed_actions":["update_finding_response"]}`, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			unavailable := errors.New("versioned database authority absent")
			db := &workflowCallDatabase{err: unavailable}
			repository := &PostgresRepository{database: db, securityAgentExecution: true}
			mutation := WorkflowMutation{Action: "create", Kind: "security_agent", ID: "pid_89000021-0000-4000-8000-000000000001", Operation: "createSecurityAgent", IdempotencyKey: "existing-test-write-route-0001", Intent: json.RawMessage(`{}`), Body: json.RawMessage(test.body), AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ReceiptID: "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc"}
			_, err := repository.MutateWorkflow(context.Background(), fixtureRequestIdentity(t), mutation)
			if test.rejected {
				if !errors.Is(err, ErrRepositoryOperation) || db.query != "" {
					t.Fatalf("malformed body reached database: query=%s err=%v", db.query, err)
				}
				return
			}
			if !errors.Is(err, unavailable) {
				t.Fatalf("database refusal not preserved: %v", err)
			}
			if test.versioned {
				want := `SELECT public.zasp_production_security_agent_existing_tests_mutate_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14,$15,$16)`
				if db.query != want || len(db.args) != 16 || db.args[14] != migrations.ProductionSecurityAgentExistingTests().Checksum() || db.args[15] != migrations.SecurityAgentExistingTestsFingerprint() {
					t.Fatalf("test write used unpinned/legacy authority: query=%s arguments=%d", db.query, len(db.args))
				}
			} else if db.query != postgresSecurityAgentDefinitionMutateSQL || len(db.args) != 14 {
				t.Fatalf("legacy routing changed: %s", db.query)
			}
		})
	}
}

func TestSecurityAgentExistingTestReplayUsesVersionedAuthority(t *testing.T) {
	for _, test := range []struct {
		name, intent        string
		versioned, rejected bool
	}{
		{"case_alias", `{"body":{"allowed_actions":["run_test"],"Allowed_Actions":["update_finding_response"]}}`, true, false},
		{"rerun", `{"body":{"allowed_actions":["rerun_test"]}}`, true, false},
		{"reference", `{"body":{"existing_test":{"definition_id":"pid_89000012-0000-4000-8000-000000000002","definition_version":1}}}`, true, false},
		{"duplicate_body", `{"body":{"allowed_actions":["run_test"]},"body":{}}`, false, true},
		{"duplicate_actions", `{"body":{"allowed_actions":["run_test"],"allowed_actions":[]}}`, false, true},
		{"null_body", `{"body":null}`, false, true},
		{"legacy", `{"body":{}}`, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := &workflowCallDatabase{err: ErrRepositoryUnavailable}
			repository := &PostgresRepository{database: db, securityAgentExecution: true}
			_, found, err := repository.ReplayWorkflow(context.Background(), fixtureRequestIdentity(t), "createSecurityAgent", "existing-test-replay-route-0001", json.RawMessage(test.intent))
			if test.rejected {
				if found || !errors.Is(err, ErrRepositoryOperation) || db.query != "" {
					t.Fatalf("ambiguous replay reached authority: %s %v", db.query, err)
				}
				return
			}
			want, n := postgresSecurityAgentDefinitionReplaySQL, 7
			if test.versioned {
				want, n = `SELECT public.zasp_production_security_agent_existing_tests_replay_definition($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`, 9
			}
			if found || !errors.Is(err, ErrRepositoryUnavailable) || db.query != want || len(db.args) != n {
				t.Fatalf("wrong replay authority: found=%v err=%v query=%s args=%d", found, err, db.query, len(db.args))
			}
			if test.versioned && (db.args[7] != migrations.ProductionSecurityAgentExistingTests().Checksum() || db.args[8] != migrations.SecurityAgentExistingTestsFingerprint()) {
				t.Fatal("replay did not bind compiled55 pins")
			}
		})
	}
}
