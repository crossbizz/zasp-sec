package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The installed activation writer keeps validated disabled, then enables the
// supervised revision with its own approval-bound grant before autonomous.
func assertTemporalTestFullActivation(t *testing.T, ctx context.Context, owner *pgx.Conn, repository *PostgresRepository, identity RequestIdentity, supervisedOnly ...bool) {
	t.Helper()
	const definition = "pid_f0740000-0000-4000-8000-000000000101"
	var body, intent json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT body||jsonb_build_object('id',$2::text,'enabled',false),jsonb_build_object('resource_id','','expected_version',0,'body',(body-'id')||jsonb_build_object('enabled',false)) FROM zasp_security_agent_definitions WHERE definition_id=$1`, public62Definition, definition).Scan(&body, &intent); err != nil {
		t.Fatal(err)
	}
	created, err := repository.MutateWorkflow(ctx, identity, WorkflowMutation{Action: "create", Kind: "security_agent", ID: definition, Operation: "createSecurityAgent", IdempotencyKey: "test74-full-create", Intent: intent, Body: body, AuditID: "pid_f0740000-0000-4000-8000-000000000102", CorrelationID: "pid_f0740000-0000-4000-8000-000000000103", ReceiptID: "pid_f0740000-0000-4000-8000-000000000104"})
	if err != nil || created.Version != 1 {
		t.Fatal("actual74 typed creation", created, err)
	}
	for i, activation := range []string{"validated", "supervised", "autonomous"} {
		request := SecurityAgentActivation{DefinitionID: definition, IdempotencyKey: "test74-full-activation-" + activation, ExpectedVersion: int64(i + 1), TargetActivation: activation, FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: fmt.Sprintf("pid_f0740000-0000-4000-8000-%012d", 110+i*3), CorrelationID: fmt.Sprintf("pid_f0740000-0000-4000-8000-%012d", 111+i*3), ReceiptID: fmt.Sprintf("pid_f0740000-0000-4000-8000-%012d", 112+i*3)}
		result, err := repository.ActivateSecurityAgent(ctx, identity, request)
		if err != nil || result.Version != int64(i+2) || result.Enabled != (activation != "validated") || result.Replayed {
			t.Fatal("actual74 activation transition", activation, result, err)
		}
		if replay, err := repository.ActivateSecurityAgent(ctx, identity, request); err != nil || !replay.Replayed || replay.AuditID != result.AuditID || replay.Version != result.Version || replay.Enabled != result.Enabled {
			t.Fatal("actual74 activation replay", activation, replay, err)
		}
		var proof bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_temporal74.service_grants WHERE definition_id=$1)=$2 AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.service_grants WHERE definition_id=$1 AND definition_version<3) AND (SELECT count(*) FROM zasp_security_agent_audit WHERE audit_id=$3 AND event_kind='definition_activated')=1`, definition, i, request.AuditID).Scan(&proof); err != nil || !proof {
			t.Fatal("intermediate revision delegated or replay duplicated audit", activation, proof, err)
		}
		if activation == "supervised" && len(supervisedOnly) > 0 && supervisedOnly[0] {
			return
		}
	}
}
