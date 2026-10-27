package authorization

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func optionalPlannerDispatchStatement(operation WorkerOperation) (string, bool) {
	switch operation {
	case "ordered68.planning.start":
		return `SELECT to_jsonb(CASE WHEN zasp_optional_egress_v1.caller_ready('planner-forward',$2) THEN zasp_optional_egress_v1.admit_planner_dispatch('ordered68',$1::jsonb) ELSE false END)`, true
	case "test74.planning.start":
		return `SELECT to_jsonb(CASE WHEN zasp_optional_egress_v1.caller_ready('planner-forward',$2) THEN zasp_optional_egress_v1.admit_planner_dispatch('test74',$1::jsonb) ELSE false END)`, true
	case "finding.planning.start":
		return `SELECT to_jsonb(CASE WHEN zasp_optional_egress_v1.caller_ready('planner-forward',$2) THEN zasp_optional_egress_v1.admit_planner_dispatch('finding78',$1::jsonb) ELSE false END)`, true
	default:
		return "", false
	}
}

// AdmitOptionalPlannerDispatch obtains NEW current worker authorization after
// the original start permit committed. It checks the optional switch without
// executing start again or minting another provider permit. The original job
// digest binds the immutable body, pricing and credential in the fresh proof.
func (e *WorkerExecutor) AdmitOptionalPlannerDispatch(ctx context.Context, operation WorkerOperation, request json.RawMessage, profilePin string) error {
	statement, ok := optionalPlannerDispatchStatement(operation)
	if !ok || !migrations.IsOptionalEgressProfileChecksum(profilePin) {
		return ErrInvalid
	}
	decision, err := e.Authorize(ctx, operation, request)
	if err != nil {
		return err
	}
	raw, err := e.executeWorkerStatementArguments(ctx, decision, statement, decision.request, profilePin)
	if err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return ErrDenied
	}
	return nil
}

// OptionalEgressReady is only the supplementary profile/principal probe. It
// does not replace the original key, runtime or family readiness checks.
func (e *WorkerExecutor) OptionalEgressReady(ctx context.Context, profilePin string) error {
	if e == nil || e.pool == nil || e.key == nil || e.key.purpose != WorkerForward || e.adapter || e.discovery || ctx == nil || ctx.Err() != nil || !migrations.IsOptionalEgressProfileChecksum(profilePin) {
		return ErrInvalid
	}
	var ready bool
	if err := e.pool.QueryRow(ctx, `SELECT zasp_optional_egress_v1.caller_ready('planner-forward',$1)`, profilePin).Scan(&ready); err != nil {
		return workerDatabaseError(err)
	}
	if !ready {
		return ErrDenied
	}
	return nil
}
