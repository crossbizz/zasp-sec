package authorization

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// ExecuteWithApprovalOrigin consumes an ORIGINAL opaque native planning
// decision. The supplementary wrapper authenticates it before the original
// plan runs in the same transaction and only captures its new enqueue.
// Ordinary Execute, legacy plans, compensation and other families are intact.
// An inactive/unregistered supplementary module refuses; this method does not
// create an API grant, issue a new worker proof or enable a runtime profile.
func (e *WorkerExecutor) ExecuteWithApprovalOrigin(ctx context.Context, d WorkerDecision) (json.RawMessage, error) {
	statement, ok := e.approvalOriginExecutionStatement(d.operation)
	spec, supported := workerOperation(d.operation)
	if e == nil || e.approvalOriginProfile == "" || e.key == nil || e.pool == nil || ctx == nil || ctx.Err() != nil || !ok || !supported || e.adapter || e.discovery || e.key.purpose != WorkerForward || spec.purpose != WorkerForward || len(d.envelope) == 0 || len(d.request) > spec.limit || !json.Valid(d.request) {
		return nil, ErrInvalid
	}
	return e.executeWorkerStatement(ctx, d, statement)
}
func approvalOriginStatement(op WorkerOperation) (string, bool) {
	switch op {
	case "finding.planning.admit":
		return `SELECT zasp_approval_maintenance.admit_with_origin('finding78',$1::jsonb)`, true
	case "test74.planning.admit":
		return `SELECT zasp_approval_maintenance.admit_with_origin('test74',$1::jsonb)`, true
	case "ordered68.progress":
		return `SELECT zasp_approval_maintenance.admit_with_origin('ordered68_progress',$1::jsonb)`, true
	case "ordered68.planning.admit":
		return `SELECT zasp_approval_maintenance.admit_with_origin('ordered68',$1::jsonb)`, true
	default:
		return "", false
	}
}

// NewApprovalOriginWorkerExecutor selects the supplementary capture path only
// after exact live catalog/checksum admission. It does not activate delivery or
// alter compensation. The original worker key and all native source checks are
// still required by Execute and by each original native operation.
func NewApprovalOriginWorkerExecutor(ctx context.Context, pool *pgxpool.Pool, checker Checker, store, model string, key *WorkerKey, pin string) (*WorkerExecutor, error) {
	decoded, decodeErr := hex.DecodeString(pin)
	if ctx == nil || ctx.Err() != nil || key == nil || key.purpose != WorkerForward || decodeErr != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != pin {
		return nil, ErrInvalid
	}
	original, err := NewWorkerExecutor(pool, checker, store, model, key)
	if err != nil {
		return nil, err
	}
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT zasp_approval_maintenance.projection_profile_state()`).Scan(&raw); err != nil {
		return nil, workerDatabaseError(err)
	}
	state, err := decodeApprovalMaintenanceProfileState(raw)
	if err != nil || !state.CatalogReady || state.Checksum != pin {
		return nil, ErrDenied
	}
	original.approvalOriginProfile = pin
	return original, nil
}

// The activated mode never retries admission through the inactive capture path.
// The supplementary SQL authenticates current native intent and the exact org
// activation in the same transaction as the original planning operation.
func (e *WorkerExecutor) approvalOriginExecutionStatement(op WorkerOperation) (string, bool) {
	if e == nil {
		return "", false
	}
	if e.approvalActivationProfile == "" {
		return approvalOriginStatement(op)
	}
	if e.approvalOriginProfile == "" {
		return "", false
	}
	switch op {
	case "finding.planning.admit":
		return `SELECT zasp_approval_activation_v1.admit_with_origin('finding78',$1::jsonb)`, true
	case "test74.planning.admit":
		return `SELECT zasp_approval_activation_v1.admit_with_origin('test74',$1::jsonb)`, true
	case "ordered68.progress":
		return `SELECT zasp_approval_activation_v1.admit_with_origin('ordered68_progress',$1::jsonb)`, true
	case "ordered68.planning.admit":
		return `SELECT zasp_approval_activation_v1.admit_with_origin('ordered68',$1::jsonb)`, true
	default:
		return "", false
	}
}

// NewActivatedCurrentMaintenanceWorkerExecutor requires explicit compiled pins
// and the live supplementary catalog. Delivery authority remains organization
// specific and is validated by the supplemental wrapper, never inferred here.
func NewActivatedCurrentMaintenanceWorkerExecutor(ctx context.Context, pool *pgxpool.Pool, checker Checker, store, model string, key *WorkerKey, approvalPin, connectorPin, activationPin string) (*WorkerExecutor, error) {
	expected, err := migrations.ApprovalActivationProfileChecksum()
	connectorExpected, connectorErr := migrations.ConnectorMaintenanceProfileChecksum()
	if ctx == nil || ctx.Err() != nil || err != nil || connectorErr != nil || activationPin != expected || approvalPin != migrations.ApprovalMaintenanceProfileChecksum() || connectorPin != connectorExpected {
		return nil, ErrInvalid
	}
	original, err := NewCurrentMaintenanceWorkerExecutor(ctx, pool, checker, store, model, key, approvalPin, connectorPin)
	if err != nil {
		return nil, err
	}
	var ready bool
	if err := pool.QueryRow(ctx, `SELECT zasp_approval_activation_v1.catalog_ready($1)`, activationPin).Scan(&ready); err != nil {
		return nil, workerDatabaseError(err)
	}
	if !ready {
		return nil, ErrDenied
	}
	original.approvalActivationProfile = activationPin
	return original, nil
}
