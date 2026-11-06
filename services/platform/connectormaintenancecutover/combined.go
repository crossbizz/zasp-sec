package connectormaintenancecutover

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"time"
)

// NewCombinedControlled retains the original measured, one-use local permit.
// It does not establish deployment fleet withdrawal or projection delivery.
func NewCombinedControlled(c Config, activationPin string) (*Coordinator, func(), error) {
	if !checksum.MatchString(activationPin) {
		return nil, nil, ErrRefused
	}
	coordinator, close, err := NewControlled(c)
	if err != nil {
		return nil, nil, err
	}
	coordinator.sql = &combinedActivation{nativeActivation: nativeActivation{c.OperatorPool, c.ProfileChecksum, c.ApprovalProfileChecksum, c.StoreID, c.ModelID}, activation: activationPin}
	return coordinator, close, nil
}

type combinedActivation struct {
	nativeActivation
	activation string
}

func (s *combinedActivation) activate(ctx context.Context, organization string, writer identity, verify func(context.Context) error) error {
	if ctx.Err() != nil || organization == "" || len(organization) > 256 || verify == nil {
		return activationRefused(ctx, "invalid")
	}
	tx, e := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return activationRefused(ctx, "sql-begin")
	}
	defer func() {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(c)
	}()
	// Fixed role selection preserves session_user and original72 operator() while
	// satisfying original79 FORCE RLS's exact current_user policy. Wrong pools refuse.
	if _, e = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); e != nil {
		return activationRefused(ctx, "sql-role")
	}
	// Lock is the original79 lock before ANY organization/origin row operation.
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||$1,0))`, organization); e != nil {
		return activationRefused(ctx, "sql-lock")
	}
	var desired, applied, generation int64
	var store, model string
	if e = tx.QueryRow(ctx, `SELECT desired,applied,generation,store_id,model_id FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE`, organization).Scan(&desired, &applied, &generation, &store, &model); e != nil || desired < 1 || desired != applied || generation < 1 || store != s.store || model != s.model {
		return activationRefused(ctx, "sql-baseline")
	}
	// Real SDK/process observations are repeated AFTER acquisition of the lock.
	if err := verify(ctx); err != nil {
		return err
	}
	// This digest records the internally measured witness; SQL cannot manufacture
	// its authority. No API takes a caller-supplied withdrawal digest.
	witness, _ := json.Marshal(struct {
		PID                    int
		Start, Executable, SHA string
		Dev, Ino               uint64
	}{writer.pid, writer.start, writer.executable, writer.sha256, writer.dev, writer.ino})
	sum := sha256.Sum256(witness)
	digest := hex.EncodeToString(sum[:])
	var raw []byte
	if e = tx.QueryRow(ctx, `SELECT zasp_approval_activation_v1.activate_controlled_organization($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, organization, s.activation, s.profile, s.approval, s.store, s.model, digest, desired, applied, generation).Scan(&raw); e != nil || len(raw) > 65536 {
		return activationRefused(ctx, "sql-activation")
	}
	// PostgreSQL's fixed jsonb_build_object supplies these exact nine fields.
	var result map[string]json.RawMessage
	if json.Unmarshal(raw, &result) != nil || len(result) != 9 {
		return activationRefused(ctx, "sql-result")
	}
	for _, name := range []string{"organization_id", "activated", "connector_origins", "approval_origins", "desired", "applied", "generation", "store_id", "model_id"} {
		if result[name] == nil || string(result[name]) == "null" {
			return activationRefused(ctx, "sql-result")
		}
	}
	var org, sid, mid string
	var active bool
	var origins, approvalOrigins int
	var d, a, g int64
	if json.Unmarshal(result["organization_id"], &org) != nil || json.Unmarshal(result["store_id"], &sid) != nil || json.Unmarshal(result["model_id"], &mid) != nil || json.Unmarshal(result["activated"], &active) != nil || json.Unmarshal(result["connector_origins"], &origins) != nil || json.Unmarshal(result["approval_origins"], &approvalOrigins) != nil || json.Unmarshal(result["desired"], &d) != nil || json.Unmarshal(result["applied"], &a) != nil || json.Unmarshal(result["generation"], &g) != nil || org != organization || sid != s.store || mid != s.model || !active || origins < 0 || origins > 20 || approvalOrigins < 0 || approvalOrigins > 20 || a != applied || g != generation || (d != desired && d != desired+1) || ctx.Err() != nil {
		return activationRefused(ctx, "sql-result")
	}
	var readDesired, readApplied, readGeneration int64
	var readStore, readModel string
	if e = tx.QueryRow(ctx, `SELECT desired,applied,generation,store_id,model_id FROM zasp_authorization79.organizations WHERE organization_id=$1`, organization).Scan(&readDesired, &readApplied, &readGeneration, &readStore, &readModel); e != nil || readDesired != d || readApplied != a || readGeneration != g || readStore != sid || readModel != mid || ctx.Err() != nil {
		return activationRefused(ctx, "sql-result")
	}
	if e = tx.Commit(ctx); e != nil {
		return activationRefused(ctx, "sql-commit")
	}
	return nil
	// Commit does NOT establish composed Reconcile/Stage/Ack or product readiness.
}
