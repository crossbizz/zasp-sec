package connectormaintenancecutover

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Config selects explicit operator authorities; it supplies no withdrawal hash.
// NewControlled measures ONE exact local writer. It cannot attest a deployment
// fleet or restart exclusion and is never a production deployment constructor.
type Config struct {
	Endpoint, StoreID, ModelID, OldTokenFile, NewTokenFile, ProfileChecksum, ApprovalProfileChecksum string
	OperatorPool                                                                                     *pgxpool.Pool
}

var ulid = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
var checksum = regexp.MustCompile(`^[a-f0-9]{64}$`)

type nativeActivation struct {
	pool                            *pgxpool.Pool
	profile, approval, store, model string
}

func NewControlled(c Config) (*Coordinator, func(), error) {
	if c.OperatorPool == nil || !ulid.MatchString(c.StoreID) || !ulid.MatchString(c.ModelID) || !checksum.MatchString(c.ProfileChecksum) || !checksum.MatchString(c.ApprovalProfileChecksum) {
		return nil, nil, ErrRefused
	}
	observations, e := newEvidence(c.Endpoint, c.StoreID, c.ModelID, c.OldTokenFile, c.NewTokenFile)
	if e != nil {
		return nil, nil, ErrRefused
	}
	return &Coordinator{observations: observations, sql: &nativeActivation{c.OperatorPool, c.ProfileChecksum, c.ApprovalProfileChecksum, c.StoreID, c.ModelID}, ttl: 30 * time.Second}, observations.close, nil
}
func (s *nativeActivation) activate(ctx context.Context, organization string, writer identity, verify func(context.Context) error) error {
	if ctx.Err() != nil || organization == "" || len(organization) > 256 || verify == nil {
		return ErrRefused
	}
	tx, e := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return ErrRefused
	}
	defer func() {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(c)
	}()
	// Fixed role selection preserves session_user and original72 operator() while
	// satisfying original79 FORCE RLS's exact current_user policy. Wrong pools refuse.
	if _, e = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); e != nil {
		return ErrRefused
	}
	// Lock is the original79 lock before ANY organization/origin row operation.
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||$1,0))`, organization); e != nil {
		return ErrRefused
	}
	var desired, applied, generation int64
	var store, model string
	if e = tx.QueryRow(ctx, `SELECT desired,applied,generation,store_id,model_id FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE`, organization).Scan(&desired, &applied, &generation, &store, &model); e != nil || desired < 1 || desired != applied || generation < 1 || store != s.store || model != s.model {
		return ErrRefused
	}
	// Real SDK/process observations are repeated AFTER acquisition of the lock.
	if verify(ctx) != nil {
		return ErrRefused
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
	if e = tx.QueryRow(ctx, `SELECT zasp_connector_maintenance.activate_controlled_organization($1,$2,$3,$4,$5,$6,$7,$8,$9)`, organization, s.profile, s.approval, s.store, s.model, digest, desired, applied, generation).Scan(&raw); e != nil || len(raw) > 65536 {
		return ErrRefused
	}
	// PostgreSQL's fixed jsonb_build_object supplies these exact eight fields.
	var result map[string]json.RawMessage
	if json.Unmarshal(raw, &result) != nil || len(result) != 8 {
		return ErrRefused
	}
	for _, name := range []string{"organization_id", "activated", "origins", "desired", "applied", "generation", "store_id", "model_id"} {
		if result[name] == nil || string(result[name]) == "null" {
			return ErrRefused
		}
	}
	var org, sid, mid string
	var active bool
	var origins int
	var d, a, g int64
	if json.Unmarshal(result["organization_id"], &org) != nil || json.Unmarshal(result["store_id"], &sid) != nil || json.Unmarshal(result["model_id"], &mid) != nil || json.Unmarshal(result["activated"], &active) != nil || json.Unmarshal(result["origins"], &origins) != nil || json.Unmarshal(result["desired"], &d) != nil || json.Unmarshal(result["applied"], &a) != nil || json.Unmarshal(result["generation"], &g) != nil || org != organization || sid != s.store || mid != s.model || !active || origins < 0 || origins > 20 || a != applied || g != generation || (d != desired && d != desired+1) || ctx.Err() != nil {
		return ErrRefused
	}
	if e = tx.Commit(ctx); e != nil {
		return ErrRefused
	}
	return nil
	// Commit does NOT establish composed Reconcile/Stage/Ack or product readiness.
}

// A complete deployment writer/fleet/restart observer is not supplied by this
// controlled component. Do not reinterpret one PID as a complete fleet.
func NewDeployment(c Config) (*Coordinator, func(), error) { return nil, nil, ErrRefused }
