package connectormaintenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// Operation contains every original reconciliation transition and the new
// no-attempt reservation boundary. Callers cannot supply SQL/function names.
type Operation uint8

const (
	RecoverExpiredFinalAttempts Operation = iota + 1
	ReserveReconciliation
	PauseDenied
	ReleaseUnattempted
	BeginProviderAttempt
	BeginSecretFailureAttempt
	CompleteOAuth
	CompleteCleanup
	CompletePKCECleanup
	Quarantine
	Fail
	CompleteRevocation
	ReadWorkflow
	BeforeCompensation
)

type Executor struct {
	pool             *pgxpool.Pool
	profile, version string
}

// NewExecutor refuses before returning when the complete registered native
// profile, actual original SQL principal and verifier are unavailable. There is
// no legacy QueryJSON fallback, partial-function mode or readiness override.
func NewExecutor(ctx context.Context, pool *pgxpool.Pool, profile string, key []byte) (*Executor, error) {
	if ctx == nil || ctx.Err() != nil || pool == nil || !digest(profile) || len(key) != 32 {
		return nil, ErrConfiguration
	}
	h := sha256.Sum256(key)
	e := &Executor{pool: pool, profile: profile, version: hex.EncodeToString(h[:])}
	if e.Ready(ctx) != nil {
		return nil, ErrConfiguration
	}
	return e, nil
}

func (e *Executor) Ready(ctx context.Context) error {
	return e.transaction(ctx, func(tx pgx.Tx) error {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT zasp_connector_maintenance.caller_ready($1,$2)`, e.profile, e.version).Scan(&ok); err != nil {
			return databaseError(err)
		}
		if !ok {
			return ErrUnavailable
		}
		return nil
	})
}

func (e *Executor) transaction(ctx context.Context, run func(pgx.Tx) error) error {
	if e == nil || e.pool == nil || ctx == nil || ctx.Err() != nil || run == nil {
		return ErrUnavailable
	}
	tx, err := e.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return databaseError(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	// Keep original72 login and all its consumers. New native purpose and HMAC
	// registration restrict THIS module; membership does not bind an executable.
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_outbox_worker`); err != nil {
		return databaseError(err)
	}
	if err = run(tx); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	return databaseError(tx.Commit(ctx))
}

func (e *Executor) query(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	var raw []byte
	err := e.transaction(ctx, func(tx pgx.Tx) error { return databaseError(tx.QueryRow(ctx, sql, args...).Scan(&raw)) })
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 131072 || !json.Valid(raw) || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return json.RawMessage(raw), nil
}

func (e *Executor) Facts(ctx context.Context, r Reference) (Facts, error) {
	var f Facts
	if !validReference(r) {
		return f, ErrUnavailable
	}
	q, err := json.Marshal(r)
	if err != nil {
		return f, ErrUnavailable
	}
	raw, err := e.query(ctx, `SELECT zasp_connector_maintenance.source($1::jsonb,$2,$3)`, q, e.profile, e.version)
	if err != nil {
		return f, err
	}
	if decodeObject(raw, &f, "profile_checksum", "context_digest", "reference", "task_id", "purpose", "grantor_id", "principal_id", "source_profile", "source_proof_digest", "committed_request_digest", "committed_effect_digest", "operation", "attempt", "lease_expires_at", "session_user") != nil || !validFacts(f, r, e.profile) {
		return Facts{}, ErrUnavailable
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return Facts{}, ErrUnavailable
	}
	var nested Reference
	if decodeObject(fields["reference"], &nested, "organization_id", "workspace_id", "environment_id", "effect_id", "integration_id", "lease_owner", "lease_token", "intent_digest") != nil || nested != r {
		return Facts{}, ErrUnavailable
	}

	return f, nil
}

func (e *Executor) Revision(ctx context.Context, org string) (authorization.Revision, error) {
	var r authorization.Revision
	if !validID(org) {
		return r, ErrUnavailable
	}
	raw, err := e.query(ctx, `SELECT zasp_connector_maintenance.revision($1,$2,$3)`, org, e.profile, e.version)
	if err != nil {
		return r, err
	}
	if decodeObject(raw, &r, "organization_id", "desired", "applied", "generation", "store_id", "model_id") != nil {
		return r, ErrUnavailable
	}
	return r, nil
}

func (e *Executor) Invoke(ctx context.Context, op Operation, request json.RawMessage, proof []byte) (json.RawMessage, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || len(request) == 0 || len(request) > 32768 || !json.Valid(request) || len(proof) > 65536 {
		return nil, ErrUnavailable
	}
	// Exact request grammar and original business arguments are revalidated by
	// native SQL. Attempted transitions require captured proof, never a newly
	// issued forward decision. Recovery may inspect only registered origins.
	switch op {
	case RecoverExpiredFinalAttempts:
		if len(proof) != 0 {
			return nil, ErrUnavailable
		}
		return e.query(ctx, `SELECT zasp_connector_maintenance.recover($1::jsonb,$2,$3)`, request, e.profile, e.version)
	case ReserveReconciliation:
		if len(proof) != 0 {
			return nil, ErrUnavailable
		}
		return e.query(ctx, `SELECT zasp_connector_maintenance.reserve($1::jsonb,$2,$3)`, request, e.profile, e.version)
	case PauseDenied, ReleaseUnattempted:
		if len(proof) != 0 {
			return nil, ErrUnavailable
		}
		return e.query(ctx, `SELECT zasp_connector_maintenance.release($1::jsonb,$2,$3,$4)`, request, op == PauseDenied, e.profile, e.version)
	case BeginProviderAttempt, BeginSecretFailureAttempt:
		if len(proof) == 0 {
			return nil, ErrUnavailable
		}
		kind := "provider"
		if op == BeginSecretFailureAttempt {
			kind = "secret_failure"
		}
		return e.query(ctx, `SELECT zasp_connector_maintenance.begin_attempt($1::jsonb,$2,$3::json,$4,$5)`, request, kind, json.RawMessage(proof), e.profile, e.version)
	case BeforeCompensation:
		if len(proof) == 0 {
			return nil, ErrUnavailable
		}
		return e.query(ctx, `SELECT zasp_connector_maintenance.validate_captured($1::jsonb,$2::json,$3,$4)`, request, json.RawMessage(proof), e.profile, e.version)
	case ReadWorkflow:
		if len(proof) == 0 {
			return nil, ErrUnavailable
		}
		return e.query(ctx, `SELECT zasp_connector_maintenance.workflow($1::jsonb,$2::json,$3,$4)`, request, json.RawMessage(proof), e.profile, e.version)
	case CompleteOAuth, CompleteCleanup, CompletePKCECleanup, Quarantine, Fail, CompleteRevocation:
		if len(proof) == 0 {
			return nil, ErrUnavailable
		}
		name := map[Operation]string{CompleteOAuth: "complete_oauth", CompleteCleanup: "complete_cleanup", CompletePKCECleanup: "complete_pkce_cleanup", Quarantine: "quarantine", Fail: "fail", CompleteRevocation: "complete_revocation"}[op]
		return e.query(ctx, `SELECT zasp_connector_maintenance.settle($1::jsonb,$2::json,$3,$4,$5)`, request, json.RawMessage(proof), name, e.profile, e.version)
	default:
		return nil, ErrUnavailable
	}
}

func databaseError(err error) error {
	if err == nil {
		return nil
	}
	var p *pgconn.PgError
	if errors.As(err, &p) && p.Code == "42501" {
		return ErrDenied
	}
	return ErrUnavailable
}

// VerifyActiveProfile admits only the closed fixed native metadata response.
// It is not permission to enqueue or execute an effect; those native functions
// repeat the live source/role/authority checks in their own transactions.
func VerifyActiveProfile(raw []byte, pin string) error {
	var state struct {
		Active       bool   `json:"active"`
		Checksum     string `json:"checksum"`
		CatalogReady bool   `json:"catalog_ready"`
	}
	if !digest(pin) || decodeObject(raw, &state, "active", "checksum", "catalog_ready") != nil || !state.Active || !state.CatalogReady || state.Checksum != pin {
		return ErrUnavailable
	}
	return nil
}
