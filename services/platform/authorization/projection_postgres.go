package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"time"
)

type PostgresProjectionRepository struct{ pool *pgxpool.Pool }

func NewPostgresProjectionRepository(pool *pgxpool.Pool) (*PostgresProjectionRepository, error) {
	if pool == nil {
		return nil, ErrInvalid
	}
	return &PostgresProjectionRepository{pool}, nil
}
func (r *PostgresProjectionRepository) Revision(ctx context.Context, o string) (Revision, error) {
	if r == nil || ctx == nil {
		return Revision{}, ErrInvalid
	}
	var result Revision
	var data []byte
	if err := r.pool.QueryRow(ctx, `SELECT zasp_authorization79.revision($1)`, o).Scan(&data); err != nil {
		return result, projectionDatabaseError(err)
	}
	if json.Unmarshal(data, &result) != nil {
		return Revision{}, ErrPending
	}
	return result, nil
}

// WithOrganization holds a session advisory lock but no SQL transaction during
// external service calls. Grant writes remain available and invalidate the CAS.
func (r *PostgresProjectionRepository) WithOrganization(ctx context.Context, o string, fn func(ProjectionSession) error) (result error) {
	if r == nil || ctx == nil || fn == nil {
		return ErrInvalid
	}
	if _, err := domain.ParseProductID(o); err != nil {
		return ErrInvalid
	}
	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended('zasp-auth79/'||$1,0))`, o).Scan(&locked); err != nil {
		return projectionDatabaseError(err)
	}
	if !locked {
		return ErrBusy
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if result != nil {
			reason := "delivery_failed"
			if errors.Is(result, ErrInvalid) {
				reason = "invalid_source"
			}
			if errors.Is(result, ErrConflict) {
				reason = "conflict"
			}
			_, _ = conn.Exec(cleanup, `SELECT zasp_authorization79.blocked($1,$2)`, o, reason)
		}
		var unlocked bool
		if err := conn.QueryRow(cleanup, `SELECT pg_advisory_unlock(hashtextextended('zasp-auth79/'||$1,0))`, o).Scan(&unlocked); err != nil || !unlocked {
			_ = conn.Conn().Close(cleanup)
			if result == nil {
				result = ErrUnavailable
			}
		}
	}()
	return fn(&postgresProjectionSession{conn, o})
}

type postgresProjectionSession struct {
	conn           *pgxpool.Conn
	organizationID string
}

func (s *postgresProjectionSession) Snapshot(ctx context.Context) (ProjectionSnapshot, error) {
	var data []byte
	var value ProjectionSnapshot
	if err := s.conn.QueryRow(ctx, `SELECT zasp_authorization79.snapshot($1)`, s.organizationID).Scan(&data); err != nil {
		return value, projectionDatabaseError(err)
	}
	if json.Unmarshal(data, &value) != nil {
		return value, ErrInvalid
	}
	return value, nil
}
func (s *postgresProjectionSession) Stage(ctx context.Context, r Revision, tuples []fga.ClientTupleKey) error {
	return s.deliver(ctx, r, tuples, `SELECT zasp_authorization79.stage($1,$2,$3,$4,$5,$6::jsonb)`)
}
func (s *postgresProjectionSession) Acknowledge(ctx context.Context, r Revision, tuples []fga.ClientTupleKey) error {
	return s.deliver(ctx, r, tuples, `SELECT zasp_authorization79.ack($1,$2,$3,$4,$5,$6::jsonb)`)
}
func (s *postgresProjectionSession) deliver(ctx context.Context, r Revision, tuples []fga.ClientTupleKey, query string) error {
	if r.OrganizationID != s.organizationID || r.validate() != nil {
		return ErrInvalid
	}
	if tuples == nil {
		tuples = []fga.ClientTupleKey{}
	}
	data, err := json.Marshal(tuples)
	if err != nil {
		return ErrInvalid
	}
	_, err = s.conn.Exec(ctx, query, r.OrganizationID, r.Desired, r.Generation, r.StoreID, r.ModelID, data)
	return projectionDatabaseError(err)
}

type PendingProjection struct {
	Revision
	PendingSince  time.Time  `json:"pending_since"`
	LastAttemptAt *time.Time `json:"last_attempt_at"`
	BlockedReason string     `json:"blocked_reason"`
}

func (r *PostgresProjectionRepository) Pending(ctx context.Context, limit int) ([]PendingProjection, error) {
	if r == nil || ctx == nil || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	var data []byte
	if err := r.pool.QueryRow(ctx, `SELECT zasp_authorization79.pending($1)`, limit).Scan(&data); err != nil {
		return nil, projectionDatabaseError(err)
	}
	var value []PendingProjection
	if json.Unmarshal(data, &value) != nil {
		return nil, ErrInvalid
	}
	return value, nil
}
func projectionDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) {
		switch pgerr.Code {
		case "40001", "40P01", "55P03":
			return ErrConflict
		case "23514":
			return ErrInvalid
		}
	}
	return ErrUnavailable
}

// RetryableConflict includes errors from the caller's own product SQL statements.
// Recognizing one never retries: rollback and restart the entire authorization
// attempt, preserving the original effect and idempotency identifiers.
func RetryableConflict(err error) bool {
	return errors.Is(err, ErrConflict) || errors.Is(projectionDatabaseError(err), ErrConflict)
}

// RevalidateDecision must run in the same transaction as the sensitive read or
// write, before that action, and its row lock must be retained through commit.
// The caller must ALSO revalidate current identity/session/PAT, SQL ownership,
// policy/approval/budget and any product-state fence. Retry ErrConflict only by
// rolling back and restarting at Check with stable effect/idempotency IDs.
func RevalidateDecision(ctx context.Context, tx pgx.Tx, decision CheckedDecision, request CheckRequest) error {
	if ctx == nil || tx == nil || !decision.Decision.Allowed || decision.Request != request || decision.Revision.validate() != nil || decision.Revision.OrganizationID != request.OrganizationID || decision.Decision.ModelID != decision.Revision.ModelID {
		return ErrInvalid
	}
	r := decision.Revision
	_, err := tx.Exec(ctx, `SELECT zasp_authorization79.revalidate($1,$2,$3,$4,$5)`, r.OrganizationID, r.Desired, r.Generation, r.StoreID, r.ModelID)
	return projectionDatabaseError(err)
}
