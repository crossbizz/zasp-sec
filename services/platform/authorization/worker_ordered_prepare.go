package authorization

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type orderedPreparationDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func orderedPreparationStatement(operation WorkerOperation) (string, bool) {
	switch operation {
	case "ordered68.effect.reserve":
		return `SELECT zasp_authorization80_worker.prepare_ordered68_effect($1::jsonb)`, false
	case "ordered68.application.source", "ordered68.delivery.apply.prepare", "ordered68.delivery.apply.store":
		return `SELECT zasp_authorization80_worker.prepare_ordered68_policy($1,$2::jsonb)`, true
	}
	return "", false
}

// PrepareOrdered68Operation captures only native-derived current scope. It
// does not authorize an effect: callers must subsequently obtain a fresh FGA
// decision against the projected scope and use the fixed consuming entry.
// Captured compensation can never establish new forward scope through here.
func (e *WorkerExecutor) PrepareOrdered68Operation(ctx context.Context, operation WorkerOperation, request json.RawMessage) error {
	if e == nil {
		return ErrInvalid
	}
	return e.prepareOrdered68Operation(ctx, operation, request, e.pool, e)
}

func (e *WorkerExecutor) prepareOrdered68Operation(ctx context.Context, operation WorkerOperation, request json.RawMessage, db orderedPreparationDB, revisions RevisionReader) error {
	statement, policy := orderedPreparationStatement(operation)
	limit := 4096
	if policy {
		limit = 32768
	}
	if statement == "" || e == nil || e.key == nil || e.pool == nil || db == nil || e.key.purpose != WorkerForward || e.adapter || e.discovery || ctx == nil || ctx.Err() != nil || len(request) > limit || !json.Valid(request) {
		return ErrInvalid
	}
	var scope struct {
		OrganizationID string `json:"organization_id"`
	}
	if policy {
		// Check before capture: no native write may precede an unbounded wait.
		if _, ok := ctx.Deadline(); !ok || revisions == nil {
			return ErrInvalid
		}
		if json.Unmarshal(request, &scope) != nil {
			return ErrInvalid
		}
		if _, err := domain.ParseProductID(scope.OrganizationID); err != nil {
			return ErrInvalid
		}
	}
	request = append(json.RawMessage(nil), request...)
	args := []any{request}
	if policy {
		args = []any{string(operation), request}
	}
	if _, err := db.Exec(ctx, statement, args...); err != nil {
		return workerDatabaseError(err)
	}
	if policy {
		return waitOrderedPolicyProjection(ctx, revisions, scope.OrganizationID, e.storeID, e.modelID)
	}
	return nil
}

// This wait observes convergence, not authority. The caller must still run
// fresh Authorize and native consumption within the SAME operation context.
// No capture, FGA write, positive decision or revision is cached or retried.
func waitOrderedPolicyProjection(ctx context.Context, reader RevisionReader, organization, storeID, modelID string) error {
	if ctx == nil || reader == nil {
		return ErrInvalid
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrInvalid
	}
	var prior Revision
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := reader.Revision(ctx, organization)
		// A reader may return a current revision concurrently with cancellation.
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		if err != nil {
			return err
		}
		if current.validate() != nil || current.OrganizationID != organization || current.StoreID != storeID || current.ModelID != modelID {
			return ErrPending
		}
		if prior.OrganizationID != "" && (current.Desired < prior.Desired || current.Applied < prior.Applied || current.Generation < prior.Generation) {
			return ErrConflict
		}
		if current.Desired == current.Applied {
			return nil
		}
		prior = current
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
