package orchestration

import (
	"context"
	"time"

	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

type DiscoveryScheduleStart struct {
	Ref      DiscoveryScheduleRef `json:"ref"`
	Revision int64                `json:"revision"`
}
type DiscoveryOccurrence struct {
	Schedule DiscoveryScheduleStart `json:"schedule"`
	DueAt    time.Time              `json:"due_at"` // Nominal wakeup only; SQL owns persisted due.
}
type DiscoveryAdmission struct {
	Outcome string          `json:"outcome"` // admitted or not_due
	Start   *DiscoveryStart `json:"start,omitempty"`
}
type DiscoveryStart struct {
	Ref           RunRef                 `json:"ref"`
	IntegrationID string                 `json:"integration_id"`
	InputDigest   string                 `json:"input_digest"`
	Continuation  *DiscoveryContinuation `json:"continuation,omitempty"`
}

// Checkpoint receipts bound history continuation. They grant no provider access:
// Activities reload the actual scoped checkpoint and cursor from product SQL.
type DiscoveryContinuation struct {
	CheckpointVersion int64     `json:"checkpoint_version"`
	ReceiptDigest     string    `json:"receipt_digest"`
	Deadline          time.Time `json:"deadline"`
}
type DiscoveryPage struct {
	Outcome           string `json:"outcome"`
	CheckpointVersion int64  `json:"checkpoint_version"`
	ReceiptDigest     string `json:"receipt_digest"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

// Expected checkpoint is an untrusted scoped precondition, never authority.
// SQL resolves/replays the corresponding page receipt on retry. A mismatch
// must refuse before fresh provider I/O; next-page work gets a new precondition.
type DiscoveryPageCommand struct {
	Start                     DiscoveryStart `json:"start"`
	ExpectedCheckpointVersion int64          `json:"expected_checkpoint_version"`
	ExpectedCheckpointDigest  string         `json:"expected_checkpoint_digest"`
	Deadline                  time.Time      `json:"deadline"`
}
type DiscoveryApplyCommand struct {
	Start                 DiscoveryStart `json:"start"`
	Deadline              time.Time      `json:"deadline"`
	CompleteReceiptDigest string         `json:"complete_receipt_digest"`
}

// Reconciliation can read/settle existing scoped evidence only. It cannot
// collect, apply inventory, resend a provider effect, or overwrite uncertainty.
type DiscoveryReconcile struct {
	Start    DiscoveryStart `json:"start"`
	Deadline time.Time      `json:"deadline"`
	Reason   string         `json:"reason"`
}
type DiscoveryResult struct {
	Outcome       string `json:"outcome"`
	ReceiptDigest string `json:"receipt_digest,omitempty"`
}
type DiscoveryFinish struct {
	Start         DiscoveryStart `json:"start"`
	Outcome       string         `json:"outcome"`
	ReceiptDigest string         `json:"receipt_digest,omitempty"`
}

// DiscoveryProduct is the P4B Activity implementation contract, not an authority
// implementation. Register these exact method names only after installed SQL
// readiness passes. Never wrap discoveryProcessor or its lease/heartbeat loop.
//
// Admission treats the nominal DueAt only as a wakeup. Under a scoped lock it
// reads current revision/enabled/connector authority and the persisted oldest
// due using DB time. It atomically admits that occurrence, advances via
// PlanDiscoveryDue and commits durable start delivery, or returns not_due.
// Stable IDs use canonical tenant+schedule+integration+PERSISTED due, not the
// wakeup time. Schedule ID is service principal, not its creator's session.
//
// Collect reloads the scoped provider/cursor/version/manifest from SQL, checks
// current connector authority before fresh provider I/O, collects a bounded page
// and durably records its digest/checkpoint. Replays are receipt-idempotent.
// A known-safe retryable receipt advances the command precondition but leaves
// the provider cursor and inventory generation unchanged. SQL enforces any
// retry-not-before; neither elapsed time nor a new token can authorize an
// unknown effect to resend. This receipt version is not a provider cursor.
// Cursor/configuration/credential/body never cross this interface. Shared
// manual/periodic provider access uses narrow generation/resource serialization.
//
// Apply requires verified complete collection and idempotently writes scoped
// inventory; partial/denied/unknown cannot make a complete snapshot. Finish
// persists typed product outcomes and validates the matching inventory receipt.
// Errors must be classified and redacted before entering Temporal history.
// Fresh collection/application must enforce the command's original deadline
// against the persisted run budget before I/O; it is an untrusted precondition,
// not permission to extend that budget. SDK timeouts cannot fence late I/O.
// ReconcileDiscoveryOutcome atomically settles only durable existing evidence:
// incomplete without application, outcome_unknown for unresolved application,
// succeeded only with verified committed inventory receipt. It never retries
// apply and never replaces unknown/committed evidence with cancelled.
type DiscoveryProduct interface {
	AdmitDiscoveryScheduled(context.Context, DiscoveryOccurrence) (DiscoveryAdmission, error)
	CollectDiscoveryPage(context.Context, DiscoveryPageCommand) (DiscoveryPage, error)
	ApplyDiscoverySnapshot(context.Context, DiscoveryApplyCommand) (string, error)
	FinishDiscovery(context.Context, DiscoveryFinish) error
	ReconcileDiscoveryOutcome(context.Context, DiscoveryReconcile) (DiscoveryResult, error)
}

func (s DiscoveryStart) valid() bool {
	return s.Ref.valid() && validID(s.IntegrationID) && digestPattern.MatchString(s.InputDigest)
}

func DiscoveryWorkflowID(s DiscoveryStart) (string, error) {
	if !s.valid() {
		return "", ErrInvalid
	}
	return "discovery/v1/" + s.Ref.OrganizationID + "/" + s.Ref.WorkspaceID + "/" + s.Ref.EnvironmentID + "/" + s.IntegrationID + "/" + s.Ref.RunID, nil
}

func discoveryContext(ctx workflow.Context, deadline time.Time, attempts int32) (workflow.Context, bool) {
	remaining := deadline.Sub(workflow.Now(ctx))
	if remaining <= 0 {
		return ctx, false
	}
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: min(5*time.Minute, remaining), ScheduleToCloseTimeout: min(30*time.Minute, remaining),
		WaitForCancellation: true,
		RetryPolicy:         &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 2, MaximumInterval: time.Minute, MaximumAttempts: attempts},
	}), true
}

// The Schedule's nominal time is evidence, not a clock read or authorization.
// SQL must validate it against current product configuration in admission.
func DiscoveryScheduledWorkflow(ctx workflow.Context, s DiscoveryScheduleStart) (DiscoveryResult, error) {
	if !s.Ref.valid() || s.Revision < 1 || s.Revision > 1000000 {
		return DiscoveryResult{}, discoveryRefused()
	}
	attrs := workflow.GetInfo(ctx).SearchAttributes.GetIndexedFields()
	var by string
	var due time.Time
	id, _ := DiscoveryScheduleID(s.Ref)
	dc := converter.GetDefaultDataConverter()
	if attrs["TemporalScheduledById"] == nil || attrs["TemporalScheduledStartTime"] == nil || dc.FromPayload(attrs["TemporalScheduledById"], &by) != nil || dc.FromPayload(attrs["TemporalScheduledStartTime"], &due) != nil || by != id || due.IsZero() {
		return DiscoveryResult{}, discoveryRefused()
	}
	deadline := workflow.Now(ctx).Add(24 * time.Hour)
	bounded, _ := discoveryContext(ctx, deadline, 5)
	var admission DiscoveryAdmission
	if err := workflow.ExecuteActivity(bounded, "AdmitDiscoveryScheduled", DiscoveryOccurrence{Schedule: s, DueAt: due.UTC()}).Get(ctx, &admission); err != nil {
		return DiscoveryResult{}, err
	}
	if admission.Outcome == "not_due" && admission.Start == nil {
		return DiscoveryResult{Outcome: "not_due"}, nil
	}
	admitted := admission.Start
	if admission.Outcome != "admitted" || admitted == nil || admitted.Continuation != nil || !admitted.valid() || admitted.Ref.OrganizationID != s.Ref.OrganizationID || admitted.Ref.WorkspaceID != s.Ref.WorkspaceID || admitted.Ref.EnvironmentID != s.Ref.EnvironmentID || admitted.IntegrationID != s.Ref.IntegrationID {
		return DiscoveryResult{}, discoveryRefused()
	}
	// Atomic admission commits the common start outbox. Running collection here
	// too would create a second consumer beside the duplicate-safe outbox start.
	return DiscoveryResult{Outcome: "admitted"}, nil
}

// Manual callers start this only after common product admission commits.
// Every Activity still checks current authority; workflow input grants nothing.
func DiscoveryWorkflow(ctx workflow.Context, s DiscoveryStart) (result DiscoveryResult, resultErr error) {
	if !s.valid() {
		return DiscoveryResult{}, discoveryRefused()
	}
	checkpoint := int64(0)
	checkpointDigest := ""
	deadline := workflow.Now(ctx).Add(24 * time.Hour)
	if c := s.Continuation; c != nil {
		if c.CheckpointVersion < 0 || c.Deadline.IsZero() || c.Deadline.After(deadline) ||
			(c.CheckpointVersion == 0 && c.ReceiptDigest != "") ||
			(c.CheckpointVersion > 0 && !digestPattern.MatchString(c.ReceiptDigest)) {
			return DiscoveryResult{}, discoveryRefused()
		}
		checkpoint, checkpointDigest, deadline = c.CheckpointVersion, c.ReceiptDigest, c.Deadline
		s.Continuation = nil
	}
	reconciled := false
	reconcile := func(reason string) (DiscoveryResult, error) {
		reconciled = true
		return reconcileDiscovery(ctx, DiscoveryReconcile{Start: s, Deadline: deadline, Reason: reason})
	}
	defer func() {
		if reconciled || (!temporal.IsCanceledError(resultErr) && ctx.Err() == nil) {
			return
		}
		prior := resultErr
		result, resultErr = reconcile("cancelled")
		if resultErr == nil && result.Outcome == "cancelled" {
			resultErr = prior
			if resultErr == nil {
				resultErr = temporal.NewCanceledError()
			}
		}
	}()
	// Bound history, not inventory size. Deadline persists across continuation;
	// its exhaustion leaves incomplete product state for the recovery route.
	for pages := 0; pages < 256 && workflow.Now(ctx).Before(deadline); pages++ {
		var page DiscoveryPage
		command := DiscoveryPageCommand{Start: s, ExpectedCheckpointVersion: checkpoint, ExpectedCheckpointDigest: checkpointDigest, Deadline: deadline}
		bounded, ok := discoveryContext(ctx, deadline, 5)
		if !ok {
			return reconcile("deadline")
		}
		if err := workflow.ExecuteActivity(bounded, "CollectDiscoveryPage", command).Get(ctx, &page); err != nil {
			if !workflow.Now(ctx).Before(deadline) {
				return reconcile("deadline")
			}
			if temporal.IsCanceledError(err) || ctx.Err() != nil {
				return DiscoveryResult{}, err
			}
			// Refused current authority can leave a known-no-IO waiting run.
			// Only product evidence decides incomplete versus uncertain dispatch.
			return reconcile("activity_failed")
		}
		if page.CheckpointVersion < 0 || page.RetryAfterSeconds < 0 || page.RetryAfterSeconds > 3600 {
			return DiscoveryResult{}, discoveryRefused()
		}
		result := DiscoveryResult{Outcome: page.Outcome}
		if !workflow.Now(ctx).Before(deadline) {
			return reconcile("deadline")
		}
		switch page.Outcome {
		case "partial":
			if page.CheckpointVersion <= checkpoint || !digestPattern.MatchString(page.ReceiptDigest) {
				return DiscoveryResult{}, discoveryRefused()
			}
			checkpoint = page.CheckpointVersion
			checkpointDigest = page.ReceiptDigest
			continue
		case "retryable":
			// The product receipt advances while the provider cursor does not.
			// Reusing the old command would replay its retryable outcome forever;
			// it must never be interpreted as permission to resend that effect.
			if page.CheckpointVersion <= checkpoint || !digestPattern.MatchString(page.ReceiptDigest) {
				return DiscoveryResult{}, discoveryRefused()
			}
			checkpoint, checkpointDigest = page.CheckpointVersion, page.ReceiptDigest
			delay := page.RetryAfterSeconds
			if delay == 0 {
				delay = 30
			}
			if err := workflow.Sleep(ctx, min(time.Duration(delay)*time.Second, deadline.Sub(workflow.Now(ctx)))); err != nil {
				return DiscoveryResult{}, err
			}
			continue
		case "complete":
			if page.CheckpointVersion < checkpoint || !digestPattern.MatchString(page.ReceiptDigest) {
				return DiscoveryResult{}, discoveryRefused()
			}
			var receipt string
			bounded, ok = discoveryContext(ctx, deadline, 1)
			if !ok {
				return reconcile("deadline")
			}
			apply := DiscoveryApplyCommand{Start: s, Deadline: deadline, CompleteReceiptDigest: page.ReceiptDigest}
			if err := workflow.ExecuteActivity(bounded, "ApplyDiscoverySnapshot", apply).Get(ctx, &receipt); err != nil {
				return reconcile("apply_uncertain")
			}
			if !digestPattern.MatchString(receipt) {
				return reconcile("apply_uncertain")
			}
			if !workflow.Now(ctx).Before(deadline) {
				return reconcile("deadline")
			}
			result = DiscoveryResult{Outcome: "succeeded", ReceiptDigest: receipt}
		case "incomplete", "denied", "revoked", "malformed", "cancelled", "outcome_unknown", "terminal":
		default:
			return DiscoveryResult{}, discoveryRefused()
		}
		bounded, ok = discoveryContext(ctx, deadline, 5)
		if !ok {
			return reconcile("deadline")
		}
		if err := workflow.ExecuteActivity(bounded, "FinishDiscovery", DiscoveryFinish{Start: s, Outcome: result.Outcome, ReceiptDigest: result.ReceiptDigest}).Get(ctx, nil); err != nil {
			return reconcile("settlement_uncertain")
		}
		return result, nil
	}
	if !workflow.Now(ctx).Before(deadline) {
		return reconcile("deadline")
	}
	s.Continuation = &DiscoveryContinuation{CheckpointVersion: checkpoint, ReceiptDigest: checkpointDigest, Deadline: deadline}
	return DiscoveryResult{}, workflow.NewContinueAsNewError(ctx, DiscoveryWorkflow, s)
}

func reconcileDiscovery(ctx workflow.Context, q DiscoveryReconcile) (DiscoveryResult, error) {
	disconnected, cancel := workflow.NewDisconnectedContext(ctx)
	defer cancel()
	disconnected = workflow.WithActivityOptions(disconnected, workflow.ActivityOptions{
		StartToCloseTimeout: 20 * time.Second, ScheduleToCloseTimeout: time.Minute,
		RetryPolicy: &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	var result DiscoveryResult
	if err := workflow.ExecuteActivity(disconnected, "ReconcileDiscoveryOutcome", q).Get(disconnected, &result); err != nil {
		return DiscoveryResult{}, err
	}
	switch result.Outcome {
	case "succeeded":
		if !digestPattern.MatchString(result.ReceiptDigest) {
			return DiscoveryResult{}, discoveryRefused()
		}
	case "incomplete", "outcome_unknown", "cancelled", "denied", "revoked", "malformed", "terminal":
		if result.ReceiptDigest != "" {
			return DiscoveryResult{}, discoveryRefused()
		}
	default:
		return DiscoveryResult{}, discoveryRefused()
	}
	return result, nil
}

func discoveryRefused() error {
	return temporal.NewNonRetryableApplicationError("discovery product contract refused", "DiscoveryContractRefused", nil)
}
