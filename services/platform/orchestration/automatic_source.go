package orchestration

import (
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

type AutomaticSourceRef struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	EventID        string `json:"event_id"`
}

type AutomaticSourceStart struct {
	Ref   AutomaticSourceRef `json:"ref"`
	After string             `json:"after,omitempty"`
	Retry bool               `json:"retry,omitempty"`
}

type AutomaticPage struct {
	After    string `json:"after"`
	More     bool   `json:"more"`
	Retry    bool   `json:"retry"`
	Scanned  int    `json:"scanned"`
	Admitted int    `json:"admitted"`
}

// Schedule inputs always start at the empty cursor. Only the owned Workflow
// carries later page progress and deferred-sweep state across continuation.
type AutomaticCatchupStart struct {
	Ref      TestSelectorRef `json:"ref"`
	Revision int64           `json:"revision"`
	After    string          `json:"after,omitempty"`
	Retry    bool            `json:"retry,omitempty"`
}

func (r AutomaticSourceRef) Valid() bool {
	return validID(r.OrganizationID) && validID(r.WorkspaceID) && validID(r.EnvironmentID) && validID(r.EventID)
}

func AutomaticSourceWorkflowID(r AutomaticSourceRef) (string, error) {
	if !r.Valid() {
		return "", ErrInvalid
	}
	return "automatic-source/v1/" + r.OrganizationID + "/" + r.WorkspaceID + "/" + r.EnvironmentID + "/" + r.EventID, nil
}

func (p AutomaticPage) Valid(after string) bool {
	if p.Scanned < 0 || p.Scanned > 25 || p.Admitted < 0 || p.Admitted > p.Scanned || (p.After != "" && !validID(p.After)) {
		return false
	}
	if p.Scanned == 0 {
		return !p.More && !p.Retry && p.After == after
	}
	return p.After > after
}

func automaticInputValid(ctx workflow.Context, after string, retry bool) bool {
	return (after == "" || validID(after)) && (workflow.GetInfo(ctx).ContinuedExecutionRunID != "" || (after == "" && !retry))
}

func AutomaticSourceWorkflow(ctx workflow.Context, q AutomaticSourceStart) error {
	if !q.Ref.Valid() || !automaticInputValid(ctx, q.After, q.Retry) {
		return automaticInvalid()
	}
	return automaticPages(ctx, &q.After, &q.Retry, func(ctx workflow.Context, p *AutomaticPage) error {
		return workflow.ExecuteActivity(ctx, "AutomaticSourcePage", q).Get(ctx, p)
	}, func(ctx workflow.Context) error {
		return workflow.NewContinueAsNewError(ctx, AutomaticSourceWorkflow, q)
	})
}

func AutomaticCatchupWorkflow(ctx workflow.Context, q AutomaticCatchupStart) error {
	if !q.Ref.Valid() || q.Revision < 1 || q.Revision > 1000000 || !automaticInputValid(ctx, q.After, q.Retry) {
		return automaticInvalid()
	}
	return automaticPages(ctx, &q.After, &q.Retry, func(ctx workflow.Context, p *AutomaticPage) error {
		return workflow.ExecuteActivity(ctx, "AutomaticCatchupPage", q).Get(ctx, p)
	}, func(ctx workflow.Context) error {
		return workflow.NewContinueAsNewError(ctx, AutomaticCatchupWorkflow, q)
	})
}

func automaticInvalid() error {
	return temporal.NewNonRetryableApplicationError("automatic source contract rejected", "invalid", nil)
}

// All retries and continuation belong to Temporal. A capacity deferral only
// requests another complete sweep; it cannot strand the later definitions.
func automaticPages(ctx workflow.Context, after *string, retry *bool, page func(workflow.Context, *AutomaticPage) error, next func(workflow.Context) error) error {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{StartToCloseTimeout: 30 * time.Second, RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, MaximumInterval: 30 * time.Second}})
	for i := 0; i < 100; i++ {
		var p AutomaticPage
		if err := page(ctx, &p); err != nil {
			return err
		}
		if !p.Valid(*after) {
			return automaticInvalid()
		}
		*after, *retry = p.After, *retry || p.Retry
		if p.More {
			continue
		}
		if !*retry {
			return nil
		}
		if err := workflow.Sleep(ctx, time.Second); err != nil {
			return err
		}
		*after, *retry = "", false
	}
	return next(ctx)
}
