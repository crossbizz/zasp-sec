package orchestration

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

const RetentionScheduleID = "retention-reference-expiry-v1"
const RetentionWorkflowPrefix = "retention-reference-expiry/v1"
const RetentionActivityName = "RetentionReferenceSweep"

// RetentionCycle contains only Temporal's own execution identity. Tenant scope,
// policy, cursors and private expiry claims never cross this history boundary.
type RetentionCycle struct {
	WorkflowID string `json:"workflow_id"`
	RunID      string `json:"run_id"`
}

var retentionRunID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func (c RetentionCycle) Valid() bool {
	return (c.WorkflowID == RetentionWorkflowPrefix || strings.HasPrefix(c.WorkflowID, RetentionWorkflowPrefix+"-")) && len(c.WorkflowID) <= 255 && !strings.ContainsAny(c.WorkflowID, "\r\n\x00") && retentionRunID.MatchString(c.RunID)
}

func (c RetentionCycle) Key() (string, error) {
	if !c.Valid() {
		return "", ErrInvalid
	}
	h := sha256.Sum256([]byte("retention-reference-expiry/v1\x00" + c.WorkflowID + "\x00" + c.RunID))
	return hex.EncodeToString(h[:]), nil
}

type RetentionCounters struct {
	Scopes  int `json:"scopes"`
	Scanned int `json:"scanned"`
	Expired int `json:"expired"`
}

func (c RetentionCounters) Valid() bool {
	return c.Scopes >= 0 && c.Scopes <= 16 && c.Scanned >= 0 && c.Scanned <= 1600 && c.Expired >= 0 && c.Expired <= c.Scanned && (c.Scopes != 0 || c.Scanned == 0)
}

// RetentionScheduledWorkflow intentionally has no input parameters.
func RetentionScheduledWorkflow(ctx workflow.Context) (RetentionCounters, error) {
	info := workflow.GetInfo(ctx)
	cycle := RetentionCycle{WorkflowID: info.WorkflowExecution.ID, RunID: info.WorkflowExecution.RunID}
	attrs := info.SearchAttributes.GetIndexedFields()
	var by string
	var due time.Time
	dc := converter.GetDefaultDataConverter()
	if !cycle.Valid() || attrs["TemporalScheduledById"] == nil || attrs["TemporalScheduledStartTime"] == nil || dc.FromPayload(attrs["TemporalScheduledById"], &by) != nil || dc.FromPayload(attrs["TemporalScheduledStartTime"], &due) != nil || by != RetentionScheduleID || due.IsZero() {
		return RetentionCounters{}, activityError(ErrInvalid)
	}
	bounded := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute, ScheduleToCloseTimeout: 5 * time.Minute,
		WaitForCancellation: true,
		RetryPolicy:         &temporal.RetryPolicy{InitialInterval: time.Second, MaximumInterval: 30 * time.Second, BackoffCoefficient: 2, MaximumAttempts: 5},
	})
	var result RetentionCounters
	if err := workflow.ExecuteActivity(bounded, RetentionActivityName, cycle).Get(ctx, &result); err != nil {
		return RetentionCounters{}, err
	}
	if !result.Valid() {
		return RetentionCounters{}, activityError(ErrInvalid)
	}
	return result, nil
}
