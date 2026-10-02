package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type productDiscoveryCollectorFactory interface {
	BuildProductDiscoveryCollector(context.Context, domain.Scope, apiserver.DiscoveryCollectionInput, func(context.Context) error) (discoveryJobCollector, error)
}

// No execution-job repository or lease processor sits behind these Activities.
// SQL owns dispatch identities, current authority, replay and inventory commits.
type temporalDiscoveryProduct struct {
	database      apiserver.JSONDatabase
	collectors    productDiscoveryCollectorFactory
	authorization *workerDiscoveryDatabase
}

func newTemporalDiscoveryProduct(database apiserver.JSONDatabase, collectors productDiscoveryCollectorFactory) (*temporalDiscoveryProduct, error) {
	if nilWorkerDependency(database) || nilWorkerDependency(collectors) {
		return nil, errWorkerExecution
	}
	p := &temporalDiscoveryProduct{database: database, collectors: collectors}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Ready(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *temporalDiscoveryProduct) Ready(ctx context.Context) error {
	if p != nil && p.authorization != nil {
		if err := p.authorization.ready(ctx); err != nil {
			return err
		}
	}
	var ready bool
	if err := p.query(ctx, `SELECT to_jsonb(zasp_temporal72.principal_ready('zasp_discovery_worker'))`, &ready); err != nil || !ready {
		return errWorkerExecution
	}
	return nil
}

func (p *temporalDiscoveryProduct) query(ctx context.Context, sql string, destination any, args ...any) error {
	if p == nil || nilWorkerDependency(p.database) || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	raw, err := p.database.QueryJSON(ctx, sql, args...)
	if err != nil || json.Unmarshal(raw, destination) != nil {
		return errWorkerExecution
	}
	return nil
}

func discoveryProductArgs(start orchestration.DiscoveryStart) ([]any, domain.Scope, error) {
	if _, err := orchestration.DiscoveryWorkflowID(start); err != nil {
		return nil, domain.Scope{}, errWorkerExecution
	}
	o, oe := domain.ParseProductID(start.Ref.OrganizationID)
	w, we := domain.ParseProductID(start.Ref.WorkspaceID)
	e, ee := domain.ParseProductID(start.Ref.EnvironmentID)
	if oe != nil || we != nil || ee != nil {
		return nil, domain.Scope{}, errWorkerExecution
	}
	scope, err := domain.NewScope(o, w, e)
	if err != nil {
		return nil, domain.Scope{}, errWorkerExecution
	}
	return []any{start.Ref.OrganizationID, start.Ref.WorkspaceID, start.Ref.EnvironmentID, start.Ref.RunID, start.IntegrationID, start.InputDigest}, scope, nil
}

func (p *temporalDiscoveryProduct) AdmitDiscoveryScheduled(ctx context.Context, q orchestration.DiscoveryOccurrence) (orchestration.DiscoveryAdmission, error) {
	var result orchestration.DiscoveryAdmission
	r := q.Schedule.Ref
	if _, err := orchestration.DiscoveryScheduleID(r); err != nil || q.Schedule.Revision < 1 || q.DueAt.IsZero() {
		return result, errWorkerExecution
	}
	err := p.query(ctx, `SELECT zasp_temporal72.scheduled_admit($1,$2,$3,$4,$5,$6,$7)`, &result, r.OrganizationID, r.WorkspaceID, r.EnvironmentID, r.ScheduleID, r.IntegrationID, q.Schedule.Revision, q.DueAt)
	return result, err
}

func (p *temporalDiscoveryProduct) CollectDiscoveryPage(ctx context.Context, q orchestration.DiscoveryPageCommand) (orchestration.DiscoveryPage, error) {
	var empty orchestration.DiscoveryPage
	args, scope, err := discoveryProductArgs(q.Start)
	if err != nil || q.Deadline.IsZero() {
		return empty, errWorkerExecution
	}
	var prepared struct {
		EffectID string                              `json:"effect_id"`
		Input    *apiserver.DiscoveryCollectionInput `json:"input"`
		Page     *orchestration.DiscoveryPage        `json:"page"`
	}
	args = append(args, q.Deadline, q.ExpectedCheckpointVersion, q.ExpectedCheckpointDigest)
	if err = p.queryDiscovery(ctx, "prepare_page", q.Start, map[string]any{"budget_us": q.Deadline.UnixMicro(), "expected": q.ExpectedCheckpointVersion, "expected_digest": q.ExpectedCheckpointDigest}, `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`, &prepared, args...); err != nil {
		return empty, err
	}
	if prepared.Page != nil && prepared.Input == nil && prepared.EffectID == "" {
		return *prepared.Page, nil
	}
	if prepared.Input == nil || prepared.Page != nil || !collection.ValidExecutionIdentity(0, prepared.EffectID) || prepared.Input.EffectID != prepared.EffectID || !prepared.Input.Deadline.Equal(q.Deadline) {
		return empty, errWorkerExecution
	}
	input := prepared.Input
	// PostgreSQL emits an explicit +00:00 offset. Go may decode that into the
	// host's Local location when it currently has the same offset. Normalize the
	// instant without changing the persisted budget or observation precision.
	input.ObservationTime = input.ObservationTime.UTC()
	input.Deadline = input.Deadline.UTC()
	if input.JobID != q.Start.Ref.RunID || input.IntegrationID != q.Start.IntegrationID {
		return empty, errWorkerExecution
	}
	defer func() {
		clear(input.Configuration)
		clear(input.CheckpointDigest)
		clear(input.CheckpointManifestChecksum)
	}()
	// jsonb has its own key order/spacing. Credential decoders require canonical
	// JSON bytes, so canonicalize the persisted reference-only object without
	// changing its values. SQL still checks the original configuration digest.
	var configuration map[string]json.RawMessage
	if json.Unmarshal(input.Configuration, &configuration) != nil || configuration == nil {
		return empty, errWorkerExecution
	}
	canonical, err := json.Marshal(configuration)
	if err != nil {
		return empty, errWorkerExecution
	}
	clear(input.Configuration)
	input.Configuration = canonical
	request, err := input.CollectionRequest(scope)
	if err != nil {
		return empty, errWorkerExecution
	}
	guard := func(current context.Context) error {
		var allowed bool
		if err := p.queryDiscovery(current, "guard_page", q.Start, map[string]any{"effect_id": prepared.EffectID, "budget_us": q.Deadline.UnixMicro()}, `SELECT to_jsonb(zasp_temporal72.guard_page_effect($1,$2,$3,$4,$5,$6))`, &allowed, q.Start.Ref.OrganizationID, q.Start.Ref.WorkspaceID, q.Start.Ref.EnvironmentID, q.Start.Ref.RunID, prepared.EffectID, q.Deadline); err != nil {
			return err
		}
		if !allowed {
			return errWorkerExecution
		}
		return nil
	}
	collector, buildErr := p.collectors.BuildProductDiscoveryCollector(ctx, scope, *input, guard)
	var outcome collection.Outcome
	collectErr := buildErr
	if buildErr == nil && !nilWorkerDependency(collector) {
		outcome, collectErr = callBoundCollectionCollector(collector, ctx, request)
		collector.Destroy()
	}
	details := map[string]any{"outcome": "outcome_unknown"}
	if collectErr == nil {
		switch value := outcome.(type) {
		case collection.CompleteResult:
			details = discoveryPageDetails("complete", value.NextCursor(), value.Manifest())
			candidate := value.Snapshot()
			details["candidate"] = map[string]any{"entities": json.RawMessage(candidate.Entities()), "relationships": json.RawMessage(candidate.Relationships()), "evidence": json.RawMessage(candidate.Evidence())}
		case collection.PartialResult:
			details = discoveryPageDetails("partial", value.NextCursor(), value.Manifest())
		}
	} else {
		var failure *collection.Failure
		if errors.As(collectErr, &failure) {
			code := string(failure.Code())
			if code == "rate_limited" {
				code = "retryable"
			}
			if code == "partial" {
				code = "incomplete"
			}
			details["outcome"] = code
			if code == "retryable" {
				delay := 1
				if !failure.RetryAt().IsZero() {
					delay = int(time.Until(failure.RetryAt()).Seconds()) + 1
				}
				if delay < 1 {
					delay = 1
				}
				if delay > 900 {
					details["outcome"] = "terminal"
				} else {
					details["retry_after_seconds"] = delay
				}
			}
		}
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return empty, errWorkerExecution
	}
	// If cancellation prevents recording, preparation remains unknown. Never
	// invent a checkpoint or retry permission to compensate for a missing reply.
	var result orchestration.DiscoveryPage
	err = p.queryDiscovery(ctx, "record_page", q.Start, map[string]any{"effect_id": prepared.EffectID, "details": json.RawMessage(raw)}, `SELECT zasp_temporal72.record_page($1,$2,$3,$4,$5,$6::jsonb)`, &result, q.Start.Ref.OrganizationID, q.Start.Ref.WorkspaceID, q.Start.Ref.EnvironmentID, q.Start.Ref.RunID, prepared.EffectID, string(raw))
	return result, err
}

func discoveryPageDetails(outcome string, cursor collection.Cursor, manifest collection.RawManifest) map[string]any {
	d := manifest.Descriptor()
	checksum := d.Checksum()
	return map[string]any{"outcome": outcome, "cursor": map[string]any{"provider": cursor.Provider, "version": cursor.Version, "value": cursor.Value}, "manifest": map[string]any{"reference": d.ObjectReference(), "key": d.Key(), "version_id": d.VersionID(), "checksum": hex.EncodeToString(checksum[:]), "size_bytes": d.Size(), "media_type": d.MediaType(), "schema_version": d.SchemaVersion(), "parser_version": d.ParserVersion(), "tool_version": d.ToolVersion()}}
}

func (p *temporalDiscoveryProduct) ApplyDiscoverySnapshot(ctx context.Context, q orchestration.DiscoveryApplyCommand) (string, error) {
	args, _, err := discoveryProductArgs(q.Start)
	if err != nil || q.Deadline.IsZero() {
		return "", errWorkerExecution
	}
	var prepared struct {
		EffectID string                         `json:"effect_id"`
		Result   *orchestration.DiscoveryResult `json:"result"`
	}
	args = append(args, q.Deadline, q.CompleteReceiptDigest)
	if err = p.queryDiscovery(ctx, "prepare_apply", q.Start, map[string]any{"budget_us": q.Deadline.UnixMicro(), "complete_receipt": q.CompleteReceiptDigest}, `SELECT zasp_temporal72.prepare_apply($1,$2,$3,$4,$5,$6,$7,$8)`, &prepared, args...); err != nil {
		return "", err
	}
	if prepared.Result != nil {
		if prepared.EffectID == "" && prepared.Result.Outcome == "succeeded" && collection.ValidExecutionIdentity(0, prepared.Result.ReceiptDigest) {
			return prepared.Result.ReceiptDigest, nil
		}
		return "", errWorkerExecution
	}
	if !collection.ValidExecutionIdentity(0, prepared.EffectID) {
		return "", errWorkerExecution
	}
	bounded, cancel := context.WithDeadline(ctx, q.Deadline)
	defer cancel()
	var result orchestration.DiscoveryResult
	if err = p.queryDiscovery(bounded, "commit_apply", q.Start, map[string]any{"effect_id": prepared.EffectID, "budget_us": q.Deadline.UnixMicro()}, `SELECT zasp_temporal72.commit_apply($1,$2,$3,$4,$5,$6)`, &result, q.Start.Ref.OrganizationID, q.Start.Ref.WorkspaceID, q.Start.Ref.EnvironmentID, q.Start.Ref.RunID, prepared.EffectID, q.Deadline); err != nil {
		return "", err
	}
	if result.Outcome != "succeeded" || !collection.ValidExecutionIdentity(0, result.ReceiptDigest) {
		return "", errWorkerExecution
	}
	return result.ReceiptDigest, nil
}

func (p *temporalDiscoveryProduct) FinishDiscovery(ctx context.Context, q orchestration.DiscoveryFinish) error {
	args, _, err := discoveryProductArgs(q.Start)
	if err != nil {
		return err
	}
	var result orchestration.DiscoveryResult
	args = append(args, q.Outcome, q.ReceiptDigest)
	if err = p.queryDiscovery(ctx, "finish", q.Start, map[string]any{"outcome": q.Outcome, "receipt": q.ReceiptDigest}, `SELECT zasp_temporal72.finish($1,$2,$3,$4,$5,$6,$7,$8)`, &result, args...); err != nil {
		return err
	}
	if result.Outcome != q.Outcome || result.ReceiptDigest != q.ReceiptDigest {
		return errWorkerExecution
	}
	return nil
}

func (p *temporalDiscoveryProduct) ReconcileDiscoveryOutcome(ctx context.Context, q orchestration.DiscoveryReconcile) (orchestration.DiscoveryResult, error) {
	var result orchestration.DiscoveryResult
	args, _, err := discoveryProductArgs(q.Start)
	if err != nil || q.Deadline.IsZero() {
		return result, errWorkerExecution
	}
	args = append(args, q.Deadline, q.Reason, "")
	err = p.queryDiscovery(ctx, "settle", q.Start, map[string]any{"budget_us": q.Deadline.UnixMicro(), "reason": q.Reason, "receipt": ""}, `SELECT zasp_temporal72.settle($1,$2,$3,$4,$5,$6,$7,$8,$9)`, &result, args...)
	return result, err
}

var _ orchestration.DiscoveryProduct = (*temporalDiscoveryProduct)(nil)
