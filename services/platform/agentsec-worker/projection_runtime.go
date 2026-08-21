package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch"
	"github.com/zasp-ai/zasp-sec/services/platform/riskprojection"
)

const (
	projectionPageSize             = 500
	projectionMaximumEntities      = 1_000
	projectionMaximumRelationships = 2_000
	projectionMaximumEvidence      = 1_000
)

var projectionFindingCheckPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type projectionAuthority interface {
	ClaimProjectionWork(context.Context, string, string, string, int, int) ([]apiserver.ProjectionWorkLease, error)
	GetSnapshotProjectionPage(context.Context, domain.Scope, string, string, string, int) (apiserver.SnapshotProjectionPage, error)
	HeartbeatProjectionWork(context.Context, domain.Scope, apiserver.ProjectionHeartbeat) (apiserver.LeaseHeartbeatResult, error)
	FinishProjectionWork(context.Context, domain.Scope, apiserver.ProjectionWorkCompletion) (apiserver.WorkCompletionResult, error)
}

type projectionProjector interface {
	Apply(context.Context, projectionCandidate) (projectionDriverResult, error)
}

type projectionCandidate struct {
	Scope                                             domain.Scope
	SnapshotID, IntegrationID, Source, Kind, Version  string
	Worker, LeaseToken                                string
	Generation                                        int64
	InputDigest                                       [sha256.Size]byte
	ManifestReference, ManifestKey, ManifestVersionID string
	ManifestChecksum                                  [sha256.Size]byte
	ManifestSizeBytes                                 int64
	ManifestMediaType, ManifestSchemaVersion          string
	ParserVersion, ToolVersion                        string
	Entities, Relationships, Evidence                 []json.RawMessage
}

type projectionDriverResult struct {
	Receipt string
	Digest  [sha256.Size]byte
}

type searchSnapshotStore interface {
	ApplySnapshot(context.Context, inventorysearch.Snapshot) (inventorysearch.ApplyResult, error)
}

type graphSnapshotStore interface {
	ApplySnapshot(context.Context, graphstore.CompleteSnapshot) (graphstore.SnapshotApplyResult, error)
}

type searchProjectionProjector struct{ store searchSnapshotStore }
type graphProjectionProjector struct{ store graphSnapshotStore }

func newSearchProjectionProjector(store searchSnapshotStore) (*searchProjectionProjector, error) {
	if store == nil {
		return nil, errWorkerExecution
	}
	return &searchProjectionProjector{store: store}, nil
}

func newGraphProjectionProjector(store graphSnapshotStore) (*graphProjectionProjector, error) {
	if store == nil {
		return nil, errWorkerExecution
	}
	return &graphProjectionProjector{store: store}, nil
}

func (projector *searchProjectionProjector) Apply(ctx context.Context, candidate projectionCandidate) (projectionDriverResult, error) {
	entities, _, ok := decodeProjectionCandidate(candidate, "search")
	if projector == nil || projector.store == nil || !ok {
		return projectionDriverResult{}, errWorkerExecution
	}
	integrationID, integrationErr := domain.ParseProductID(candidate.IntegrationID)
	snapshotID, snapshotErr := domain.ParseProductID(candidate.SnapshotID)
	if integrationErr != nil || snapshotErr != nil {
		return projectionDriverResult{}, errWorkerExecution
	}
	documents := make([]inventorysearch.Document, len(entities))
	for index, entity := range entities {
		attributes, valid := searchAttributes(entity.StableFields)
		if !valid {
			return projectionDriverResult{}, errWorkerExecution
		}
		documents[index] = inventorysearch.Document{EntityID: entity.ID, Kind: entity.Kind, DisplayName: entity.DisplayName, Attributes: attributes}
	}
	result, err := projector.store.ApplySnapshot(ctx, inventorysearch.Snapshot{
		Scope: candidate.Scope, IntegrationID: integrationID, SnapshotID: snapshotID, Generation: candidate.Generation, InputDigest: candidate.InputDigest, Documents: documents,
	})
	if err != nil {
		return projectionDriverResult{}, err
	}
	if result.SnapshotID != snapshotID || result.Generation != candidate.Generation || result.InputDigest != candidate.InputDigest || result.ContentDigest == [sha256.Size]byte{} {
		return projectionDriverResult{}, errWorkerExecution
	}
	return projectionDriverResult{Receipt: "opensearch:snapshot:" + candidate.SnapshotID + ":" + resultDigestHex(result.ContentDigest), Digest: result.ContentDigest}, nil
}

func (projector *graphProjectionProjector) Apply(ctx context.Context, candidate projectionCandidate) (projectionDriverResult, error) {
	entities, relationships, ok := decodeProjectionCandidate(candidate, "graph")
	if projector == nil || projector.store == nil || !ok {
		return projectionDriverResult{}, errWorkerExecution
	}
	integrationID, integrationErr := domain.ParseProductID(candidate.IntegrationID)
	snapshotID, snapshotErr := domain.ParseProductID(candidate.SnapshotID)
	if integrationErr != nil || snapshotErr != nil {
		return projectionDriverResult{}, errWorkerExecution
	}
	nodes := make([]graphstore.Node, len(entities))
	known := make(map[domain.ProductID]struct{}, len(entities))
	for index, entity := range entities {
		nodes[index] = graphstore.Node{Scope: candidate.Scope, NodeID: entity.ID, Kind: entity.Kind}
		known[entity.ID] = struct{}{}
	}
	edges := make([]graphstore.Edge, len(relationships))
	for index, relationship := range relationships {
		if _, exists := known[relationship.FromEntityID]; !exists {
			return projectionDriverResult{}, errWorkerExecution
		}
		if _, exists := known[relationship.ToEntityID]; !exists {
			return projectionDriverResult{}, errWorkerExecution
		}
		edges[index] = graphstore.Edge{Scope: candidate.Scope, EdgeID: relationship.ID, Kind: relationship.Kind, SourceID: relationship.FromEntityID, TargetID: relationship.ToEntityID}
	}
	result, err := projector.store.ApplySnapshot(ctx, graphstore.CompleteSnapshot{
		Scope: candidate.Scope, IntegrationID: integrationID, Source: candidate.Source, SnapshotID: snapshotID, Generation: candidate.Generation,
		InputDigest: candidate.InputDigest, Projection: graphstore.Projection{Nodes: nodes, Edges: edges},
	})
	if err != nil {
		return projectionDriverResult{}, err
	}
	if result.SnapshotID != snapshotID || result.Source != candidate.Source || result.Generation != candidate.Generation || result.InputDigest != candidate.InputDigest || result.ContentDigest == [sha256.Size]byte{} {
		return projectionDriverResult{}, errWorkerExecution
	}
	return projectionDriverResult{Receipt: "neo4j:snapshot:" + candidate.SnapshotID + ":" + resultDigestHex(result.ContentDigest), Digest: result.ContentDigest}, nil
}

type projectionEntity struct {
	ID             domain.ProductID
	Kind           string
	SourceNativeID string
	DisplayName    string
	StableFields   map[string]json.RawMessage
}

type projectionRelationship struct {
	ID, FromEntityID, ToEntityID domain.ProductID
	Kind, SourceNativeID         string
}

type projectionEvidence struct {
	ID                string `json:"id"`
	EntityID          string `json:"entity_id,omitempty"`
	FindingID         string `json:"finding_id,omitempty"`
	CheckID           string `json:"check_id,omitempty"`
	Severity          string `json:"severity,omitempty"`
	Status            string `json:"status,omitempty"`
	ObservedAt        string `json:"observed_at,omitempty"`
	ObjectReference   string `json:"object_reference"`
	ArtifactReference string `json:"artifact_reference"`
	ArtifactKey       string `json:"artifact_key"`
	ArtifactVersionID string `json:"artifact_version_id"`
	ChecksumHex       string `json:"checksum_hex"`
	SizeBytes         int64  `json:"size_bytes"`
	MediaType         string `json:"media_type"`
	SchemaVersion     string `json:"schema_version"`
	ParserVersion     string `json:"parser_version"`
	ToolVersion       string `json:"tool_version"`
}

func decodeProjectionCandidate(candidate projectionCandidate, wantKind string) ([]projectionEntity, []projectionRelationship, bool) {
	if candidate.Scope.Validate() != nil || candidate.Kind != wantKind || candidate.Generation < 1 || candidate.InputDigest == [sha256.Size]byte{} || !validProjectionCounts(candidate) {
		return nil, nil, false
	}
	entities := make([]projectionEntity, len(candidate.Entities))
	known := make(map[domain.ProductID]struct{}, len(candidate.Entities))
	for index, raw := range candidate.Entities {
		var value struct {
			ID             string                     `json:"id"`
			Kind           string                     `json:"kind"`
			SourceNativeID string                     `json:"source_native_id"`
			DisplayName    string                     `json:"display_name"`
			StableFields   map[string]json.RawMessage `json:"stable_fields"`
			Attributes     map[string]json.RawMessage `json:"attributes"`
		}
		if !decodeStrictProjection(raw, &value) || value.StableFields == nil || value.Attributes == nil || value.Kind == "" || value.SourceNativeID == "" || value.DisplayName == "" {
			return nil, nil, false
		}
		id, err := domain.ParseProductID(value.ID)
		if err != nil {
			return nil, nil, false
		}
		if _, duplicate := known[id]; duplicate {
			return nil, nil, false
		}
		known[id] = struct{}{}
		entities[index] = projectionEntity{ID: id, Kind: value.Kind, SourceNativeID: value.SourceNativeID, DisplayName: value.DisplayName, StableFields: value.StableFields}
	}
	relationships := make([]projectionRelationship, len(candidate.Relationships))
	seenRelationships := make(map[domain.ProductID]struct{}, len(candidate.Relationships))
	for index, raw := range candidate.Relationships {
		var value struct {
			ID             string                     `json:"id"`
			Kind           string                     `json:"kind"`
			SourceNativeID string                     `json:"source_native_id"`
			FromEntityID   string                     `json:"from_entity_id"`
			ToEntityID     string                     `json:"to_entity_id"`
			Attributes     map[string]json.RawMessage `json:"attributes"`
		}
		if !decodeStrictProjection(raw, &value) || value.Attributes == nil || value.Kind == "" || value.SourceNativeID == "" {
			return nil, nil, false
		}
		id, idErr := domain.ParseProductID(value.ID)
		from, fromErr := domain.ParseProductID(value.FromEntityID)
		to, toErr := domain.ParseProductID(value.ToEntityID)
		if idErr != nil || fromErr != nil || toErr != nil || from == to {
			return nil, nil, false
		}
		if _, duplicate := seenRelationships[id]; duplicate {
			return nil, nil, false
		}
		seenRelationships[id] = struct{}{}
		relationships[index] = projectionRelationship{ID: id, FromEntityID: from, ToEntityID: to, Kind: value.Kind, SourceNativeID: value.SourceNativeID}
	}
	for _, raw := range candidate.Evidence {
		var value projectionEvidence
		if !decodeStrictProjection(raw, &value) {
			return nil, nil, false
		}
		if _, err := domain.ParseProductID(value.ID); err != nil {
			return nil, nil, false
		}
		if value.EntityID != "" {
			entityID, err := domain.ParseProductID(value.EntityID)
			if err != nil {
				return nil, nil, false
			}
			if _, exists := known[entityID]; !exists {
				return nil, nil, false
			}
		}
		finding := value.FindingID != "" || value.CheckID != "" || value.Severity != "" || value.Status != "" || value.ObservedAt != ""
		if finding {
			if _, err := domain.ParseProductID(value.FindingID); err != nil || value.EntityID == "" || !projectionFindingCheckPattern.MatchString(value.CheckID) || value.Severity != "high" || value.Status != "PASS" && value.Status != "FAIL" {
				return nil, nil, false
			}
			observed, err := time.Parse(time.RFC3339, value.ObservedAt)
			if err != nil || observed.Location() != time.UTC || observed.Nanosecond() != 0 || observed.Format(time.RFC3339) != value.ObservedAt {
				return nil, nil, false
			}
		}
		if value.ArtifactReference == "" || value.ArtifactKey == "" || value.ArtifactVersionID == "" || len(value.ChecksumHex) != sha256.Size*2 || value.SizeBytes < 1 || value.MediaType == "" || value.SchemaVersion == "" || value.ParserVersion != candidate.ParserVersion || value.ToolVersion != candidate.ToolVersion {
			return nil, nil, false
		}
	}
	return entities, relationships, true
}

func validProjectionCounts(candidate projectionCandidate) bool {
	return len(candidate.Entities) <= projectionMaximumEntities &&
		len(candidate.Relationships) <= projectionMaximumRelationships &&
		len(candidate.Evidence) <= projectionMaximumEvidence
}

func decodeStrictProjection(raw json.RawMessage, destination any) bool {
	if len(raw) < 2 || len(raw) > 1<<20 || raw[0] != '{' || raw[len(raw)-1] != '}' {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if decoder.Decode(destination) != nil {
		return false
	}
	return decoder.Decode(&struct{}{}) == io.EOF
}

func searchAttributes(fields map[string]json.RawMessage) ([]inventorysearch.Attribute, bool) {
	attributes := make([]inventorysearch.Attribute, 0, len(fields))
	for name, raw := range fields {
		if name == "" || strings.TrimSpace(name) != name {
			return nil, false
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		var text string
		switch typed := value.(type) {
		case string:
			text = typed
		case bool:
			text = strconv.FormatBool(typed)
		case json.Number:
			text = typed.String()
		default:
			return nil, false
		}
		attributes = append(attributes, inventorysearch.Attribute{Name: name, Value: text})
	}
	sort.Slice(attributes, func(left, right int) bool { return attributes[left].Name < attributes[right].Name })
	return attributes, true
}

func resultDigestHex(value [sha256.Size]byte) string { return hex.EncodeToString(value[:]) }

type projectionProcessorConfig struct {
	Authority         projectionAuthority
	Projector         projectionProjector
	Kind, WorkerID    string
	LeaseSeconds      int
	BatchSize         int
	HeartbeatInterval time.Duration
	NewLeaseToken     func() (string, error)
	Metrics           *workerMetrics
	Now               func() time.Time
}

type projectionProcessor struct{ config projectionProcessorConfig }

func newProjectionProcessor(config projectionProcessorConfig) (*projectionProcessor, error) {
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = time.Duration(config.LeaseSeconds) * time.Second / 3
	}
	if config.Metrics == nil {
		config.Metrics = newWorkerMetrics()
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.Authority == nil || config.Projector == nil || !stringInWorker(config.Kind, "risk", "graph", "search") ||
		!workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 5 || config.LeaseSeconds > 900 ||
		config.BatchSize < 1 || config.BatchSize > 64 || config.HeartbeatInterval < 10*time.Millisecond ||
		config.HeartbeatInterval > time.Duration(config.LeaseSeconds)*time.Second/2 || config.NewLeaseToken == nil {
		return nil, errWorkerExecution
	}
	return &projectionProcessor{config: config}, nil
}

func (processor *projectionProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	leaseToken, err := processor.config.NewLeaseToken()
	if err != nil || len(leaseToken) < 16 || len(leaseToken) > 128 {
		processor.config.Metrics.observeFailure()
		return errWorkerExecution
	}
	leases, err := processor.config.Authority.ClaimProjectionWork(ctx, processor.config.Kind, processor.config.WorkerID, leaseToken, processor.config.LeaseSeconds, processor.config.BatchSize)
	if err != nil {
		processor.config.Metrics.observeFailure()
		return errWorkerExecution
	}
	processor.config.Metrics.observeProjectionClaim(leases, processor.config.Now())
	results := make(chan error, len(leases))
	for _, lease := range leases {
		lease := lease
		processor.config.Metrics.addInflight(1)
		go func() {
			processErr := processor.process(ctx, lease, leaseToken)
			if processErr != nil {
				processor.config.Metrics.observeFailure()
			}
			processor.config.Metrics.addInflight(-1)
			results <- processErr
		}()
	}
	failed := false
	for range leases {
		if <-results != nil {
			failed = true
		}
	}
	if failed {
		return errWorkerExecution
	}
	return nil
}

func (processor *projectionProcessor) process(ctx context.Context, lease apiserver.ProjectionWorkLease, leaseToken string) error {
	scope, ok := projectionLeaseScope(lease)
	if !ok || lease.Kind != processor.config.Kind {
		return errWorkerExecution
	}
	workCtx, cancel := context.WithCancel(ctx)
	heartbeatDone := make(chan error, 1)
	go func() {
		heartbeatErr := processor.heartbeat(workCtx, scope, lease, leaseToken)
		if heartbeatErr != nil {
			cancel()
		}
		heartbeatDone <- heartbeatErr
	}()
	candidate, err := processor.loadCandidate(workCtx, scope, lease, leaseToken)
	var result projectionDriverResult
	if err == nil {
		result, err = processor.config.Projector.Apply(workCtx, candidate)
	}
	if workCtx.Err() != nil {
		cancel()
		if <-heartbeatDone != nil {
			processor.config.Metrics.observeLeaseLoss()
		}
		return errWorkerExecution
	}
	var finishErr error
	if err != nil {
		finishErr = processor.finishFailureBounded(workCtx, scope, lease, leaseToken, err)
	} else if len(result.Receipt) < 16 || len(result.Receipt) > 512 || result.Digest == [sha256.Size]byte{} {
		finishErr = errWorkerExecution
	} else {
		finishErr = processor.finishSuccessBounded(workCtx, scope, lease, leaseToken, result)
	}
	cancel()
	if heartbeatErr := <-heartbeatDone; heartbeatErr != nil {
		processor.config.Metrics.observeLeaseLoss()
		return errWorkerExecution
	}
	return finishErr
}

func (processor *projectionProcessor) finishSuccessBounded(ctx context.Context, scope domain.Scope, lease apiserver.ProjectionWorkLease, leaseToken string, result projectionDriverResult) error {
	finishCtx, cancel := context.WithTimeout(ctx, minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 10*time.Second))
	defer cancel()
	completion, err := processor.config.Authority.FinishProjectionWork(finishCtx, scope, apiserver.ProjectionWorkCompletion{
		SnapshotID: lease.SnapshotID, Kind: lease.Kind, Version: lease.Version, Worker: processor.config.WorkerID, LeaseToken: leaseToken,
		Outcome: "succeeded", DriverReceipt: result.Receipt, DriverDigest: result.Digest[:],
	})
	if err != nil || completion.State != "succeeded" {
		return errWorkerExecution
	}
	return nil
}

func (processor *projectionProcessor) finishFailureBounded(ctx context.Context, scope domain.Scope, lease apiserver.ProjectionWorkLease, leaseToken string, cause error) error {
	finishCtx, cancel := context.WithTimeout(ctx, minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 10*time.Second))
	defer cancel()
	return processor.finishFailure(finishCtx, scope, lease, leaseToken, cause)
}

func (processor *projectionProcessor) heartbeat(ctx context.Context, scope domain.Scope, lease apiserver.ProjectionWorkLease, leaseToken string) error {
	ticker := time.NewTicker(processor.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			renewCtx, cancel := context.WithTimeout(ctx, minDuration(processor.config.HeartbeatInterval, 5*time.Second))
			_, err := processor.config.Authority.HeartbeatProjectionWork(renewCtx, scope, apiserver.ProjectionHeartbeat{
				SnapshotID: lease.SnapshotID, Kind: lease.Kind, Version: lease.Version, Worker: processor.config.WorkerID, LeaseToken: leaseToken, LeaseSeconds: processor.config.LeaseSeconds,
			})
			cancel()
			if err != nil {
				return errWorkerExecution
			}
		}
	}
}

func (processor *projectionProcessor) loadCandidate(ctx context.Context, scope domain.Scope, lease apiserver.ProjectionWorkLease, leaseToken string) (projectionCandidate, error) {
	var candidate projectionCandidate
	candidate.Scope, candidate.SnapshotID, candidate.Kind, candidate.Version = scope, lease.SnapshotID, lease.Kind, lease.Version
	candidate.Worker, candidate.LeaseToken = processor.config.WorkerID, leaseToken
	copy(candidate.InputDigest[:], lease.InputDigest)
	for _, section := range []string{"entities", "relationships", "evidence"} {
		afterID := ""
		for {
			page, err := processor.config.Authority.GetSnapshotProjectionPage(ctx, scope, lease.SnapshotID, section, afterID, projectionPageSize)
			if err != nil {
				return projectionCandidate{}, err
			}
			if !bindProjectionPage(&candidate, page, section) {
				return projectionCandidate{}, errWorkerExecution
			}
			switch section {
			case "entities":
				candidate.Entities = append(candidate.Entities, cloneRawMessages(page.Items)...)
			case "relationships":
				candidate.Relationships = append(candidate.Relationships, cloneRawMessages(page.Items)...)
			case "evidence":
				candidate.Evidence = append(candidate.Evidence, cloneRawMessages(page.Items)...)
			}
			if !validProjectionCounts(candidate) {
				return projectionCandidate{}, errWorkerExecution
			}
			if page.NextID == nil {
				break
			}
			afterID = *page.NextID
		}
	}
	return candidate, nil
}

func bindProjectionPage(candidate *projectionCandidate, page apiserver.SnapshotProjectionPage, section string) bool {
	if candidate == nil || page.Section != section || page.SnapshotID != candidate.SnapshotID || len(page.CandidateDigest) != sha256.Size || !bytes.Equal(page.CandidateDigest, candidate.InputDigest[:]) {
		return false
	}
	var manifest [sha256.Size]byte
	copy(manifest[:], page.ManifestChecksum)
	if candidate.IntegrationID == "" {
		candidate.IntegrationID, candidate.Source, candidate.Generation = page.IntegrationID, page.Source, page.Generation
		candidate.ManifestReference, candidate.ManifestKey, candidate.ManifestVersionID = page.ManifestReference, page.ManifestKey, page.ManifestVersionID
		candidate.ManifestChecksum, candidate.ManifestSizeBytes = manifest, page.ManifestSizeBytes
		candidate.ManifestMediaType, candidate.ManifestSchemaVersion = page.ManifestMediaType, page.ManifestSchemaVersion
		candidate.ParserVersion, candidate.ToolVersion = page.ParserVersion, page.ToolVersion
		return candidate.IntegrationID != "" && candidate.Source != "" && candidate.Generation > 0 && manifest != [sha256.Size]byte{}
	}
	return page.IntegrationID == candidate.IntegrationID && page.Source == candidate.Source && page.Generation == candidate.Generation &&
		page.ManifestReference == candidate.ManifestReference && page.ManifestKey == candidate.ManifestKey && page.ManifestVersionID == candidate.ManifestVersionID &&
		manifest == candidate.ManifestChecksum && page.ManifestSizeBytes == candidate.ManifestSizeBytes && page.ManifestMediaType == candidate.ManifestMediaType &&
		page.ManifestSchemaVersion == candidate.ManifestSchemaVersion && page.ParserVersion == candidate.ParserVersion && page.ToolVersion == candidate.ToolVersion
}

func (processor *projectionProcessor) finishFailure(ctx context.Context, scope domain.Scope, lease apiserver.ProjectionWorkLease, leaseToken string, cause error) error {
	outcome, code, retry := "failed", "projection_rejected", 0
	if errors.Is(cause, context.Canceled) || errors.Is(cause, inventorysearch.ErrCanceled) || errors.Is(cause, graphstore.ErrSnapshotCanceled) {
		outcome, code = "cancelled", "cancelled"
	} else if errors.Is(cause, inventorysearch.ErrRetryable) || errors.Is(cause, inventorysearch.ErrUnknownOutcome) || errors.Is(cause, inventorysearch.ErrUnavailable) ||
		errors.Is(cause, graphstore.ErrSnapshotRetryable) || errors.Is(cause, graphstore.ErrSnapshotUnknownOutcome) || errors.Is(cause, graphstore.ErrSnapshotUnavailable) ||
		errors.Is(cause, riskprojection.ErrUnavailable) || errors.Is(cause, apiserver.ErrRepositoryUnavailable) {
		outcome, code, retry = "retryable", "projection_unavailable", 30
	}
	completion, err := processor.config.Authority.FinishProjectionWork(ctx, scope, apiserver.ProjectionWorkCompletion{
		SnapshotID: lease.SnapshotID, Kind: lease.Kind, Version: lease.Version, Worker: processor.config.WorkerID, LeaseToken: leaseToken,
		Outcome: outcome, LastError: code, RetryAfterSeconds: retry,
	})
	if err != nil || completion.State != outcome && !(outcome == "retryable" && completion.State == "failed") {
		return errWorkerExecution
	}
	if outcome == "retryable" {
		processor.config.Metrics.observeRetry()
		if completion.State == "failed" {
			processor.config.Metrics.observeExhaustion()
		}
	} else if outcome == "failed" {
		processor.config.Metrics.observeFailure()
	}
	return nil
}

func projectionLeaseScope(lease apiserver.ProjectionWorkLease) (domain.Scope, bool) {
	organization, organizationErr := domain.ParseProductID(lease.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(lease.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(lease.EnvironmentID)
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil {
		return domain.Scope{}, false
	}
	scope, err := domain.NewScope(organization, workspace, environment)
	return scope, err == nil
}

func cloneRawMessages(values []json.RawMessage) []json.RawMessage {
	cloned := make([]json.RawMessage, len(values))
	for index := range values {
		cloned[index] = bytes.Clone(values[index])
	}
	return cloned
}

func stringInWorker(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}
