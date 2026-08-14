package main

import (
	"context"
	"errors"
	"regexp"
	"time"
)

const (
	proofPrefix = "zasp-m0-08-"
	indexRole   = "session-events"
)

var (
	errConfiguration = errors.New("configuration rejected")
	errProvider      = errors.New("event projection operation failed")
	errOwnership     = errors.New("event projection ownership rejected")
	errScope         = errors.New("event scope rejected")
	errContent       = errors.New("event content rejected")
	errCleanup       = errors.New("event projection cleanup failed")

	markerPattern     = regexp.MustCompile(`^[a-f0-9]{16}$`)
	scopeValuePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}$`)
)

type OrganizationScope struct{ organizationID string }

func newOrganizationScope(value string) (OrganizationScope, error) {
	if !scopeValuePattern.MatchString(value) {
		return OrganizationScope{}, errScope
	}
	return OrganizationScope{organizationID: value}, nil
}

func (s OrganizationScope) OrganizationID() string { return s.organizationID }

type SessionFilter struct {
	SessionID, EnvironmentID string
}

type NormalizedSessionEvent struct {
	EventID        string `json:"event_id"`
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	SessionID      string `json:"session_id"`
	AgentID        string `json:"agent_id"`
	Source         string `json:"source"`
	SourceEventID  string `json:"source_event_id"`
	EventClass     string `json:"event_class"`
	Action         string `json:"action"`
	Decision       string `json:"decision"`
	EventTime      string `json:"event_time"`
}

type EventStore interface {
	IndexSessionEvent(context.Context, OrganizationScope, NormalizedSessionEvent) error
	QuerySession(context.Context, OrganizationScope, SessionFilter) ([]NormalizedSessionEvent, error)
}

type ProjectionAdmin interface {
	ListIndexes(context.Context, string) ([]IndexState, error)
	CreateIndex(context.Context, IndexSpec) (IndexState, error)
	InspectIndex(context.Context, string) (IndexState, error)
	ListDocuments(context.Context, string, int) ([]NormalizedSessionEvent, error)
	DeleteIndex(context.Context, string) error
}

type IndexSpec struct {
	Name, Proof, Marker, Role, Dynamic string
	Shards, Replicas                   int
	Fields                             map[string]string
}

type IndexState = IndexSpec

type ProofOptions struct {
	Endpoint       string
	Marker         string
	Events         EventStore
	Admin          ProjectionAdmin
	CleanupTimeout time.Duration
	PollInterval   time.Duration
}

type ProofResult struct {
	Indexed, ScopedQuery, CrossOrganizationZero, Cleanup, Audit bool
}

type cleanupTarget struct {
	spec  IndexSpec
	event *NormalizedSessionEvent
}

func RunProof(ctx context.Context, options ProofOptions) (result ProofResult, resultErr error) {
	if ctx == nil || !markerPattern.MatchString(options.Marker) || options.Events == nil || options.Admin == nil {
		return result, errConfiguration
	}
	if _, err := validateEndpoint(ctx, options.Endpoint, nil); err != nil {
		return result, errConfiguration
	}
	if options.CleanupTimeout <= 0 {
		options.CleanupTimeout = 15 * time.Second
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 100 * time.Millisecond
	}
	var target *cleanupTarget
	defer func() {
		panicked := recover() != nil
		if target != nil {
			if safeCleanupAndAudit(options, target) != nil {
				resultErr = errCleanup
				return
			}
			result.Cleanup, result.Audit = true, true
		}
		if panicked {
			resultErr = errProvider
		}
	}()

	prefix := proofPrefix + options.Marker
	indexes, err := options.Admin.ListIndexes(ctx, prefix)
	if err != nil {
		return result, errProvider
	}
	if len(indexes) != 0 {
		return result, errOwnership
	}

	spec := expectedIndexSpec(options.Marker)
	created, createErr := options.Admin.CreateIndex(ctx, spec)
	if createErr != nil && !isAmbiguousMutation(createErr) {
		return result, errProvider
	}
	if createErr == nil {
		target = &cleanupTarget{spec: copyIndexSpec(spec)}
		if !validIndexState(created, spec) {
			return result, errOwnership
		}
	}
	state, inspectErr := options.Admin.InspectIndex(ctx, spec.Name)
	if createErr != nil || inspectErr != nil || !validIndexState(state, spec) {
		candidates, listErr := options.Admin.ListIndexes(ctx, prefix)
		if listErr != nil || len(candidates) != 1 || candidates[0].Name != spec.Name {
			if createErr != nil || inspectErr != nil || listErr != nil {
				return result, errProvider
			}
			return result, errOwnership
		}
		reconciled, reconcileErr := options.Admin.InspectIndex(ctx, spec.Name)
		if reconcileErr != nil || !validIndexState(reconciled, spec) {
			return result, errOwnership
		}
		target = &cleanupTarget{spec: copyIndexSpec(spec)}
	}

	organizationA, err := newOrganizationScope("org-a-" + options.Marker)
	if err != nil {
		return result, errScope
	}
	organizationB, err := newOrganizationScope("org-b-" + options.Marker)
	if err != nil {
		return result, errScope
	}
	event := expectedEvent(options.Marker, organizationA.OrganizationID())
	indexErr := options.Events.IndexSessionEvent(ctx, organizationA, event)
	if indexErr == nil {
		target.event = copyEvent(event)
	} else if !isAmbiguousMutation(indexErr) {
		return result, eventStoreError(indexErr)
	}
	documents, documentsErr := options.Admin.ListDocuments(ctx, spec.Name, 2)
	if documentsErr != nil || len(documents) != 1 || documents[0] != event {
		if indexErr != nil || documentsErr != nil {
			return result, errProvider
		}
		return result, errContent
	}
	target.event = copyEvent(event)
	result.Indexed = true

	filter := SessionFilter{SessionID: event.SessionID, EnvironmentID: event.EnvironmentID}
	organizationAHits, err := options.Events.QuerySession(ctx, organizationA, filter)
	if err != nil {
		return result, eventStoreError(err)
	}
	if len(organizationAHits) != 1 || organizationAHits[0] != event {
		return result, errContent
	}
	result.ScopedQuery = true

	organizationBHits, err := options.Events.QuerySession(ctx, organizationB, filter)
	if err != nil {
		return result, eventStoreError(err)
	}
	if len(organizationBHits) != 0 {
		return result, errScope
	}
	result.CrossOrganizationZero = true
	return result, nil
}

func eventStoreError(err error) error {
	switch {
	case errors.Is(err, errScope):
		return errScope
	case errors.Is(err, errContent):
		return errContent
	default:
		return errProvider
	}
}

func safeCleanupAndAudit(options ProofOptions, target *cleanupTarget) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errCleanup
		}
	}()
	return cleanupAndAudit(options, target)
}

func cleanupAndAudit(options ProofOptions, target *cleanupTarget) error {
	ctx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
	defer cancel()
	current, err := options.Admin.InspectIndex(ctx, target.spec.Name)
	if err != nil || !validIndexState(current, target.spec) {
		return errCleanup
	}
	documents, err := options.Admin.ListDocuments(ctx, target.spec.Name, 2)
	if err != nil || len(documents) > 1 {
		return errCleanup
	}
	if len(documents) == 1 && (target.event == nil || documents[0] != *target.event) {
		return errCleanup
	}
	// Delete is not blindly retried. A lost response is accepted only after the
	// exact generated prefix is observed absent below.
	_ = options.Admin.DeleteIndex(ctx, target.spec.Name)
	prefix := proofPrefix + options.Marker
	if err := pollUntil(ctx, options.PollInterval, func() (bool, error) {
		indexes, err := options.Admin.ListIndexes(ctx, prefix)
		if err != nil {
			return false, errCleanup
		}
		return len(indexes) == 0, nil
	}); err != nil {
		return err
	}
	indexes, err := options.Admin.ListIndexes(ctx, prefix)
	if err != nil || len(indexes) != 0 {
		return errCleanup
	}
	return nil
}

func pollUntil(ctx context.Context, interval time.Duration, check func() (bool, error)) error {
	for {
		ready, err := check()
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errCleanup
		case <-timer.C:
		}
	}
}

func expectedIndexSpec(marker string) IndexSpec {
	return IndexSpec{
		Name: proofPrefix + marker + "-events", Proof: "m0-08", Marker: marker, Role: indexRole,
		Dynamic: "strict", Shards: 1, Replicas: 0,
		Fields: map[string]string{
			"event_id": "keyword", "organization_id": "keyword", "workspace_id": "keyword",
			"environment_id": "keyword", "session_id": "keyword", "agent_id": "keyword",
			"source": "keyword", "source_event_id": "keyword", "event_class": "keyword",
			"action": "keyword", "decision": "keyword", "event_time": "date:strict_date_time",
		},
	}
}

func expectedEvent(marker, organizationID string) NormalizedSessionEvent {
	return NormalizedSessionEvent{
		EventID: "event-" + marker, OrganizationID: organizationID,
		WorkspaceID: "workspace-" + marker, EnvironmentID: "environment-" + marker,
		SessionID: "session-" + marker, AgentID: "agent-" + marker,
		Source: "runtime-gateway", SourceEventID: "source-" + marker,
		EventClass: "tool", Action: "invoke", Decision: "allowed",
		EventTime: "2026-08-13T00:00:00Z",
	}
}

func validIndexState(state IndexState, expected IndexSpec) bool {
	return state.Name == expected.Name && state.Proof == expected.Proof && state.Marker == expected.Marker && state.Role == expected.Role &&
		state.Dynamic == expected.Dynamic && state.Shards == expected.Shards && state.Replicas == expected.Replicas &&
		equalMaps(state.Fields, expected.Fields)
}

func equalMaps(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func copyIndexSpec(source IndexSpec) IndexSpec {
	fields := make(map[string]string, len(source.Fields))
	for key, value := range source.Fields {
		fields[key] = value
	}
	source.Fields = fields
	return source
}

func copyEvent(source NormalizedSessionEvent) *NormalizedSessionEvent {
	result := source
	return &result
}

func fixedCategory(err error) string {
	switch {
	case errors.Is(err, errConfiguration):
		return "configuration"
	case errors.Is(err, errScope):
		return "scope"
	case errors.Is(err, errOwnership):
		return "ownership"
	case errors.Is(err, errContent):
		return "content"
	case errors.Is(err, errCleanup):
		return "cleanup"
	default:
		return "operation"
	}
}
