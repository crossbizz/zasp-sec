package main

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/eventstore"
)

type EventStoreProofOptions struct {
	Marker         string
	Events         eventstore.EventStore
	Admin          ProjectionAdmin
	CleanupTimeout time.Duration
	PollInterval   time.Duration
}

type EventStoreProofResult struct {
	Indexed, Searched, Scoped, CrossOrganizationZero, Cleanup, Audit bool
}

type eventStoreCleanupTarget struct {
	spec           IndexSpec
	events         eventstore.EventStore
	scope          domain.Scope
	filter         eventstore.Filter
	event          *eventstore.Event
	attempted      bool
	eventUncertain bool
	owned          bool
	uncertain      bool
}

func RunEventStoreProof(ctx context.Context, options EventStoreProofOptions) (result EventStoreProofResult, resultErr error) {
	if ctx == nil || !markerPattern.MatchString(options.Marker) || nilInterfaceValue(options.Events) || nilInterfaceValue(options.Admin) {
		return result, errConfiguration
	}
	if options.CleanupTimeout <= 0 {
		options.CleanupTimeout = 20 * time.Second
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 100 * time.Millisecond
	}
	var target *eventStoreCleanupTarget
	defer func() {
		panicked := recover() != nil
		if target != nil {
			if safeEventStoreCleanupAndAudit(options, target) != nil {
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
	target = &eventStoreCleanupTarget{spec: copyIndexSpec(spec), events: options.Events, uncertain: true}
	created, createErr := options.Admin.CreateIndex(ctx, spec)
	if createErr != nil && !isAmbiguousMutation(createErr) {
		target = nil
		return result, errProvider
	}
	if createErr == nil && !validIndexState(created, spec) {
		createErr = ambiguousMutationError()
	} else if createErr == nil {
		target.owned, target.uncertain = true, false
	}
	state, inspectErr := options.Admin.InspectIndex(ctx, spec.Name)
	if createErr != nil || inspectErr != nil || !validIndexState(state, spec) {
		candidates, listErr := options.Admin.ListIndexes(ctx, prefix)
		if listErr != nil || len(candidates) != 1 || candidates[0].Name != spec.Name {
			return result, errOwnership
		}
		reconciled, reconcileErr := options.Admin.InspectIndex(ctx, spec.Name)
		if reconcileErr != nil || !validIndexState(reconciled, spec) {
			return result, errOwnership
		}
	}
	target.owned, target.uncertain = true, false

	scopeA, scopeB, event, identityErr := expectedProductEvent(options.Marker)
	if identityErr != nil {
		return result, errConfiguration
	}
	filter := eventstore.Filter{SessionID: event.SessionID, Limit: 2}
	target.scope, target.filter = scopeA, filter
	target.attempted = true
	target.event = copyProductEvent(event)
	target.eventUncertain = true
	if err := options.Events.Index(ctx, scopeA, event); err != nil {
		return result, productEventStoreError(err)
	}
	target.eventUncertain = false
	result.Indexed = true
	hitsA, err := options.Events.Search(ctx, scopeA, filter)
	if err != nil {
		return result, productEventStoreError(err)
	}
	if len(hitsA) != 1 || hitsA[0] != event {
		return result, errContent
	}
	result.Searched, result.Scoped = true, true
	hitsB, err := options.Events.Search(ctx, scopeB, filter)
	if err != nil {
		return result, productEventStoreError(err)
	}
	if len(hitsB) != 0 {
		return result, errScope
	}
	result.CrossOrganizationZero = true
	return result, nil
}

func safeEventStoreCleanupAndAudit(options EventStoreProofOptions, target *eventStoreCleanupTarget) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errCleanup
		}
	}()
	if !target.owned {
		owned, absent, err := rearmEventStoreCleanupTarget(options, target)
		if err != nil {
			return errCleanup
		}
		if absent {
			return auditEventStoreAbsence(options)
		}
		if !owned {
			return errCleanup
		}
		target.owned, target.uncertain = true, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
	defer cancel()
	current, err := options.Admin.InspectIndex(ctx, target.spec.Name)
	if err != nil || !validIndexState(current, target.spec) {
		return errCleanup
	}
	if !target.attempted {
		documents, listErr := options.Admin.ListDocuments(ctx, target.spec.Name, 2)
		if listErr != nil || len(documents) != 0 {
			return errCleanup
		}
	} else {
		hits, searchErr := target.events.Search(ctx, target.scope, target.filter)
		if searchErr != nil || len(hits) > 1 {
			return errCleanup
		}
		if len(hits) == 1 && (target.event == nil || hits[0] != *target.event) {
			return errCleanup
		}
		if len(hits) == 0 && target.event != nil && !target.eventUncertain {
			return errCleanup
		}
	}
	_ = options.Admin.DeleteIndex(ctx, target.spec.Name)
	prefix := proofPrefix + options.Marker
	if err := pollUntil(ctx, options.PollInterval, func() (bool, error) {
		indexes, listErr := options.Admin.ListIndexes(ctx, prefix)
		if listErr != nil {
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

func rearmEventStoreCleanupTarget(options EventStoreProofOptions, target *eventStoreCleanupTarget) (bool, bool, error) {
	if target == nil || !target.uncertain {
		return false, false, errCleanup
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
	defer cancel()
	prefix := proofPrefix + options.Marker
	for {
		indexes, listErr := options.Admin.ListIndexes(ctx, prefix)
		if listErr == nil {
			switch len(indexes) {
			case 0:
			case 1:
				if indexes[0].Name != target.spec.Name {
					return false, false, errCleanup
				}
				current, inspectErr := options.Admin.InspectIndex(ctx, target.spec.Name)
				if inspectErr == nil {
					if !validIndexState(current, target.spec) {
						return false, false, errCleanup
					}
					return true, false, nil
				}
			default:
				return false, false, errCleanup
			}
		}
		timer := time.NewTimer(options.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			finalCtx, finalCancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
			indexes, finalErr := options.Admin.ListIndexes(finalCtx, prefix)
			finalCancel()
			if finalErr == nil && len(indexes) == 0 {
				return false, true, nil
			}
			return false, false, errCleanup
		case <-timer.C:
		}
	}
}

func auditEventStoreAbsence(options EventStoreProofOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
	defer cancel()
	indexes, err := options.Admin.ListIndexes(ctx, proofPrefix+options.Marker)
	if err != nil || len(indexes) != 0 {
		return errCleanup
	}
	return nil
}

func expectedProductEvent(marker string) (domain.Scope, domain.Scope, eventstore.Event, error) {
	parse := func(prefix byte) (domain.ProductID, error) {
		return domain.ParseProductID("pid_" + string(prefix) + marker[1:8] + "-0000-4000-8000-00000000000" + string(prefix))
	}
	organizationA, errA := parse('1')
	organizationB, errB := parse('2')
	workspace, errWorkspace := parse('3')
	environment, errEnvironment := parse('4')
	eventID, errEvent := parse('5')
	sessionID, errSession := parse('6')
	agentID, errAgent := parse('7')
	if errA != nil || errB != nil || errWorkspace != nil || errEnvironment != nil || errEvent != nil || errSession != nil || errAgent != nil {
		return domain.Scope{}, domain.Scope{}, eventstore.Event{}, errConfiguration
	}
	scopeA, err := domain.NewScope(organizationA, workspace, environment)
	if err != nil {
		return domain.Scope{}, domain.Scope{}, eventstore.Event{}, errConfiguration
	}
	scopeB, err := domain.NewScope(organizationB, workspace, environment)
	if err != nil {
		return domain.Scope{}, domain.Scope{}, eventstore.Event{}, errConfiguration
	}
	eventTime, err := time.Parse(productTimestampLayout, "2026-08-15T20:21:22.123Z")
	if err != nil {
		return domain.Scope{}, domain.Scope{}, eventstore.Event{}, errConfiguration
	}
	event := eventstore.Event{
		Scope: scopeA, EventID: eventID, SessionID: sessionID, AgentID: agentID,
		Source: "runtime_gateway", SourceEventID: "source-" + marker,
		Class: "tool", Action: "invoke", Decision: "allowed", EventTime: eventTime,
	}
	return scopeA, scopeB, event, nil
}

func productEventStoreError(err error) error {
	switch {
	case errors.Is(err, eventstore.ErrEvent), errors.Is(err, eventstore.ErrFilter):
		return errContent
	default:
		return errProvider
	}
}

func copyProductEvent(event eventstore.Event) *eventstore.Event {
	copy := event
	return &copy
}

func nilInterfaceValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
