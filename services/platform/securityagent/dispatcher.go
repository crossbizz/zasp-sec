package securityagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type RunJob struct {
	Name, OrganizationID, RunID, IdempotencyKey string
}
type TriggerDispatcher struct {
	repository *MemoryRepository
	dedup      *TriggerDeduplicator
	enqueue    func(context.Context, RunJob) error
}

func NewTriggerDispatcher(repository *MemoryRepository, dedup *TriggerDeduplicator, enqueue func(context.Context, RunJob) error) (*TriggerDispatcher, error) {
	if repository == nil || dedup == nil || enqueue == nil {
		return nil, ErrRejected
	}
	return &TriggerDispatcher{repository: repository, dedup: dedup, enqueue: enqueue}, nil
}
func ValidateTriggerEvent(event TriggerEvent) error {
	if !validTriggerEvent(event) {
		return ErrRejected
	}
	switch event.Kind {
	case "finding":
		if !bounded(event.Family, 64) || severityRank(event.Severity) == 0 {
			return ErrRejected
		}
	case "attack_path":
		if !contains([]string{"potential", "verified"}, event.EvidenceState) {
			return ErrRejected
		}
	case "runtime_decision":
		if !bounded(event.PolicyAction, 64) || !bounded(event.Risk, 64) || !bounded(event.AgentID, 128) || !bounded(event.SessionID, 128) {
			return ErrRejected
		}
	default:
		return ErrRejected
	}
	return nil
}
func (dispatcher *TriggerDispatcher) Dispatch(ctx context.Context, event TriggerEvent, cooldown time.Duration) ([]RunJob, error) {
	if dispatcher == nil || dispatcher.repository == nil || dispatcher.dedup == nil || dispatcher.enqueue == nil || invalidContext(ctx) || ValidateTriggerEvent(event) != nil || cooldown <= 0 || cooldown > 24*time.Hour {
		return nil, ErrRejected
	}
	agents, _, err := dispatcher.repository.ListAgents(ctx, event.OrganizationID, "", 100)
	if err != nil {
		return nil, err
	}
	jobs := []RunJob{}
	for _, agent := range agents {
		if !matchesTriggerAgent(agent, event) {
			continue
		}
		agentEvent := event
		digest := sha256.Sum256([]byte(event.SourceID + "\x1f" + agent.ID))
		agentEvent.SourceID = hex.EncodeToString(digest[:])
		fingerprint, created, err := dispatcher.dedup.Claim(agentEvent, cooldown, event.At)
		if err != nil {
			return nil, err
		}
		if !created {
			continue
		}
		runID := "run-" + fingerprint[:32]
		run := SecurityAgentRun{ID: runID, OrganizationID: event.OrganizationID, AgentID: agent.ID, State: RunQueued, TriggerEvidenceIDs: []string{event.SourceID}, DefinitionVersion: agent.DefinitionVersion, Version: 1}
		if err := dispatcher.repository.CreateRun(ctx, run); err != nil {
			existing, getErr := dispatcher.repository.GetRun(ctx, event.OrganizationID, runID)
			if getErr != nil || existing.AgentID != agent.ID || existing.State != RunQueued {
				dispatcher.dedup.release(fingerprint)
				return nil, ErrRejected
			}
		}
		job := RunJob{Name: "security_agent.run", OrganizationID: event.OrganizationID, RunID: runID, IdempotencyKey: fingerprint}
		if err := dispatcher.enqueue(ctx, job); err != nil {
			dispatcher.dedup.release(fingerprint)
			return nil, ErrRejected
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}
func matchesTriggerAgent(agent SecurityAgent, event TriggerEvent) bool {
	if !agent.Enabled || !agent.DeletedAt.IsZero() || agent.OrganizationID != event.OrganizationID || agent.Trigger.Kind != event.Kind || !contains(agent.Scope.EnvironmentIDs, event.EnvironmentID) {
		return false
	}
	switch event.Kind {
	case "finding":
		return agent.Trigger.Source == event.Family
	case "attack_path":
		return agent.Trigger.Source == event.EvidenceState
	case "runtime_decision":
		return agent.Trigger.Source == event.PolicyAction
	default:
		return false
	}
}

type TriggerSource struct {
	persist  func(context.Context, TriggerEvent) error
	dispatch func(context.Context, TriggerEvent, time.Duration) ([]RunJob, error)
}

func NewTriggerSource(persist func(context.Context, TriggerEvent) error, dispatch func(context.Context, TriggerEvent, time.Duration) ([]RunJob, error)) (*TriggerSource, error) {
	if persist == nil || dispatch == nil {
		return nil, ErrRejected
	}
	return &TriggerSource{persist: persist, dispatch: dispatch}, nil
}
func (source *TriggerSource) Emit(ctx context.Context, event TriggerEvent, cooldown time.Duration) ([]RunJob, error) {
	if source == nil || source.persist == nil || source.dispatch == nil || invalidContext(ctx) || ValidateTriggerEvent(event) != nil || cooldown <= 0 || cooldown > 24*time.Hour {
		return nil, ErrRejected
	}
	if err := source.persist(ctx, event); err != nil {
		return nil, ErrRejected
	}
	return source.dispatch(ctx, event, cooldown)
}
