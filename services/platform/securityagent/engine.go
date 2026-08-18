package securityagent

import (
	"context"
	"sync"
	"time"
)

type RunJobHandler struct {
	mu        sync.Mutex
	completed map[string]bool
}

func NewRunJobHandler() *RunJobHandler { return &RunJobHandler{completed: map[string]bool{}} }
func (handler *RunJobHandler) Handle(ctx context.Context, job RunJob, process func(context.Context, RunJob) error) error {
	if handler == nil || invalidContext(ctx) || process == nil || job.Name != "security_agent.run" || !bounded(job.OrganizationID, 128) || !bounded(job.RunID, 128) || !bounded(job.IdempotencyKey, 128) {
		return ErrRejected
	}
	key, _ := idempotencyKey(job.OrganizationID, job.IdempotencyKey)
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.completed[key] {
		return nil
	}
	if err := process(ctx, job); err != nil {
		return ErrRejected
	}
	handler.completed[key] = true
	return nil
}

type PlanStore struct {
	mu     sync.RWMutex
	plans  map[string]Plan
	errors map[string][]string
}

func NewPlanStore() *PlanStore {
	return &PlanStore{plans: map[string]Plan{}, errors: map[string][]string{}}
}
func (store *PlanStore) put(organizationID, runID string, plan Plan) {
	key, _ := idempotencyKey(organizationID, runID)
	store.mu.Lock()
	store.plans[key] = clonePlan(plan)
	store.mu.Unlock()
}
func (store *PlanStore) recordError(organizationID, runID, code string) {
	key, _ := idempotencyKey(organizationID, runID)
	store.mu.Lock()
	store.errors[key] = append(store.errors[key], code)
	store.mu.Unlock()
}
func (store *PlanStore) Errors(organizationID, runID string) []string {
	if store == nil {
		return []string{}
	}
	key, err := idempotencyKey(organizationID, runID)
	if err != nil {
		return []string{}
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return cloneStrings(store.errors[key])
}
func (store *PlanStore) Get(organizationID, runID string) (Plan, error) {
	if store == nil {
		return Plan{}, ErrRejected
	}
	key, err := idempotencyKey(organizationID, runID)
	if err != nil {
		return Plan{}, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	value, ok := store.plans[key]
	if !ok {
		return Plan{}, ErrRejected
	}
	return clonePlan(value), nil
}

func PlanQueuedRun(ctx context.Context, repository *MemoryRepository, store *PlanStore, organizationID, runID string, planner func(context.Context, SecurityAgentRun) (Plan, error), validate func(Plan) error) (SecurityAgentRun, error) {
	if invalidContext(ctx) || repository == nil || store == nil || planner == nil || validate == nil {
		return SecurityAgentRun{}, ErrRejected
	}
	run, err := repository.GetRun(ctx, organizationID, runID)
	if err != nil || run.State != RunQueued {
		return SecurityAgentRun{}, ErrRejected
	}
	planning, err := repository.TransitionRun(ctx, organizationID, runID, RunQueued, RunPlanning, run.Version)
	if err != nil {
		return SecurityAgentRun{}, err
	}
	plan, planErr := planner(ctx, planning)
	if planErr != nil || validate(plan) != nil {
		failed, transitionErr := repository.TransitionRun(ctx, organizationID, runID, RunPlanning, RunFailed, planning.Version)
		store.recordError(organizationID, runID, "security_agent_planner_failed")
		if transitionErr != nil {
			return SecurityAgentRun{}, ErrRejected
		}
		return failed, ErrRejected
	}
	store.put(organizationID, runID, plan)
	return planning, nil
}

func ExecuteAutoStep(ctx context.Context, registry *Registry, agent SecurityAgent, scope PlannerScope, request ActionRequest) (ActionResult, error) {
	if registry == nil {
		return ActionResult{}, ErrRejected
	}
	metadata, err := registry.Metadata(request.ActionKey)
	if err != nil || AuthorizeAction(agent, metadata, scope) != AuthorizationAllow {
		return ActionResult{}, ErrRejected
	}
	return registry.Execute(ctx, request)
}

func CreateStepApproval(ctx context.Context, repository *MemoryRepository, run SecurityAgentRun, stepID string, createdAt, expiresAt time.Time) (Approval, error) {
	if invalidContext(ctx) || repository == nil || run.State != RunPlanning || !bounded(stepID, 128) || createdAt.Location() != time.UTC || createdAt.IsZero() || expiresAt.Location() != time.UTC || !expiresAt.After(createdAt) {
		return Approval{}, ErrRejected
	}
	approval := Approval{ID: "approval-" + run.ID + "-" + stepID, OrganizationID: run.OrganizationID, RunID: run.ID, StepID: stepID, State: ApprovalPending, CreatedAt: createdAt, ExpiresAt: expiresAt, Version: 1}
	runKey, _ := idempotencyKey(run.OrganizationID, run.ID)
	approvalKey, _ := idempotencyKey(run.OrganizationID, approval.ID)
	repository.mu.Lock()
	defer repository.mu.Unlock()
	current, ok := repository.runs[runKey]
	if !ok || current.State != RunPlanning || current.Version != run.Version {
		return Approval{}, ErrRejected
	}
	if _, exists := repository.approvals[approvalKey]; exists {
		return Approval{}, ErrRejected
	}
	current.State = RunWaitingApproval
	current.Version++
	repository.runs[runKey] = current
	repository.approvals[approvalKey] = approval
	return approval, nil
}

type ApprovalCoordinator struct {
	repository *MemoryRepository
	freshAuth  func(context.Context, string, time.Time) bool
	enqueue    func(context.Context, RunJob) error
	mu         sync.Mutex
	enqueued   map[string]bool
}

func NewApprovalCoordinator(repository *MemoryRepository, freshAuth func(context.Context, string, time.Time) bool, enqueue func(context.Context, RunJob) error) (*ApprovalCoordinator, error) {
	if repository == nil || freshAuth == nil || enqueue == nil {
		return nil, ErrRejected
	}
	return &ApprovalCoordinator{repository: repository, freshAuth: freshAuth, enqueue: enqueue, enqueued: map[string]bool{}}, nil
}
func (coordinator *ApprovalCoordinator) Decide(ctx context.Context, organizationID, approvalID, principalID string, at time.Time, decision ApprovalState) (Approval, error) {
	if coordinator == nil || invalidContext(ctx) || !bounded(principalID, 128) || at.Location() != time.UTC {
		return Approval{}, ErrRejected
	}
	approval, err := coordinator.repository.GetApproval(ctx, organizationID, approvalID)
	if err != nil {
		return Approval{}, err
	}
	run, err := coordinator.repository.GetRun(ctx, organizationID, approval.RunID)
	if err != nil || run.State == RunCancelled {
		return Approval{}, ErrRejected
	}
	if approval.State == ApprovalPending {
		if !coordinator.freshAuth(ctx, principalID, at) {
			return Approval{}, ErrRejected
		}
		approval, err = coordinator.repository.DecideApproval(ctx, organizationID, approvalID, principalID, at, decision, approval.Version)
		if err != nil {
			return Approval{}, err
		}
	} else if approval.State != decision {
		return Approval{}, ErrRejected
	}
	if approval.State == ApprovalRejected || approval.State == ApprovalCancelled {
		if run.State == RunWaitingApproval {
			_, _ = coordinator.repository.TransitionRun(ctx, organizationID, run.ID, RunWaitingApproval, RunNeedsHuman, run.Version)
		}
		return approval, nil
	}
	return approval, coordinator.enqueueResume(ctx, approval)
}
func (coordinator *ApprovalCoordinator) enqueueResume(ctx context.Context, approval Approval) error {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	key := approval.OrganizationID + "\x1f" + approval.ID
	if coordinator.enqueued[key] {
		return nil
	}
	job := RunJob{Name: "security_agent.run", OrganizationID: approval.OrganizationID, RunID: approval.RunID, IdempotencyKey: "resume-" + approval.ID}
	if err := coordinator.enqueue(ctx, job); err != nil {
		return ErrRejected
	}
	coordinator.enqueued[key] = true
	return nil
}

type ExecutionClass string

const (
	ExecutionSuccess        ExecutionClass = "success"
	ExecutionKnownFailure   ExecutionClass = "known_failure"
	ExecutionUnknownOutcome ExecutionClass = "unknown_outcome"
)

type ExecutionReceipt struct {
	Acknowledged, KnownFailure bool
	OutcomeID                  string
}

func ClassifyExecution(receipt ExecutionReceipt, err error) ExecutionClass {
	if err == nil && receipt.Acknowledged && bounded(receipt.OutcomeID, 128) {
		return ExecutionSuccess
	}
	if receipt.KnownFailure {
		return ExecutionKnownFailure
	}
	return ExecutionUnknownOutcome
}
func ShouldRetryExecution(class ExecutionClass) bool { return false }

type StepVerifier func(context.Context, ActionResult) VerificationOutcome
type VerifierDispatcher struct {
	mu     sync.RWMutex
	values map[string]StepVerifier
}

func NewVerifierDispatcher() *VerifierDispatcher {
	return &VerifierDispatcher{values: map[string]StepVerifier{}}
}
func (dispatcher *VerifierDispatcher) Register(kind string, verifier StepVerifier) error {
	if dispatcher == nil || !bounded(kind, 64) || verifier == nil {
		return ErrRejected
	}
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if _, ok := dispatcher.values[kind]; ok {
		return ErrRejected
	}
	dispatcher.values[kind] = verifier
	return nil
}
func (dispatcher *VerifierDispatcher) Verify(ctx context.Context, kind string, result ActionResult) (outcome VerificationOutcome) {
	defer func() {
		if recover() != nil {
			outcome = VerificationOutcome{State: VerificationInconclusive}
		}
	}()
	if dispatcher == nil || invalidContext(ctx) || !bounded(kind, 64) {
		return VerificationOutcome{State: VerificationInconclusive}
	}
	dispatcher.mu.RLock()
	verifier, ok := dispatcher.values[kind]
	dispatcher.mu.RUnlock()
	if !ok {
		return VerificationOutcome{State: VerificationInconclusive}
	}
	outcome = verifier(ctx, result)
	if outcome.State != VerificationVerified {
		return VerificationOutcome{State: VerificationInconclusive}
	}
	return outcome
}
func EvaluateRunOutcome(goal string, outcomes []VerificationOutcome) RunState {
	if !contains([]string{"contain", "remediate"}, goal) || len(outcomes) == 0 {
		return RunInconclusive
	}
	for _, outcome := range outcomes {
		if outcome.State != VerificationVerified {
			return RunInconclusive
		}
	}
	if goal == "contain" {
		return RunContained
	}
	return RunRemediated
}
func CancelRun(ctx context.Context, repository *MemoryRepository, organizationID, runID string) (SecurityAgentRun, error) {
	if invalidContext(ctx) || repository == nil {
		return SecurityAgentRun{}, ErrRejected
	}
	run, err := repository.GetRun(ctx, organizationID, runID)
	if err != nil || !CanTransition(run.State, RunCancelled) {
		return SecurityAgentRun{}, ErrRejected
	}
	return repository.TransitionRun(ctx, organizationID, runID, run.State, RunCancelled, run.Version)
}
func clonePlan(value Plan) Plan {
	value.Steps = append([]PlanStep(nil), value.Steps...)
	for index := range value.Steps {
		value.Steps[index].Parameters = cloneParameters(value.Steps[index].Parameters)
	}
	return value
}
