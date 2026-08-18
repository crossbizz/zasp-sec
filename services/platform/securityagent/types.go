package securityagent

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

var ErrRejected = errors.New("security agent operation rejected")

type Trigger struct{ Kind, Source string }
type Scope struct {
	OrganizationID string
	EnvironmentIDs []string
}
type Autonomy string

const (
	AutonomySupervised Autonomy = "supervised"
	AutonomyAutonomous Autonomy = "autonomous"
)

type RunLimits struct {
	MaxSteps    int
	MaxDuration time.Duration
}
type Verification struct{ Kind string }

type SecurityAgent struct {
	ID, OrganizationID, Name string
	Trigger                  Trigger
	Scope                    Scope
	Autonomy                 Autonomy
	Limits                   RunLimits
	AllowedActions           []string
	Verification             Verification
	DefinitionVersion        int
	Version                  int64
	Enabled                  bool
	DeletedAt                time.Time
}

func ValidateAgent(value SecurityAgent) error {
	if !bounded(value.ID, 128) || !bounded(value.OrganizationID, 128) || !bounded(value.Name, 256) || !bounded(value.Trigger.Kind, 64) || !bounded(value.Trigger.Source, 64) || value.Scope.OrganizationID != value.OrganizationID || len(value.Scope.EnvironmentIDs) == 0 || len(value.Scope.EnvironmentIDs) > 100 || (value.Autonomy != AutonomySupervised && value.Autonomy != AutonomyAutonomous) || value.Limits.MaxSteps <= 0 || value.Limits.MaxSteps > 100 || value.Limits.MaxDuration <= 0 || value.Limits.MaxDuration > 24*time.Hour || len(value.AllowedActions) == 0 || len(value.AllowedActions) > 32 || !bounded(value.Verification.Kind, 64) || value.DefinitionVersion <= 0 {
		return ErrRejected
	}
	if !uniqueBounded(value.Scope.EnvironmentIDs, 128) || !uniqueBounded(value.AllowedActions, 128) {
		return ErrRejected
	}
	return nil
}

type RunState string

const (
	RunQueued          RunState = "queued"
	RunPlanning        RunState = "planning"
	RunWaitingApproval RunState = "waiting_approval"
	RunRunning         RunState = "running"
	RunVerifying       RunState = "verifying"
	RunContained       RunState = "contained"
	RunRemediated      RunState = "remediated"
	RunNeedsHuman      RunState = "needs_human"
	RunFailed          RunState = "failed"
	RunInconclusive    RunState = "inconclusive"
	RunCancelled       RunState = "cancelled"
)

var transitions = map[RunState]map[RunState]bool{
	RunQueued:          {RunPlanning: true, RunCancelled: true},
	RunPlanning:        {RunWaitingApproval: true, RunRunning: true, RunNeedsHuman: true, RunFailed: true, RunCancelled: true},
	RunWaitingApproval: {RunRunning: true, RunNeedsHuman: true, RunFailed: true, RunCancelled: true},
	RunRunning:         {RunVerifying: true, RunContained: true, RunNeedsHuman: true, RunFailed: true, RunInconclusive: true, RunCancelled: true},
	RunVerifying:       {RunContained: true, RunRemediated: true, RunNeedsHuman: true, RunFailed: true, RunInconclusive: true},
	RunContained:       {RunVerifying: true, RunRemediated: true, RunNeedsHuman: true, RunFailed: true, RunInconclusive: true},
}

func CanTransition(current, next RunState) bool { return current == next || transitions[current][next] }

type SecurityAgentRun struct {
	ID, OrganizationID, AgentID string
	State                       RunState
	TriggerEvidenceIDs          []string
	DefinitionVersion           int
	Version                     int64
}

type PlanStep struct {
	Index      int
	ActionKey  string
	Parameters map[string]string
}
type Plan struct {
	Version int
	Summary string
	Steps   []PlanStep
}

type ActionMetadata struct {
	Key              string
	InputSchema      map[string]string
	RiskClass        string
	TargetTypes      []string
	ApprovalFloor    string
	Reversible       bool
	Idempotent       bool
	VerificationKind string
}

func ValidateActionMetadata(value ActionMetadata) error {
	if !bounded(value.Key, 128) || len(value.InputSchema) == 0 || len(value.InputSchema) > 32 || !contains([]string{"low", "moderate", "containment", "destructive"}, value.RiskClass) || len(value.TargetTypes) == 0 || !uniqueBounded(value.TargetTypes, 64) || !contains([]string{"none", "operator", "admin"}, value.ApprovalFloor) || !bounded(value.VerificationKind, 64) {
		return ErrRejected
	}
	for key, schema := range value.InputSchema {
		if !bounded(key, 64) || !validSchema(schema) {
			return ErrRejected
		}
	}
	return nil
}

func ValidatePlan(value Plan, actions map[string]ActionMetadata) error {
	if value.Version != 1 || !bounded(value.Summary, 500) || len(value.Steps) == 0 || len(value.Steps) > 100 || len(actions) == 0 {
		return ErrRejected
	}
	for index, step := range value.Steps {
		if step.Index != index || !bounded(step.ActionKey, 128) {
			return ErrRejected
		}
		metadata, ok := actions[step.ActionKey]
		if !ok || ValidateActionMetadata(metadata) != nil || len(step.Parameters) != len(metadata.InputSchema) {
			return ErrRejected
		}
		for key, schema := range metadata.InputSchema {
			input, ok := step.Parameters[key]
			if !ok || !validInput(schema, input) {
				return ErrRejected
			}
		}
	}
	return nil
}

func validSchema(value string) bool {
	if value == "string" || value == "duration" {
		return true
	}
	if !strings.HasPrefix(value, "enum:") {
		return false
	}
	return uniqueBounded(strings.Split(strings.TrimPrefix(value, "enum:"), ","), 64)
}
func validInput(schema, value string) bool {
	if !bounded(value, 256) {
		return false
	}
	switch {
	case schema == "string":
		return true
	case schema == "duration":
		duration, err := time.ParseDuration(value)
		return err == nil && duration > 0 && duration <= 24*time.Hour
	case strings.HasPrefix(schema, "enum:"):
		return contains(strings.Split(strings.TrimPrefix(schema, "enum:"), ","), value)
	default:
		return false
	}
}
func bounded(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
func uniqueBounded(values []string, max int) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] || !bounded(value, max) {
			return false
		}
		seen[value] = true
	}
	return len(values) > 0
}
func contains[T comparable](values []T, target T) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func cloneStrings(values []string) []string { return append([]string(nil), values...) }
func cloneParameters(values map[string]string) map[string]string {
	result := map[string]string{}
	for key, value := range values {
		result[key] = value
	}
	return result
}
func idempotencyKey(parts ...string) (string, error) {
	for _, part := range parts {
		if !bounded(part, 128) {
			return "", ErrRejected
		}
	}
	return strings.Join(parts, "\x1f"), nil
}
func parsePositiveInt(value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, ErrRejected
	}
	return parsed, nil
}
