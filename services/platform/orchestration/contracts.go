// Package orchestration delivers committed product commands. It does not own
// admission, authorization, provider effects, or run completion.
package orchestration

import (
	"context"
	"errors"
	"regexp"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var (
	ErrInvalid     = errors.New("orchestration command rejected")
	ErrConflict    = errors.New("orchestration input conflict")
	ErrUnavailable = errors.New("orchestration unavailable")
	digestPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type RunRef struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	RunID          string `json:"run_id"`
}
type StartRequest struct {
	Ref               RunRef `json:"ref"`
	DefinitionVersion int64  `json:"definition_version"`
	InputDigest       string `json:"input_digest"`
}
type Message struct {
	Ref        RunRef `json:"ref"`
	EventID    string `json:"event_id"`
	Kind       string `json:"kind"`
	DecisionID string `json:"decision_id"`
}
type Engine interface {
	Start(context.Context, StartRequest) error
	Notify(context.Context, Message) error
}

func validID(s string) bool { p, err := domain.ParseProductID(s); return err == nil && p.String() == s }
func (r RunRef) valid() bool {
	return validID(r.OrganizationID) && validID(r.WorkspaceID) && validID(r.EnvironmentID) && validID(r.RunID)
}
func (r StartRequest) valid() bool {
	return r.Ref.valid() && r.DefinitionVersion >= 1 && r.DefinitionVersion <= 1000000 && digestPattern.MatchString(r.InputDigest)
}
func (m Message) valid() bool {
	return m.Ref.valid() && validID(m.EventID) && validID(m.DecisionID) && (m.Kind == "approval" || m.Kind == "cancel")
}
func WorkflowID(r RunRef) (string, error) {
	if !r.valid() {
		return "", ErrInvalid
	}
	return "security-agent/v1/" + r.OrganizationID + "/" + r.WorkspaceID + "/" + r.EnvironmentID + "/" + r.RunID, nil
}
