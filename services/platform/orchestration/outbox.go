package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

type Command struct {
	Ref               RunRef `json:"ref"`
	EventID           string `json:"event_id"`
	Kind              string `json:"kind"`
	DecisionID        string `json:"decision_id"`
	DefinitionVersion int64  `json:"definition_version"`
	InputDigest       string `json:"input_digest"`
	ExecutionOwner    string `json:"execution_owner"`
}
type Store interface {
	Pending(context.Context) ([]Command, error)
	Attempt(context.Context, Command) error
	Ack(context.Context, Command) error
}
type Relay struct {
	Store  Store
	Engine Engine
}

func (r *Relay) RunOnce(ctx context.Context) error {
	if ctx == nil || r == nil || r.Store == nil || r.Engine == nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	commands, err := r.Store.Pending(ctx)
	if err != nil {
		return ErrUnavailable
	}
	var failures error
	for _, c := range commands {
		if ctx.Err() != nil {
			return errors.Join(failures, ErrUnavailable)
		}
		if c.ExecutionOwner != "temporal" || !c.Ref.valid() || !validID(c.EventID) {
			failures = errors.Join(failures, ErrInvalid)
			continue
		}
		// Rotate this row before the RPC. A timeout or process exit must not
		// leave a slow failing prefix first on every subsequent poll.
		if err = r.Store.Attempt(ctx, c); err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		if c.Kind == "start" {
			err = r.Engine.Start(ctx, StartRequest{c.Ref, c.DefinitionVersion, c.InputDigest})
		} else if c.Kind == "approval" || c.Kind == "cancel" {
			err = r.Engine.Notify(ctx, Message{c.Ref, c.EventID, c.Kind, c.DecisionID})
		} else {
			err = ErrInvalid
		}
		if err == nil {
			err = r.Store.Ack(ctx, c)
		}
		failures = errors.Join(failures, err)
	}
	return failures
}

type JSONDatabase interface {
	QueryJSON(context.Context, string, ...any) (json.RawMessage, error)
}

// SQLStore performs each call as its own product transaction. No transaction
// spans a Temporal RPC. Concurrent relays may redeliver the same command.
type SQLStore struct {
	Database JSONDatabase
	Timeout  time.Duration
}

func (s SQLStore) Pending(ctx context.Context) ([]Command, error) {
	if ctx == nil || s.Database == nil || s.Timeout <= 0 || s.Timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	raw, err := s.Database.QueryJSON(bounded, `SELECT zasp_temporal65.pending()`)
	if err != nil {
		return nil, ErrUnavailable
	}
	var commands []Command
	if json.Unmarshal(raw, &commands) != nil || len(commands) > 100 {
		return nil, ErrUnavailable
	}
	return commands, nil
}
func (s SQLStore) Ack(ctx context.Context, c Command) error {
	return s.record(ctx, c, `SELECT zasp_temporal65.ack($1,$2,$3,$4,$5)`)
}

// Attempt records only polling order. It is neither acceptance nor a lease;
// another relay may deliver the same row and the engine must remain idempotent.
func (s SQLStore) Attempt(ctx context.Context, c Command) error {
	return s.record(ctx, c, `SELECT zasp_temporal65.attempt($1,$2,$3,$4,$5)`)
}

func (s SQLStore) record(ctx context.Context, c Command, statement string) error {
	if ctx == nil || s.Database == nil || s.Timeout <= 0 || s.Timeout > 30*time.Second || !c.Ref.valid() || !validID(c.EventID) {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	raw, err := s.Database.QueryJSON(bounded, statement, c.Ref.OrganizationID, c.Ref.WorkspaceID, c.Ref.EnvironmentID, c.Ref.RunID, c.EventID)
	if err != nil || string(raw) != "true" {
		return ErrUnavailable
	}
	return nil
}
