package orchestration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
)

type AutomaticSourceStore interface {
	Pending(context.Context) ([]AutomaticSourceRef, error)
	Attempt(context.Context, AutomaticSourceRef) error
	Ack(context.Context, AutomaticSourceRef) error
}
type AutomaticSourceStartClient interface {
	Start(context.Context, AutomaticSourceRef) error
}
type AutomaticSourceRelay struct {
	Store   AutomaticSourceStore
	Starter AutomaticSourceStartClient
}

func (r *AutomaticSourceRelay) RunOnce(ctx context.Context) error {
	if r == nil || r.Store == nil || r.Starter == nil || ctx == nil {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	refs, err := r.Store.Pending(bounded)
	if err != nil {
		return err
	}
	if len(refs) > 25 {
		return ErrInvalid
	}
	var result error
	for _, ref := range refs {
		if bounded.Err() != nil {
			return errors.Join(result, ErrUnavailable)
		}
		if !ref.Valid() {
			result = errors.Join(result, ErrInvalid)
			continue
		}
		// Commit polling order before the RPC. Neither an ambiguous outcome nor
		// a process exit acknowledges this source or pins it ahead of all others.
		err = r.Store.Attempt(bounded, ref)
		if err == nil {
			err = r.Starter.Start(bounded, ref)
		}
		if err == nil && bounded.Err() != nil {
			err = ErrUnavailable
		}
		if err == nil {
			err = r.Store.Ack(bounded, ref)
		}
		result = errors.Join(result, err)
	}
	return result
}

type AutomaticSourceSQLStore struct {
	Database JSONDatabase
	Timeout  time.Duration
}

func (s AutomaticSourceSQLStore) query(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	if ctx == nil || s.Database == nil || s.Timeout <= 0 || s.Timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	raw, err := s.Database.QueryJSON(bounded, sql, args...)
	if err != nil || bounded.Err() != nil {
		return nil, ErrUnavailable
	}
	return raw, nil
}
func (s AutomaticSourceSQLStore) Pending(ctx context.Context) ([]AutomaticSourceRef, error) {
	raw, err := s.query(ctx, `SELECT zasp_temporal77.pending_sources($1)`, 25)
	if err != nil {
		return nil, err
	}
	var refs []AutomaticSourceRef
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&refs) != nil || refs == nil || len(refs) > 25 || decoder.Decode(new(any)) != io.EOF {
		return nil, ErrUnavailable
	}
	seen := map[AutomaticSourceRef]bool{}
	for _, ref := range refs {
		if !ref.Valid() || seen[ref] {
			return nil, ErrUnavailable
		}
		seen[ref] = true
	}
	return refs, nil
}
func (s AutomaticSourceSQLStore) Attempt(ctx context.Context, ref AutomaticSourceRef) error {
	if !ref.Valid() {
		return ErrInvalid
	}
	raw, err := s.query(ctx, `SELECT to_jsonb(zasp_temporal77.attempt_source($1,$2,$3,$4))`, ref.OrganizationID, ref.WorkspaceID, ref.EnvironmentID, ref.EventID)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return ErrUnavailable
	}
	return nil
}
func (s AutomaticSourceSQLStore) Ack(ctx context.Context, ref AutomaticSourceRef) error {
	id, err := AutomaticSourceWorkflowID(ref)
	if err != nil {
		return err
	}
	raw, err := s.query(ctx, `SELECT to_jsonb(zasp_temporal77.ack_source($1,$2,$3,$4,$5))`, ref.OrganizationID, ref.WorkspaceID, ref.EnvironmentID, ref.EventID, id)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return ErrUnavailable
	}
	return nil
}
