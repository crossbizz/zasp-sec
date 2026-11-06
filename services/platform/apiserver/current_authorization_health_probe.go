package apiserver

import (
	"context"
	"sync/atomic"
	"time"
)

type currentAuthorizationHealthKey struct{}

// This observation is confined to one bounded health callback. It is never
// stored on a database, reused by the next probe, or consumed by product SQL.
// The two role-specific queries use independent connections, not one MVCC
// transaction. Product authorization continues to validate its own authority.
type currentAuthorizationHealthObservation struct {
	parent               context.Context
	core, security       *PostgresJSONDatabase
	checksum, audit, key string
	deadline             time.Time
	active               atomic.Bool
}

// WithCurrentAuthorizationHealthProbe freshly admits both API principals before
// checking components. Only identical fixed release/principal metadata can use
// that observation during the callback; all other checks remain independent.
// The optional observer receives a fixed security-principal selector and the
// existing probe result. It must not publish dependency error contents.
func WithCurrentAuthorizationHealthProbe(ctx context.Context, core, security *PostgresJSONDatabase, key string, observer func(context.Context, bool, error), check func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || core == nil || security == nil || core == security || check == nil {
		return ErrRepositoryUnavailable
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return ErrRepositoryUnavailable
	}
	probe, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	for _, candidate := range []struct {
		db        *PostgresJSONDatabase
		authority string
		security  bool
	}{
		{core, "zasp_discovery_api", false}, {security, "zasp_security_agent_api", true},
	} {
		go func() {
			err := candidate.db.CurrentAuthorizationRuntimeReady(probe, candidate.authority, key)
			if observer != nil {
				observer(probe, candidate.security, err)
			}
			results <- err
		}()
	}
	failed := false
	for range 2 {
		if <-results != nil {
			failed = true
			cancel()
		}
	}
	if failed || probe.Err() != nil {
		return ErrRepositoryUnavailable
	}
	checksum, audit := authorizationRuntimeChecksums()
	observation := &currentAuthorizationHealthObservation{parent: probe, core: core, security: security, checksum: checksum, audit: audit, key: key, deadline: deadline}
	observation.active.Store(true)
	defer observation.active.Store(false)
	err := check(context.WithValue(probe, currentAuthorizationHealthKey{}, observation))
	if err != nil {
		return err
	}
	if probe.Err() != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}

// Called only after the database's existing state/argument checks, with mu held.
func (database *PostgresJSONDatabase) hasCurrentAuthorizationHealthObservation(ctx context.Context, authority string) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	observation, ok := ctx.Value(currentAuthorizationHealthKey{}).(*currentAuthorizationHealthObservation)
	if !ok || observation == nil || !observation.active.Load() || observation.parent == nil || observation.parent.Err() != nil {
		return false
	}
	deadline, bounded := ctx.Deadline()
	checksum, audit := authorizationRuntimeChecksums()
	if !bounded || deadline.After(observation.deadline) || observation.checksum != checksum || observation.audit != audit || len(observation.key) != 64 {
		return false
	}
	return (database == observation.core && (authority == "" || authority == "zasp_discovery_api")) ||
		(database == observation.security && (authority == "" || authority == "zasp_security_agent_api"))
}
