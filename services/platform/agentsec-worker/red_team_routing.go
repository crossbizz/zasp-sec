package main

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Select from persisted database authority for every transition. Never infer
// protocol from a queue payload or fall back after a linked operation fails.
type routedRedTeamAuthority struct {
	legacy          *apiserver.RedTeamExecutionRepository
	linked          *apiserver.LinkedRedTeamExecutionRepository
	installedLinked bool
}

func newRoutedRedTeamAuthority(db apiserver.JSONDatabase) (*routedRedTeamAuthority, error) {
	if probe, ok := db.(interface {
		LegacyTestsAvailable(context.Context, string) (bool, error)
	}); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		installed, err := probe.LegacyTestsAvailable(ctx, "zasp_red_team_worker")
		cancel()
		if err != nil {
			return nil, errRuntimeUnavailable
		}
		if installed {
			linked, err := apiserver.NewLinkedRedTeamExecutionRepository(db)
			if err != nil {
				return nil, errRuntimeUnavailable
			}
			//71 admits only persisted legacy single-test links. Standalone and
			// retained ordered work do not acquire this transitional authority.
			return &routedRedTeamAuthority{linked: linked, installedLinked: true}, nil
		}
	}
	legacy, err := apiserver.NewRedTeamExecutionRepository(db, apiserver.RedTeamExecutionAuthorityWorker)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	linked, err := apiserver.NewLinkedRedTeamExecutionRepository(db)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	return &routedRedTeamAuthority{legacy: legacy, linked: linked}, nil
}

func (r *routedRedTeamAuthority) Ready(ctx context.Context) error {
	if r == nil || r.linked == nil || r.linked.Ready(ctx) != nil {
		return errRuntimeUnavailable
	}
	if !r.installedLinked && (r.legacy == nil || r.legacy.Ready(ctx) != nil) {
		return errRuntimeUnavailable
	}
	return nil
}

func (r *routedRedTeamAuthority) ReadyArtifacts(ctx context.Context) error {
	if r.Ready(ctx) != nil || !r.installedLinked && r.legacy.ReadyArtifacts(ctx) != nil {
		return errRuntimeUnavailable
	}
	return nil
}

func (r *routedRedTeamAuthority) protocol(ctx context.Context, scope domain.Scope, run string) (string, error) {
	if r == nil || r.linked == nil || !r.installedLinked && r.legacy == nil {
		return "", errRuntimeUnavailable
	}
	protocol, err := r.linked.RunProtocol(ctx, scope, run)
	if err != nil || r.installedLinked && protocol != "linked" {
		return "", errRuntimeUnavailable
	}
	return protocol, nil
}

func (r *routedRedTeamAuthority) ClaimRedTeamRun(ctx context.Context, scope domain.Scope, run, worker, lease string, seconds int) (apiserver.RedTeamRunClaim, error) {
	protocol, err := r.protocol(ctx, scope, run)
	if err != nil {
		return apiserver.RedTeamRunClaim{}, err
	}
	if protocol == "linked" {
		return r.linked.ClaimRedTeamRun(ctx, scope, run, worker, lease, seconds)
	}
	return r.legacy.ClaimRedTeamRun(ctx, scope, run, worker, lease, seconds)
}

func (r *routedRedTeamAuthority) HeartbeatRedTeamRun(ctx context.Context, scope domain.Scope, run, worker, lease string, seconds int) (apiserver.RedTeamRunHeartbeat, error) {
	protocol, err := r.protocol(ctx, scope, run)
	if err != nil {
		return apiserver.RedTeamRunHeartbeat{}, err
	}
	if protocol == "linked" {
		return r.linked.HeartbeatRedTeamRun(ctx, scope, run, worker, lease, seconds)
	}
	return r.legacy.HeartbeatRedTeamRun(ctx, scope, run, worker, lease, seconds)
}

func (r *routedRedTeamAuthority) FinishRedTeamRun(ctx context.Context, scope domain.Scope, input apiserver.RedTeamRunCompletion) (apiserver.RedTeamRun, error) {
	protocol, err := r.protocol(ctx, scope, input.RunID)
	if err != nil {
		return apiserver.RedTeamRun{}, err
	}
	if protocol == "linked" {
		return r.linked.FinishRedTeamRun(ctx, scope, input)
	}
	return r.legacy.FinishRedTeamRun(ctx, scope, input)
}

func (r *routedRedTeamAuthority) RetryRedTeamRun(ctx context.Context, scope domain.Scope, run, worker, lease string, digest [sha256.Size]byte, code string, next time.Time) (apiserver.RedTeamRun, error) {
	protocol, err := r.protocol(ctx, scope, run)
	if err != nil || protocol != "legacy" {
		return apiserver.RedTeamRun{}, errWorkerExecution
	}
	// Linked work without a terminal receipt stays pending for reconciliation;
	// the linked claim itself permits only expired, provably unstarted work.
	return r.legacy.RetryRedTeamRun(ctx, scope, run, worker, lease, digest, code, next)
}

func (r *routedRedTeamAuthority) CancelClaimedRedTeamRun(ctx context.Context, scope domain.Scope, run, worker, lease string, digest [sha256.Size]byte) (apiserver.RedTeamRun, error) {
	protocol, err := r.protocol(ctx, scope, run)
	if err != nil || protocol != "legacy" {
		return apiserver.RedTeamRun{}, errWorkerExecution
	}
	return r.legacy.CancelClaimedRedTeamRun(ctx, scope, run, worker, lease, digest)
}

func (r *routedRedTeamAuthority) CancelLinkedRedTeamRun(ctx context.Context, scope domain.Scope, run, worker, lease string, digest [sha256.Size]byte) (apiserver.RedTeamRun, error) {
	protocol, err := r.protocol(ctx, scope, run)
	if err != nil || protocol != "linked" {
		return apiserver.RedTeamRun{}, errWorkerExecution
	}
	return r.linked.CancelLinkedRedTeamRun(ctx, scope, run, worker, lease, digest)
}
