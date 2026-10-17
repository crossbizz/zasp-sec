package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Delegate the original actual composite diagnostic fixture. New transaction
// events stay separate, preserving its existing pending/failure/event contract.
type authorizationConfirmationLoopQueryer struct {
	delegate                             *innerDiagnosticQueryer
	active, authority, identityCommitted bool
	tx                                   *authorizationConfirmationLoopTransaction
	failureStep, failureMode             string
	events                               []string
	temporalEvents                       []string
	commitPositions                      []int
	violations, workerInstalls           int
}

func (q *authorizationConfirmationLoopQueryer) QueryRow(c context.Context, s string, a ...any) pgx.Row {
	if strings.Contains(s, "public.zasp_discovery_principal_bindings") && (!q.active || !q.authority) {
		q.violations++
		return releaseReadinessErrorRow{}
	}
	step := q.delegate.runner.pending
	if step != "" {
		private := temporalConfirmationFixtureStep(step) || step == "up-authorization-temporal-identity-profile" || step == "up-authorization-worker-profile"
		if private {
			if !q.active || !q.authority || q.tx == nil {
				q.violations++
				return releaseReadinessErrorRow{}
			}
			q.tx.step = step
			q.recordConfirmationEvent("read", step)
		} else if q.active {
			q.violations++
			return releaseReadinessErrorRow{}
		}
		row := q.delegate.QueryRow(c, s, a...)
		if private && q.failureStep == step && q.failureMode == "catalog" {
			return scriptedPrincipalRow{value: false}
		}
		return row
	}
	return q.delegate.QueryRow(c, s, a...)
}
func (q *authorizationConfirmationLoopQueryer) beginPrincipalAuthorityTransaction(context.Context) (retentionOperatorTransaction, error) {
	if q.active {
		q.violations++
		return nil, errors.New("nested recorder transaction")
	}
	q.active = true
	q.tx = &authorizationConfirmationLoopTransaction{q: q}
	return q.tx, nil
}

type authorizationConfirmationLoopTransaction struct {
	q    *authorizationConfirmationLoopQueryer
	step string
}

func (x *authorizationConfirmationLoopTransaction) QueryRow(c context.Context, s string, a ...any) pgx.Row {
	return x.q.QueryRow(c, s, a...)
}
func (x *authorizationConfirmationLoopTransaction) Exec(_ context.Context, s string, _ ...any) (pgconn.CommandTag, error) {
	if s != "SET LOCAL ROLE zasp_discovery_authority" {
		return pgconn.CommandTag{}, errors.New("unexpected authority command")
	}
	x.q.authority = true
	return pgconn.NewCommandTag("SET"), nil
}
func (x *authorizationConfirmationLoopTransaction) Commit(context.Context) error {
	if x.step != "" {
		if x.q.failureStep == x.step && x.q.failureMode == "commit" {
			x.q.recordConfirmationEvent("commit-refused", x.step)
			return errors.New("private commit detail")
		}
		x.q.recordConfirmationEvent("commit", x.step)
		x.q.commitPositions = append(x.q.commitPositions, len(x.q.delegate.runner.events))
		if x.step == "up-authorization-temporal-identity-profile" {
			x.q.identityCommitted = true
		}
	}
	x.q.active = false
	x.q.authority = false
	x.q.tx = nil
	return nil
}
func (x *authorizationConfirmationLoopTransaction) Rollback(context.Context) error {
	x.q.active = false
	x.q.authority = false
	x.q.tx = nil
	return nil
}

type authorizationConfirmationLoopRunner struct {
	*innerDiagnosticRunner
	observer *authorizationConfirmationLoopQueryer
}

func (r *authorizationConfirmationLoopRunner) UpProductionAuthorizationTemporalIdentityProfile(c context.Context) error {
	if r.observer.active || r.observer.authority {
		r.observer.violations++
		return errors.New("authority leaked into identity installer")
	}
	r.observer.events = append(r.observer.events, "install:up-authorization-temporal-identity-profile")
	return r.install(c, "up-authorization-temporal-identity-profile")
}
func (r *authorizationConfirmationLoopRunner) UpProductionAuthorizationWorkerAuditProfile(c context.Context) error {
	r.observer.workerInstalls++
	if r.observer.active || r.observer.authority || !r.observer.identityCommitted {
		r.observer.violations++
		return errors.New("worker installer crossed uncommitted identity confirmation")
	}
	r.observer.events = append(r.observer.events, "install:up-authorization-worker-profile")
	return r.install(c, "up-authorization-worker-profile")
}
func TestAuthorizationConfirmationActualInnerLoopCommitAndFailureOrder(t *testing.T) {
	const identity = "up-authorization-temporal-identity-profile"
	const worker = "up-authorization-worker-profile"
	for _, mode := range []string{"accepted", "identity-catalog", "identity-commit", "worker-catalog", "worker-commit"} {
		t.Run(mode, func(t *testing.T) {
			original := &innerDiagnosticRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}, cause: errors.New("fixture-private-cause")}
			q := &authorizationConfirmationLoopQueryer{delegate: &innerDiagnosticQueryer{runner: original}}
			if strings.HasPrefix(mode, "identity-") {
				q.failureStep = identity
				q.failureMode = strings.TrimPrefix(mode, "identity-")
			}
			if strings.HasPrefix(mode, "worker-") {
				q.failureStep = worker
				q.failureMode = strings.TrimPrefix(mode, "worker-")
			}
			checked := &authorizationConfirmationLoopRunner{innerDiagnosticRunner: original, observer: q}
			r := &registeredReleaseMigrationRunner{releaseMigrationRunner: checked, queryer: q, registration: discoveryPrincipalRegistration{migration: "fixture_operator"}}
			err := runReleaseMigration(context.Background(), r, []string{"up-authorization-runtime-profile"})
			want := []string{"install:" + identity, "read:" + identity}
			if q.failureStep != identity || q.failureMode != "catalog" {
				if q.failureStep == identity {
					want = append(want, "commit-refused:"+identity)
				} else {
					want = append(want, "commit:"+identity, "install:"+worker, "read:"+worker)
					if q.failureMode == "commit" {
						want = append(want, "commit-refused:"+worker)
					} else if q.failureMode != "catalog" {
						want = append(want, "commit:"+worker)
					}
				}
			}
			if !reflect.DeepEqual(q.events, want) || q.violations != 0 || q.active || q.authority {
				t.Fatal("actual inner confirmation bypassed authority or crossed read/commit/installer boundary")
			}
			if mode == "accepted" {
				if err != nil || q.workerInstalls != 1 {
					t.Fatal("actual complete confirmation sequence refused")
				}
			} else {
				if err == nil || !errors.Is(err, errReleasePrincipalRegistration) || err.Error() != "authorization runtime profile refused: step="+q.failureStep+" stage=forward-readiness" {
					t.Fatal("actual original command/stage refusal identity changed")
				}
				if q.failureStep == identity && q.workerInstalls != 0 {
					t.Fatal("worker installed after refused identity confirmation")
				}
			}
			// Authority now guards all fourteen confirmations. Transaction events
			// remain separate from the original diagnostic dispatch/readiness roster.
			prefix := []string{}
			for _, step := range innerDiagnosticSteps[:12] {
				prefix = append(prefix, "install:"+step, "forward-readiness:"+step)
			}
			if len(original.events) < len(prefix) || !reflect.DeepEqual(original.events[:len(prefix)], prefix) {
				t.Fatal("original Temporal dispatch/confirmation prefix changed")
			}
		})
	}
}
