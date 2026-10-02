package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"strings"
	"testing"
	"time"
)

type recoveryObserverFunc func(context.Context, orchestration.StartRequest) (orchestration.SingleTestOriginalObservation, error)

func (f recoveryObserverFunc) ObserveOriginal(c context.Context, q orchestration.StartRequest) (orchestration.SingleTestOriginalObservation, error) {
	return f(c, q)
}
func TestSingleTestRecoveryRepositoryContracts(t *testing.T) {
	id := orderedPublicIdentity()
	q := SingleTestRecoveryMutation{RunID: public62Finding, DefinitionVersion: 2, InputDigest: strings.Repeat("a", 64), ExpectedVersion: 3, IdempotencyKey: "single-recovery-test-0001", AuditID: public62Definition, CorrelationID: id.PrincipalID.String(), ReceiptID: public62Finding}
	start := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: id.Scope.OrganizationID().String(), WorkspaceID: id.Scope.WorkspaceID().String(), EnvironmentID: id.Scope.EnvironmentID().String(), RunID: q.RunID}, DefinitionVersion: 2, InputDigest: q.InputDigest}
	workflowID, _ := orchestration.SingleTestWorkflowID(start.Ref)
	commandID, _ := CanonicalDiscoveryID(id.Scope, "single_test_cleanup_recovery", q.RunID)
	ref := orchestration.SingleTestRecoveryRef{Start: start, CommandID: commandID, CommandDigest: strings.Repeat("b", 64)}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	accepted := SingleTestRecoveryMutationResult{Body: SingleTestRecoveryView{RequestIdentity: SingleTestRecoveryRequestIdentity{2, q.InputDigest}, RunID: q.RunID, Status: "queued", Reason: "queued", ParentVersion: 4, Command: &ref, AcceptedAt: &stamp}, AuditID: q.AuditID, CorrelationID: q.CorrelationID, ReceiptID: q.ReceiptID}
	for _, mode := range []string{"new", "replay", "running", "stale_version", "foreign_preflight", "invalid_result", "identity_mismatch", "reason_mismatch", "revoked_after_describe"} {
		t.Run(mode, func(t *testing.T) {
			calls := []string{}
			observed := 0
			db := &orderedPublicDB{query: func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				calls = append(calls, sql)
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded SQL")
				}
				if sql == singleTestRecoveryPreflightSQL {
					p := singleTestRecoveryPreflight{Start: start, RunVersion: 3, WorkflowID: workflowID}
					if mode == "stale_version" {
						p.RunVersion = 4
					}
					if mode == "replay" {
						p.Replay = &accepted
						p.Replay.Replayed = true
					}
					if mode == "foreign_preflight" {
						p.Start.Ref.OrganizationID = q.RunID
					}
					return json.Marshal(p)
				}
				if sql != singleTestRecoveryAdmitSQL {
					t.Fatal("unexpected SQL", sql)
				}
				if mode == "revoked_after_describe" {
					return nil, ErrRepositoryAuthentication
				}
				result := accepted
				if mode == "invalid_result" {
					result.Body.Command = nil
				}
				if mode == "identity_mismatch" {
					result.Body.RequestIdentity.InputDigest = strings.Repeat("c", 64)
				}
				if mode == "reason_mismatch" {
					result.Body.Reason = "cleanup_pending"
				}
				return json.Marshal(result)
			}}
			observer := recoveryObserverFunc(func(ctx context.Context, got orchestration.StartRequest) (orchestration.SingleTestOriginalObservation, error) {
				observed++
				if got != start {
					t.Fatal("different original")
				}
				if mode == "running" {
					return orchestration.SingleTestOriginalObservation{}, orchestration.ErrConflict
				}
				return orchestration.SingleTestOriginalObservation{WorkflowID: workflowID, Status: "absent", ObservedAt: time.Now().UTC()}, nil
			})
			repo, err := NewSingleTestRecoveryRepository(db, observer)
			if err != nil {
				t.Fatal(err)
			}
			got, err := repo.Request(context.Background(), id, q)
			if mode == "new" || mode == "replay" {
				if err != nil || got.Body.RunID != q.RunID {
					t.Fatal(got, err)
				}
			} else if err == nil {
				t.Fatal("unsafe request accepted")
			}
			if mode == "replay" || mode == "foreign_preflight" || mode == "stale_version" {
				if observed != 0 || len(calls) != 1 {
					t.Fatal("replay/invalid preflight reached observation")
				}
			}
			if mode == "running" && (!errors.Is(err, ErrRepositoryConflict) || len(calls) != 1) {
				t.Fatal("running original admitted", err)
			}
		})
	}
}
