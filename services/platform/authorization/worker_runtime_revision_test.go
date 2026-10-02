package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func runtimeRevisionFixture(t *testing.T, operation WorkerOperation, devices int) (workerOperationSpec, workerFacts, *adapterSetReader, *adapterSetChecker, []CheckRequest) {
	t.Helper()
	spec, ok := workerOperation(operation)
	if !ok {
		t.Fatal("operation missing")
	}
	permission := "view"
	if spec.testExecution {
		permission = "run_tests"
	}
	f := workerFacts{OrganizationID: org, WorkspaceID: workspace, EnvironmentID: environment, RunID: task, GrantorID: principal, PrincipalID: resource, DefinitionID: resource, TestID: resource, TargetID: resource, TargetKind: "agent", TriggerKind: "runtime_decision", TriggerID: resource, RuntimeProtocol: "configured77-event-occurrence", RuntimeDigest: strings.Repeat("a", 64), SourceSessionID: resource, SourceAgentID: resource, SessionUser: "registered_worker"}
	targets := []map[string]string{{"kind": "security_agent", "id": resource, "permission": "manage_workflows"}, {"kind": "security_agent_run", "id": task, "permission": "manage_workflows"}, {"kind": "test", "id": resource, "permission": permission}, {"kind": "agent", "id": resource, "permission": permission}, {"kind": "session", "id": resource, "permission": "investigate_sessions"}, {"kind": "agent", "id": resource, "permission": "view"}}
	for i := 0; i < devices; i++ {
		id := fmt.Sprintf("pid_70000000-0000-4000-8000-%012d", i+1)
		f.SourceDeviceIDs = append(f.SourceDeviceIDs, id)
		targets = append(targets, map[string]string{"kind": "gateway_device", "id": id, "permission": "view"})
	}
	raw, _ := json.Marshal(targets)
	if json.Unmarshal(raw, &f.Checks) != nil {
		t.Fatal("fixture checks")
	}
	r, c, _ := adapterSetFixture()
	var requests []CheckRequest
	for _, target := range f.Checks {
		q := CheckRequest{PrincipalKind: "user", PrincipalID: principal, OrganizationID: org, WorkspaceID: workspace, EnvironmentID: environment, ResourceType: target.Kind, ResourceID: target.ID, Permission: target.Permission}
		requests = append(requests, q)
		q.PrincipalKind, q.PrincipalID, q.TaskID = "service", resource, task
		requests = append(requests, q)
	}
	return spec, f, r, c, requests
}

// This is the actual proof encoder used after Authorize's final revision read.
// Full canonical count100+anchor metadata must fit; excess bytes must never be
// truncated or signed into a decision that the native limit cannot accept.
func TestRuntimeWorkerProofByteLimit(t *testing.T) {
	_, f, r, _, _ := runtimeRevisionFixture(t, "test74.adapter.start", 101)
	key, err := NewWorkerKey(WorkerForward, []byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	executor := &WorkerExecutor{key: key}
	facts, _ := json.Marshal(f)
	request := json.RawMessage(`{"operation":"start"}`)
	decision, err := executor.signWorkerDecision("test74.adapter.start", request, nil, facts, r.value, f.SessionUser, time.Unix(1800000000, 0))
	if err != nil {
		t.Fatal("maximum canonical device proof refused", err)
	}
	var envelope struct {
		Body []byte `json:"body"`
	}
	if json.Unmarshal(decision.envelope, &envelope) != nil || len(envelope.Body) > 32768 || len(envelope.Body) < 10000 {
		t.Fatal("maximum proof encoding changed", len(envelope.Body))
	}
	var decoded struct {
		Facts workerFacts `json:"facts"`
	}
	if json.Unmarshal(envelope.Body, &decoded) != nil || len(decoded.Facts.SourceDeviceIDs) != 101 || len(decoded.Facts.Checks) != 107 {
		t.Fatal("maximum evidence truncated")
	}
	var full map[string]any
	if json.Unmarshal(facts, &full) != nil {
		t.Fatal("facts fixture")
	}
	full["extra_capture"] = strings.Repeat("x", 32768)
	oversize, _ := json.Marshal(full)
	if d, err := executor.signWorkerDecision("test74.adapter.start", request, nil, oversize, r.value, f.SessionUser, time.Unix(1800000000, 0)); !errors.Is(err, ErrInvalid) || len(d.envelope) != 0 {
		t.Fatal("native proof-byte limit bypassed", err)
	}
}

// A missing last device, a skipped subject, or a per-Check revision read would
// fail this complete-set contract. The two-read budget has no wall-clock sleep.
func TestRuntimeTestRevisionCompleteSet(t *testing.T) {
	for _, operation := range []WorkerOperation{"test74.planning.load", "test74.effect.reserve", "test74.adapter.start"} {
		for _, count := range []int{1, 100, 101} {
			t.Run(fmt.Sprintf("%s/%d", operation, count), func(t *testing.T) {
				spec, f, r, c, requests := runtimeRevisionFixture(t, operation, count)
				r.budget = 2
				got, err := checkRuntimeTestRevisionSet(context.Background(), r, c, spec, f, requests, r.value.StoreID, r.value.ModelID)
				if err != nil || got != r.value || r.reads != 2 || len(c.seen) != 12+2*count {
					t.Fatal("incomplete runtime authority", err, r.reads, len(c.seen))
				}
				for i, q := range requests {
					if c.seen[i] != q {
						t.Fatal("target or subject substituted", i)
					}
				}
				r.budget = 4
				r.value.Desired++
				r.value.Applied++
				c.seen = nil
				next, err := checkRuntimeTestRevisionSet(context.Background(), r, c, spec, f, requests, r.value.StoreID, r.value.ModelID)
				if err != nil || next == got || next != r.value || r.reads != 4 {
					t.Fatal("cross-call revision reuse", err)
				}
			})
		}
	}
}

func TestRuntimeTestRevisionRejectsChangedAuthority(t *testing.T) {
	for _, name := range []string{"first revision", "last revision", "generation", "store", "model", "last denied", "last wrong model", "last transport", "foreign organization", "foreign workspace", "foreign environment", "wrong task", "wrong subject", "truncated", "extra", "missing device", "unknown protocol", "compensation", "non-test", "pending", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			spec, f, r, c, requests := runtimeRevisionFixture(t, "test74.adapter.start", 101)
			store, model := r.value.StoreID, r.value.ModelID
			want := ErrConflict
			ctx := context.Background()
			last := len(requests) - 1
			switch name {
			case "first revision":
				c.changeAt = 1
			case "last revision":
				c.changeAt = len(requests)
			case "generation", "store", "model":
				c.changeAt = len(requests)
				c.mutation = name
			case "last denied":
				c.denyAt = len(requests)
				want = ErrDenied
			case "last wrong model":
				c.wrongModelAt = len(requests)
			case "last transport":
				c.failAt = len(requests)
				want = ErrUnavailable
			case "foreign organization":
				requests[last].OrganizationID = resource
				want = ErrInvalid
			case "foreign workspace":
				requests[last].WorkspaceID = resource
				want = ErrInvalid
			case "foreign environment":
				requests[last].EnvironmentID = resource
				want = ErrInvalid
			case "wrong task":
				requests[last].TaskID = resource
				want = ErrInvalid
			case "wrong subject":
				requests[last].PrincipalID = principal
				want = ErrInvalid
			case "truncated":
				requests = requests[:last]
				want = ErrInvalid
			case "extra":
				requests = append(requests, requests[last])
				want = ErrInvalid
			case "missing device":
				f.SourceDeviceIDs = f.SourceDeviceIDs[:100]
				want = ErrInvalid
			case "unknown protocol":
				f.RuntimeProtocol = "unrecognized"
				want = ErrInvalid
			case "compensation":
				spec.current = false
				want = ErrInvalid
			case "non-test":
				spec.testExecution = false
				want = ErrInvalid
			case "pending":
				r.value.Desired++
				want = ErrPending
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = ErrUnavailable
			}
			got, err := checkRuntimeTestRevisionSet(ctx, r, c, spec, f, requests, store, model)
			if !errors.Is(err, want) || got != (Revision{}) {
				t.Fatal("changed runtime authority accepted", err, want)
			}
		})
	}
}
