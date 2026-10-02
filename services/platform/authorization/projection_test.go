package authorization

import (
	"context"
	"errors"
	fga "github.com/openfga/go-sdk/client"
	"testing"
)

func projectionFixture() ProjectionSnapshot {
	scope := ProjectionScope{org, workspace, environment}
	return ProjectionSnapshot{Revision: Revision{OrganizationID: org, Desired: 2, Applied: 1, Generation: 1, StoreID: storeID, ModelID: modelID}, Scopes: []ProjectionScope{scope}, Members: []ProjectionMember{{Kind: "user", ID: principal}, {Kind: "agent", ID: resource}}, Roles: []ProjectionRole{{scope, principal, "security_admin"}, {scope, principal, "compliance_viewer"}}, Resources: []ProjectionResource{{scope, "finding", resource}}, Grants: []ProjectionGrant{{ProjectionResource: ProjectionResource{scope, "finding", resource}, PrincipalKind: "agent", PrincipalID: resource, Permission: "run_tests", TaskID: task}}}
}

// Breaks if projection invents broad organization roles, omits machine membership,
// merges sibling scope grants, or accepts two parents for a product object.
func TestPermissionProjection(t *testing.T) {
	snapshot := projectionFixture()
	tuples, err := Project(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	must := []fga.ClientTupleKey{{User: "user:" + principal, Relation: "security_admin", Object: "environment:" + org + "/" + workspace + "/" + environment}, {User: "agent:" + resource, Relation: "member", Object: "organization:" + org}}
	for _, want := range must {
		found := false
		for _, tuple := range tuples {
			if tuple.User == want.User && tuple.Relation == want.Relation && tuple.Object == want.Object {
				found = true
			}
		}
		if !found {
			t.Errorf("missing source projection: %#v", want)
		}
	}
	for _, mutate := range []func(*ProjectionSnapshot){
		func(s *ProjectionSnapshot) { s.Roles[0].OrganizationID = "pid_10000000-0000-4000-8000-000000000002" },
		func(s *ProjectionSnapshot) { s.Members = s.Members[:1] },
		func(s *ProjectionSnapshot) {
			duplicate := s.Scopes[0]
			duplicate.WorkspaceID = "pid_20000000-0000-4000-8000-000000000002"
			s.Scopes = append(s.Scopes, duplicate)
		},
		func(s *ProjectionSnapshot) { s.Grants[0].TaskID = "" },
	} {
		bad := projectionFixture()
		mutate(&bad)
		if _, err := Project(bad); err == nil {
			t.Fatal("invalid source facts projected")
		}
	}
}

type revisionFixture struct{ value Revision }

func (r revisionFixture) Revision(context.Context, string) (Revision, error) { return r.value, nil }

type checkFixture struct{ calls int }

func (c *checkFixture) Check(context.Context, CheckRequest) (Decision, error) {
	c.calls++
	return Decision{Allowed: true, ModelID: modelID}, nil
}
func TestRevisionBoundary(t *testing.T) {
	revision := projectionFixture().Revision
	checker := &checkFixture{}
	result, err := CheckRevision(context.Background(), revisionFixture{revision}, checker, exampleRequest(), storeID, modelID)
	if !errors.Is(err, ErrPending) || result.Decision.Allowed || checker.calls != 0 {
		t.Fatal("pending projection was usable", result, err)
	}
	revision.Applied = revision.Desired
	result, err = CheckRevision(context.Background(), revisionFixture{revision}, checker, exampleRequest(), storeID, modelID)
	if err != nil || !result.Decision.Allowed || result.Revision != revision {
		t.Fatal("applied revision unavailable", result, err)
	}
	result, err = CheckRevision(context.Background(), revisionFixture{revision}, checker, exampleRequest(), storeID, "01K00000000000000000000009")
	if err == nil || result.Decision.Allowed {
		t.Fatal("wrong active model accepted")
	}
	raced := &changingRevisionFixture{value: revision}
	result, err = CheckRevision(context.Background(), raced, checker, exampleRequest(), storeID, modelID)
	if !errors.Is(err, ErrConflict) || result.Decision.Allowed {
		t.Fatal("revision changed during Check was allowed", result, err)
	}
}

type changingRevisionFixture struct {
	value Revision
	calls int
}

func (r *changingRevisionFixture) Revision(context.Context, string) (Revision, error) {
	r.calls++
	if r.calls > 1 {
		r.value.Desired++
	}
	return r.value, nil
}

type projectionStore struct {
	snapshot ProjectionSnapshot
	staged   bool
	acked    bool
	failAck  bool
	changed  bool
	order    []string
}

func (s *projectionStore) WithOrganization(ctx context.Context, _ string, fn func(ProjectionSession) error) error {
	return fn(s)
}
func (s *projectionStore) Snapshot(context.Context) (ProjectionSnapshot, error) {
	return s.snapshot, nil
}
func (s *projectionStore) Stage(_ context.Context, r Revision, tuples []fga.ClientTupleKey) error {
	s.staged = true
	s.order = append(s.order, "stage")
	s.snapshot.Known = tuples
	return nil
}
func (s *projectionStore) Acknowledge(_ context.Context, r Revision, tuples []fga.ClientTupleKey) error {
	s.order = append(s.order, "ack")
	if s.failAck {
		return ErrUnavailable
	}
	if s.changed {
		return ErrConflict
	}
	s.acked = true
	s.snapshot.Revision.Applied = r.Desired
	return nil
}

type projectionWriter struct {
	store *projectionStore
	fail  bool
	calls int
}

func (w *projectionWriter) Replace(_ context.Context, _ Revision, previous, desired []fga.ClientTupleKey) error {
	w.calls++
	if !w.store.staged {
		return errors.New("write before durable stage")
	}
	w.store.order = append(w.store.order, "write")
	if w.fail {
		return ErrUnavailable
	}
	return nil
}

// Tests the application delivery order and durable retry contract, not SDK retries.
func TestProjectionReconciliation(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		writeFail, ackFail, changed bool
	}{{"success", false, false, false}, {"incomplete write", true, false, false}, {"crash before ack", false, true, false}, {"concurrent grant revision", false, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			s := &projectionStore{snapshot: projectionFixture(), failAck: tc.ackFail, changed: tc.changed}
			w := &projectionWriter{store: s, fail: tc.writeFail}
			receipt, err := Reconcile(context.Background(), s, w, org, storeID, modelID)
			failure := tc.writeFail || tc.ackFail || tc.changed
			if failure {
				if err == nil || receipt.Applied || s.acked {
					t.Fatal("incomplete revision acknowledged", receipt, err)
				}
			} else if err != nil || !receipt.Applied || !s.acked {
				t.Fatal("complete revision not acknowledged", receipt, err)
			}
			if tc.ackFail {
				s.failAck = false
				receipt, err = Reconcile(context.Background(), s, w, org, storeID, modelID)
				if err != nil || !receipt.Applied || w.calls != 2 {
					t.Fatal("crash replay did not reapply current state", receipt, err)
				}
			}
		})
	}
}
