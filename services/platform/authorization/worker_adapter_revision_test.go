package authorization

import (
	"context"
	"errors"
	"testing"
)

type adapterSetReader struct {
	value         Revision
	reads, budget int
	fail          bool
}

func (r *adapterSetReader) Revision(context.Context, string) (Revision, error) {
	r.reads++
	if r.fail || r.budget > 0 && r.reads > r.budget {
		return Revision{}, context.DeadlineExceeded
	}
	return r.value, nil
}

type adapterSetChecker struct {
	read                                   *adapterSetReader
	seen                                   []CheckRequest
	changeAt, denyAt, wrongModelAt, failAt int
	mutation                               string
}

func (c *adapterSetChecker) Check(_ context.Context, q CheckRequest) (Decision, error) {
	c.seen = append(c.seen, q)
	i := len(c.seen)
	if i == c.changeAt {
		switch c.mutation {
		case "generation":
			c.read.value.Generation++
		case "store":
			c.read.value.StoreID = "01K00000000000000000000009"
		case "model":
			c.read.value.ModelID = "01K00000000000000000000009"
		default:
			c.read.value.Desired++
			c.read.value.Applied++
		}
	}
	if i == c.failAt {
		return Decision{}, ErrUnavailable
	}
	model := c.read.value.ModelID
	if i == c.wrongModelAt {
		model = "01K00000000000000000000009"
	}
	return Decision{Allowed: i != c.denyAt, ModelID: model}, nil
}
func adapterSetFixture() (*adapterSetReader, *adapterSetChecker, []CheckRequest) {
	r := &adapterSetReader{value: Revision{OrganizationID: org, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}}
	var requests []CheckRequest
	for _, target := range []struct{ kind, permission string }{{"security_agent", "manage_workflows"}, {"security_agent_run", "manage_workflows"}, {"test", "run_tests"}, {"agent", "run_tests"}} {
		q := exampleRequest()
		q.ResourceType, q.Permission = target.kind, target.permission
		requests = append(requests, q)
		q.PrincipalKind, q.TaskID = "service", task
		requests = append(requests, q)
	}
	return r, &adapterSetChecker{read: r}, requests
}

// The finite database budget models the measured deadline without sleeping.
// The result must cover all eight real mapped requests, not a partial allow.
func TestAdapterRevisionSetFitsFiniteReaderBudget(t *testing.T) {
	r, c, requests := adapterSetFixture()
	r.budget = 4
	want := r.value
	got, err := checkAdapterRevisionSet(context.Background(), r, c, requests, r.value.StoreID, r.value.ModelID)
	if err != nil || got != want || len(c.seen) != 8 {
		t.Fatal("complete adapter authority set exceeded finite revision budget", err, len(c.seen))
	}
	for i, q := range requests {
		if c.seen[i] != q {
			t.Fatal("adapter check target skipped or substituted")
		}
	}
}

func TestAdapterRevisionSetRefusesChangedOrInvalidAuthority(t *testing.T) {
	for _, name := range []string{"early change", "last change", "generation change", "store change", "model change", "mixed organization", "mixed workspace", "mixed environment", "pending", "store", "model", "malformed revision", "foreign tenant", "malformed request", "denied", "wrong result model", "checker unavailable", "reader unavailable", "empty", "truncated"} {
		t.Run(name, func(t *testing.T) {
			r, c, requests := adapterSetFixture()
			store, model := r.value.StoreID, r.value.ModelID
			want := ErrConflict
			switch name {
			case "early change":
				c.changeAt = 1
			case "last change":
				c.changeAt = 8
			case "generation change":
				c.changeAt = 8
				c.mutation = "generation"
			case "store change":
				c.changeAt = 8
				c.mutation = "store"
			case "model change":
				c.changeAt = 8
				c.mutation = "model"
			case "mixed organization":
				requests[7].OrganizationID = principal
				want = ErrInvalid
			case "mixed workspace":
				requests[7].WorkspaceID = principal
				want = ErrInvalid
			case "mixed environment":
				requests[7].EnvironmentID = principal
				want = ErrInvalid
			case "pending":
				r.value.Desired++
				want = ErrPending
			case "store":
				store = "01K00000000000000000000009"
				want = ErrPending
			case "model":
				model = "01K00000000000000000000009"
				want = ErrPending
			case "malformed revision":
				r.value.Generation = 0
				want = ErrPending
			case "foreign tenant":
				r.value.OrganizationID = principal
				want = ErrPending
			case "malformed request":
				requests[7].TaskID = ""
				want = ErrInvalid
			case "denied":
				c.denyAt = 8
				want = ErrDenied
			case "wrong result model":
				c.wrongModelAt = 8
			case "checker unavailable":
				c.failAt = 8
				want = ErrUnavailable
			case "reader unavailable":
				r.fail = true
				want = ErrUnavailable
			case "empty":
				requests = nil
				want = ErrInvalid
			case "truncated":
				requests = requests[:7]
				want = ErrInvalid
			}
			got, err := checkAdapterRevisionSet(context.Background(), r, c, requests, store, model)
			if !errors.Is(err, want) || got != (Revision{}) {
				t.Fatal("invalid adapter authority accepted", err)
			}
		})
	}
}
