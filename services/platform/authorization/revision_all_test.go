package authorization

import (
	"context"
	"errors"
	"testing"
)

type countingRevisionFixture struct {
	value   Revision
	calls   int
	advance int // The read (one-based) from which the revision has advanced; zero never.
	fail    int // The read (one-based) that fails; zero never.
}

func (r *countingRevisionFixture) Revision(context.Context, string) (Revision, error) {
	r.calls++
	if r.fail == r.calls {
		return Revision{}, errors.New("unavailable")
	}
	value := r.value
	if r.advance > 0 && r.calls >= r.advance {
		value.Desired++
		value.Applied++
	}
	return value, nil
}

type recordingCheckFixture struct {
	requests []CheckRequest
	model    string
	deny     string // The permission that is denied.
	fail     string // The permission whose check fails.
}

func (c *recordingCheckFixture) Check(_ context.Context, request CheckRequest) (Decision, error) {
	c.requests = append(c.requests, request)
	if request.Permission == c.fail {
		return Decision{}, ErrUnavailable
	}
	return Decision{Allowed: request.Permission != c.deny, ModelID: c.model}, nil
}

// The permissions of one resource are decided between one pair of revision
// reads, and the result is what CheckRevision returns for each in turn.
func TestCheckRevisionAll(t *testing.T) {
	revision := projectionFixture().Revision
	revision.Applied = revision.Desired
	requests := func() []CheckRequest {
		var result []CheckRequest
		for _, permission := range []string{"view", "view_audit", "view_compliance"} {
			request := exampleRequest()
			request.Permission = permission
			result = append(result, request)
		}
		return result
	}
	reader := &countingRevisionFixture{value: revision}
	checker := &recordingCheckFixture{model: modelID, deny: "view_audit"}
	checked, err := CheckRevisionAll(context.Background(), reader, checker, requests(), storeID, modelID)
	if err != nil || len(checked) != 3 || reader.calls != 2 || len(checker.requests) != 3 {
		t.Fatalf("checked=%d reads=%d checks=%d err=%v", len(checked), reader.calls, len(checker.requests), err)
	}
	for n, request := range requests() {
		single, err := CheckRevision(context.Background(), revisionFixture{revision}, &recordingCheckFixture{model: modelID, deny: "view_audit"}, request, storeID, modelID)
		if err != nil || checked[n] != single || checker.requests[n] != request {
			t.Fatalf("decision %d = %+v, CheckRevision = %+v (%v)", n, checked[n], single, err)
		}
	}
	if !checked[0].Decision.Allowed || checked[1].Decision.Allowed || !checked[2].Decision.Allowed {
		t.Fatalf("decisions = %+v", checked)
	}

	pending := revision
	pending.Applied--
	checker = &recordingCheckFixture{model: modelID}
	if checked, err = CheckRevisionAll(context.Background(), &countingRevisionFixture{value: pending}, checker, requests(), storeID, modelID); !errors.Is(err, ErrPending) || checked != nil || len(checker.requests) != 0 {
		t.Fatalf("pending projection was usable: %v %v", checked, err)
	}
	if checked, err = CheckRevisionAll(context.Background(), &countingRevisionFixture{value: revision}, &recordingCheckFixture{model: modelID}, requests(), storeID, "01K00000000000000000000009"); !errors.Is(err, ErrPending) || checked != nil {
		t.Fatalf("another active model was usable: %v %v", checked, err)
	}
	// The revision advanced after the first read: no decision is returned.
	if checked, err = CheckRevisionAll(context.Background(), &countingRevisionFixture{value: revision, advance: 2}, &recordingCheckFixture{model: modelID}, requests(), storeID, modelID); !errors.Is(err, ErrConflict) || checked != nil {
		t.Fatalf("revision changed during the checks was allowed: %v %v", checked, err)
	}
	if checked, err = CheckRevisionAll(context.Background(), &countingRevisionFixture{value: revision}, &recordingCheckFixture{model: "01K00000000000000000000009"}, requests(), storeID, modelID); !errors.Is(err, ErrConflict) || checked != nil {
		t.Fatalf("decision of another model was allowed: %v %v", checked, err)
	}
	if checked, err = CheckRevisionAll(context.Background(), &countingRevisionFixture{value: revision}, &recordingCheckFixture{model: modelID, fail: "view_compliance"}, requests(), storeID, modelID); !errors.Is(err, ErrUnavailable) || checked != nil {
		t.Fatalf("failed check was allowed: %v %v", checked, err)
	}
	for _, fail := range []int{1, 2} {
		if checked, err = CheckRevisionAll(context.Background(), &countingRevisionFixture{value: revision, fail: fail}, &recordingCheckFixture{model: modelID}, requests(), storeID, modelID); !errors.Is(err, ErrUnavailable) || checked != nil {
			t.Fatalf("failed revision read %d was allowed: %v %v", fail, checked, err)
		}
	}
	foreign := requests()
	foreign[2].OrganizationID = "pid_90000009-0000-4000-8000-000000000009"
	checker = &recordingCheckFixture{model: modelID}
	if checked, err = CheckRevisionAll(context.Background(), &countingRevisionFixture{value: revision}, checker, foreign, storeID, modelID); !errors.Is(err, ErrInvalid) || checked != nil || len(checker.requests) != 0 {
		t.Fatalf("requests of two organizations were checked: %v %v", checked, err)
	}
	if _, err = CheckRevisionAll(context.Background(), &countingRevisionFixture{value: revision}, checker, nil, storeID, modelID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty request set: %v", err)
	}
}
