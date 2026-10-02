package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type orderedListLegacy struct {
	runs      map[string]SecurityAgentRun
	approvals map[string]SecurityAgentApproval
	calls     int
	err       error
}

func (l *orderedListLegacy) GetSecurityAgentRun(_ context.Context, _ RequestIdentity, id string) (SecurityAgentRunDetail, error) {
	l.calls++
	return SecurityAgentRunDetail{Run: l.runs[id]}, l.err
}
func (l *orderedListLegacy) GetSecurityAgentApproval(_ context.Context, _ RequestIdentity, id string) (SecurityAgentApproval, error) {
	l.calls++
	return l.approvals[id], l.err
}

func orderedListPage(id RequestIdentity, op string, ids ...string) map[string]any {
	items := []any{}
	for _, rid := range ids {
		items = append(items, map[string]any{"id": rid, "created_at": "2026-09-20T00:00:00.000000Z"})
	}
	return map[string]any{"contract_version": 62, "organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "operation": op, "items": items, "next_created_at": "", "next_id": ""}
}

func orderedListAuthority(t *testing.T, id RequestIdentity, page map[string]any, family string, fixture any) (*SecurityAgentOrderedResourceAuthority, *orderedPublicDB) {
	t.Helper()
	db := &orderedPublicDB{query: func(_ context.Context, _ string, args ...any) (json.RawMessage, error) {
		var q map[string]any
		_ = json.Unmarshal(args[2].(json.RawMessage), &q)
		switch q["operation"] {
		case "run_candidates", "approval_candidates":
			return json.Marshal(page)
		case "classify":
			return json.Marshal(map[string]any{"contract_version": 62, "resource_kind": q["resource_kind"], "resource_id": q["resource_id"], "family": family})
		case "resource_run", "resource_approval":
			return json.Marshal(fixture)
		default:
			t.Fatalf("unexpected operation (prototype list forbidden): %v", q)
		}
		return nil, errors.New("unexpected")
	}}
	a, _ := NewSecurityAgentOrderedResourceAuthority(db)
	return a, db
}

// Regression: the private router must serve the two list routes through its
// isolated list authority rather than rejecting or delegating a candidate page.
func TestSecurityAgentOrderedListEmptyHTTP(t *testing.T) {
	for _, op := range []string{"listSecurityAgentRuns", "listSecurityAgentApprovals"} {
		candidateOp := "run_candidates"
		if op == "listSecurityAgentApprovals" {
			candidateOp = "approval_candidates"
		}
		a, db := orderedListAuthority(t, orderedPublicIdentity(), orderedListPage(orderedPublicIdentity(), candidateOp), "legacy_or_missing", nil)
		h := orderedHTTPHandler(t, a, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("list delegated") }))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, orderedHTTPRequest(orderedPublicIdentity(), op, "GET", "", ""))
		if w.Code != 200 || w.Body.String() != "{\"items\":[]}\n" || db.calls != 1 {
			t.Fatalf("%s: %d %s calls=%d", op, w.Code, w.Body.String(), db.calls)
		}
	}
}

// These failures catch duplicate/foreign/misordered pages and leaking a partial
// result when a later candidate cannot be safely projected.
func TestSecurityAgentOrderedListBoundary(t *testing.T) {
	id := orderedPublicIdentity()
	for name, change := range map[string]func(map[string]any){
		"duplicate":      func(p map[string]any) { p["items"] = append(p["items"].([]any), p["items"].([]any)[0]) },
		"foreign-scope":  func(p map[string]any) { p["environment_id"] = public62Finding },
		"bad-id":         func(p map[string]any) { p["items"].([]any)[0].(map[string]any)["id"] = "private" },
		"partial-cursor": func(p map[string]any) { p["next_id"] = public62Definition },
		"wrong-cursor": func(p map[string]any) {
			p["next_id"] = public62Finding
			p["next_created_at"] = "2026-09-20T00:00:00.000000Z"
		},
		"short-with-cursor": func(p map[string]any) {
			p["next_id"] = public62Definition
			p["next_created_at"] = "2026-09-20T00:00:00.000000Z"
		},
		"private-field": func(p map[string]any) { p["worker_id"] = "secret" },
		"timestamp": func(p map[string]any) {
			p["items"].([]any)[0].(map[string]any)["created_at"] = "2026-09-20T00:00:00+00:00"
		},
		"ascending-id": func(p map[string]any) {
			p["items"] = append(p["items"].([]any), map[string]any{"id": public62Finding, "created_at": "2026-09-20T00:00:00.000000Z"})
		},
		"ascending-time": func(p map[string]any) {
			p["items"] = append(p["items"].([]any), map[string]any{"id": public62Finding, "created_at": "2026-09-20T00:00:01.000000Z"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := orderedListPage(id, "run_candidates", public62Definition)
			change(p)
			a, _ := orderedListAuthority(t, id, p, "legacy_or_missing", nil)
			h := orderedHTTPHandler(t, a, http.NotFoundHandler())
			w := httptest.NewRecorder()
			h.ServeHTTP(w, orderedHTTPRequest(id, "listSecurityAgentRuns", "GET", "", ""))
			if w.Code != 503 || strings.Contains(w.Body.String(), "secret") {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}

func TestSecurityAgentOrderedListProjection(t *testing.T) {
	id := orderedPublicIdentity()
	for _, family := range []string{"legacy_or_missing", "ordered_release61"} {
		for _, bearer := range []bool{false, true} {
			t.Run(family+map[bool]string{false: "/browser", true: "/bearer"}[bearer], func(t *testing.T) {
				identity := id
				if bearer {
					identity.CredentialKind = CredentialBearerToken
				}
				p := orderedListPage(identity, "run_candidates", public62Definition)
				a, _ := orderedListAuthority(t, identity, p, family, orderedResourceFixture(identity, public62Definition, false))
				run := SecurityAgentRun{ID: public62Definition, AgentID: public62Definition, State: "queued", EvidenceIDs: []string{public62Finding}, DefinitionVersion: 2, Version: 1}
				legacy := &orderedListLegacy{runs: map[string]SecurityAgentRun{public62Definition: run}}
				h, err := newSecurityAgentOrderedHTTPHandler(a, legacy, func() (http.Handler, error) { return http.NotFoundHandler(), nil }, []byte(strings.Repeat("k", 32)))
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, orderedHTTPRequest(identity, "listSecurityAgentRuns", "GET", "", ""))
				if bearer && family == "ordered_release61" {
					if w.Code != 400 || legacy.calls != 0 {
						t.Fatal(w.Code, legacy.calls)
					}
					return
				}
				var out struct {
					Items []SecurityAgentRun `json:"items"`
				}
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Items) != 1 || out.Items[0].ID != public62Definition {
					t.Fatal(w.Code, w.Body.String())
				}
				if family == "legacy_or_missing" && !reflect.DeepEqual(out.Items[0], run) {
					t.Fatal(out)
				}
			})
		}
	}
}

func TestSecurityAgentOrderedListCandidateValidation(t *testing.T) {
	id := orderedPublicIdentity()
	validBefore := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		op, filter, state string
		limit             int
		before            time.Time
		beforeID          string
	}{
		{"list", "", "", 10, time.Time{}, ""}, {"run_candidates", "bad", "", 10, time.Time{}, ""}, {"run_candidates", "", "pending", 10, time.Time{}, ""}, {"approval_candidates", "", "running", 10, time.Time{}, ""}, {"run_candidates", "", "", 0, time.Time{}, ""}, {"run_candidates", "", "", 101, time.Time{}, ""}, {"run_candidates", "", "", 10, validBefore, ""}, {"run_candidates", "", "", 10, time.Time{}, public62Definition},
	} {
		a, db := orderedListAuthority(t, id, orderedListPage(id, "run_candidates"), "legacy_or_missing", nil)
		_, err := a.candidates(context.Background(), id, tc.op, tc.filter, tc.state, tc.limit, tc.before, tc.beforeID)
		if err != ErrRepositoryOperation || db.calls != 0 {
			t.Fatal(tc, err, db.calls)
		}
	}
	for _, kind := range []CredentialKind{CredentialBrowserSession, CredentialBearerToken} {
		id.CredentialKind = kind
		db := &orderedPublicDB{query: func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
			if sql != securityAgentPublicSQL || len(args) != 3 || args[0] != migrations.ProductionSecurityAgentPublic().Checksum() || args[1] != migrations.SecurityAgentPublicFingerprint() {
				t.Fatal(sql, args)
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 5*time.Second {
				t.Fatal("unbounded query")
			}
			var q map[string]any
			_ = json.Unmarshal(args[2].(json.RawMessage), &q)
			if len(q) != 10 || q["actor_id"] != id.PrincipalID.String() || q["resource_filter"] != public62Finding || q["before_created_at"] != "2026-09-21T00:00:00.000000Z" || q["before_id"] != public62Finding || q["limit"] != float64(100) {
				t.Fatal(q)
			}
			return json.Marshal(orderedListPage(id, "run_candidates", public62Definition))
		}}
		a, _ := NewSecurityAgentOrderedResourceAuthority(db)
		if _, err := a.candidates(context.Background(), id, "run_candidates", public62Finding, "queued", 100, validBefore, public62Finding); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSecurityAgentOrderedListMixedAndCursor(t *testing.T) {
	id := orderedPublicIdentity()
	const legacyID = "pid_ffffffff-ffff-4fff-8fff-fffffffffff1"
	legacyRun := SecurityAgentRun{ID: legacyID, AgentID: public62Finding, State: "queued", EvidenceIDs: []string{public62Finding}, DefinitionVersion: 1, Version: 1}
	page := orderedListPage(id, "run_candidates", legacyID, public62Definition)
	page["next_created_at"], page["next_id"] = "2026-09-20T00:00:00.000000Z", public62Definition
	db := &orderedPublicDB{query: func(_ context.Context, _ string, args ...any) (json.RawMessage, error) {
		var q map[string]any
		_ = json.Unmarshal(args[2].(json.RawMessage), &q)
		switch q["operation"] {
		case "run_candidates":
			return json.Marshal(page)
		case "classify":
			family := "legacy_or_missing"
			if q["resource_id"] == public62Definition {
				family = "ordered_release61"
			}
			return json.Marshal(map[string]any{"contract_version": 62, "resource_kind": "run", "resource_id": q["resource_id"], "family": family})
		case "resource_run":
			return json.Marshal(orderedResourceFixture(id, public62Definition, false))
		default:
			t.Fatal(q)
		}
		return nil, nil
	}}
	a, _ := NewSecurityAgentOrderedResourceAuthority(db)
	legacy := &orderedListLegacy{runs: map[string]SecurityAgentRun{legacyID: legacyRun}}
	h, _ := newSecurityAgentOrderedHTTPHandler(a, legacy, func() (http.Handler, error) { return http.NotFoundHandler(), nil }, []byte(strings.Repeat("k", 32)))
	r := orderedHTTPRequest(id, "listSecurityAgentRuns", "GET", "", "")
	r.URL.RawQuery = "limit=2"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var got struct {
		Items []SecurityAgentRun `json:"items"`
		Next  string             `json:"next_cursor"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || len(got.Items) != 2 || got.Items[0].ID != legacyID || got.Items[1].ID != public62Definition || got.Next == "" || legacy.calls != 1 {
		t.Fatal(w.Code, w.Body.String(), legacy.calls)
	}
	for _, query := range []string{"limit=3&cursor=" + got.Next, "limit=2&status=queued&cursor=" + got.Next, "limit=2&cursor=" + got.Next + "x", "limit=0", "limit=101", "limit=2&limit=2", "bogus=1", "cursor="} {
		r := orderedHTTPRequest(id, "listSecurityAgentRuns", "GET", "", "")
		r.URL.RawQuery = query
		w := httptest.NewRecorder()
		calls := db.calls
		h.ServeHTTP(w, r)
		if w.Code != 400 || db.calls != calls {
			t.Fatal(query, w.Code, db.calls, calls)
		}
	}
}

func TestSecurityAgentOrderedListErrorsAndChanges(t *testing.T) {
	id := orderedPublicIdentity()
	for _, stage := range []string{"candidate", "classify", "projection", "changed-family", "wrong-filter", "wrong-id", "wrong-time", "cancelled"} {
		t.Run(stage, func(t *testing.T) {
			classifications := 0
			db := &orderedPublicDB{query: func(ctx context.Context, _ string, args ...any) (json.RawMessage, error) {
				var q map[string]any
				_ = json.Unmarshal(args[2].(json.RawMessage), &q)
				switch q["operation"] {
				case "run_candidates":
					if stage == "candidate" {
						return nil, errors.New("private SQL")
					}
					return json.Marshal(orderedListPage(id, "run_candidates", public62Definition))
				case "classify":
					classifications++
					if stage == "classify" {
						return nil, context.DeadlineExceeded
					}
					family := "ordered_release61"
					if stage == "changed-family" && classifications > 2 {
						family = "legacy_or_missing"
					}
					return json.Marshal(map[string]any{"contract_version": 62, "resource_kind": "run", "resource_id": q["resource_id"], "family": family})
				case "resource_run":
					if stage == "projection" {
						return nil, ErrRepositoryConflict
					}
					fixture := orderedResourceFixture(id, public62Definition, false)
					if stage == "wrong-id" {
						fixture["ordered"].(map[string]any)["run_id"] = public62Finding
					}
					if stage == "wrong-time" {
						fixture["created_at"] = "2026-09-20T00:00:01Z"
					}
					return json.Marshal(fixture)
				}
				t.Fatal(q)
				return nil, nil
			}}
			a, _ := NewSecurityAgentOrderedResourceAuthority(db)
			h := orderedHTTPHandler(t, a, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("fallback") }))
			r := orderedHTTPRequest(id, "listSecurityAgentRuns", "GET", "", "")
			if stage == "wrong-filter" {
				r.URL.RawQuery = "status=running"
			}
			if stage == "cancelled" {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || strings.Contains(w.Body.String(), "private SQL") || strings.Contains(w.Body.String(), "\"items\"") {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}

func TestSecurityAgentOrderedListContextCompatibility(t *testing.T) {
	for _, raw := range []string{`{"id":"one","state":"pending"}`, `{"id":"one","approval_context":{"nested":[1,2]},"state":"pending"}`} {
		if got := string(orderedListWithoutContext([]byte(raw))); got != `{"id":"one","state":"pending"}` {
			t.Fatal(got)
		}
	}
}

func TestSecurityAgentOrderedListLegacyApprovalBytes(t *testing.T) {
	id := orderedPublicIdentity()
	expiry := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	approval := SecurityAgentApproval{ID: public62Definition, RunID: public62Finding, StepID: "pid_01000001-0000-4000-8000-000000000001", State: "pending", ExpiresAt: expiry, Version: 1, ExpectedEffect: "Move finding to under review", Reversible: true, EvidenceSummary: []string{public62Finding}}
	for _, header := range []string{"", "v1", "v2"} {
		a, _ := orderedListAuthority(t, id, orderedListPage(id, "approval_candidates", public62Definition), "legacy_or_missing", nil)
		legacy := &orderedListLegacy{approvals: map[string]SecurityAgentApproval{public62Definition: approval}}
		h, err := newSecurityAgentOrderedHTTPHandler(a, legacy, func() (http.Handler, error) { return http.NotFoundHandler(), nil }, []byte(strings.Repeat("k", 32)))
		if err != nil {
			t.Fatal(err)
		}
		r := orderedHTTPRequest(id, "listSecurityAgentApprovals", "GET", "", "")
		r.URL.RawQuery = "state=pending&run_id=" + public62Finding
		r.Header.Set("X-Zasp-Approval-Context", header)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want, _ := json.Marshal(map[string]any{"items": []SecurityAgentApproval{approval}})
		if w.Code != 200 || w.Body.String() != string(want)+"\n" || legacy.calls != 1 {
			t.Fatal(w.Code, w.Body.String(), string(want))
		}
	}
}

func TestSecurityAgentOrderedListConstruction(t *testing.T) {
	a, _ := orderedHTTPAuthority(t, "legacy_or_missing", nil, nil)
	factory := func() (http.Handler, error) { return http.NotFoundHandler(), nil }
	for _, l := range []securityAgentLegacyListAuthority{nil, (*orderedListLegacy)(nil)} {
		if h, e := newSecurityAgentOrderedHTTPHandler(a, l, factory, []byte(strings.Repeat("k", 32))); h != nil || e != ErrRepositoryConfiguration {
			t.Fatal(h, e)
		}
	}
	for _, key := range []string{"", strings.Repeat("k", 31), strings.Repeat("k", 4097)} {
		if h, e := newSecurityAgentOrderedHTTPHandler(a, &orderedListLegacy{}, factory, []byte(key)); h != nil || e != ErrRepositoryConfiguration {
			t.Fatal(h, e)
		}
	}
}

func TestSecurityAgentOrderedListCandidateBounds(t *testing.T) {
	id := orderedPublicIdentity()
	for _, n := range []int{1, 100, 101} {
		ids := []string{}
		for i := n; i > 0; i-- {
			ids = append(ids, fmt.Sprintf("pid_%08x-0000-4000-8000-000000000001", i))
		}
		a, _ := orderedListAuthority(t, id, orderedListPage(id, "run_candidates", ids...), "legacy_or_missing", nil)
		page, err := a.candidates(context.Background(), id, "run_candidates", "", "", 100, time.Time{}, "")
		if n <= 100 && (err != nil || len(page.Items) != n) || n > 100 && err != ErrRepositoryUnavailable {
			t.Fatal(n, page, err)
		}
	}
	// A signed cursor does not authorize returning its boundary row again.
	a, _ := orderedListAuthority(t, id, orderedListPage(id, "run_candidates", public62Definition), "legacy_or_missing", nil)
	at, _ := time.Parse(orderedListTimeFormat, "2026-09-20T00:00:00.000000Z")
	if _, err := a.candidates(context.Background(), id, "run_candidates", "", "", 10, at, public62Definition); err != ErrRepositoryUnavailable {
		t.Fatal(err)
	}
}

func TestSecurityAgentOrderedListLegacyReclassified(t *testing.T) {
	id := orderedPublicIdentity()
	classifications := 0
	projections := 0
	db := &orderedPublicDB{query: func(_ context.Context, _ string, args ...any) (json.RawMessage, error) {
		var q map[string]any
		_ = json.Unmarshal(args[2].(json.RawMessage), &q)
		switch q["operation"] {
		case "run_candidates":
			return json.Marshal(orderedListPage(id, "run_candidates", public62Definition))
		case "classify":
			classifications++
			family := "legacy_or_missing"
			if classifications > 1 {
				family = "ordered_release61"
			}
			return json.Marshal(map[string]any{"contract_version": 62, "resource_kind": "run", "resource_id": public62Definition, "family": family})
		default:
			projections++
			return json.Marshal(orderedResourceFixture(id, public62Definition, false))
		}
	}}
	a, _ := NewSecurityAgentOrderedResourceAuthority(db)
	legacy := &orderedListLegacy{runs: map[string]SecurityAgentRun{public62Definition: {ID: public62Definition, AgentID: public62Finding, State: "queued", EvidenceIDs: []string{public62Finding}, DefinitionVersion: 1, Version: 1}}}
	h, _ := newSecurityAgentOrderedHTTPHandler(a, legacy, func() (http.Handler, error) { return http.NotFoundHandler(), nil }, []byte(strings.Repeat("k", 32)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, orderedHTTPRequest(id, "listSecurityAgentRuns", "GET", "", ""))
	if w.Code != 503 || legacy.calls != 1 || projections != 0 || strings.Contains(w.Body.String(), "items") {
		t.Fatal(w.Code, legacy.calls, projections, w.Body.String())
	}
}
