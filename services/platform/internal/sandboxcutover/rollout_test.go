package sandboxcutover

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type queryObservationFixture struct {
	observation Observation
	err         error
	calls       int
	after       func()
}

func (q *queryObservationFixture) ObserveQuery(ctx context.Context, _ ReleaseBinding) (Observation, error) {
	q.calls++
	if q.after != nil {
		q.after()
	}
	return q.observation, q.err
}

func TestCutoverRolloutRefusesUnprovenCompletion(t *testing.T) {
	for _, fault := range []string{"digest", "future", "expired", "uid", "template", "resource-version", "audit", "duplicate-progressing", "malformed-progressing", "final-cancellation", "final-expiry"} {
		t.Run(fault, func(t *testing.T) {
			f := newKubeFixture(t)
			client := f.client(t)
			audit := f.audit()
			state, err := client.DispatchQuery(context.Background(), f.config.Binding, f.old(), audit)
			if err != nil {
				t.Fatal(err)
			}
			metadata := f.deployment["metadata"].(map[string]any)
			metadata["generation"] = 2
			status := map[string]any{"observedGeneration": 2}
			f.deployment["status"] = status
			observer := &queryObservationFixture{observation: Observation{time.Now(), strings.Repeat("f", 64), state.API}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var finalRead atomic.Bool
			switch fault {
			case "digest":
				observer.observation.IdentityDigest = ""
			case "future":
				observer.observation.ObservedAt = time.Now().Add(time.Hour)
			case "expired":
				observer.observation.ObservedAt = time.Now().Add(-time.Minute)
			case "uid":
				observer.observation.API.UID = "foreign-api"
			case "template":
				observer.observation.API.TemplateDigest = f.config.Binding.From.APITemplateDigest
			case "resource-version":
				observer.after = func() { f.mu.Lock(); defer f.mu.Unlock(); metadata["resourceVersion"] = "newer-version" }
			case "audit":
				observer.after = func() {
					f.mu.Lock()
					defer f.mu.Unlock()
					metadata["annotations"].(map[string]any)[auditPrefix+"transition-id"] = "another-transition"
				}
			case "duplicate-progressing":
				condition := map[string]any{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}
				status["conditions"] = []any{condition, condition}
			case "malformed-progressing":
				status["conditions"] = []any{map[string]any{"type": "Progressing", "status": false, "reason": "ProgressDeadlineExceeded"}}
			case "final-cancellation", "final-expiry":
				original := f.server.Config.Handler
				var reads atomic.Int32
				f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/deployments/") {
						if reads.Add(1) == 2 {
							finalRead.Store(true)
							if fault == "final-cancellation" {
								cancel()
							} else {
								time.Sleep(1100 * time.Millisecond)
							}
						}
					}
					original.ServeHTTP(w, r)
				})
				if fault == "final-expiry" {
					observer.observation.ObservedAt = time.Now().Add(-29 * time.Second)
				}
			}
			result := ReconcileSandboxQueryRollout(ctx, f.config.Binding, audit, client, observer)
			if result.Outcome != Applied || result.Rollout != Pending || f.patches != 1 {
				t.Fatal("unproven rollout credited", result, f.patches)
			}
			if (fault == "final-cancellation" || fault == "final-expiry") && !finalRead.Load() {
				t.Fatal("test did not reach final reconciliation")
			}
		})
	}
}

func TestCutoverRolloutSeparatesAppliedOutcomesWithoutAnotherWrite(t *testing.T) {
	for _, outcome := range []string{"complete", "pending", "failed", "stale-failure"} {
		t.Run(outcome, func(t *testing.T) {
			f := newKubeFixture(t)
			client := f.client(t)
			audit := f.audit()
			state, err := client.DispatchQuery(context.Background(), f.config.Binding, f.old(), audit)
			if err != nil {
				t.Fatal(err)
			}
			f.deployment["metadata"].(map[string]any)["generation"] = 2
			status := map[string]any{"observedGeneration": 2}
			f.deployment["status"] = status
			observer := &queryObservationFixture{observation: Observation{time.Now(), strings.Repeat("f", 64), state.API}}
			want := Complete
			if outcome == "pending" {
				observer.err = errors.New("old replica still present")
				want = Pending
			}
			if outcome == "failed" || outcome == "stale-failure" {
				status["conditions"] = []any{map[string]any{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}}
				want = Failed
				if outcome == "stale-failure" {
					status["observedGeneration"] = 1
					want = Pending
				}
			}
			result := ReconcileSandboxQueryRollout(context.Background(), f.config.Binding, audit, client, observer)
			if result.Outcome != Applied || result.Rollout != want || result.Audit != audit || f.patches != 1 {
				t.Fatal("rollout changed dispatch or misclassified outcome", result, f.patches)
			}
		})
	}
}

func TestCutoverRolloutUnknownTransitionRemainsIndeterminate(t *testing.T) {
	for _, fault := range []string{"audit", "uid", "missing"} {
		t.Run(fault, func(t *testing.T) {
			f := newKubeFixture(t)
			client := f.client(t)
			audit := f.audit()
			if _, err := client.DispatchQuery(context.Background(), f.config.Binding, f.old(), audit); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "audit":
				audit.TransitionID = "not-this-transition"
			case "uid":
				f.deployment["metadata"].(map[string]any)["uid"] = "replacement-api"
			case "missing":
				original := f.server.Config.Handler
				f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.Contains(r.URL.Path, "/deployments/") {
						w.WriteHeader(404)
						return
					}
					original.ServeHTTP(w, r)
				})
			}
			observer := &queryObservationFixture{}
			result := ReconcileSandboxQueryRollout(context.Background(), f.config.Binding, audit, client, observer)
			if result.Outcome != Indeterminate || result.Rollout != Pending || observer.calls != 0 || f.patches != 1 || result.ResultResourceVersion != "" {
				t.Fatal("unobserved transition credited", result, observer.calls, f.patches)
			}
		})
	}
}
