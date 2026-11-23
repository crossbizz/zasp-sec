package sessionintent

import "testing"

func TestOutcomeRequiresMatchingSourceEvidence(t *testing.T) {
	for _, c := range []struct {
		source, class, action, receipt string
		want                           Outcome
	}{
		{"gateway", "policy", "block", "", Prevented},
		{"gateway", "tool", "invoke", "", Unknown},
		{"otlp", "policy", "block", "", Unknown},
		{"tetragon", "network", "connect", "", Unknown},
		{"tetragon", "file", "write", "", Unknown},
		{"tetragon", "runtime", "exec", "", Completed},
		{"authenticated_workload", "tool", "block", "", Unknown},
		{"authenticated_workload", "tool", "allow", "raised", Unknown},
		{"authenticated_workload", "tool", "block", "not_dispatched", Prevented},
		{"authenticated_workload", "tool", "block", "returned", Completed},
	} {
		if got := Evaluate(c.source, c.class, c.action, c.receipt); got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
}
