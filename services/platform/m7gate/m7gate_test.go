package m7gate

import "testing"

func TestGateRequiresDegradedSuiteAndSixIndependentFlows(t *testing.T) {
	complete := Evidence{
		DegradedStates: []string{"ai", "connector", "event_index", "graph", "remote_otlp"},
		Session:        true, Compliance: true, DataControl: true,
		SystemHealth: true, AIDegrade: true, UIAPICoverage: true,
	}
	report, err := Evaluate(complete)
	if err != nil || report.Status != "PASS" || report.Checks != 6 || report.DegradedChecks != 5 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	complete.AIDegrade = false
	if _, err := Evaluate(complete); err == nil {
		t.Fatal("gate accepted a missing independent flow")
	}
	complete.AIDegrade = true
	complete.DegradedStates = append(complete.DegradedStates, "connector")
	if _, err := Evaluate(complete); err == nil {
		t.Fatal("gate accepted duplicate degraded-state evidence")
	}
}
