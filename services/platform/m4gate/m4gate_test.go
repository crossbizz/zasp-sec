package m4gate

import "testing"

func TestEvaluateRequiresAllFiveEvidenceStages(t *testing.T) {
	report, err := Evaluate(Fixture{Inventory: true, Capability: true, Posture: true, AttackPath: true, ExposureUX: true})
	if err != nil || report.Status != "PASS" || report.Checks != 5 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if _, err := Evaluate(Fixture{Inventory: true, Capability: true, Posture: true, AttackPath: true}); err == nil {
		t.Fatal("incoherent fixture passed")
	}
}
