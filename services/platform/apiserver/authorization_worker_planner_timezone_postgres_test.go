package apiserver

import "testing"

// These consuming cases fail when copied74/78 validators compare timestamps
// as session-local strings, or recovery changes captured accounting/evidence.
// Admission, provider transport and recovery remain the existing real fixture.
func TestWorkerPlannerTimezoneConsumersPostgres(t *testing.T) {
	for _, family := range []string{"test74", "finding78"} {
		for _, phase := range []string{"planning-prepared-revoke", "planning-sent-revoke", "planning-sent-late"} {
			t.Run(family+"/"+phase, func(t *testing.T) {
				if family == "test74" {
					runWorkerTest74PlanningFixture(t, "product-"+phase+"-timezone")
				} else {
					runWorkerFindingPlanningProductFixture(t, phase+"-timezone")
				}
			})
		}
	}
}
