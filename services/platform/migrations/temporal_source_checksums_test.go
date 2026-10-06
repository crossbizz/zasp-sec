package migrations

import "testing"

// A cached or hard-coded checksum would conceal changed SQL from the readiness
// consumer. Every source, including both composed-source fragments, stays live.
func TestTemporalSourceChecksumsObserveSourceChanges(t *testing.T) {
	for _, tc := range []struct {
		name     string
		source   *string
		checksum func() string
	}{
		{"Domain", &temporalDomainBaseSQL, TemporalDomainChecksum},
		{"Executor", &temporalExecutorSQL, TemporalExecutorChecksum},
		{"Workflow", &temporalWorkflowSQL, TemporalWorkflowChecksum},
		{"Compatibility", &temporalCompatibilitySQL, TemporalCompatibilityChecksum},
		{"LegacyTests", &temporalLegacyTestsSQL, TemporalLegacyTestsChecksum},
		{"Discovery", &temporalDiscoverySQL, TemporalDiscoveryChecksum},
		{"Admission", &temporalAdmissionSQL, TemporalAdmissionChecksum},
		{"TestExecutor", &temporalTestExecutorSQL, TemporalTestExecutorChecksum},
		{"TestSelector", &temporalTestSelectorSQL, TemporalTestSelectorChecksum},
		{"HumanAdmission", &temporalHumanAdmissionSQL, TemporalHumanAdmissionChecksum},
		{"ExecutorPlanningFragment", &temporalExecutorPlanningSQL, TemporalExecutorChecksum},
		{"TestExecutorPlanningFragment", &temporalTestPlanningSQL, TemporalTestExecutorChecksum},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := *tc.source
			defer func() { *tc.source = original }()
			before := tc.checksum()
			*tc.source += "\n-- changed source\n"
			if tc.checksum() == before {
				t.Fatal("changed migration source concealed by checksum")
			}
			*tc.source = original
			if tc.checksum() != before {
				t.Fatal("restored source identity changed")
			}
		})
	}
}
