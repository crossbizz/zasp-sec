package securityagent

import (
	"reflect"
	"testing"
	"time"
)

const (
	release61EnvironmentID  = "pid_70000003-0000-4000-8000-000000000003"
	release61ExistingTestID = "pid_89800001-0000-4000-8000-000000000001"
)

// A mutation of any closed family field must make this classifier reject it.
func TestRelease61DefinitionFamilyClassifierClosedContract(t *testing.T) {
	cases := map[string]func(*Release61DefinitionFamilyInput){
		"exact family": func(*Release61DefinitionFamilyInput) {},
		"reversed actions": func(v *Release61DefinitionFamilyInput) {
			v.Definition.AllowedActions = []string{"run_test", "create_temporary_policy"}
		},
		"duplicate actions": func(v *Release61DefinitionFamilyInput) {
			v.Definition.AllowedActions = []string{"create_temporary_policy", "create_temporary_policy"}
		},
		"singleton actions": func(v *Release61DefinitionFamilyInput) {
			v.Definition.AllowedActions = []string{"create_temporary_policy"}
		},
		"partial actions": func(v *Release61DefinitionFamilyInput) {
			v.Definition.AllowedActions = []string{"create_temporary_policy", ""}
		},
		"superset actions": func(v *Release61DefinitionFamilyInput) {
			v.Definition.AllowedActions = []string{"create_temporary_policy", "run_test", "isolate_session"}
		},
		"autonomous":         func(v *Release61DefinitionFamilyInput) { v.Definition.Autonomy = AutonomyAutonomous },
		"other autonomy":     func(v *Release61DefinitionFamilyInput) { v.Definition.Autonomy = Autonomy("manual") },
		"wrong verification": func(v *Release61DefinitionFamilyInput) { v.Definition.Verification.Kind = "policy_state" },
		"wrong step count":   func(v *Release61DefinitionFamilyInput) { v.Definition.Limits.MaxSteps = 1 },
		"zero environments":  func(v *Release61DefinitionFamilyInput) { v.Definition.Scope.EnvironmentIDs = nil },
		"multiple environments": func(v *Release61DefinitionFamilyInput) {
			v.Definition.Scope.EnvironmentIDs = []string{release61EnvironmentID, "pid_70000004-0000-4000-8000-000000000004"}
		},
		"malformed environment target": func(v *Release61DefinitionFamilyInput) {
			v.Definition.Scope.EnvironmentIDs = []string{"environment-a"}
		},
		"absent existing test": func(v *Release61DefinitionFamilyInput) { v.ExistingTest = nil },
		"missing reference":    func(v *Release61DefinitionFamilyInput) { v.ExistingTest.DefinitionID = "" },
		"malformed existing test target": func(v *Release61DefinitionFamilyInput) {
			v.ExistingTest.DefinitionID = "test-a"
		},
		"unpinned existing test": func(v *Release61DefinitionFamilyInput) { v.ExistingTest.DefinitionVersion = 0 },
		"negative test version":  func(v *Release61DefinitionFamilyInput) { v.ExistingTest.DefinitionVersion = -1 },
		"excess test version":    func(v *Release61DefinitionFamilyInput) { v.ExistingTest.DefinitionVersion = 1_000_001 },
		"absent cost ceiling":    func(v *Release61DefinitionFamilyInput) { v.MaxAICostNanoCredits = 0 },
		"negative cost ceiling":  func(v *Release61DefinitionFamilyInput) { v.MaxAICostNanoCredits = -1 },
		"excess cost ceiling":    func(v *Release61DefinitionFamilyInput) { v.MaxAICostNanoCredits = 1_000_000_000_001 },
		"enabled input":          func(v *Release61DefinitionFamilyInput) { v.Definition.Enabled = true },
		"wrong trigger": func(v *Release61DefinitionFamilyInput) {
			v.Definition.Trigger = Trigger{Kind: "runtime_decision", Source: "block"}
		},
		"wrong attack path source": func(v *Release61DefinitionFamilyInput) {
			v.Definition.Trigger = Trigger{Kind: "attack_path", Source: "potential"}
		},
		"wrong target": func(v *Release61DefinitionFamilyInput) { v.ExistingTest.DefinitionID = release61EnvironmentID },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value := release61DefinitionFamilyFixture()
			mutate(&value)
			if got := IsRelease61OrderedDefinitionFamily(value); got != (name == "exact family") {
				t.Fatalf("classified=%v", got)
			}
		})
	}

	for _, source := range []string{"observed", "verified"} {
		t.Run("attack path "+source, func(t *testing.T) {
			value := release61DefinitionFamilyFixture()
			value.Definition.Trigger = Trigger{Kind: "attack_path", Source: source}
			if !IsRelease61OrderedDefinitionFamily(value) {
				t.Fatal("reviewed attack-path trigger rejected")
			}
		})
	}
}

func TestRelease61DefinitionFamilyClassifierDeterministicAndPanicFree(t *testing.T) {
	if IsRelease61OrderedDefinitionFamily(Release61DefinitionFamilyInput{}) {
		t.Fatal("zero input classified as release-61")
	}
	value := release61DefinitionFamilyFixture()
	before := release61DefinitionFamilyFixture()
	for range 100 {
		if !IsRelease61OrderedDefinitionFamily(value) {
			t.Fatal("same input produced a different classification")
		}
	}
	if !reflect.DeepEqual(value, before) {
		t.Fatalf("classifier mutated input: got=%#v want=%#v", value, before)
	}
}

func TestRelease61DefinitionFamilyKeepsActionReadinessClosed(t *testing.T) {
	if !ProductionActionAvailable("create_temporary_policy", AutonomySupervised) {
		t.Fatal("existing supervised temporary-policy readiness changed")
	}
	if ProductionActionAvailable("create_temporary_policy", AutonomyAutonomous) {
		t.Fatal("existing temporary-policy autonomy widened")
	}
	if ProductionActionAvailable("run_test", AutonomySupervised) || ProductionActionAvailable("run_test", AutonomyAutonomous) {
		t.Fatal("run_test became generally production-available")
	}
	value := release61DefinitionFamilyFixture()
	value.Definition.AllowedActions = []string{"run_test"}
	value.Definition.Limits.MaxSteps = 1
	if IsRelease61OrderedDefinitionFamily(value) {
		t.Fatal("single run_test classified as the ordered family")
	}
}

func release61DefinitionFamilyFixture() Release61DefinitionFamilyInput {
	return Release61DefinitionFamilyInput{
		Definition: SecurityAgent{
			ID:             "pid_70000004-0000-4000-8000-000000000004",
			OrganizationID: "pid_70000001-0000-4000-8000-000000000001",
			Name:           "Contain and retest",
			Trigger:        Trigger{Kind: "finding", Source: "credential"},
			Scope: Scope{
				OrganizationID: "pid_70000001-0000-4000-8000-000000000001",
				EnvironmentIDs: []string{release61EnvironmentID},
			},
			Autonomy: AutonomySupervised,
			Limits: RunLimits{
				MaxSteps:           2,
				MaxDuration:        time.Hour,
				TemporaryPolicyTTL: 10 * time.Minute,
				MaxAITokens:        4_000,
				MaxConcurrent:      2,
			},
			AllowedActions:    []string{"create_temporary_policy", "run_test"},
			Verification:      Verification{Kind: "test_run"},
			DefinitionVersion: 3,
			Enabled:           false,
		},
		ExistingTest:         &ExistingTestReference{DefinitionID: release61ExistingTestID, DefinitionVersion: 7},
		MaxAICostNanoCredits: 10_000_000,
	}
}
