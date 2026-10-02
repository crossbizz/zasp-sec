package securityagent

import "github.com/zasp-ai/zasp-sec/services/platform/domain"

const (
	release61MaximumDefinitionVersion = int64(1_000_000)
	release61MaximumAICostNanoCredits = int64(1_000_000_000_000)
)

// ExistingTestReference pins the exact existing-test definition selected by an
// operator. It records intent only; durable admission must still re-authorize
// the referenced definition in the requester's tenant and environment.
type ExistingTestReference struct {
	DefinitionID      string
	DefinitionVersion int64
}

// Release61DefinitionFamilyInput contains the public definition fields that
// distinguish the reviewed ordered family from every legacy definition.
type Release61DefinitionFamilyInput struct {
	Definition           SecurityAgent
	ExistingTest         *ExistingTestReference
	MaxAICostNanoCredits int64
}

// IsRelease61OrderedDefinitionFamily classifies only the reviewed disabled
// create_temporary_policy -> run_test draft. Classification does not make
// either action available and does not replace durable admission checks.
func IsRelease61OrderedDefinitionFamily(value Release61DefinitionFamilyInput) bool {
	definition := value.Definition
	if ValidateAgent(definition) != nil || definition.Enabled || !definition.DeletedAt.IsZero() ||
		definition.Autonomy != AutonomySupervised || definition.Limits.MaxSteps != 2 ||
		definition.Verification.Kind != "test_run" || definition.DefinitionVersion > int(release61MaximumDefinitionVersion) ||
		len(definition.Scope.EnvironmentIDs) != 1 ||
		len(definition.AllowedActions) != 2 ||
		definition.AllowedActions[0] != "create_temporary_policy" || definition.AllowedActions[1] != "run_test" ||
		!release61DefinitionTrigger(definition.Trigger) ||
		value.MaxAICostNanoCredits < 1 || value.MaxAICostNanoCredits > release61MaximumAICostNanoCredits {
		return false
	}
	if _, err := domain.ParseProductID(definition.Scope.EnvironmentIDs[0]); err != nil {
		return false
	}

	reference := value.ExistingTest
	if reference == nil || reference.DefinitionVersion < 1 || reference.DefinitionVersion > release61MaximumDefinitionVersion ||
		reference.DefinitionID == definition.Scope.EnvironmentIDs[0] {
		return false
	}
	_, err := domain.ParseProductID(reference.DefinitionID)
	return err == nil
}

func release61DefinitionTrigger(value Trigger) bool {
	switch value.Kind {
	case "finding":
		return bounded(value.Source, 64)
	case "attack_path":
		return value.Source == "observed" || value.Source == "verified"
	default:
		return false
	}
}
