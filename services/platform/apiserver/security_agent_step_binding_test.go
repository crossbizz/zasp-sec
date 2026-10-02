package apiserver

import (
	"encoding/json"
	"testing"
)

// Replacing a one-to-one binding with map overwrite or repeated lookup must
// fail these repository-boundary cases, even when both arrays have equal length.
func TestSecurityAgentRunDetailRequiresUniqueStepBindings(t *testing.T) {
	for _, kind := range []string{"distinct", "duplicate plan", "duplicate execution"} {
		t.Run(kind, func(t *testing.T) {
			detail := runContextDetailFixture(t, "")
			secondPlan := detail.Plan.Steps[0]
			secondPlan.ID = "pid_78000008-0000-4000-8000-000000000008"
			secondPlan.Index = 1
			secondExecution := detail.Execution[0]
			secondExecution.StepID = secondPlan.ID
			detail.Plan.Steps = append(detail.Plan.Steps, secondPlan)
			detail.Execution = append(detail.Execution, secondExecution)
			switch kind {
			case "duplicate plan":
				detail.Plan.Steps[1].ID = detail.Plan.Steps[0].ID
				detail.Execution[1].StepID = detail.Execution[0].StepID
			case "duplicate execution":
				detail.Execution[1].StepID = detail.Execution[0].StepID
			}
			payload, err := json.Marshal(detail)
			if err != nil {
				t.Fatal(err)
			}
			got, err := decodeSecurityAgentStoredRunDetail(payload, runContextTestRunID)
			if kind == "distinct" {
				if err != nil || len(got.Execution) != 2 || got.Execution[1].StepID != "pid_78000008-0000-4000-8000-000000000008" {
					t.Fatal("distinct persisted steps were not preserved")
				}
			} else if err != ErrRepositoryUnavailable || got.Run.ID != "" {
				t.Fatal("ambiguous step binding escaped the repository boundary")
			}
		})
	}
}
