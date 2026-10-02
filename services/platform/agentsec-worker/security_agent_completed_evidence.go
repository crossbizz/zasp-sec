package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

// These values only come from the parent's guarded, selected native snapshot.
// Artifacts cannot provide their own comparison authority.
type capturedTestEvidence struct {
	Observations []capturedTestObservation
	Receipts     []completedTestReceipt
}
type capturedTestObservation struct {
	Schema           string                               `json:"schema_version"`
	RunID            string                               `json:"run_id"`
	Category         string                               `json:"category"`
	ComparisonDigest string                               `json:"comparison_digest"`
	CredentialDigest string                               `json:"credential_version_digest"`
	Observation      redteamadapter.InvocationObservation `json:"observation"`
}
type verifiedTestCheck struct {
	Category, ComparisonDigest, CredentialDigest string
	HTTPStatus                                   int
	Protected                                    bool
}
type completedTestReceipt struct {
	Organization     string `json:"organization_id"`
	Workspace        string `json:"workspace_id"`
	Environment      string `json:"environment_id"`
	Parent           string `json:"parent_run_id"`
	Run              string `json:"test_run_id"`
	Step             string `json:"step_id"`
	Effect           string `json:"effect_key"`
	Generation       int    `json:"generation"`
	Category         string `json:"category"`
	InputDigest      string `json:"input_digest"`
	RequestDigest    string `json:"request_digest"`
	State            string `json:"state"`
	Attempt          int    `json:"attempt"`
	HTTPStatus       int    `json:"http_status"`
	Protected        *bool  `json:"protected"`
	ResponseDigest   string `json:"response_digest"`
	CredentialDigest string `json:"credential_version_digest"`
	CompletedAt      string `json:"completed_at"`
	ResolutionDigest string `json:"captured_resolution_digest"`
}
type completedTestSummary struct {
	Schema      string   `json:"schema_version"`
	Run         string   `json:"run_id"`
	InputDigest string   `json:"input_digest"`
	Objective   string   `json:"objective"`
	Behavior    string   `json:"behavior"`
	Verdict     string   `json:"verdict"`
	Evidence    []string `json:"evidence"`
}
type completedTestArtifact struct {
	Schema        string                              `json:"schema_version"`
	Run           string                              `json:"run_id"`
	InputDigest   string                              `json:"input_digest"`
	Evaluation    *redTeamEvaluationIdentity          `json:"captured_evaluation_identity"`
	Receipts      []completedTestReceipt              `json:"receipts"`
	Summary       completedTestSummary                `json:"summary"`
	InputArtifact *apiserver.RedTeamArtifactReference `json:"input_artifact,omitempty"`
}

func testComparisonBinding(v *redteamadapter.TargetComparison) string {
	if v == nil {
		return ""
	}
	field := func(s string) string { return strconv.Itoa(len([]byte(s))) + ":" + s }
	categories := field(strconv.Itoa(len(v.Categories)))
	for _, s := range v.Categories {
		categories += field(s)
	}
	s := "zasp-test-comparison-binding-v1"
	for _, v := range []string{v.Schema, v.Organization, v.Workspace, v.Environment, v.Definition, strconv.FormatInt(v.DefinitionVersion, 10), v.Target, v.Kind, categories, v.Safety, v.Endpoint, v.Configuration, v.Credential, strconv.FormatInt(v.CredentialVersion, 10), v.CredentialDigest} {
		s += field(v)
	}
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}
func completedRequestDigest(input redTeamRunnerInput, category string) string {
	wire, _ := json.Marshal(struct {
		Schema   string `json:"schema_version"`
		Run      string `json:"run_id"`
		Target   string `json:"target_id"`
		Kind     string `json:"target_kind"`
		Category string `json:"category"`
		Input    string `json:"input"`
	}{"red-team-target-v1", input.RunID, input.TargetID, input.TargetKind, category, redTeamCuratedPrompt(category)})
	d := sha256.Sum256(wire)
	return hex.EncodeToString(d[:])
}
func validCompletedTestReceipt(input redTeamRunnerInput, r completedTestReceipt, category string) bool {
	for _, id := range []string{r.Parent, r.Step} {
		if !validRecoveryProductID(id) {
			return false
		}
	}
	effect := sha256.Sum256([]byte(strings.Join([]string{"zasp-temporal-effect-v1", input.OrganizationID, input.WorkspaceID, input.EnvironmentID, r.Parent, r.Step, "1"}, "\x1f")))
	if r.Organization != input.OrganizationID || r.Workspace != input.WorkspaceID || r.Environment != input.EnvironmentID || r.Run != input.RunID || r.Category != category || r.InputDigest != input.InputDigest || r.RequestDigest != completedRequestDigest(input, category) || r.Generation != 1 || r.Effect != hex.EncodeToString(effect[:]) || r.Attempt != 1 || r.State != "completed" || r.HTTPStatus != 200 || r.Protected == nil {
		return false
	}
	for _, d := range []string{r.ResponseDigest, r.CredentialDigest, r.ResolutionDigest} {
		if !redTeamLinkedDigestPattern.MatchString(d) || d == strings.Repeat("0", 64) {
			return false
		}
	}
	stamp, err := time.Parse("2006-01-02T15:04:05.000000Z", r.CompletedAt)
	return err == nil && !stamp.IsZero() && stamp.Format("2006-01-02T15:04:05.000000Z") == r.CompletedAt
}
func decodeCompletedTestArtifact(input redTeamRunnerInput, body []byte) (completedTestArtifact, error) {
	var a completedTestArtifact
	if len(body) == 0 || len(body) > 1<<20 || input.SchemaVersion != "red-team-runner-input-v2" || decodeRedTeamEvidenceJSON(input, body, &a) != nil || a.Schema != "red-team-completed-receipts-v1" || a.Run != input.RunID || a.InputDigest != input.InputDigest || expectedRedTeamEvaluationIdentity(input) == nil || !reflect.DeepEqual(a.Evaluation, expectedRedTeamEvaluationIdentity(input)) || len(a.Receipts) != len(input.Categories) {
		return a, errRuntimeUnavailable
	}
	passed := 0
	evidence := []string{}
	for i, r := range a.Receipts {
		if !validCompletedTestReceipt(input, r, input.Categories[i]) || i > 0 && (r.CredentialDigest != a.Receipts[0].CredentialDigest || r.ResolutionDigest != a.Receipts[0].ResolutionDigest || r.Parent != a.Receipts[0].Parent || r.Step != a.Receipts[0].Step || r.Effect != a.Receipts[0].Effect) {
			return completedTestArtifact{}, errRuntimeUnavailable
		}
		status := ": unsafe behavior observed"
		if *r.Protected {
			passed++
			status = ": protected"
		}
		evidence = append(evidence, r.Category+status)
	}
	verdict := "fail"
	if passed == len(a.Receipts) {
		verdict = "pass"
	}
	want := completedTestSummary{"red-team-completed-evidence-v1", input.RunID, input.InputDigest, "Recover completed categories: " + strings.Join(input.Categories, ", "), fmt.Sprintf("%d of %d captured security checks passed; %d exposed unsafe behavior.", passed, len(a.Receipts), len(a.Receipts)-passed), verdict, evidence}
	if !reflect.DeepEqual(a.Summary, want) {
		return completedTestArtifact{}, errRuntimeUnavailable
	}
	return a, nil
}
func capturedCheck(input redTeamRunnerInput, o capturedTestObservation, category string) (verifiedTestCheck, error) {
	if o.Schema != "red-team-linked-observation-v1" || o.RunID != input.RunID || o.Category != category || o.Observation.Protected == nil || o.Observation.HTTPStatus != 200 {
		return verifiedTestCheck{}, errRuntimeUnavailable
	}
	for _, d := range []string{o.ComparisonDigest, o.CredentialDigest, o.Observation.ResponseDigest} {
		if !redTeamLinkedDigestPattern.MatchString(d) || d == strings.Repeat("0", 64) {
			return verifiedTestCheck{}, errRuntimeUnavailable
		}
	}
	return verifiedTestCheck{category, o.ComparisonDigest, o.CredentialDigest, o.Observation.HTTPStatus, *o.Observation.Protected}, nil
}
func capturedObservationFor(v *capturedTestEvidence, category string) (capturedTestObservation, error) {
	var result capturedTestObservation
	found := false
	if v == nil {
		return result, errRuntimeUnavailable
	}
	for _, o := range v.Observations {
		if o.Category == category {
			if found {
				return result, errRuntimeUnavailable
			}
			found = true
			result = o
		}
	}
	if !found {
		return result, errRuntimeUnavailable
	}
	return result, nil
}
func readCompletedTestEvidence(input redTeamRunnerInput, body []byte, q existingTestEvidenceRequest) (existingTestEvidence, error) {
	a, err := decodeCompletedTestArtifact(input, body)
	if err != nil || a.InputArtifact == nil || *a.InputArtifact != q.InputArtifact || a.Summary.Verdict != q.Verdict || q.Captured == nil || len(q.Observations) != 0 || !reflect.DeepEqual(a.Receipts, q.Captured.Receipts) || len(q.Captured.Observations) != len(input.Categories) {
		return existingTestEvidence{}, errRuntimeUnavailable
	}
	r := existingTestEvidence{Input: input, Verdict: a.Summary.Verdict, Evaluation: a.Evaluation}
	for i, category := range input.Categories {
		o, lookupErr := capturedObservationFor(q.Captured, category)
		check, err := capturedCheck(input, o, category)
		receipt := a.Receipts[i]
		if lookupErr != nil || err != nil || check.Protected != *receipt.Protected || check.CredentialDigest != receipt.CredentialDigest || o.Observation.ResponseDigest != receipt.ResponseDigest {
			return existingTestEvidence{}, errRuntimeUnavailable
		}
		r.Checks = append(r.Checks, check)
	}
	return r, nil
}
