package aigateway

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// A proposal can select only the reversible action and target already admitted
// for this case. Empty output means that the model made no recommendation.
type advisoryStep struct {
	Action   string `json:"action"`
	Target   string `json:"target_id"`
	Rollback string `json:"rollback"`
}

func admittedAdvisory(raw json.RawMessage) ([]advisoryStep, bool) {
	var in struct {
		Candidates []advisoryStep `json:"candidates"`
		Evidence   []string       `json:"evidence_ids"`
	}
	unique := json.NewDecoder(bytes.NewReader(raw))
	if uniqueJSON(unique, 0) != nil {
		return nil, false
	}
	if _, err := unique.Token(); err != io.EOF {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || in.Candidates == nil || len(in.Candidates) > 1 || in.Evidence == nil || len(in.Evidence) > 6 {
		return nil, false
	}
	for _, step := range in.Candidates {
		if _, err := domain.ParseProductID(step.Target); err != nil || step.Action != "isolate_session" || step.Rollback != "ttl_release" {
			return nil, false
		}
	}
	seen := map[string]bool{}
	for _, id := range in.Evidence {
		if _, err := domain.ParseProductID(id); err != nil || seen[id] {
			return nil, false
		}
		seen[id] = true
	}
	return in.Candidates, true
}

// ValidateRemediationProposal also applies to an inferred response at
// settlement. It binds model output to the specific candidate projection.
func ValidateRemediationProposal(input, output json.RawMessage) bool {
	candidates, ok := admittedAdvisory(input)
	if !ok || !ValidateSemanticOutput(PurposeRemediate, output) {
		return false
	}
	var out struct {
		Steps []advisoryStep `json:"steps"`
	}
	if json.Unmarshal(output, &out) != nil || out.Steps == nil {
		return false
	}
	return len(out.Steps) == 0 || len(out.Steps) == 1 && len(candidates) == 1 && out.Steps[0] == candidates[0]
}
