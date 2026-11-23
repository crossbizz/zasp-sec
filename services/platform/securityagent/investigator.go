package securityagent

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

var ErrInvestigationUnavailable = errors.New("qualified investigation unavailable")

type InvestigationAction struct {
	ID      string `json:"evidence_id"`
	Source  string `json:"source"`
	Outcome string `json:"outcome"`
}

type InvestigationResult struct {
	Text        string   `json:"summary"`
	EvidenceIDs []string `json:"evidence_ids"`
}

func investigationFocus(question string) string {
	q := strings.ToLower(question)
	switch {
	case strings.Contains(q, "unknown") || strings.Contains(q, "gap") || strings.Contains(q, "missing"):
		return "outcome_unknown"
	case strings.Contains(q, "block") || strings.Contains(q, "prevent"):
		return "prevented"
	case strings.Contains(q, "complete") || strings.Contains(q, "return"):
		return "completed"
	default:
		return "overview"
	}
}

// Tier: 3 | Purpose: security_agent_triage on previously authorized receipts.
// Model: one qualified private model; examine at most six evidence records.
// Authority: a read-only projection of action outcomes, with no dispatch tools.
// Fallback: reject missing, unbounded or unrelated model citations.
func InvestigateSession(ctx context.Context, d aigateway.ProviderDriver, question string, actions []InvestigationAction) (InvestigationResult, error) {
	var result InvestigationResult
	if ctx == nil || d == nil || len(actions) == 0 || len(actions) > 101 || len(question) > 4000 {
		return result, ErrInvestigationUnavailable
	}
	focus := investigationFocus(question)
	rows := make([]InvestigationAction, 0, 6)
	counts := map[string]int{}
	for _, a := range actions {
		if len(a.ID) != 40 || !slices.Contains([]string{"gateway", "tetragon", "otlp", "authenticated_workload"}, a.Source) || !slices.Contains([]string{"prevented", "completed", "outcome_unknown"}, a.Outcome) {
			return result, ErrInvestigationUnavailable
		}
		counts[a.Outcome]++
		if len(rows) < 6 && (focus == "overview" || a.Outcome == focus) {
			rows = append(rows, a)
		}
	}
	if len(rows) == 0 {
		return InvestigationResult{Text: "The inspected receipts contain no actions with this outcome.", EvidenceIDs: []string{actions[0].ID}}, nil
	}
	input, _ := json.Marshal(map[string]any{"question_category": focus, "counts": counts, "receipts": rows})
	raw, err := d.Evaluate(ctx, aigateway.PurposeTriage, input)
	if err != nil || !aigateway.ValidateSemanticOutput(aigateway.PurposeTriage, raw) || json.Unmarshal(raw, &result) != nil || strings.TrimSpace(result.Text) == "" || len(result.EvidenceIDs) < 1 || len(result.EvidenceIDs) > len(rows) {
		return InvestigationResult{}, ErrInvestigationUnavailable
	}
	seen := map[string]bool{}
	for _, id := range result.EvidenceIDs {
		if seen[id] || !slices.ContainsFunc(rows, func(r InvestigationAction) bool { return r.ID == id }) {
			return InvestigationResult{}, ErrInvestigationUnavailable
		}
		seen[id] = true
	}
	return result, nil
}
