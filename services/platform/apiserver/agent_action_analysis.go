package apiserver

import (
	"encoding/json"
	"net/http"
	"slices"
	"sort"
)

const analysisReadSQL = "SELECT zasp_authorization80.action_analysis($1,$2,$3,$4,$5,NULL,NULL,NULL)"
const analysisWriteSQL = "SELECT zasp_authorization80.action_analysis($1,$2,$3,$4,$5,$6,$7,$8::jsonb)"

func init() {
	productStatementRules[analysisReadSQL] = productStatementRule{operations: []string{"getAgentActionAnalysis"}, arguments: 5, scope: 1, actor: 4, object: 5, kind: "agent", browserOnly: true}
	productStatementRules[analysisWriteSQL] = productStatementRule{operations: []string{"putAgentActionAnalysis"}, arguments: 8, scope: 1, actor: 4, object: 5, kind: "agent", browserOnly: true}
}

type analysisTransition struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Reject explicit null so the stored consent matches the declared wire type.
type classifierConsent bool

func (c *classifierConsent) UnmarshalJSON(raw []byte) error {
	switch string(raw) {
	case "true":
		*c = true
	case "false":
		*c = false
	default:
		return ErrRepositoryOperation
	}
	return nil
}

type analysisSettings struct {
	ClassifierOptIn classifierConsent    `json:"classifier_opt_in,omitempty"`
	Operations      []string             `json:"allowed_operations"`
	Classifications []string             `json:"allowed_classifications"`
	Destinations    []string             `json:"allowed_destinations"`
	Transitions     []analysisTransition `json:"blocked_transitions"`
}

func validAnalysisDestination(v string) bool {
	return stringIn(v, "internal", "approved_partner", "external", "public")
}
func (s *analysisSettings) normalise() bool {
	if s.Operations == nil || s.Classifications == nil || s.Destinations == nil || s.Transitions == nil || len(s.Transitions) > 32 || len(s.Destinations) > 4 {
		return false
	}
	for _, xs := range [][]string{s.Operations, s.Classifications, s.Destinations} {
		if len(xs) > 32 {
			return false
		}
		slices.Sort(xs)
		for j, k := range xs {
			if !workloadLabel.MatchString(k) || j > 0 && xs[j-1] == k {
				return false
			}
		}
	}
	for _, d := range s.Destinations {
		if !validAnalysisDestination(d) {
			return false
		}
	}
	sort.Slice(s.Transitions, func(i, j int) bool {
		a, b := s.Transitions[i], s.Transitions[j]
		return a.From < b.From || a.From == b.From && a.To < b.To
	})
	for j, k := range s.Transitions {
		if !workloadLabel.MatchString(k.From) || !workloadLabel.MatchString(k.To) || j > 0 && s.Transitions[j-1] == k {
			return false
		}
	}
	return true
}
func serveActionAnalysis(db JSONDatabase, w http.ResponseWriter, r *http.Request, op RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	i, ok := IdentityFromRequest(r)
	if !ok || i.CredentialKind != CredentialBrowserSession {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	id := op.PathParameters["id"]
	if !validProductID(id) || r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	query := analysisReadSQL
	args := []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), id}
	switch op.OperationID {
	case "putAgentActionAnalysis":
		var cfg analysisSettings
		k, n, ok := discoveryMutationHeaders(r, true)
		if r.Method != http.MethodPut || !ok || n >= 1_000_000 || decodeProductionJSON(r, &cfg) != nil || !cfg.normalise() {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		blob, _ := json.Marshal(cfg)
		args = append(args, k, n, string(blob))
		query = analysisWriteSQL
	case "getAgentActionAnalysis":
		if r.Method != http.MethodGet {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	raw, err := db.QueryJSON(r.Context(), query, args...)
	if err != nil {
		writeProductionError(w, r, discoveryProviderError(err))
		return
	}
	if string(raw) == "null" {
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	if string(raw) == `"conflict"` {
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	var reply struct {
		Agent    string `json:"agent_id"`
		Revision int64  `json:"revision"`
	}
	if json.Unmarshal(raw, &reply) != nil || reply.Agent != id || reply.Revision < 0 {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	w.Header().Set("ETag", quoteVersion(reply.Revision))
	writeProductionResponse(w, r, 200, raw, nil)
}
