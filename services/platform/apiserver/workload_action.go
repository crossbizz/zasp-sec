package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

const (
	permissionDecideActions   = "decide_actions"
	currentWorkloadActionSQL  = "SELECT zasp_authorization80.workload_action($1,$2,$3,$4,$5::jsonb,$6::jsonb)"
	currentWorkloadOutcomeSQL = "SELECT zasp_authorization80.workload_outcome($1,$2,$3,$4,$5,$6::jsonb)"
)

var workloadLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var workloadRevision = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var errUnsupportedWorkloadContext = errors.New("workload action policy requires unavailable context")

type workloadActionRequest struct {
	SchemaVersion string `json:"schema_version"`
	ActionID      string `json:"action_id"`
	ActionKind    string `json:"action_kind"`
	Operation     string `json:"operation"`
	Resource      struct {
		Kind           string `json:"kind"`
		Classification string `json:"classification"`
	} `json:"resource"`
	Session *string `json:"source_session_ref,omitempty"`
	Call    *string `json:"source_call_ref,omitempty"`
}

func (r workloadActionRequest) valid() bool {
	return r.SchemaVersion == "action.v1" && r.ActionKind == "tool_call" && workloadLabel.MatchString(r.ActionID) && workloadLabel.MatchString(r.Operation) &&
		workloadLabel.MatchString(r.Resource.Kind) && workloadLabel.MatchString(r.Resource.Classification) &&
		(r.Session == nil || workloadLabel.MatchString(*r.Session)) && (r.Call == nil || workloadLabel.MatchString(*r.Call))
}

type workloadOutcome struct {
	SchemaVersion string `json:"schema_version"`
	ActionID      string `json:"action_id"`
	DecisionID    string `json:"decision_id"`
	Status        string `json:"status"`
}
type workloadReceipt struct {
	ActionID       string `json:"action_id"`
	DecisionID     string `json:"decision_id"`
	PolicyRevision string `json:"policy_revision_id"`
	Mode           string `json:"mode"`
	Verdict        string `json:"verdict"`
	Reason         string `json:"reason_code"`
	Coverage       string `json:"coverage"`
	WouldBlock     bool   `json:"would_block"`
}

type workloadPolicy struct {
	ID      string          `json:"id"`
	Version int64           `json:"version"`
	Body    json.RawMessage `json:"body"`
}
type workloadAdmission struct {
	Isolated     bool             `json:"isolated"`
	BoundAgent   string           `json:"bound_agent_id"`
	BoundSession string           `json:"bound_session_id"`
	Policies     []workloadPolicy `json:"policies"`
	Revision     string           `json:"revision"`
	Receipt      *workloadReceipt `json:"receipt"`
	Error        string           `json:"error"`
}

type workloadActionHandler struct {
	database     JSONDatabase
	newProductID func() (string, error)
}

func (decision workloadReceipt) validFor(actionID string) bool {
	if decision.ActionID != actionID || !validProductID(decision.DecisionID) ||
		!workloadRevision.MatchString(decision.PolicyRevision) || decision.Coverage != "pre_action_supported" ||
		!stringIn(decision.Mode, "enforce", "monitor") {
		return false
	}
	switch decision.Reason {
	case "rule_blocked", "supervised_session_isolation":
		return decision.Verdict == "block" && decision.Mode == "enforce"
	case "rule_would_block":
		return decision.Verdict == "allow" && decision.WouldBlock
	case "no_matching_restriction":
		return decision.Verdict == "allow" && !decision.WouldBlock
	default:
		return false
	}
}

func (outcome workloadOutcome) validFor(actionID string) bool {
	return outcome.SchemaVersion == "action-outcome.v1" && workloadLabel.MatchString(actionID) &&
		outcome.ActionID == actionID && validProductID(outcome.DecisionID) &&
		stringIn(outcome.Status, "not_dispatched", "returned", "raised", "cancelled")
}

func workloadStatementAllowed(g RequestAuthorization, args []any) bool {
	if len(args) != 6 || g.Identity.CredentialKind != CredentialBearerToken ||
		!authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String()) {
		return false
	}
	if g.OperationID == "recordWorkloadActionOutcome" {
		var observation workloadOutcome
		raw, ok := args[5].(json.RawMessage)
		return ok && len(raw) <= 2048 && decodeStrictDiscovery(raw, &observation) == nil && observation.validFor(g.PathParameters["actionId"])
	}
	var action workloadActionRequest
	raw, ok := args[4].(json.RawMessage)
	if !ok || len(raw) > 2048 || decodeStrictDiscovery(raw, &action) != nil || !action.valid() {
		return false
	}
	if args[5] == nil {
		return true
	}
	var proposed workloadReceipt
	raw, ok = args[5].(json.RawMessage)
	return ok && len(raw) <= 2048 && decodeStrictDiscovery(raw, &proposed) == nil && proposed.validFor(action.ActionID)
}

func (h *workloadActionHandler) serve(w http.ResponseWriter, r *http.Request, op RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	i, ok := IdentityFromRequest(r)
	if !ok || i.CredentialKind != CredentialBearerToken {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	switch op.OperationID {
	case "createWorkloadActionDecision":
		var action workloadActionRequest
		if decodeProductionJSON(r, &action) != nil || !action.valid() || r.Header.Get("Idempotency-Key") != action.ActionID {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		h.decide(w, r, i, action)
	case "recordWorkloadActionOutcome":
		var observation workloadOutcome
		a := op.PathParameters["actionId"]
		if decodeProductionJSON(r, &observation) != nil || !observation.validFor(a) || r.Header.Get("Idempotency-Key") != a+"-outcome" {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		h.outcome(w, r, i, observation)
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
	}
}

func (h *workloadActionHandler) decide(w http.ResponseWriter, r *http.Request, i RequestIdentity, a workloadActionRequest) {
	body, err := json.Marshal(a)
	if err != nil {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	query := func(receipt json.RawMessage) (workloadAdmission, error) {
		var value workloadAdmission
		var proposed any
		if receipt != nil {
			proposed = receipt
		}
		raw, err := h.database.QueryJSON(r.Context(), currentWorkloadActionSQL, i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), json.RawMessage(body), proposed)
		if err != nil {
			return value, discoveryProviderError(err)
		}
		err = decodeStrictDiscovery(raw, &value)
		return value, err
	}
	result, err := query(nil)
	if err == nil && result.Error == "" && result.Receipt == nil {
		var receipt workloadReceipt
		receipt, err = h.evaluate(r.Context(), i, a, result)
		if errors.Is(err, errUnsupportedWorkloadContext) {
			writeProductionStatusError(w, r, http.StatusUnprocessableEntity, "policy_context_unavailable", "An active rule requires an identity this adapter cannot establish", false)
			return
		}
		if err == nil {
			candidate, encodeErr := json.Marshal(receipt)
			if encodeErr != nil {
				writeProductionError(w, r, ErrRepositoryUnavailable)
				return
			}
			result, err = query(candidate)
		}
	}
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	switch result.Error {
	case "action_id_conflict":
		writeProductionStatusError(w, r, http.StatusConflict, "action_id_conflict", "This action identifier was already used with different inputs", false)
		return
	case "policy_changed":
		writeProductionStatusError(w, r, http.StatusConflict, "policy_changed", "Policy changed during evaluation. Retry this admission.", true)
		return
	}
	receipt := result.Receipt
	if result.Error != "" || receipt == nil || !receipt.validFor(a.ActionID) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeJSONValue(w, r, http.StatusOK, receipt, nil)
}

func (h *workloadActionHandler) evaluate(ctx context.Context, i RequestIdentity, a workloadActionRequest, s workloadAdmission) (workloadReceipt, error) {
	if !workloadRevision.MatchString(s.Revision) || s.Policies == nil || len(s.Policies) > 64 {
		return workloadReceipt{}, ErrRepositoryUnavailable
	}
	decisionID, err := h.newProductID()
	if err != nil || !validProductID(decisionID) {
		return workloadReceipt{}, ErrRepositoryUnavailable
	}
	result := workloadReceipt{ActionID: a.ActionID, DecisionID: decisionID, PolicyRevision: s.Revision, Mode: "monitor", Verdict: "allow", Reason: "no_matching_restriction", Coverage: "pre_action_supported"}
	if s.Isolated {
		result.Mode = "enforce"
		result.Verdict = "block"
		result.Reason = "supervised_session_isolation"
		return result, nil
	}
	input := map[string]string{"principal_id": i.PrincipalID.String(), "environment_id": i.Scope.EnvironmentID().String(), "action": a.Operation, "resource": a.Resource.Classification}
	if s.BoundAgent != "" || s.BoundSession != "" {
		if !validProductID(s.BoundAgent) || !validProductID(s.BoundSession) {
			return workloadReceipt{}, ErrRepositoryUnavailable
		}
		input["agent_id"], input["session_id"] = s.BoundAgent, s.BoundSession
	}
	for _, entry := range s.Policies {
		var current policy.Policy
		if entry.Version < 1 || decodePolicyValue(entry.Body, entry.ID, &current) != nil || current.Trigger != "tool" || !stringIn(current.Rollout, "monitor", "enforced") {
			return workloadReceipt{}, ErrRepositoryUnavailable
		}
		if current.Rollout == "enforced" && current.Action == policy.ActionBlock {
			result.Mode = "enforce"
		}
		// An absent identity cannot safely resolve an applicable restriction.
		// A known, unequal AND condition rules this policy out up front.
		unknown, disjoint := false, false
		for _, condition := range current.Conditions {
			value, known := input[condition.Field]
			if !known {
				unknown = true
			} else if value != condition.Value {
				disjoint = true
			}
		}
		if disjoint {
			continue
		}
		if unknown {
			return workloadReceipt{}, errUnsupportedWorkloadContext
		}
		compiled, err := policy.Compile(current)
		if err != nil {
			return workloadReceipt{}, ErrRepositoryUnavailable
		}
		match, err := policy.Evaluate(ctx, compiled, input)
		if err != nil {
			return workloadReceipt{}, ErrRepositoryUnavailable
		}
		if match.Matched && match.Action == policy.ActionBlock {
			if current.Rollout == "enforced" {
				result.Verdict = "block"
				result.Reason = "rule_blocked"
			} else {
				result.WouldBlock = true
				if result.Verdict == "allow" {
					result.Reason = "rule_would_block"
				}
			}
		}
	}
	return result, nil
}

func (h *workloadActionHandler) outcome(w http.ResponseWriter, r *http.Request, i RequestIdentity, value workloadOutcome) {
	body, err := json.Marshal(value)
	if err != nil {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	raw, err := h.database.QueryJSON(r.Context(), currentWorkloadOutcomeSQL, i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), value.ActionID, json.RawMessage(body))
	if err != nil {
		writeProductionError(w, r, discoveryProviderError(err))
		return
	}
	var result struct {
		Error    string `json:"error"`
		Recorded bool   `json:"recorded"`
	}
	if decodeStrictDiscovery(raw, &result) != nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	switch result.Error {
	case "unknown_action":
		writeProductionError(w, r, ErrRepositoryNotFound)
	case "action_outcome_conflict":
		writeProductionStatusError(w, r, http.StatusConflict, "action_outcome_conflict", "A different outcome was already reported", false)
	case "":
		if !result.Recorded {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		writeProductionResponse(w, r, http.StatusOK, raw, nil)
	default:
		writeProductionError(w, r, ErrRepositoryUnavailable)
	}
}
