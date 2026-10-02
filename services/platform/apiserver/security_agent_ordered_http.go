package apiserver

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"time"
)

type securityAgentOrderedHTTPHandler struct {
	authority *SecurityAgentOrderedResourceAuthority
	legacy    http.Handler
	lists     securityAgentLegacyListAuthority
	cursor    securityAgentPublicHTTPHandler
}

// Production construction is gated by exact deployment readiness.
func newSecurityAgentOrderedHTTPHandler(a *SecurityAgentOrderedResourceAuthority, lists securityAgentLegacyListAuthority, legacy func() (http.Handler, error), signingKey []byte) (handler http.Handler, err error) {
	defer func() {
		if recover() != nil {
			handler = nil
			err = ErrRepositoryConfiguration
		}
	}()
	if a == nil || a.resolver == nil || a.repository == nil || nilInterface(a.resolver.database) || nilInterface(a.repository.database) || nilInterface(lists) || legacy == nil || len(signingKey) < 32 || len(signingKey) > 4096 {
		return nil, ErrRepositoryConfiguration
	}
	h, e := legacy()
	if e != nil || nilInterface(h) {
		return nil, ErrRepositoryConfiguration
	}
	return &securityAgentOrderedHTTPHandler{authority: a, legacy: h, lists: lists, cursor: securityAgentPublicHTTPHandler{config: SecurityAgentPublicHandlerConfig{SigningKey: append([]byte(nil), signingKey...)}}}, nil
}

func (h *securityAgentOrderedHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	route, ok := RoutedOperationFromRequest(r)
	if !ok {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	switch route.OperationID {
	case "listSecurityAgentRuns", "listSecurityAgentApprovals":
		h.list(w, r, route.OperationID)
		return
	case "getSecurityAgentActivation", "activateSecurityAgent", "runSecurityAgent", "getSecurityAgentRun", "cancelSecurityAgentRun", "getSecurityAgentApproval", "decideSecurityAgentApproval":
	default:
		h.legacy.ServeHTTP(w, r)
		return
	}
	id, ok := IdentityFromRequest(r)
	if !ok || r.URL == nil || r.URL.RawQuery != "" || !public62ID(route.PathParameters["id"]) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, 16*1024+1))
		_ = r.Body.Close()
		if err != nil || len(body) > 16*1024 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	resource := route.PathParameters["id"]
	var result any
	var version int64
	var err error
	status := http.StatusOK
	var audit, receipt string
	switch route.OperationID {
	case "getSecurityAgentRun":
		if r.Method != "GET" || len(body) != 0 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		var v SecurityAgentOrderedRunResource
		v, err = h.authority.Run(r.Context(), id, resource)
		result = struct {
			SecurityAgentRunDetail
			Ordered struct {
				ContractVersion int                       `json:"contract_version"`
				Steps           []SecurityAgentPublicStep `json:"steps"`
			} `json:"ordered"`
		}{SecurityAgentRunDetail: v.Detail, Ordered: struct {
			ContractVersion int                       `json:"contract_version"`
			Steps           []SecurityAgentPublicStep `json:"steps"`
		}{62, append([]SecurityAgentPublicStep{}, v.Steps...)}}
		version = v.Detail.Run.Version
	case "getSecurityAgentActivation":
		if r.Method != "GET" || len(body) != 0 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		var v SecurityAgentActivationState
		v, err = h.authority.GetActivation(r.Context(), id, resource)
		result = v
		version = v.Version
	case "getSecurityAgentApproval":
		if r.Method != "GET" || len(body) != 0 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		var v SecurityAgentOrderedApprovalResource
		v, err = h.authority.Approval(r.Context(), id, resource)
		result = v.Approval
		version = v.Approval.Version
	default:
		result, version, status, audit, receipt, err = h.mutate(r, id, route.OperationID, resource, body)
	}
	if err == ErrSecurityAgentNotOwned {
		r.Body = io.NopCloser(bytes.NewReader(body))
		h.legacy.ServeHTTP(w, r)
		return
	}
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(version, 10)+`"`)
	if audit != "" {
		w.Header().Set("X-Audit-ID", audit)
		w.Header().Set("X-Mutation-Receipt-ID", receipt)
	}
	writeJSONValue(w, r, status, result, nil)
}

func (h *securityAgentOrderedHTTPHandler) mutate(r *http.Request, id RequestIdentity, op, resource string, body []byte) (result any, version int64, status int, audit, receipt string, err error) {
	status = http.StatusOK
	key, expected, valid := discoveryMutationHeaders(r, false)
	if r.Method != http.MethodPost || !valid {
		err = ErrRepositoryOperation
		return
	}
	decode := func(target any) bool {
		return exactHeaderValue(r.Header.Values("Content-Type"), "application/json") && public62Decode(body, target) == nil
	}
	fresh := func() bool {
		return id.FreshAuthenticated && validSecurityAgentFreshAuthentication(time.Now(), id.FreshAuthExpiresAt) && exactHeaderValue(r.Header.Values("X-Zasp-Fresh-Auth"), "confirmed")
	}
	switch op {
	case "activateSecurityAgent":
		var input struct {
			Activation string `json:"activation"`
		}
		if !decode(&input) {
			err = ErrRepositoryOperation
			return
		}
		// Receipt-aware classification precedes semantic validation and must not
		// be replaced by a current-definition read: historical replay owns intent.
		if err = h.authority.ownMutation(r.Context(), id, SecurityAgentMutationActivate, resource, key, nil); err != nil {
			return
		}
		if !fresh() {
			err = ErrRepositoryAuthentication
			return
		}
		var v SecurityAgentActivationResult
		v, err = h.authority.Activate(r.Context(), id, SecurityAgentOrderedActivation{resource, expected, input.Activation, key})
		result = SecurityAgentActivationState{ID: v.ID, Activation: v.Activation, Enabled: v.Enabled, Version: v.Version}
		version, audit, receipt = v.Version, v.AuditID, v.ReceiptID
	case "runSecurityAgent":
		var input struct {
			EnvironmentID  string `json:"environment_id"`
			TriggerKind    string `json:"trigger_kind"`
			TriggerID      string `json:"trigger_id"`
			TriggerVersion int64  `json:"trigger_version"`
			TriggerSource  string `json:"trigger_source"`
		}
		if !decode(&input) {
			// The exact legacy body has no version. Only key-bound retained proof
			// may classify it; an owned request still cannot execute without a version.
			var legacy struct {
				EnvironmentID string `json:"environment_id"`
				TriggerKind   string `json:"trigger_kind"`
				TriggerID     string `json:"trigger_id"`
			}
			if decode(&legacy) && legacy.EnvironmentID == id.Scope.EnvironmentID().String() && public62ID(legacy.TriggerID) {
				if err = h.authority.ownTriggerKey(r.Context(), id, resource, key); err != nil {
					return
				}
			}
			err = ErrRepositoryOperation
			return
		}
		if err = h.authority.ownMutation(r.Context(), id, SecurityAgentMutationTrigger, resource, key, &SecurityAgentMutationTriggerIdentity{input.TriggerID, input.TriggerVersion}); err != nil {
			return
		}
		if input.EnvironmentID != id.Scope.EnvironmentID().String() {
			err = ErrRepositoryOperation
			return
		}
		var v SecurityAgentRunResult
		v, err = h.authority.Trigger(r.Context(), id, SecurityAgentOrderedTrigger{SecurityAgentPublicTrigger{resource, expected, input.TriggerID, input.TriggerVersion, key}, input.TriggerKind, input.TriggerSource})
		result = SecurityAgentRun{ID: v.ID, AgentID: v.AgentID, State: v.State, EvidenceIDs: v.EvidenceIDs, DefinitionVersion: v.DefinitionVersion, Version: v.Version}
		version, status, audit, receipt = v.Version, http.StatusAccepted, v.AuditID, v.ReceiptID
	case "cancelSecurityAgentRun":
		if len(body) != 0 {
			err = ErrRepositoryOperation
			return
		}
		var v SecurityAgentOrderedCancellationResult
		v, err = h.authority.Cancel(r.Context(), id, SecurityAgentPublicCancellation{resource, expected, key})
		result = struct {
			SecurityAgentRun
			Ordered struct {
				CleanupRequired bool `json:"cleanup_required"`
			} `json:"ordered"`
		}{SecurityAgentRun: SecurityAgentRun{ID: v.Result.ID, AgentID: v.Result.AgentID, State: v.Result.State, EvidenceIDs: v.Result.EvidenceIDs, DefinitionVersion: v.Result.DefinitionVersion, Version: v.Result.Version}, Ordered: struct {
			CleanupRequired bool `json:"cleanup_required"`
		}{v.CleanupRequired}}
		version, audit, receipt = v.Result.Version, v.Result.AuditID, v.Result.ReceiptID
	case "decideSecurityAgentApproval":
		var input struct {
			Decision string `json:"decision"`
		}
		if !decode(&input) {
			err = ErrRepositoryOperation
			return
		}
		if err = h.authority.own(r.Context(), id, SecurityAgentResourceApproval, resource); err != nil {
			return
		}
		if !fresh() {
			err = ErrRepositoryAuthentication
			return
		}
		var v SecurityAgentApprovalResult
		v, err = h.authority.Decide(r.Context(), id, SecurityAgentOrderedDecision{resource, expected, input.Decision, key})
		result = SecurityAgentApproval{ID: v.ID, RunID: v.RunID, StepID: v.StepID, State: v.State, ExpiresAt: v.ExpiresAt, Version: v.Version, ExpectedEffect: v.ExpectedEffect, Reversible: v.Reversible, TTLSeconds: v.TTLSeconds, EvidenceSummary: v.EvidenceSummary}
		version, audit, receipt = v.Version, v.AuditID, v.ReceiptID
	default:
		err = ErrRepositoryOperation
	}
	return
}
