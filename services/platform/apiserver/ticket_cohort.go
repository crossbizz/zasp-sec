package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

const cohortInspectSQL = "SELECT zasp_authorization80.ticket_cohort_inspect($1,$2,$3,$4,$5,$6,$7,$8)"
const cohortCommitSQL = "SELECT zasp_authorization80.ticket_cohort_commit($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)"

func init() {
	productStatementRules[cohortInspectSQL] = productStatementRule{operations: []string{"getTicketCohort", "publishTicketCohort"}, arguments: 8, scope: 1, actor: 4, browserOnly: true, check: func(g RequestAuthorization, a []any) bool {
		return a[4] == g.OperationID && a[5] == g.PathParameters["cohort"] && authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String())
	}}
	productStatementRules[cohortCommitSQL] = productStatementRule{operations: []string{"publishTicketCohort"}, arguments: 9, scope: 1, actor: 4, browserOnly: true, fresh: true, check: func(g RequestAuthorization, a []any) bool {
		return a[4] == g.PathParameters["cohort"] && authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String())
	}}
}

type cohortDevice struct {
	ID                string `json:"id"`
	Version           int64  `json:"version"`
	Generation        uint64 `json:"generation"`
	PolicyRevision    uint64 `json:"policy_revision"`
	ManagedRevision   uint64 `json:"managed_revision"`
	ManagedGeneration uint64 `json:"managed_generation"`
	ManagedMode       string `json:"managed_mode"`
	Adapter           string `json:"adapter"`
	State             string `json:"state"`
	Online            bool   `json:"online"`
	Acknowledged      bool   `json:"acknowledged"`
	Allowed           bool   `json:"allowed_observed"`
	Outside           bool   `json:"outside_observed"`
	QueueClear        bool   `json:"queue_clear"`
}
type cohortView struct {
	proofStatus      string
	Cohort           string         `json:"cohort"`
	EnvironmentClass string         `json:"environment_class"`
	Revision         int64          `json:"revision"`
	Phase            string         `json:"phase"`
	Destination      string         `json:"allowed_destination"`
	Assigned         int            `json:"assigned"`
	Members          []cohortDevice `json:"members"`
	Plan             *cohortPlan    `json:"plan"`
	Reason           string         `json:"reason"`
}
type cohortProof struct {
	Bundle       redteam.TicketProofBundle `json:"bundle"`
	At           time.Time                 `json:"submitted_at"`
	ControlBound bool                      `json:"control_bound"`
}

func cohortProofStatus(evidence []cohortProof, scope endpointprotocol.Binding, cohort string) string {
	if len(evidence) > 16 {
		return "independent_ticket_proof_limit"
	}
	result := "independent_ticket_proof_required"
	for _, entry := range evidence {
		bundle := entry.Bundle
		if !bundle.Archivable() || bundle.Scenario.CohortID != cohort || bundle.Scenario.Scope != (redteam.TicketScope{OrganizationID: scope.Organization, WorkspaceID: scope.Workspace, EnvironmentID: scope.Environment}) {
			return "independent_ticket_proof_invalid"
		}
		verdict, err := redteam.VerifyTicketProof(bundle.Scenario, bundle.Adapter, bundle.Recorder, entry.At)
		if err != nil {
			return "independent_ticket_proof_invalid"
		}
		if verdict.Verdict == "unexpected_effect" {
			return "canary_unexpected_target_effect"
		}
		if verdict.Verdict == "passed" && entry.ControlBound {
			result = "passed"
		}
	}
	return result
}

type cohortStore struct {
	Proofs []cohortProof `json:"proofs"`

	View     cohortView        `json:"view"`
	Keys     map[string][]byte `json:"keys"`
	Snapshot string            `json:"snapshot"`
	Receipt  json.RawMessage   `json:"receipt"`
}
type cohortItem struct {
	Version int64                   `json:"expected_device_version"`
	Policy  endpointprotocol.Policy `json:"policy"`
}
type cohortHeader struct {
	Schema   string `json:"schema_version"`
	Cohort   string `json:"cohort"`
	Phase    string `json:"phase"`
	Revision int64  `json:"expected_rollout_revision"`
}
type cohortPlan struct {
	cohortHeader
	Items []cohortItem `json:"items"`
}
type cohortEnvelope struct {
	Version int64                   `json:"expected_device_version"`
	Bundle  endpointprotocol.Signed `json:"bundle"`
}
type cohortUpload struct {
	cohortHeader
	Items []cohortEnvelope `json:"items"`
}
type cohortWrite struct {
	ID         string                  `json:"id"`
	Generation uint64                  `json:"generation"`
	Version    int64                   `json:"expected_version"`
	Revision   uint64                  `json:"revision"`
	Mode       string                  `json:"mode"`
	Expires    time.Time               `json:"expires_at"`
	Bundle     endpointprotocol.Signed `json:"bundle"`
}

func cohortTargets(view cohortView, phase, destination string) ([]cohortDevice, string) {
	if !stringIn(view.EnvironmentClass, "test", "development", "staging") {
		return nil, "nonproduction_required"
	}
	if view.Assigned > 32 || len(view.Members) != view.Assigned {
		return nil, "cohort_too_large"
	}
	if !endpointprotocol.Label.MatchString(destination) {
		return nil, "destination_required"
	}
	if phase != "monitor" && destination != view.Destination {
		return nil, "destination_changed"
	}
	var candidates, previous, canaries []cohortDevice
	for _, d := range view.Members {
		known := d.State == "active" && (d.Adapter == "macos_claude_ticket" || view.EnvironmentClass == "test" && d.Adapter == "linux_claude_ticket_test")
		if d.ManagedRevision > 0 {
			if d.ManagedGeneration != d.Generation || d.ManagedRevision != d.PolicyRevision || d.State != "active" {
				return nil, "managed_member_changed"
			}
			previous = append(previous, d)
			if d.ManagedMode == "enforce" {
				canaries = append(canaries, d)
			}
		}
		if known {
			if d.PolicyRevision >= 1<<53 {
				return nil, "revision_limit"
			}
			candidates = append(candidates, d)
		}
	}
	if len(candidates) == 0 && phase != "rollback" {
		return nil, "no_ticket_adapter"
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	switch phase {
	case "monitor":
		if !stringIn(view.Phase, "none", "monitor", "rollback") {
			return nil, "rollback_first"
		}
		for _, d := range candidates {
			if d.ManagedRevision == 0 && d.PolicyRevision != 0 {
				return nil, "independent_policy_present"
			}
		}
		return candidates, "ready"
	case "canary", "promote":
		if phase == "canary" && view.Phase != "monitor" || phase == "promote" && view.Phase != "canary" {
			return nil, "phase_out_of_order"
		}
		if len(candidates) != len(previous) {
			return nil, "membership_changed"
		}
		for _, d := range candidates {
			if d.ManagedRevision == 0 {
				return nil, "membership_changed"
			}
			if !d.Online || !d.Acknowledged || !d.QueueClear || !d.Allowed || !d.Outside {
				return nil, "paired_device_evidence_required"
			}
		}
		if phase == "canary" {
			return candidates[:1], "ready"
		}
		if view.proofStatus != "passed" {
			if view.proofStatus == "" {
				return nil, "independent_ticket_proof_required"
			}
			return nil, view.proofStatus
		}
		if len(canaries) != 1 {
			return nil, "canary_record_missing"
		}
		rest := []cohortDevice{}
		for _, d := range candidates {
			if d.ManagedMode == "monitor" {
				rest = append(rest, d)
			}
		}
		if len(rest) == 0 {
			return nil, "canary_covers_cohort"
		}
		return rest, "ready"
	case "rollback":
		if !stringIn(view.Phase, "canary", "promote") || len(canaries) == 0 {
			return nil, "nothing_to_restore"
		}
		sort.Slice(canaries, func(i, j int) bool { return canaries[i].ID < canaries[j].ID })
		return canaries, "ready"
	}
	return nil, "unsupported_phase"
}
func cohortPrepare(view *cohortView, binding endpointprotocol.Binding, phase, destination string, now time.Time) {
	if phase == "" {
		view.Reason = "status"
		return
	}
	devices, reason := cohortTargets(*view, phase, destination)
	view.Reason = reason
	if reason != "ready" {
		return
	}
	plan := &cohortPlan{cohortHeader: cohortHeader{Schema: "ticket-cohort-plan.v1", Cohort: view.Cohort, Phase: phase, Revision: view.Revision}}
	mode := "monitor"
	if phase == "canary" || phase == "promote" {
		mode = "enforce"
	}
	for _, d := range devices {
		binding.Device = d.ID
		binding.Generation = d.Generation
		p := endpointprotocol.Policy{Audience: endpointprotocol.PolicyAudience, Binding: binding, Revision: d.PolicyRevision + 1, IssuedAt: now.UTC().Truncate(time.Second), ExpiresAt: now.UTC().Truncate(time.Second).Add(4 * time.Hour), Mode: mode, Tool: endpointprotocol.TicketTool, AllowedDestination: destination}
		plan.Items = append(plan.Items, cohortItem{d.Version, p})
	}
	view.Plan = plan
}

// The signature covers the exact JSON bytes. Reject ambiguous field aliases at
// each layer before interpreting a signed batch or its policy.
func strictCohortUpload(raw []byte, out *cohortUpload) bool {
	if !validAgentExportContentJSON(string(raw)) || !exactJSONFields(raw, "schema_version", "cohort", "phase", "expected_rollout_revision", "items") || decodeStrictDiscovery(raw, out) != nil {
		return false
	}
	var shape struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(raw, &shape) != nil {
		return false
	}
	for _, item := range shape.Items {
		var envelope struct {
			Bundle json.RawMessage `json:"bundle"`
		}
		if !exactJSONFields(item, "expected_device_version", "bundle") || json.Unmarshal(item, &envelope) != nil || !exactJSONFields(envelope.Bundle, "payload", "signature") {
			return false
		}
	}
	return true
}
func strictCohortPolicy(raw []byte) bool {
	var shape struct {
		Binding json.RawMessage `json:"binding"`
	}
	return validAgentExportContentJSON(string(raw)) && exactJSONFields(raw, "audience", "binding", "revision", "issued_at", "expires_at", "mode", "tool", "allowed_destination") && json.Unmarshal(raw, &shape) == nil && exactJSONFields(shape.Binding, "organization_id", "workspace_id", "environment_id", "device_id", "credential_generation")
}

func (h *endpointFleetHandler) cohort(w http.ResponseWriter, r *http.Request, op RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	user, ok := IdentityFromRequest(r)
	cohort := op.PathParameters["cohort"]
	if !ok || user.CredentialKind != CredentialBrowserSession {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	if !cohortLabel.MatchString(cohort) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	scope := user.Scope
	b := endpointprotocol.Binding{Organization: scope.OrganizationID().String(), Workspace: scope.WorkspaceID().String(), Environment: scope.EnvironmentID().String()}
	base := []any{b.Organization, b.Workspace, b.Environment, user.PrincipalID.String()}
	var signed cohortUpload
	var key, digest, phase, destination string
	if op.OperationID == "getTicketCohort" {
		q, ok := exactWorkflowQuery(r.URL.RawQuery, map[string]int{"phase": 16, "allowed_destination": 128})
		if r.Method != http.MethodGet || !ok {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		phase, destination = q.Get("phase"), q.Get("allowed_destination")
		if phase != "" && !stringIn(phase, "monitor", "canary", "promote", "rollback") {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
	} else {
		key = r.Header.Get("Idempotency-Key")
		if !user.FreshAuthenticated {
			writeProductionError(w, r, ErrRepositoryAuthorization)
			return
		}
		if op.OperationID != "publishTicketCohort" || r.Method != http.MethodPut || r.URL.RawQuery != "" || len(r.Header.Values("Idempotency-Key")) != 1 || !validPublicIdempotency(key) || r.Body == nil {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil || len(raw) > 65536 || !strictCohortUpload(raw, &signed) || signed.Schema != "ticket-cohort-bundle.v1" || signed.Cohort != cohort || len(signed.Items) < 1 || len(signed.Items) > 32 || signed.Revision < 0 || signed.Revision >= 1000000 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		canonical, _ := json.Marshal(signed)
		sum := sha256.Sum256(canonical)
		digest = hex.EncodeToString(sum[:])
		phase = signed.Phase
	}
	args := append(append([]any{}, base...), op.OperationID, cohort, key, digest)
	raw, err := h.database.QueryJSON(r.Context(), cohortInspectSQL, args...)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	if string(raw) == `"conflict"` {
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	var store cohortStore
	if json.Unmarshal(raw, &store) != nil || store.View.Cohort != cohort || store.View.Members == nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	if len(store.Receipt) > 0 && string(store.Receipt) != "null" {
		writeProductionResponse(w, r, 200, store.Receipt, nil)
		return
	}
	store.View.proofStatus = cohortProofStatus(store.Proofs, b, cohort)
	now := h.clock()
	if op.OperationID == "getTicketCohort" {
		if destination == "" {
			destination = store.View.Destination
		}
		cohortPrepare(&store.View, b, phase, destination, now)
		writeJSONValue(w, r, 200, store.View, nil)
		return
	}
	if signed.Revision != store.View.Revision {
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	if !strictCohortPolicy(signed.Items[0].Bundle.Payload) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	var first endpointprotocol.Policy
	_ = json.Unmarshal(signed.Items[0].Bundle.Payload, &first)
	destination = first.AllowedDestination
	cohortPrepare(&store.View, b, phase, destination, now)
	if store.View.Plan == nil || len(store.View.Plan.Items) != len(signed.Items) {
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	writes := make([]cohortWrite, 0, len(signed.Items))
	for j, entry := range signed.Items {
		expected := store.View.Plan.Items[j]
		p, ok := entry.Bundle.PolicyFor(store.Keys[expected.Policy.Binding.Device], expected.Policy.Binding, now)
		if !ok || !strictCohortPolicy(entry.Bundle.Payload) || entry.Version != expected.Version || p.Revision != expected.Policy.Revision || p.AllowedDestination != expected.Policy.AllowedDestination || p.Mode != expected.Policy.Mode {
			writeProductionError(w, r, ErrRepositoryConflict)
			return
		}
		writes = append(writes, cohortWrite{p.Binding.Device, p.Binding.Generation, entry.Version, p.Revision, p.Mode, p.ExpiresAt, entry.Bundle})
	}
	payload, _ := json.Marshal(map[string]any{"phase": phase, "allowed_destination": destination, "expected_revision": signed.Revision, "targets": writes})
	raw, err = h.database.QueryJSON(r.Context(), cohortCommitSQL, append(base, cohort, key, digest, store.Snapshot, string(payload))...)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	if string(raw) == `"conflict"` {
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	writeProductionResponse(w, r, 200, raw, nil)
}
