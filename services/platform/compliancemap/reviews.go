package compliancemap

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// Product surfaces are named independently of any tenant's instrumentation.
// A scope can be applicable even if an environment has never sent a receipt.
const (
	managedEndpoint   = "managed_endpoint"
	addonSupply       = "addon_supply_chain"
	governedAction    = "governed_action"
	identityInventory = "identity_inventory"
	contextAdapter    = "context_adapter"
	modelPipeline     = "model_data_promotion"
)

// The web surface detail and the scoped catalog share this bounded inventory.
//
//go:embed surfaces.json
var productSurfaceIndex []byte

var allSurfaces = func() string {
	var rows []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(productSurfaceIndex, &rows); err != nil {
		panic(err)
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	return strings.Join(ids, ",")
}()

type surfaceReason struct{ scope, reason string }

var atlasReviews = map[string]surfaceReason{
	"AML.T0051":     {governedAction, "Requires attributable input and a reviewed result on a governed route. Policy configuration alone describes exposure."},
	"AML.T0051.001": {governedAction + "," + contextAdapter, "An indirect-input determination requires source provenance and a reviewed input-to-action test. Receiving external content is common in legitimate sessions."},
	"AML.T0053":     {governedAction, "Invocation requires an attributable tool action. The published title differs from the legacy label LLM Plugin Compromise. An unapproved installation or normal invocation cannot establish adversary use."},
	"AML.T0055":     {identityInventory, "Credential inventory identifies relationships. An unsecured credential observation requires separate evidence of actual exposure."},
	"AML.T0109":     {addonSupply, "Requires a previously trusted artifact, the exact replacement and independent confirmation that the replacement was malicious. A changed digest can be a routine upgrade."},
	"AML.T0110":     {addonSupply + "," + governedAction, "Requires independently confirmed poisoning of an identified tool version. A text match, installation or ordinary invocation is insufficient."},
	"AML.M0014":     {addonSupply + "," + modelPipeline, "Artifact verification requires an attributable check against an approved digest, version or signature. A version inventory alone establishes neither authenticity nor rejection."},
	"AML.M0028":     {governedAction + "," + managedEndpoint, "Test access control for the scoped tool or adapter. An independent target observation is required for verified prevention."},
	"AML.T0080":     {contextAdapter, "Writer, record and recall provenance can establish which context version was used. A legitimate write is a counterexample to a poisoning claim."},
	"AML.T0070":     {contextAdapter, "An authorized retrieval record locates a document version. Confirmed poisoning requires separate evidence about that content."},
	"AML.T0086":     {governedAction, "A tool can send data externally. Confirmation requires attributable data class, destination and independent delivery evidence."},
	"AML.T0099":     {contextAdapter + "," + governedAction, "The relevant scope is data presented to a tool. Independently reviewed data integrity and use are required."},
	"AML.M0024":     {governedAction + "," + contextAdapter, "Authenticated session observations can support a telemetry review within the named adapter."},
	"AML.M0025":     {modelPipeline, "Review approved source and promoted version in the supported model or dataset adapter."},
	"AML.M0029":     {governedAction, "A bound approval must identify the presented recipient, action and expiry as well as the decision."},
	"AML.M0036":     {governedAction, "Resource-limit evaluation requires an independent meter and an attributable bounded workflow."},
}

var owaspReviews = map[string]surfaceReason{
	"ASI01": {governedAction, "Declared purpose and bound destination can be compared with the observed action. A deviation does not establish its cause."},
	"ASI02": {governedAction, "Tool inventory and governed actions support separate reviews of available and exercised authority."},
	"ASI03": {identityInventory + "," + governedAction, "Review effective identity privileges and the principal bound to each action."},
	"ASI04": {addonSupply + "," + managedEndpoint, "Reviewed local add-on files, versions, approvals and dependency provenance inform supply-chain posture."},
	"ASI05": {managedEndpoint + "," + governedAction, "Distinguish a capability that could run code from a process or action that was observed."},
	"ASI06": {contextAdapter, "Versioned writes and recalls can identify the record used by an instrumented workflow."},
	"ASI07": {governedAction, "Review the recorded sender, recipient, authentication and freshness on a named handoff."},
	"ASI08": {governedAction, "Correlate related operations and bounded retries. Scope the result to the recorded workflow."},
	"ASI09": {governedAction, "Compare the displayed approval with the executed action, recipient, scope and expiry."},
	"ASI10": {identityInventory + "," + governedAction, "Missing ownership is inventory posture. Agent behavior requires corresponding observed actions."},
	"LLM01": {governedAction + "," + contextAdapter, "Input provenance and independently reviewed effects establish the scope of a prompt-injection test."},
	"LLM02": {governedAction, "Effective egress permissions and confirmed disclosure are different observations."},
	"LLM03": {addonSupply + "," + managedEndpoint, "Review exact component versions, provenance and approval at the observed installation or repository."},
	"LLM04": {modelPipeline, "Review promotion approval and artifact integrity for the recorded model or dataset version."},
	"LLM05": {governedAction, "Typed output validation requires the downstream consumer and validation result."},
	"LLM06": {identityInventory + "," + governedAction, "Permission inventory describes capability. Exercised authority requires an action record."},
	"LLM07": {contextAdapter, "A controlled marker test identifies the specific hidden-context boundary that was inspected."},
	"LLM08": {contextAdapter, "A retrieval adapter can report collection, document ACL decision and tenant binding."},
	"LLM09": {contextAdapter, "Only a workflow with a named source of truth supports an assessment of grounding."},
	"LLM10": {governedAction, "A metered route can test scoped budgets and reconcile independently measured usage."},
}

// These reviewed cross-edition associations name equivalent topics, including
// the broadening of system prompt leakage. They never carry evidence by rank.
var llm2026 = map[string]string{
	"LLM01": "LLM01", "LLM02": "LLM02", "LLM03": "LLM04", "LLM04": "LLM05", "LLM05": "LLM10",
	"LLM06": "LLM03", "LLM07": "LLM08", "LLM08": "LLM09", "LLM09": "LLM07", "LLM10": "LLM06",
}

func scopeReview(entry CatalogEntry) (owner, applicability, scope, rationale string) {
	if entry.Status == "retired" {
		return "Detection engineering", "out_of_scope", allSurfaces, "Legacy Zasp identifier absent from the pinned release. Historical links retain their old title. No successor or current evidence is inferred."
	}
	if entry.Framework == EnterpriseFramework {
		return "Endpoint security", "applicable", managedEndpoint, "Scoped T1059 review requires an attributable process launch, interpreter identity, supported OS, adapter version and session. An installed script or source-code match does not establish execution."
	}
	if entry.Framework == ATLASFramework {
		if review, ok := atlasReviews[entry.UpstreamID]; ok {
			return "Detection engineering", "applicable", review.scope, review.reason
		}
		switch entry.UpstreamID {
		case "AML.T0041", "AML.T0008.001", "AML.T0008.003", "AML.T0010.000":
			return "Detection engineering", "out_of_scope", allSurfaces, "The supported software adapters do not observe physical acquisition, access or hardware supply-chain operations."
		default:
			return "Detection engineering", "unassessed", allSurfaces, "No reviewed association to a supported adapter or workflow is recorded for this entry. Each surface remains unassessed."
		}
	}
	id := entry.UpstreamID
	if entry.Framework == LLMFramework && entry.Edition == "2026" {
		for previous, current := range llm2026 {
			if current == id {
				id = previous
				break
			}
		}
	}
	review := owaspReviews[id]
	return "Application security", "applicable", review.scope, review.reason
}

// ReviewSurface returns the catalog decision for one product surface. An
// association reviewed for another adapter is unassessed on this surface.
func ReviewSurface(entry CatalogEntry, surface string) (applicability, rationale string, known bool) {
	current, ok := LookupEdition(entry.Framework, entry.Edition, entry.UpstreamID)
	if !ok || !containsSurface(allSurfaces, surface) {
		return "", "", false
	}
	if containsSurface(current.Scope, surface) {
		return current.Applicability, current.Rationale, true
	}
	return "unassessed", "No association has been reviewed on this product surface.", true
}

func containsSurface(scopes, surface string) bool {
	for _, scope := range strings.Split(scopes, ",") {
		if scope == surface {
			return true
		}
	}
	return false
}
