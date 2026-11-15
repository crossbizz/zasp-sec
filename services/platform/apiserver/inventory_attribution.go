package apiserver

import (
	"regexp"
	"time"
)

// InventoryAttribution says where an inventory object lives, which
// integration found it and, for an agent, who created it and whom to ask
// when nobody has taken ownership. Every member is nil where the provider
// says nothing: nothing is guessed. The owner and team a person assigned are
// the summary's own Owner and Team; the suggestions here never replace them.
type InventoryAttribution struct {
	// Location is the account, project, subscription, tenant, organization,
	// repository, cluster or namespace the object was found in.
	Location *InventoryLocation `json:"location"`
	// Integration is the integration whose observation is the winning one.
	Integration *InventoryIntegrationReference `json:"integration"`
	// Creator is the identity the provider says created the agent.
	Creator *InventoryCreator `json:"creator"`
	// SuggestedOwner and SuggestedTeam are set only while no person has
	// assigned the owner, or the team.
	SuggestedOwner *InventorySuggestion `json:"suggested_owner"`
	SuggestedTeam  *InventorySuggestion `json:"suggested_team"`
}

// InventoryLocation names where an object was found. ID is the provider's
// identifier; Label is the provider's name for a tenant whose identifier is
// opaque and the identifier everywhere else.
type InventoryLocation struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Label string `json:"label"`
}

type InventoryIntegrationReference struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// InventoryCreator is who created an agent and how that is known: Source is
// cloudtrail, audit_log, provider_record, codeowners, label or annotation.
type InventoryCreator struct {
	Identity  string  `json:"identity"`
	CreatedAt *string `json:"created_at"`
	Source    string  `json:"source"`
}

// InventorySuggestion is a derived owner or team and where it comes from. A
// suggested owner has the source of the creator it is derived from; a
// suggested team has the source label (a label or annotation of the object)
// or okta (the department of the Okta user with the creator's email address).
type InventorySuggestion struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

var (
	inventoryLocationKinds = map[string]bool{
		"aws_account": true, "gcp_project": true, "gcp_scope": true, "github_repository": true, "github_organization": true,
		"kubernetes_namespace": true, "kubernetes_cluster": true, "microsoft_subscription": true, "power_platform_environment": true,
		"microsoft_tenant": true, "okta_tenant": true, "salesforce_org": true, "saas_workspace": true,
	}
	inventoryCreatorSources  = map[string]bool{"annotation": true, "audit_log": true, "cloudtrail": true, "codeowners": true, "label": true, "provider_record": true}
	inventoryTeamSources     = map[string]bool{"label": true, "okta": true}
	inventoryCreatorIdentity = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9._%+@:/=-]{0,253}$`)
)

// validInventoryAttribution checks the attribution of a summary. Only an
// agent has a creator or a suggestion, and a suggestion is absent once a
// person assigned the value it suggests.
func validInventoryAttribution(item InventorySummary, kind InventoryKind) bool {
	attribution := item.Attribution
	if attribution == nil {
		return true
	}
	if location := attribution.Location; location != nil && (!inventoryLocationKinds[location.Kind] || !printableInventoryString(location.ID, 1, 512, false) || !printableInventoryString(location.Label, 1, 256, false)) {
		return false
	}
	if integration := attribution.Integration; integration != nil && (!validProductID(integration.ID) || !printableInventoryString(integration.Name, 1, 128, false)) {
		return false
	}
	if kind != InventoryKindAgent {
		return attribution.Creator == nil && attribution.SuggestedOwner == nil && attribution.SuggestedTeam == nil
	}
	if creator := attribution.Creator; creator != nil {
		if !inventoryCreatorIdentity.MatchString(creator.Identity) || !inventoryCreatorSources[creator.Source] {
			return false
		}
		if creator.CreatedAt != nil {
			if _, err := time.Parse(time.RFC3339Nano, *creator.CreatedAt); err != nil {
				return false
			}
		}
	}
	if owner := attribution.SuggestedOwner; owner != nil && (item.Owner != "" || attribution.Creator == nil || owner.Value != attribution.Creator.Identity || owner.Source != attribution.Creator.Source || len(owner.Value) > 128) {
		return false
	}
	if team := attribution.SuggestedTeam; team != nil && (item.Team != "" || !inventoryTeamSources[team.Source] || !printableInventoryString(team.Value, 1, 128, false)) {
		return false
	}
	return true
}
