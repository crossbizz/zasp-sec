package authorization

import (
	_ "embed"
	"encoding/json"
)

// OperationPolicy is an explicit inventory, not a new credential middleware.
// Empty Relation requires the existing bootstrap/session handler contract, never
// anonymous bypass. FreshAuth retains the route flag, including its PAT branch.
//
// Permission is what the credential must hold: an API token's own permissions
// must include it. Relation is what the principal is checked for against the
// authorization model. They are the same for every operation but the ones in
// TokenPermissionOperations.
type OperationPolicy struct {
	ID, Method, Path, Permission, Relation, Surface string
	Security                                        []string
	FreshAuth                                       bool
}

// TokenPermissionOperations are the operations whose Permission is a
// permission of an API token only and not a relation of the authorization
// model, with the relation each one checks instead. The guardrail decision
// API is one: its token needs decide_guardrails, which no role holds, and the
// token's owner must be able to view the Environment. A token created for a
// gateway with that permission alone therefore cannot read inventory,
// findings or anything else, and a token with view alone cannot ask for
// decisions.
//
// The traffic routes of the hosted gateway require
// use_gateway, which no role holds either, so a token created for an agent's
// gateway traffic cannot read the Environment and a reading token cannot
// send traffic. Add-on submission, endpoint sync and workload decisions also
// intersect a narrow token ceiling with the principal's Environment view.
var TokenPermissionOperations = map[string]string{
	"recordBrowserOriginDays":      "view",
	"exchangeEndpointEnrollment":   "view",
	"recordEndpointHeartbeat":      "view",
	"recordEndpointInventory":      "view",
	"recordEndpointObservations":   "view",
	"fetchEndpointPolicy":          "view",
	"createWorkloadActionDecision": "view",
	"recordWorkloadActionOutcome":  "view",
	"createGuardrailDecision":      "view",
	"attestAddonScan":              "view",
	"submitAddonScan":              "view",
	"callMCPGateway":               "view",
	"closeMCPGatewaySession":       "view",
	"createGatewayChatCompletion":  "view",
	"createGatewayResponse":        "view",
	"createGatewayMessage":         "view",
}

//go:embed operations.json
var operationBytes []byte

func Operations() []OperationPolicy {
	var result []OperationPolicy
	// This embedded build artifact is checked against current API source in tests.
	if json.Unmarshal(operationBytes, &result) != nil {
		return nil
	}
	return result
}
func LookupOperation(id string) (OperationPolicy, error) {
	for _, policy := range Operations() {
		if policy.ID == id {
			return policy, nil
		}
	}
	return OperationPolicy{}, ErrInvalid
}
