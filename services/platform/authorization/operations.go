package authorization

import (
	_ "embed"
	"encoding/json"
)

// OperationPolicy is an explicit inventory, not a new credential middleware.
// Empty Relation requires the existing bootstrap/session handler contract, never
// anonymous bypass. FreshAuth retains the route flag, including its PAT branch.
type OperationPolicy struct {
	ID, Method, Path, Permission, Relation, Surface string
	Security                                        []string
	FreshAuth                                       bool
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
