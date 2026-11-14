package demodata

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed extras/mcp-registry.json
var registryDecisions []byte

// RegistryDecision is one decision of the approved-servers registry: the
// identity of an MCP server as the inventory states it, and what a reviewer
// decided about it.
type RegistryDecision struct {
	Identity string `json:"identity"`
	// Status is "approved" or "blocked".
	Status string `json:"status"`
	Note   string `json:"note"`
}

// RegistryDecisions are the registry decisions of the dataset.
func RegistryDecisions() ([]RegistryDecision, error) {
	var decisions []RegistryDecision
	decoder := json.NewDecoder(bytes.NewReader(registryDecisions))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decisions); err != nil {
		return nil, fmt.Errorf("%w: extras/mcp-registry.json: %v", ErrDataset, err)
	}
	seen := map[string]bool{}
	for _, decision := range decisions {
		if decision.Identity == "" || seen[decision.Identity] || decision.Status != "approved" && decision.Status != "blocked" ||
			decision.Note == "" || len(decision.Note) > 512 || strings.TrimSpace(decision.Note) != decision.Note {
			return nil, fmt.Errorf("%w: extras/mcp-registry.json: decision for %q", ErrDataset, decision.Identity)
		}
		seen[decision.Identity] = true
	}
	return decisions, nil
}
