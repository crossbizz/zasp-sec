package apiserver

import "encoding/json"

// Exact lowercase keys match PostgreSQL jsonb access. Struct decoding would let
// an alternate-cased alias overwrite the actual action used by SQL.
func securityAgentExistingTestBodyAuthority(raw json.RawMessage) (bool, error) {
	body, unambiguous := budgetJSONObject(raw)
	if !unambiguous {
		return false, ErrRepositoryOperation
	}
	var actions []string
	if value, present := body["allowed_actions"]; present && json.Unmarshal(value, &actions) != nil {
		return false, ErrRepositoryOperation
	}
	_, referenced := body["existing_test"]
	return referenced || stringIn("run_test", actions...) || stringIn("rerun_test", actions...) || stringIn("start_attack_lab", actions...), nil
}

// Validate the original bytes before workflow canonicalization can erase
// duplicate keys. Required/optional names match the public definition schema.
func validateSecurityAgentDefinitionObject(raw json.RawMessage) error {
	parsed, unambiguous := budgetJSONObject(raw)
	if !unambiguous || len(raw) > 16*1024 {
		return ErrRepositoryOperation
	}
	keys := []string{"name", "trigger_kind", "trigger_source", "environment_ids", "autonomy", "max_steps", "max_duration_seconds", "temporary_policy_seconds", "ai_token_budget", "concurrency_limit", "allowed_actions", "verification_kind", "definition_version", "enabled"}
	for _, optional := range []string{"id", "max_ai_cost_nano_credits", "existing_test", "response_webhook_destination", "trigger_rules"} {
		if _, present := parsed[optional]; present {
			keys = append(keys, optional)
		}
	}
	if _, err := auditExportClosedObject(raw, 16*1024, keys...); err != nil {
		return ErrRepositoryOperation
	}
	if reference, present := parsed["existing_test"]; present {
		if _, err := decodeSecurityAgentExistingTestReference(reference); err != nil {
			return ErrRepositoryOperation
		}
	}
	if reference, present := parsed["response_webhook_destination"]; present {
		if _, err := decodeSecurityAgentResponseWebhookDestination(reference); err != nil {
			return ErrRepositoryOperation
		}
	}
	return nil
}

// The saved binding contains only an integration identity and version. SQL
// resolves the scoped destination and signing metadata at every authority edge.
type SecurityAgentResponseWebhookDestination struct {
	IntegrationID      string `json:"integration_id"`
	IntegrationVersion int64  `json:"integration_version"`
}

func decodeSecurityAgentResponseWebhookDestination(raw json.RawMessage) (SecurityAgentResponseWebhookDestination, error) {
	fail := SecurityAgentResponseWebhookDestination{}
	if _, err := auditExportClosedObject(raw, 1024, "integration_id", "integration_version"); err != nil {
		return fail, ErrRepositoryOperation
	}
	var value SecurityAgentResponseWebhookDestination
	if decodeStrictDiscovery(raw, &value) != nil || !validProductID(value.IntegrationID) || value.IntegrationVersion < 1 || value.IntegrationVersion > 1000000 {
		return fail, ErrRepositoryOperation
	}
	return value, nil
}

// This reference records operator intent, not authorization. Durable admission
// must resolve its exact scope/version and recheck target safety and credentials.
type SecurityAgentExistingTestReference struct {
	DefinitionID      string `json:"definition_id"`
	DefinitionVersion int64  `json:"definition_version"`
}

type securityAgentExistingTestReference = SecurityAgentExistingTestReference

func decodeSecurityAgentExistingTestReference(raw json.RawMessage) (securityAgentExistingTestReference, error) {
	fail := securityAgentExistingTestReference{}
	if _, err := auditExportClosedObject(raw, 1024, "definition_id", "definition_version"); err != nil {
		return fail, ErrRepositoryOperation
	}
	var value securityAgentExistingTestReference
	if decodeStrictDiscovery(raw, &value) != nil || !validProductID(value.DefinitionID) || value.DefinitionVersion < 1 || value.DefinitionVersion > 1000000 {
		return fail, ErrRepositoryOperation
	}
	return value, nil
}
