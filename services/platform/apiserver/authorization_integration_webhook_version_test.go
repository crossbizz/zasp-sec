package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestP7WebhookSigningVersionValidationBoundary(t *testing.T) {
	for _, version := range []string{strings.Repeat("a", 32), strings.Repeat("b", 64)} {
		body := json.RawMessage(`{"connector_key":"generic-webhook","name":"Webhook","configuration":{"destination_url":"https://hooks.example.test/receive","signing_secret_reference":"secret_ref_customer","signing_secret_version":"` + version + `"}}`)
		original := string(body)
		if containsSensitiveIntegrationWorkflowValue(body, "createIntegration", false) || !containsSensitiveWorkflowField(body) || string(body) != original {
			t.Fatal("scoped copy allowance changed generic filter or original")
		}
		intent := json.RawMessage(`{"resource_id":"","expected_version":0,"body":` + string(body) + `}`)
		db := &workflowCallDatabase{response: json.RawMessage(`{"found":false}`)}
		repo := &PostgresRepository{database: db}
		if _, _, err := repo.ReplayWorkflow(context.Background(), fixtureRequestIdentity(t), "createIntegration", "versioned-replay-key", intent); err != nil || db.query == "" {
			t.Fatalf("valid metadata replay blocked: %v", err)
		}
	}
	invalid := []json.RawMessage{json.RawMessage(`"short"`), json.RawMessage(`"` + strings.Repeat("x", 65) + `"`), json.RawMessage(`"` + strings.Repeat("x", 31) + `!"`), json.RawMessage(`7`), json.RawMessage(`null`), json.RawMessage(`{}`), json.RawMessage(`[]`)}
	for _, value := range invalid {
		configuration := `{"destination_url":"https://hooks.example.test/receive","signing_secret_reference":"secret_ref_customer","signing_secret_version":` + string(value) + `}`
		assertWebhookRejectedBeforeIO(t, configuration, "")
	}
	for _, config := range []string{
		`{"destination_url":"https://hooks.example.test/receive","signing_secret_reference":"secret_ref_customer","Signing_Secret_Version":"` + strings.Repeat("x", 32) + `"}`,
		`{"destination_url":"https://hooks.example.test/receive","signing_secret_reference":"secret_ref_customer","secret_version":"` + strings.Repeat("x", 32) + `"}`,
	} {
		assertWebhookRejectedBeforeIO(t, config, "")
	}
	for _, field := range []string{"secret", "password", "token", "credential_value"} {
		configuration := `{"destination_url":"https://hooks.example.test/receive","signing_secret_reference":"secret_ref_customer","signing_secret_version":"` + strings.Repeat("x", 32) + `","` + field + `":"do-not-store"}`
		assertWebhookRejectedBeforeIO(t, configuration, "")
	}
	valid := `{"destination_url":"https://hooks.example.test/receive","signing_secret_reference":"secret_ref_customer","signing_secret_version":"` + strings.Repeat("x", 32) + `"}`
	for _, extra := range []string{`,"signing_secret_version":"` + strings.Repeat("x", 32) + `"`, `,"nested":{"password":"do-not-store"}`, `,"nested":[{"token":"do-not-store"}]`} {
		assertWebhookRejectedBeforeIO(t, valid, extra)
	}
	body := json.RawMessage(`{"connector_key":"github","configuration":` + valid + `}`)
	if !containsSensitiveIntegrationWorkflowValue(body, "createIntegration", false) || !containsSensitiveIntegrationWorkflowValue(body, "createPolicy", false) {
		t.Fatal("non-webhook/non-integration exception")
	}
}

func assertWebhookRejectedBeforeIO(t *testing.T, configuration, extra string) {
	t.Helper()
	body := json.RawMessage(`{"connector_key":"generic-webhook","name":"Webhook","configuration":` + configuration + extra + `}`)
	intent := json.RawMessage(`{"resource_id":"","expected_version":0,"body":` + string(body) + `}`)
	mutation := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationClientExisting, Operation: "createIntegration", IdempotencyKey: "versioned-invalid-key", Intent: intent, Body: body, AuditID: "pid_78200091-0000-4000-8000-000000000091", CorrelationID: testCorrelationID, ReceiptID: "pid_78200092-0000-4000-8000-000000000092"}
	if validWorkflowMutation(mutation) {
		t.Fatalf("sensitive malformed metadata admitted: %s", body)
	}
	db := &workflowCallDatabase{response: json.RawMessage(`{"found":false}`)}
	repo := &PostgresRepository{database: db}
	if _, _, err := repo.ReplayWorkflow(context.Background(), fixtureRequestIdentity(t), "createIntegration", "versioned-invalid-key", intent); err == nil || db.query != "" {
		t.Fatalf("malformed metadata reached native replay: %s %v", db.query, err)
	}
}
