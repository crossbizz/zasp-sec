package infraprovider

import (
	"errors"
	"strings"
	"testing"
)

func TestLegacyAndExplicitProviderSelections(t *testing.T) {
	for _, env := range []map[string]string{
		{},
		{
			"ZASP_SECRETS_PROVIDER":          "aws-secrets-manager",
			"ZASP_RECOVERY_SIGNING_PROVIDER": "aws-kms",
			"ZASP_EVIDENCE_PROVIDER":         "s3",
			"ZASP_EVIDENCE_ENCRYPTION":       "aws-kms",
			"ZASP_QUEUE_PROVIDER":            "sqs",
		},
		{"ZASP_BACKUP_PROVIDER": "r2", "ZASP_QUEUE_PROVIDER": "sqs"},
		{"ZASP_CONNECTOR_SECRETS_PROVIDER": "openbao", "ZASP_RECOVERY_SIGNING_PROVIDER": "openbao", "ZASP_EVIDENCE_ENCRYPTION": "provider-managed"},
	} {
		if err := Validate(func(key string) string { return env[key] }); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInvalidProviderSelectionsAreRedacted(t *testing.T) {
	for _, setting := range settings {
		t.Run(setting.name, func(t *testing.T) {
			const sensitive = "mistakenly-pasted-secret"
			for _, value := range []string{sensitive, " " + setting.choices[0], strings.ToUpper(setting.choices[0])} {
				env := map[string]string{setting.name: value}
				err := Validate(func(key string) string { return env[key] })
				var selection *SelectionError
				if !errors.As(err, &selection) {
					t.Fatalf("expected a selection error for %s", setting.name)
				}
				message := selection.Error()
				if !strings.Contains(message, setting.name) || !strings.Contains(message, setting.choices[0]) || strings.Contains(message, sensitive) {
					t.Fatal("provider diagnostic must name the setting and supported value without echoing input")
				}
			}
		})
	}
}

func TestUnavailableRuntimeProvidersFailClosed(t *testing.T) {
	for key, value := range map[string]string{
		"ZASP_SECRETS_PROVIDER":  "cloudflare",
		"ZASP_EVIDENCE_PROVIDER": "r2",
		"ZASP_QUEUE_PROVIDER":    "cloudflare",
	} {
		env := map[string]string{key: value}
		if err := Validate(func(name string) string { return env[name] }); err == nil {
			t.Errorf("%s accepted an unsupported provider", key)
		}
	}
}
