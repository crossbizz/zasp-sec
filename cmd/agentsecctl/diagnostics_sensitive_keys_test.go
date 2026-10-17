package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestDiagnosticsRejectsSensitiveMapKeysBeforeAnyCommandOutput(t *testing.T) {
	for _, field := range []string{"health", "versions", "configuration"} {
		t.Run(field, func(t *testing.T) {
			for _, key := range []string{"api_key", "vendor_token", "password", "private_key", "secret", "AUTHORIZATION"} {
				t.Run(key, func(t *testing.T) {
					input := safeDiagnosticsKeyInput()
					const seededValue = "opaque-negative-fixture-73921"
					switch field {
					case "health":
						input.Health[key] = seededValue
					case "versions":
						input.Versions[key] = seededValue
					case "configuration":
						input.Configuration[key] = seededValue
					}
					bundle, builderErr := BuildDiagnosticsBundle(input)
					encoded, err := jsonBytes(input)
					if err != nil {
						t.Fatal(err)
					}
					var output bytes.Buffer
					err = runCommand(&output, bytes.NewReader(encoded), []string{"diagnostics"}, "dev")
					if !errors.Is(builderErr, errResilienceRejected) || bundle.OrganizationID != "" || !errors.Is(err, errResilienceRejected) || output.Len() != 0 {
						t.Fatal("builder or actual diagnostics command admitted sensitive-key data instead of rejecting entire bundle")
					}
				})
			}
		})
	}
}

func TestDiagnosticsSensitiveKeyGuardPreservesSafeBundleAndValueRefusals(t *testing.T) {
	input := safeDiagnosticsKeyInput()
	bundle, err := BuildDiagnosticsBundle(input)
	if err != nil || bundle.Health["api"] != "ready" || bundle.Versions["product"] != "1.5.0" || bundle.Configuration["mode"] != "single_tenant" || len(bundle.Logs) != 1 {
		t.Fatal("safe diagnostics changed")
	}
	input.Health["api"] = "changed"
	input.Versions["product"] = "changed"
	input.Configuration["mode"] = "changed"
	input.Logs[0] = "changed"
	if bundle.Health["api"] != "ready" || bundle.Versions["product"] != "1.5.0" || bundle.Configuration["mode"] != "single_tenant" || bundle.Logs[0] != "request completed" {
		t.Fatal("diagnostics retained mutable input")
	}
	for _, field := range []string{"health", "versions", "configuration", "logs"} {
		t.Run(field, func(t *testing.T) {
			unsafe := safeDiagnosticsKeyInput()
			switch field {
			case "health":
				unsafe.Health["api"] = "token=opaque-negative-fixture"
			case "versions":
				unsafe.Versions["product"] = "token=opaque-negative-fixture"
			case "configuration":
				unsafe.Configuration["mode"] = "token=opaque-negative-fixture"
			case "logs":
				unsafe.Logs = []string{"Authorization: Bearer opaque-negative-fixture"}
			}
			encoded, err := jsonBytes(unsafe)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := runCommand(&output, bytes.NewReader(encoded), []string{"diagnostics"}, "dev"); !errors.Is(err, errResilienceRejected) || output.Len() != 0 {
				t.Fatal("existing unsafe value refusal changed")
			}
		})
	}
	encoded, err := jsonBytes(safeDiagnosticsKeyInput())
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runCommand(&output, bytes.NewReader(encoded), []string{"diagnostics"}, "dev"); err != nil || !bytes.Contains(output.Bytes(), []byte(`"organization_id":"org-a"`)) {
		t.Fatal("safe actual diagnostics command failed")
	}
}

func safeDiagnosticsKeyInput() DiagnosticsInput {
	return DiagnosticsInput{OrganizationID: "org-a", Health: map[string]string{"api": "ready"}, Versions: map[string]string{"product": "1.5.0"}, Configuration: map[string]string{"mode": "single_tenant"}, Logs: []string{"request completed"}}
}
