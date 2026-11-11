package main

import (
	"bytes"
	"errors"
	"testing"
)

func environment(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

var validArguments = []string{"-organization-name", "Acme Security", "-domain", "acme.example", "-admin-email", "admin@acme.example"}

// A valid configuration that names an unreachable database, so a run that
// passes configuration is refused at the database stage without any provider
// or database write.
func validEnvironment() map[string]string {
	return map[string]string{
		"ZASP_POSTGRES_DSN": "postgres://operator@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1", "ZASP_PUBLIC_ORIGIN": "https://app.zasp.test",
		"ZASP_DEPLOYMENT_MODE": "saas", "ZASP_STYTCH_BASE_URL": "https://test.stytch.com",
		"ZASP_STYTCH_PROJECT_ID": "project-test-bootstrap", "ZASP_STYTCH_SECRET": "secret-test-bootstrap",
	}
}

func refusedStage(t *testing.T, arguments []string, values map[string]string) string {
	t.Helper()
	var output bytes.Buffer
	err := run(arguments, environment(values), &output)
	var refused refusal
	if !errors.As(err, &refused) {
		t.Fatalf("run = %v, want a staged refusal", err)
	}
	if output.Len() != 0 {
		t.Fatalf("refused run wrote output: %s", output.String())
	}
	return refused.stage
}

func TestBootstrapRefusesIncompleteArgumentsBeforeReadingConfiguration(t *testing.T) {
	for name, arguments := range map[string][]string{
		"no arguments":     nil,
		"missing email":    {"-organization-name", "Acme Security", "-domain", "acme.example"},
		"positional extra": append(append([]string{}, validArguments...), "extra"),
		"unknown flag":     append(append([]string{}, validArguments...), "-password", "x"),
		"timeout too long": append(append([]string{}, validArguments...), "-timeout", "1h"),
	} {
		t.Run(name, func(t *testing.T) {
			if stage := refusedStage(t, arguments, nil); stage != stageArguments {
				t.Fatalf("stage = %s", stage)
			}
		})
	}
}

func TestBootstrapRefusesInconsistentDeploymentConfiguration(t *testing.T) {
	for name, change := range map[string]func(map[string]string){
		"no database":               func(values map[string]string) { delete(values, "ZASP_POSTGRES_DSN") },
		"no public origin":          func(values map[string]string) { delete(values, "ZASP_PUBLIC_ORIGIN") },
		"insecure public origin":    func(values map[string]string) { values["ZASP_PUBLIC_ORIGIN"] = "http://app.zasp.test" },
		"unknown deployment mode":   func(values map[string]string) { values["ZASP_DEPLOYMENT_MODE"] = "hybrid" },
		"authorization store alone": func(values map[string]string) { values["ZASP_OPENFGA_STORE_ID"] = "01HZX0B00TSTRAPTESTST0RE01" },
		"saas with pinned organization": func(values map[string]string) {
			values["ZASP_ORGANIZATION_ID"] = "pid_10000001-0000-4000-8000-000000000001"
		},
		"saas with organization flag": func(values map[string]string) {
			values["flag-organization-id"] = "pid_10000001-0000-4000-8000-000000000001"
		},
		"single tenant without pin": func(values map[string]string) { values["ZASP_DEPLOYMENT_MODE"] = "single_tenant" },
		"no provider secret":        func(values map[string]string) { delete(values, "ZASP_STYTCH_SECRET") },
	} {
		t.Run(name, func(t *testing.T) {
			values := validEnvironment()
			change(values)
			arguments := validArguments
			if id := values["flag-organization-id"]; id != "" {
				arguments = append(append([]string{}, validArguments...), "-organization-id", id)
			}
			if stage := refusedStage(t, arguments, values); stage != stageConfiguration {
				t.Fatalf("stage = %s", stage)
			}
		})
	}
}

// A single-tenant deployment serves one configured Organization; the operator
// cannot bootstrap a different one into it.
func TestBootstrapSingleTenantOnlyProvisionsTheConfiguredOrganization(t *testing.T) {
	values := validEnvironment()
	values["ZASP_DEPLOYMENT_MODE"], values["ZASP_ORGANIZATION_ID"] = "single_tenant", "pid_10000001-0000-4000-8000-000000000001"
	other := append(append([]string{}, validArguments...), "-organization-id", "pid_20000002-0000-4000-8000-000000000002")
	if stage := refusedStage(t, other, values); stage != stageConfiguration {
		t.Fatalf("different organization stage = %s", stage)
	}
	// The configured Organization passes configuration and is refused only at
	// the unreachable database.
	if stage := refusedStage(t, validArguments, values); stage != stageDatabase {
		t.Fatalf("configured organization stage = %s", stage)
	}
}

func TestBootstrapNamesTheDatabaseStageWithoutEchoingTheDSN(t *testing.T) {
	stage := refusedStage(t, validArguments, validEnvironment())
	if stage != stageDatabase || (refusal{stage: stage}).Error() != "bootstrap refused: stage=database" {
		t.Fatalf("refusal = %q", (refusal{stage: stage}).Error())
	}
}
