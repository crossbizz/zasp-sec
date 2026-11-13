package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/multisteppricing"
)

type pricingBindingDatabase struct {
	response   string
	err        error
	statements []string
	arguments  [][]any
}

func (d *pricingBindingDatabase) SchemaVersion(context.Context) (string, error) { return "", nil }
func (d *pricingBindingDatabase) Exec(context.Context, string, ...any) error    { return nil }
func (d *pricingBindingDatabase) QueryJSON(_ context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	d.statements = append(d.statements, statement)
	d.arguments = append(d.arguments, arguments)
	if d.err != nil {
		return nil, d.err
	}
	return json.RawMessage(d.response), nil
}

const (
	pricingTestOrganization = "pid_10000001-0000-4000-8000-000000000001"
	pricingTestWorkspace    = "pid_10000002-0000-4000-8000-000000000002"
	pricingTestEnvironment  = "pid_10000003-0000-4000-8000-000000000003"
)

func pricingTestPlanner() *productionSecurityAgentPlanner {
	return &productionSecurityAgentPlanner{endpoint: "https://openrouter.ai/api/v1/chat/completions", model: "openai/gpt-5-mini", token: []byte("sk-or-v1-0123456789abcdef0123456789abcdef"), maximumTokens: 2048, policyVersion: "security-agent-planner-v1", client: &http.Client{Timeout: 20 * time.Second}}
}

func pricingTestBinding() securityAgentMultistepPricingBinding {
	organization, _ := domain.ParseProductID(pricingTestOrganization)
	workspace, _ := domain.ParseProductID(pricingTestWorkspace)
	environment, _ := domain.ParseProductID(pricingTestEnvironment)
	scope, _ := domain.NewScope(organization, workspace, environment)
	policy, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_pricing_policy", "openrouter\x1fopenai/gpt-5-mini\x1fprimary")
	account, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_pricing_account", "openrouter\x1fprimary")
	return securityAgentMultistepPricingBinding{Scope: multisteppricing.Scope{OrganizationID: pricingTestOrganization, WorkspaceID: pricingTestWorkspace, EnvironmentID: pricingTestEnvironment}, AccountProfile: "primary", CredentialReference: "secret_ref_planner/" + pricingTestOrganization + "/" + pricingTestWorkspace + "/" + pricingTestEnvironment + "/openrouter", PolicyID: policy, PolicyVersion: 3, PolicyDigest: "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", AccountID: account, AccountVersion: 2}
}

// The database resolver asks the one authorized function for the run's scope
// and this planner's model, on every request, and admits only a binding for
// that scope that this planner can form a valid lookup for.
func TestDatabasePricingBindingResolvesScopeAtUseTime(t *testing.T) {
	planner := pricingTestPlanner()
	binding := pricingTestBinding()
	if !release61PlannerAvailable(planner, binding) {
		t.Fatal("fixture binding is not a valid lookup identity for the fixture planner")
	}
	encoded, _ := json.Marshal(binding)
	database := &pricingBindingDatabase{response: string(encoded)}
	resolver, err := newDatabaseSecurityAgentPricingBindings(database, planner, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		got, found, err := resolver.binding(context.Background(), pricingTestOrganization, pricingTestWorkspace, pricingTestEnvironment)
		if err != nil || !found || got != binding {
			t.Fatalf("binding=%#v found=%v err=%v", got, found, err)
		}
	}
	if len(database.statements) != 2 || database.statements[0] != securityAgentPricingBindingSQL {
		t.Fatalf("statements=%v, want one uncached authorized read per request", database.statements)
	}
	want := []any{pricingTestOrganization, pricingTestWorkspace, pricingTestEnvironment, "openrouter", "openai/gpt-5-mini"}
	for n := range want {
		if database.arguments[0][n] != want[n] {
			t.Fatalf("argument %d=%v want %v", n+1, database.arguments[0][n], want[n])
		}
	}

	// A scope without an approved policy has no binding; that is not an error.
	database.response = `null`
	if _, found, err := resolver.binding(context.Background(), pricingTestOrganization, pricingTestWorkspace, pricingTestEnvironment); err != nil || found {
		t.Fatalf("absent approval found=%v err=%v", found, err)
	}

	refused := func(name string) {
		t.Helper()
		if _, found, err := resolver.binding(context.Background(), pricingTestOrganization, pricingTestWorkspace, pricingTestEnvironment); !errors.Is(err, errWorkerExecution) || found {
			t.Fatalf("%s: found=%v err=%v", name, found, err)
		}
	}
	mutate := func(change func(*securityAgentMultistepPricingBinding)) string {
		other := pricingTestBinding()
		change(&other)
		raw, _ := json.Marshal(other)
		return string(raw)
	}
	for name, response := range map[string]string{
		"another organization": mutate(func(b *securityAgentMultistepPricingBinding) { b.OrganizationID = pricingTestWorkspace }),
		"another environment":  mutate(func(b *securityAgentMultistepPricingBinding) { b.EnvironmentID = pricingTestWorkspace }),
		"invalid reference":    mutate(func(b *securityAgentMultistepPricingBinding) { b.CredentialReference = "plain-secret" }),
		"invalid digest":       mutate(func(b *securityAgentMultistepPricingBinding) { b.PolicyDigest = "sha256:short" }),
		"zero policy version":  mutate(func(b *securityAgentMultistepPricingBinding) { b.PolicyVersion = 0 }),
		"unknown field":        string(encoded[:len(encoded)-1]) + `,"credential_digest":"sha256:00"}`,
		"not an object":        `[]`,
		"empty":                `{}`,
	} {
		database.response = response
		refused(name)
	}
	database.response, database.err = string(encoded), errors.New("database refused")
	refused("database error")
	database.err = nil

	calls := len(database.statements)
	if _, _, err := resolver.binding(context.Background(), "organization", pricingTestWorkspace, pricingTestEnvironment); !errors.Is(err, errWorkerExecution) || len(database.statements) != calls {
		t.Fatalf("invalid scope reached the database: err=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := resolver.binding(cancelled, pricingTestOrganization, pricingTestWorkspace, pricingTestEnvironment); !errors.Is(err, errWorkerExecution) || len(database.statements) != calls {
		t.Fatalf("cancelled context reached the database: err=%v", err)
	}
	planner.mu.Lock()
	planner.closed = true
	planner.mu.Unlock()
	refused("closed planner")

	if _, err := newDatabaseSecurityAgentPricingBindings(nil, planner, 5*time.Second); err == nil {
		t.Fatal("resolver built without a database")
	}
	if _, err := newDatabaseSecurityAgentPricingBindings(database, nil, 5*time.Second); err == nil {
		t.Fatal("resolver built without a planner")
	}
}

func TestStaticPricingBindingsSelectExactlyOneScope(t *testing.T) {
	binding := pricingTestBinding()
	other := pricingTestBinding()
	other.EnvironmentID = pricingTestWorkspace
	bindings := staticSecurityAgentPricingBindings{other, binding}
	got, found, err := bindings.binding(context.Background(), pricingTestOrganization, pricingTestWorkspace, pricingTestEnvironment)
	if err != nil || !found || got != binding {
		t.Fatalf("binding=%#v found=%v err=%v", got, found, err)
	}
	if _, found, _ := bindings.binding(context.Background(), pricingTestOrganization, pricingTestEnvironment, pricingTestEnvironment); found {
		t.Fatal("a binding of another Workspace was selected")
	}
	if _, found, _ := (staticSecurityAgentPricingBindings{binding, binding}).binding(context.Background(), pricingTestOrganization, pricingTestWorkspace, pricingTestEnvironment); found {
		t.Fatal("a duplicated scope selected a binding")
	}
}

// The mounted file stays an override: when configured it is loaded and every
// binding verified against the planner; when absent the database is used.
func TestPricingBindingsSelection(t *testing.T) {
	planner := pricingTestPlanner()
	database := &pricingBindingDatabase{response: `null`}
	resolver, err := securityAgentPricingBindingsFor(workerRuntimeConfig{}, database, planner)
	if _, ok := resolver.(*databaseSecurityAgentPricingBindings); err != nil || !ok {
		t.Fatalf("without a file resolver=%T err=%v", resolver, err)
	}
	if _, err := securityAgentPricingBindingsFor(workerRuntimeConfig{}, nil, planner); err == nil {
		t.Fatal("database resolver selected without a database")
	}
	directory := t.TempDir()
	write := func(name string, value any) string {
		raw, _ := json.Marshal(value)
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	valid := write("valid.json", []securityAgentMultistepPricingBinding{pricingTestBinding()})
	resolver, err = securityAgentPricingBindingsFor(workerRuntimeConfig{TemporalPricingBindingsFile: valid}, database, planner)
	if static, ok := resolver.(staticSecurityAgentPricingBindings); err != nil || !ok || len(static) != 1 {
		t.Fatalf("with a file resolver=%T err=%v", resolver, err)
	}
	if len(database.statements) != 0 {
		t.Fatal("the override file consulted the database")
	}
	invalid := pricingTestBinding()
	invalid.CredentialReference = "plain-secret"
	for name, path := range map[string]string{"unverifiable binding": write("invalid.json", []securityAgentMultistepPricingBinding{invalid}), "missing file": filepath.Join(directory, "absent.json"), "relative path": "bindings.json", "empty list": write("empty.json", []securityAgentMultistepPricingBinding{})} {
		if _, err := securityAgentPricingBindingsFor(workerRuntimeConfig{TemporalPricingBindingsFile: path}, database, planner); err == nil {
			t.Fatalf("%s was admitted", name)
		}
	}
}
