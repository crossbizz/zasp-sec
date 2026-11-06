package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/optionalegress"
)

type optionalEgressCLIInstaller struct {
	*scriptedMigrationRunner
	normal, audit int
}

func (r *optionalEgressCLIInstaller) UpProductionOptionalEgressProfile(context.Context) error {
	r.normal++
	return nil
}
func (r *optionalEgressCLIInstaller) UpProductionOptionalEgressAuditProfile(context.Context) error {
	r.audit++
	return nil
}

// These exercise command dispatch/typed parsing, not installed PostgreSQL roles
// or provider policy approval. Native audit-profile acceptance is separate.
func TestOptionalEgressExplicitMigrationRecipes(t *testing.T) {
	for _, audit := range []bool{false, true} {
		command, pin := "up-optional-egress-profile", migrations.OptionalEgressProfileChecksum()
		if audit {
			command, pin = "up-optional-egress-audit-profile", migrations.OptionalEgressAuditProfileChecksum()
		}
		base := &optionalEgressCLIInstaller{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
		q := &releaseReadinessQueryer{}
		registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: q, registration: discoveryPrincipalRegistration{migration: "optional_operator"}}
		if !isForwardMigration([]string{command}) || isForwardMigration([]string{command, "extra"}) {
			t.Fatal("exact optional command classification")
		}
		if err := runReleaseMigration(context.Background(), registered, []string{command}); err != nil {
			t.Fatal(err)
		}
		if audit && (base.audit != 1 || base.normal != 0) || !audit && (base.normal != 1 || base.audit != 0) {
			t.Fatal("recipe dispatch crossed or fallback occurred")
		}
		post := &releaseReadinessQueryer{}
		if err := registerForwardRelease(context.Background(), post, registered.registration, []string{command}); err != nil || len(post.statements) != 1 || post.arguments[0][1] != pin || !strings.Contains(post.statements[0], "catalog_ready($2)") {
			t.Fatal("exact recipe post-install pin missing", err)
		}
		before := base.normal + base.audit
		for _, version := range []int64{0, 60, 62, 80} {
			base.version = version
			if err := runReleaseMigration(context.Background(), registered, []string{command}); !errors.Is(err, migrations.ErrInvalidState) {
				t.Fatal("noncanonical optional install admitted")
			}
		}
		base.version = 61
		registered.queryer = &releaseReadinessQueryer{failAt: 1}
		if err := runReleaseMigration(context.Background(), registered, []string{command}); !errors.Is(err, errReleasePrincipalRegistration) || base.normal+base.audit != before {
			t.Fatal("operator admission failure reached installer")
		}
		registered.queryer = q
		registered.releaseMigrationRunner = base.scriptedMigrationRunner
		if err := runReleaseMigration(context.Background(), registered, []string{command}); !errors.Is(err, migrations.ErrInvalidState) {
			t.Fatal("missing selected extension used fallback")
		}
	}
	var out bytes.Buffer
	if err := writeOptionalEgressChecksums(&out); err != nil {
		t.Fatal(err)
	}
	var pins map[string]string
	if json.Unmarshal(out.Bytes(), &pins) != nil || len(pins) != 2 || pins["normal"] != migrations.OptionalEgressProfileChecksum() || pins["audit"] != migrations.OptionalEgressAuditProfileChecksum() {
		t.Fatal("public checksum output invalid")
	}
}

func TestOptionalEgressOperatorInputsAndAtomicDispatch(t *testing.T) {
	const o = "pid_0e000002-0000-4000-8000-000000000002"
	const w = "pid_0e000003-0000-4000-8000-000000000003"
	const e = "pid_0e000004-0000-4000-8000-000000000004"
	scope := optionalEgressScopeInput{o, w, e}
	now := time.Now().UTC()
	profile := optionalegress.Profile{ProfileID: "pid_0e000005-0000-4000-8000-000000000005", ProfileVersion: 1, Provider: "openrouter", Purpose: optionalegress.Purpose, Model: "fixture/model", Backend: "Fixture Provider", AccountID: "fixture_account", CredentialReference: "secret_ref_ai/" + o + "/" + w + "/" + e + "/fixture_credential", CredentialDigest: "sha256:" + strings.Repeat("1", 64), CapabilityDigest: "sha256:" + strings.Repeat("2", 64), PricingDigest: "sha256:" + strings.Repeat("3", 64), EffectiveAt: now.Add(-time.Minute).Format(optionalegress.TimeFormat), ExpiresAt: now.Add(time.Hour).Format(optionalegress.TimeFormat), InputTokenBound: 1000, OutputTokenCap: 100, PromptPriceNanoCreditsPerMillion: 1000000, CompletionPriceNanoCreditsPerMillion: 1000000, CostCeilingNanoCredits: 2000, MaximumOutstandingNanoCredits: 200000, MaximumConcurrency: 4, TimeoutMilliseconds: 30000, PolicyVersion: "fixture_policy_v1"}
	profile.ProfileDigest, _ = optionalegress.ProfileDigest(profile)
	file := filepath.Join(t.TempDir(), "operator.json")
	env := map[string]string{migrationPrincipalEnvironment: "optional_operator", optionalEgressChecksumEnvironment: migrations.OptionalEgressAuditProfileChecksum(), optionalEgressInputEnvironment: file}
	getenv := func(k string) string { return env[k] }
	for _, tc := range []struct {
		command  string
		value    any
		function string
	}{
		{"register-optional-egress-principals", optionalEgressPrincipalInput{"optional_api", "optional_executor", "optional_captured"}, "register_principal"},
		{"configure-optional-egress-profile", optionalEgressApprovedProfileInput{scope, profile}, "register_profile"},
		{"activate-optional-egress-profile", optionalEgressActivationInput{scope, profile.ProfileID, 1, 3}, "activate_profile"},
	} {
		raw, _ := json.Marshal(tc.value)
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		parsed, err := loadOptionalEgressOperator([]string{tc.command}, getenv)
		if err != nil {
			t.Fatal("typed operator file refused", err)
		}
		if strings.Contains(fmt.Sprintf("%+v", parsed), o) || strings.Contains(fmt.Sprintf("%+v", parsed), "optional_api") {
			t.Fatal("operator input formatter leaked metadata")
		}
		q := &releaseReadinessQueryer{}
		if err := runOptionalEgressOperator(context.Background(), q, parsed); err != nil || len(q.statements) != 1 || !strings.Contains(q.statements[0], tc.function) || !strings.Contains(q.statements[0], "catalog_ready($2)") || q.arguments[0][1] != env[optionalEgressChecksumEnvironment] {
			t.Fatal("operator command lost atomic exact pin guard", err)
		}
		if tc.command == "register-optional-egress-principals" && strings.Count(q.statements[0], "register_principal(") != 3 {
			t.Fatal("principal purposes not registered in one atomic statement")
		}
		for _, databaseFailure := range []bool{false, true} {
			if err := runOptionalEgressOperator(context.Background(), &releaseReadinessQueryer{failAt: 1, queryError: databaseFailure}, parsed); !errors.Is(err, errReleasePrincipalRegistration) {
				t.Fatal("database failure exposed or admitted")
			}
		}
		if _, err := loadOptionalEgressOperator([]string{tc.command, "extra"}, getenv); !errors.Is(err, errInvalidMigrationCommand) {
			t.Fatal("extra argument accepted")
		}
	}
	for _, raw := range []string{`{"human_principal":"optional_api","planner_principal":"optional_executor","settlement_principal":"optional_captured","token":"private-secret"}`, `{"human_principal":"optional_api","human_principal":"other_api","planner_principal":"optional_executor","settlement_principal":"optional_captured"}`, `{"human_principal":null,"planner_principal":"optional_executor","settlement_principal":"optional_captured"}`, `{"HUMAN_PRINCIPAL":"optional_api","planner_principal":"optional_executor","settlement_principal":"optional_captured"}`, `{"human_principal":"optional_operator","planner_principal":"optional_executor","settlement_principal":"optional_captured"}`} {
		if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOptionalEgressOperator([]string{"register-optional-egress-principals"}, getenv); !errors.Is(err, errInvalidMigrationCommand) {
			t.Fatal("ambiguous/untrusted input accepted")
		}
	}
	valid, _ := json.Marshal(optionalEgressPrincipalInput{"optional_api", "optional_executor", "optional_captured"})
	if err := os.WriteFile(file, valid, 0600); err != nil {
		t.Fatal(err)
	}
	env[optionalEgressChecksumEnvironment] = strings.Repeat("0", 64)
	if _, err := loadOptionalEgressOperator([]string{"register-optional-egress-principals"}, getenv); err == nil {
		t.Fatal("uncompiled recipe selected")
	}
	env[optionalEgressChecksumEnvironment] = migrations.OptionalEgressAuditProfileChecksum()
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOptionalEgressOperator([]string{"register-optional-egress-principals"}, getenv); err == nil {
		t.Fatal("public operator configuration accepted")
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(file), "link.json")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	env[optionalEgressInputEnvironment] = link
	if _, err := loadOptionalEgressOperator([]string{"register-optional-egress-principals"}, getenv); err == nil {
		t.Fatal("symbolic operator file accepted")
	}
}
