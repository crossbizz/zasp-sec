package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"testing"
)

type environmentClassCLIInstaller struct {
	*scriptedMigrationRunner
	normal, audit int
}

func (r *environmentClassCLIInstaller) UpProductionEnvironmentClassProfile(context.Context) error {
	r.normal++
	return nil
}
func (r *environmentClassCLIInstaller) UpProductionEnvironmentClassAuditProfile(context.Context) error {
	r.audit++
	return nil
}

// These exercise command dispatch/typed parsing, not installed PostgreSQL roles
// or provider policy approval. Native audit-profile acceptance is separate.
func TestEnvironmentClassExplicitMigrationRecipes(t *testing.T) {
	for _, audit := range []bool{false, true} {
		command, pin := "up-environment-class-profile", migrations.EnvironmentClassProfileChecksum()
		if audit {
			command, pin = "up-environment-class-audit-profile", migrations.EnvironmentClassAuditProfileChecksum()
		}
		base := &environmentClassCLIInstaller{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
		q := &releaseReadinessQueryer{}
		registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: q, registration: discoveryPrincipalRegistration{migration: "environment_operator"}}
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
	if err := writeEnvironmentClassChecksums(&out); err != nil {
		t.Fatal(err)
	}
	var pins map[string]string
	if json.Unmarshal(out.Bytes(), &pins) != nil || len(pins) != 2 || pins["normal"] != migrations.EnvironmentClassProfileChecksum() || pins["audit"] != migrations.EnvironmentClassAuditProfileChecksum() {
		t.Fatal("public checksum output invalid")
	}
}

func TestEnvironmentClassExplicitChecksumSelection(t *testing.T) {
	for _, command := range []string{"up-environment-class-profile", "up-environment-class-audit-profile"} {
		correct := environmentClassCommandPin(command)
		for _, value := range []string{"", strings.Repeat("0", 64), correct} {
			err := validateEnvironmentClassCommand([]string{command}, func(string) string { return value })
			if (err == nil) != (value == correct) {
				t.Fatal("unselected or wrong recipe admitted")
			}
		}
		if validateEnvironmentClassCommand([]string{command, "extra"}, func(string) string { return correct }) == nil {
			t.Fatal("extra command argument admitted")
		}
	}
}
