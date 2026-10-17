package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type agentOwnershipWriteCLIInstaller struct {
	*scriptedMigrationRunner
	normal, audit int
}

func (r *agentOwnershipWriteCLIInstaller) UpProductionAgentOwnershipWriteProfile(context.Context) error {
	r.normal++
	return nil
}
func (r *agentOwnershipWriteCLIInstaller) UpProductionAgentOwnershipWriteAuditProfile(context.Context) error {
	r.audit++
	return nil
}

// Successor coverage after product drafting; the first API attempt was a
// dependency setup block, not an executed behavioral RED or compiler pass.
func TestAgentCurrentOwnershipWriteMigrationRecipesAndBoundedConfirmation(t *testing.T) {
	for _, audit := range []bool{false, true} {
		command, pin := "up-agent-ownership-write-profile", migrations.AgentOwnershipWriteProfileChecksum()
		if audit {
			command, pin = "up-agent-ownership-write-audit-profile", migrations.AgentOwnershipWriteAuditProfileChecksum()
		}
		t.Run(command, func(t *testing.T) {
			if !isForwardMigration([]string{command}) || isForwardMigration([]string{command, "extra"}) {
				t.Fatal("Agent ownership write command classification changed")
			}
			if validateAgentOwnershipWriteCommand([]string{command}, func(k string) string {
				if k == agentOwnershipWriteChecksumEnvironment {
					return pin
				}
				return ""
			}) != nil || validateAgentOwnershipWriteCommand([]string{command}, func(string) string { return "unknown" }) == nil {
				t.Fatal("exact compiled migration pin gate failed")
			}
			base := &agentOwnershipWriteCLIInstaller{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
			registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: &releaseReadinessQueryer{}, registration: discoveryPrincipalRegistration{migration: "agent_ownership_write_operator"}}
			if err := runReleaseMigration(context.Background(), registered, []string{command}); err != nil {
				t.Fatal(err)
			}
			if audit && (base.audit != 1 || base.normal != 0) || !audit && (base.normal != 1 || base.audit != 0) {
				t.Fatal("profile dispatch crossed mode")
			}
			base.version = 60
			if err := runReleaseMigration(context.Background(), registered, []string{command}); !errors.Is(err, migrations.ErrInvalidState) {
				t.Fatal("noncanonical install admitted")
			}
			for _, mode := range []string{"accepted", "catalog refused", "uncertain commit", "canceled"} {
				t.Run(mode, func(t *testing.T) {
					tx := &maintenanceConfirmationTransaction{deny: mode == "catalog refused", uncertain: mode == "uncertain commit"}
					plain := &maintenanceConfirmationTransaction{}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if mode == "canceled" {
						cancel()
					}
					begins := 0
					err := confirmForwardRelease(ctx, plain, func(context.Context) (retentionOperatorTransaction, error) { begins++; return tx, nil }, registered.registration, []string{command})
					if plain.reads != 0 {
						t.Fatal("private Agent catalog read on unselected original role")
					}
					if mode == "canceled" {
						if err == nil || tx.reads != 0 || tx.committed {
							t.Fatal("canceled confirm reached catalog")
						}
						return
					}
					if begins != 1 || !tx.authority || tx.reads != 1 || !tx.rolled || len(tx.arguments) != 2 || tx.arguments[0] != "agent_ownership_write_operator" || tx.arguments[1] != pin {
						t.Fatal("bounded Agent confirm lost configured session/pin/transaction")
					}
					if mode == "accepted" {
						if err != nil || !tx.committed {
							t.Fatal("valid Agent confirmation failed")
						}
					} else if err == nil || mode == "catalog refused" && tx.committed {
						t.Fatal("refused or uncertain confirmation succeeded")
					}
				})
			}
		})
	}
	var output bytes.Buffer
	if err := writeAgentOwnershipWriteChecksums(&output); err != nil {
		t.Fatal(err)
	}
	var pins struct {
		Normal string `json:"normal"`
		Audit  string `json:"audit"`
	}
	if json.Unmarshal(output.Bytes(), &pins) != nil || pins.Normal != migrations.AgentOwnershipWriteProfileChecksum() || pins.Audit != migrations.AgentOwnershipWriteAuditProfileChecksum() {
		t.Fatal("operator checksum recipe export changed")
	}
}
