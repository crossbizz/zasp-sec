package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type sensorNodeCoverageCLIInstaller struct {
	*scriptedMigrationRunner
	normal, audit int
}

func (r *sensorNodeCoverageCLIInstaller) UpProductionSensorNodeCoverageProfile(context.Context) error {
	r.normal++
	return nil
}
func (r *sensorNodeCoverageCLIInstaller) UpProductionSensorNodeCoverageAuditProfile(context.Context) error {
	r.audit++
	return nil
}

// Existing actual command/registered-runner/confirmation entry points are used.
// Transactions below are controlled interface fixtures: no actual CLI process,
// PostgreSQL SET LOCAL semantics, token, native or deployment proof is claimed.
func TestSensorNodeCoverageMigrationDispatchAndConfirmation(t *testing.T) {
	for _, audit := range []bool{false, true} {
		command, pin := "up-sensor-node-coverage-profile", migrations.SensorNodeCoverageProfileChecksum()
		if audit {
			command, pin = "up-sensor-node-coverage-audit-profile", migrations.SensorNodeCoverageAuditProfileChecksum()
		}
		t.Run(command, func(t *testing.T) {
			for _, mode := range []string{"dispatch", "source-principal-refused", "canonical61-refused", "strict-arguments", "confirm-accepted", "confirm-catalog-refused", "confirm-unknown-commit", "confirm-canceled"} {
				t.Run(mode, func(t *testing.T) {
					base := &sensorNodeCoverageCLIInstaller{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
					q := &releaseReadinessQueryer{}
					if mode == "source-principal-refused" {
						q.failAt = 1
					}
					registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: q, registration: discoveryPrincipalRegistration{migration: "sensor_node_coverage_operator"}}
					if strings.HasPrefix(mode, "confirm-") {
						tx := &maintenanceConfirmationTransaction{deny: mode == "confirm-catalog-refused", uncertain: mode == "confirm-unknown-commit"}
						plain := &maintenanceConfirmationTransaction{}
						ctx, cancel := context.WithCancel(context.Background())
						defer cancel()
						if mode == "confirm-canceled" {
							cancel()
						}
						begins := 0
						err := confirmForwardRelease(ctx, plain, func(context.Context) (retentionOperatorTransaction, error) { begins++; return tx, nil }, registered.registration, []string{command})
						if plain.reads != 0 {
							t.Fatal("private coverage confirmation used original unselected frame")
						}
						if mode == "confirm-canceled" {
							if err == nil || tx.reads != 0 || tx.committed {
								t.Fatal("canceled confirmation reached private metadata")
							}
							return
						}
						if begins != 1 || !tx.authority || tx.reads != 1 || !tx.rolled || len(tx.arguments) != 2 || tx.arguments[0] != "sensor_node_coverage_operator" || tx.arguments[1] != pin || !strings.Contains(tx.statement, "session_user=$1") || !strings.Contains(tx.statement, "zasp_sensor_coverage_v1.raw_seal_ready()") || !strings.Contains(tx.statement, "zasp_sensor_coverage_v1.effective_ready()") || strings.Contains(tx.statement, "catalog_ready(") {
							t.Fatal("finite own-profile confirmation/session/pin/role contract missing")
						}
						if mode == "confirm-accepted" {
							if err != nil || !tx.committed {
								t.Fatal("valid confirmed coverage profile refused")
							}
						} else if err == nil || mode == "confirm-catalog-refused" && tx.committed {
							t.Fatal("unverified coverage confirmation reported success")
						}
						return
					}
					if mode == "strict-arguments" {
						if isForwardMigration([]string{command, "extra"}) || runReleaseMigration(context.Background(), registered, []string{command, "extra"}) == nil || base.normal+base.audit != 0 {
							t.Fatal("extra command arguments reached installation")
						}
						return
					}
					if mode == "canonical61-refused" {
						base.version = 60
					}
					err := runReleaseMigration(context.Background(), registered, []string{command})
					if mode != "dispatch" {
						if err == nil || base.normal+base.audit != 0 {
							t.Fatal("refused source/canonical parent reached installer")
						}
						return
					}
					if !isForwardMigration([]string{command}) || err != nil {
						t.Fatal("actual coverage forward command dispatch absent")
					}
					if audit && (base.audit != 1 || base.normal != 0) || !audit && (base.normal != 1 || base.audit != 0) {
						t.Fatal("coverage Normal/Audit dispatch crossed recipe")
					}
					if len(q.statements) != 1 || q.statements[0] != `SELECT session_user=$1 AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')` || len(q.arguments[0]) != 1 || q.arguments[0][0] != "sensor_node_coverage_operator" {
						t.Fatal("source preread exceeded public identity/membership or lost configured operator")
					}
				})
			}
		})
	}
}

// Successor coverage added after the actual initial attempt was OPA setup
// blocked at zero cases. No tests-first behavior RED is claimed for these helpers.
func TestSensorNodeCoverageCLIInputsAndChecksums(t *testing.T) {
	for _, audit := range []bool{false, true} {
		command, pin := "up-sensor-node-coverage-profile", migrations.SensorNodeCoverageProfileChecksum()
		if audit {
			command, pin = "up-sensor-node-coverage-audit-profile", migrations.SensorNodeCoverageAuditProfileChecksum()
		}
		t.Run(command, func(t *testing.T) {
			if validateSensorNodeCoverageCommand([]string{command}, func(k string) string {
				if k == sensorNodeCoverageChecksumEnvironment {
					return pin
				}
				return ""
			}) != nil {
				t.Fatal("exact selected recipe pin refused")
			}
			for _, args := range [][]string{nil, {}, {command, "extra"}, {"up"}, {"sensor-node-coverage-profile-checksums"}} {
				if validateSensorNodeCoverageCommand(args, func(string) string { return pin }) == nil {
					t.Fatal("invalid command arguments admitted")
				}
			}
			other := migrations.SensorNodeCoverageAuditProfileChecksum()
			if audit {
				other = migrations.SensorNodeCoverageProfileChecksum()
			}
			if validateSensorNodeCoverageCommand([]string{command}, nil) == nil || validateSensorNodeCoverageCommand([]string{command}, func(string) string { return other }) == nil || validateSensorNodeCoverageCommand([]string{command}, func(string) string { return "" }) == nil {
				t.Fatal("missing or cross-variant explicit pin admitted")
			}
		})
	}
	var b bytes.Buffer
	if writeSensorNodeCoverageChecksums(nil) == nil || writeSensorNodeCoverageChecksums(&b) != nil {
		t.Fatal("checksum report writer validation changed")
	}
	var v struct {
		Normal string `json:"normal"`
		Audit  string `json:"audit"`
	}
	if json.Unmarshal(b.Bytes(), &v) != nil || v.Normal != migrations.SensorNodeCoverageProfileChecksum() || v.Audit != migrations.SensorNodeCoverageAuditProfileChecksum() {
		t.Fatal("checksum report lost exact selected recipes")
	}
}
