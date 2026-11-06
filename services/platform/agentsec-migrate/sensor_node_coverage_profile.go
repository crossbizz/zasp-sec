package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"io"
)

const sensorNodeCoverageChecksumEnvironment = "ZASP_SENSOR_NODE_COVERAGE_PROFILE_CHECKSUM"

func sensorNodeCoverageProfileCommand(command string) bool {
	return command == "up-sensor-node-coverage-profile" || command == "up-sensor-node-coverage-audit-profile"
}
func sensorNodeCoverageCommandPin(command string) string {
	if command == "up-sensor-node-coverage-profile" {
		return migrations.SensorNodeCoverageProfileChecksum()
	}
	if command == "up-sensor-node-coverage-audit-profile" {
		return migrations.SensorNodeCoverageAuditProfileChecksum()
	}
	return ""
}
func validateSensorNodeCoverageCommand(arguments []string, getenv func(string) string) error {
	if len(arguments) != 1 || getenv == nil || !sensorNodeCoverageProfileCommand(arguments[0]) || getenv(sensorNodeCoverageChecksumEnvironment) != sensorNodeCoverageCommandPin(arguments[0]) {
		return errInvalidMigrationCommand
	}
	return nil
}
func writeSensorNodeCoverageChecksums(w io.Writer) error {
	if w == nil {
		return errInvalidMigrationCommand
	}
	return json.NewEncoder(w).Encode(struct {
		Normal string `json:"normal"`
		Audit  string `json:"audit"`
	}{migrations.SensorNodeCoverageProfileChecksum(), migrations.SensorNodeCoverageAuditProfileChecksum()})
}
func (r *registeredReleaseMigrationRunner) UpProductionSensorNodeCoverageProfile(ctx context.Context) error {
	if err := r.sensorNodeCoveragePrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionSensorNodeCoverageProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionSensorNodeCoverageProfile(ctx)
}
func (r *registeredReleaseMigrationRunner) UpProductionSensorNodeCoverageAuditProfile(ctx context.Context) error {
	if err := r.sensorNodeCoveragePrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionSensorNodeCoverageAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionSensorNodeCoverageAuditProfile(ctx)
}
func sensorNodeCoveragePostInstall(ctx context.Context, q principalQueryer, principal, command string) error {
	if ctx == nil || ctx.Err() != nil || q == nil || !databasePrincipalPattern.MatchString(principal) || !sensorNodeCoverageProfileCommand(command) {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.operator() AND zasp_sensor_coverage_v1.raw_seal_ready() AND zasp_sensor_coverage_v1.effective_ready() AND EXISTS(SELECT 1 FROM zasp_sensor_coverage_v1.registration WHERE singleton AND checksum=$2)`, principal, sensorNodeCoverageCommandPin(command)).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}

// Only public identity/membership facts are read before Runner legitimately
// selects the authority role. Private parent/profile gates run inside that role.
func (r *registeredReleaseMigrationRunner) sensorNodeCoveragePrincipal(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var ok bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1 AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`, r.registration.migration).Scan(&ok); err != nil || !ok {
		return errReleasePrincipalRegistration
	}
	return nil
}
