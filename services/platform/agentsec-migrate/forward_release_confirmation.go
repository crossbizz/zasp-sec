package main

import (
	"context"
	"io"
)

// confirmForwardRelease is the actual CLI post-install path. Only the finite
// profile commands select an existing authority membership in a bounded
// transaction; the installer itself keeps its source-owner DDL frame.
func confirmForwardRelease(ctx context.Context, queryer principalQueryer, begin func(context.Context) (retentionOperatorTransaction, error), registration discoveryPrincipalRegistration, arguments []string) error {
	if !isForwardMigration(arguments) {
		return errInvalidMigrationCommand
	}

	if sensorNodeCoverageProfileCommand(arguments[0]) {
		return withRetentionOperatorTransaction(ctx, begin, func(c context.Context, q principalQueryer, _ io.Writer) error {
			return sensorNodeCoveragePostInstall(c, q, registration.migration, arguments[0])
		}, nil)
	}
	if agentExposureFilterProfileCommand(arguments[0]) {
		return withRetentionOperatorTransaction(ctx, begin, func(c context.Context, q principalQueryer, _ io.Writer) error {
			return agentExposureFilterPostInstall(c, q, registration.migration, arguments[0])
		}, nil)
	}
	if agentOwnershipWriteProfileCommand(arguments[0]) {
		return withRetentionOperatorTransaction(ctx, begin, func(c context.Context, q principalQueryer, _ io.Writer) error {
			return agentOwnershipWritePostInstall(c, q, registration.migration, arguments[0])
		}, nil)
	}
	if agentReadProfileCommand(arguments[0]) {
		return withRetentionOperatorTransaction(ctx, begin, func(c context.Context, q principalQueryer, _ io.Writer) error {
			return agentReadPostInstall(c, q, registration.migration, arguments[0])
		}, nil)
	}
	if agentOwnerFilterProfileCommand(arguments[0]) {
		return withRetentionOperatorTransaction(ctx, begin, func(c context.Context, q principalQueryer, _ io.Writer) error {
			return agentOwnerFilterPostInstall(c, q, registration.migration, arguments[0])
		}, nil)
	}
	if environmentClassProfileCommand(arguments[0]) {
		return withRetentionOperatorTransaction(ctx, begin, func(c context.Context, q principalQueryer, _ io.Writer) error {
			return environmentClassPostInstall(c, q, registration.migration, arguments[0])
		}, nil)
	}
	if retentionProfileCommand(arguments[0]) {
		return withRetentionOperatorTransaction(ctx, begin, func(c context.Context, q principalQueryer, _ io.Writer) error {
			return retentionPostInstall(c, q, registration.migration)
		}, nil)
	}
	if optionalEgressProfileCommand(arguments[0]) {
		return withRetentionOperatorTransaction(ctx, begin, func(c context.Context, q principalQueryer, _ io.Writer) error {
			return optionalEgressPostInstall(c, q, registration.migration, arguments[0])
		}, nil)
	}
	if maintenanceProfileCommand(arguments[0]) {
		return withRetentionOperatorTransaction(ctx, begin, func(c context.Context, q principalQueryer, _ io.Writer) error {
			return registerForwardRelease(c, q, registration, arguments)
		}, nil)
	}
	if authorizationProfileCommand(arguments[0]) || arguments[0] == "up-authorization-runtime-profile" {
		return withRetentionOperatorTransaction(ctx, begin, func(c context.Context, q principalQueryer, _ io.Writer) error {
			return registerForwardRelease(c, q, registration, arguments)
		}, nil)
	}
	if temporalConfirmationCommand(arguments[0]) {
		return withRetentionOperatorTransaction(ctx, begin, func(c context.Context, q principalQueryer, _ io.Writer) error {
			return registerForwardRelease(c, q, registration, arguments)
		}, nil)
	}
	return registerForwardRelease(ctx, queryer, registration, arguments)
}

// Only the twelve original composite steps select this authority read frame.
// Older Temporal commands retain their original explicit fallback semantics.
func temporalConfirmationCommand(command string) bool {
	switch command {
	case "up-temporal-domain", "up-temporal-executor", "up-temporal-workflow", "up-temporal-compatibility", "up-temporal-legacy-tests", "up-temporal-discovery", "up-temporal-admission", "up-temporal-test-executor", "up-temporal-test-selector", "up-temporal-human-admission", "up-temporal-automatic-sources", "up-temporal-finding-response":
		return true
	default:
		return false
	}
}
