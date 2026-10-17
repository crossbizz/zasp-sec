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
	return registerForwardRelease(ctx, queryer, registration, arguments)
}
