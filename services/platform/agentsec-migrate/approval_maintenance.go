package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimepostgres"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const approvalMaintenanceKeyFileEnvironment = "ZASP_APPROVAL_MAINTENANCE_KEY_FILE"

// approvalMaintenanceCommand reports whether the arguments select an
// approval-maintenance command.
func approvalMaintenanceCommand(arguments []string) bool {
	if len(arguments) != 1 {
		return false
	}
	switch arguments[0] {
	case "up-approval-maintenance-profile", "register-approval-maintenance-verifier", "approval-maintenance-checksum":
		return true
	}
	return false
}

// runApprovalMaintenanceCommand returns the process exit status.
//
//   - approval-maintenance-checksum prints the value deployments set as
//     ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM. It needs no database.
//   - register-approval-maintenance-verifier registers the delivery key the
//     API signs with. It is run once per deployment, as the operator.
//   - up-approval-maintenance-profile installs the profile on a historical
//     chain installation. The baseline already contains it; the baseline
//     generator is its only caller.
func runApprovalMaintenanceCommand(ctx context.Context, arguments []string, getenv func(string) string, stdout, stderr io.Writer) int {
	refuse := func(stage string) int {
		_, _ = io.WriteString(stderr, "approval maintenance refused: stage="+stage+"\n")
		return 1
	}
	if arguments[0] == "approval-maintenance-checksum" {
		_, _ = io.WriteString(stdout, migrations.ApprovalMaintenanceProfileChecksum()+"\n")
		return 0
	}
	dsn := getenv(postgresDSNEnvironment)
	if dsn == "" {
		return refuse("configuration")
	}
	var key []byte
	if arguments[0] == "register-approval-maintenance-verifier" {
		var err error
		if key, err = loadApprovalMaintenanceVerifierKey(getenv(approvalMaintenanceKeyFileEnvironment)); err != nil {
			return refuse("key")
		}
		defer clear(key)
	}
	connection, err := runtimepostgres.Connect(ctx, dsn)
	if err != nil {
		return refuse("database")
	}
	defer func() { _ = connection.Close(context.WithoutCancel(ctx)) }()
	if arguments[0] == "register-approval-maintenance-verifier" {
		version := sha256.Sum256(key)
		var accepted bool
		if err := connection.QueryRow(ctx, `SELECT zasp_approval_maintenance.register_verifier('approval-forward',$1,$2)`, hex.EncodeToString(version[:]), key).Scan(&accepted); err != nil || !accepted {
			return refuse("registration")
		}
		return 0
	}
	if err := configureMigrationOptimizer(ctx, connection); err != nil {
		return refuse("database")
	}
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		return refuse("database")
	}
	if err := runner.UpProductionApprovalMaintenanceProfile(ctx); err != nil {
		return refuse("profile")
	}
	return 0
}

// loadApprovalMaintenanceVerifierKey reads the 32-byte delivery key. The API
// requires the same file to be a regular, singly linked, owner-only file, so
// the operator command does too.
func loadApprovalMaintenanceVerifierKey(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errInvalidMigrationCommand
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || info.Size() != 32 {
		return nil, errInvalidMigrationCommand
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errInvalidMigrationCommand
	}
	defer file.Close()
	key, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, errInvalidMigrationCommand
	}
	return key, nil
}
