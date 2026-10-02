package main

import (
	"context"
	"fmt"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type workerVerifierRegistration struct {
	principal string
	purpose   authorization.WorkerPurpose
	key       *authorization.WorkerKey
}

func (workerVerifierRegistration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[worker verifier registration]"))
}

func loadWorkerVerifierRegistration(args []string, getenv func(string) string) (*workerVerifierRegistration, error) {
	if len(args) != 1 || getenv == nil {
		return nil, errInvalidMigrationCommand
	}
	var purpose authorization.WorkerPurpose
	var input string
	switch args[0] {
	case "register-worker-authorization-verifier":
		purpose, input = authorization.WorkerForward, "ZASP_AUTHORIZATION_WORKER_KEY_FILE"
	case "register-compensation-authorization-verifier":
		purpose, input = authorization.CapturedCompensation, "ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE"
	default:
		return nil, errInvalidMigrationCommand
	}
	principal := getenv(migrationPrincipalEnvironment)
	if !databasePrincipalPattern.MatchString(principal) {
		return nil, errInvalidMigrationCommand
	}
	key, err := authorization.LoadWorkerKeyFile(purpose, getenv(input))
	if err != nil {
		return nil, errInvalidMigrationCommand
	}
	return &workerVerifierRegistration{principal: principal, purpose: purpose, key: key}, nil
}

func registerWorkerVerifier(ctx context.Context, q principalQueryer, r *workerVerifierRegistration) error {
	if ctx == nil || ctx.Err() != nil || q == nil || r == nil || r.key == nil || r.purpose != authorization.WorkerForward && r.purpose != authorization.CapturedCompensation {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization80_worker.operator() AND zasp_temporal78.current_ready()`, r.principal).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	verifier := r.key.Verifier()
	defer clear(verifier)
	if err := q.QueryRow(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(r.purpose), r.key.Version(), verifier).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}
