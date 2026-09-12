//go:build darwin || linux

package apiserver

import (
	"context"
	"os/exec"

	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
)

var errSandboxWorkerGroupRemaining = testprocess.ErrGroupRemaining

func runSandboxWorkerCommand(ctx context.Context, command *exec.Cmd) ([]byte, error) {
	return testprocess.Run(ctx, command)
}
