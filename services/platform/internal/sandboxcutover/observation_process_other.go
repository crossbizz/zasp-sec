//go:build !darwin && !linux

package sandboxcutover

import (
	"context"
	"os/exec"
)

func runObservationProcess(context.Context, *exec.Cmd) ([]byte, error) { return nil, errRejected }
