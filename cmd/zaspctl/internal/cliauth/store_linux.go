//go:build linux

package cliauth

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// secret-tool communicates with the signed-in user's Secret Service over D-Bus.
// The credential is passed through stdin without appearing in process arguments.
func writeSecret(host, env string, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/secret-tool", "store", "--label=Zasp developer CLI", "application", "zaspctl", "origin", host, "environment", env)
	cmd.Stdin = bytes.NewReader(data)
	if cmd.Run() != nil {
		return errStore
	}
	return nil
}
func readSecret(host, env string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/secret-tool", "lookup", "application", "zaspctl", "origin", host, "environment", env).Output()
	if err != nil || len(out) > 2048 {
		return nil, errStore
	}
	return out, nil
}
