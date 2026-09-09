//go:build !linux

package main

import "context"

// Production runs on Linux. Platforms without the waitid/WNOWAIT boundary
// must not fall back to cancelling only the engine launcher.
func (productionRedTeamCommand) Run(context.Context, string, []string, []string, string) error {
	return errRuntimeUnavailable
}
