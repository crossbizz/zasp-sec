package main

import "io"

const (
	configurationCheckAccepted = "API configuration syntax accepted; runtime access and production readiness are unverified.\n"
	configurationCheckRefused  = "API configuration syntax refused.\n"
	configurationCheckUsage    = "Usage: agentsec-api [--check-config]\n"
)

// runConfigurationCommand checks the same complete environment contract as
// normal startup without constructing clients, reading credential files,
// starting workers, or opening listeners. Acceptance is configuration evidence.
func runConfigurationCommand(args []string, lookup func(string) (string, bool), output io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	if invalidRuntimeValue(output) {
		return true, errOutputUnavailable
	}
	if len(args) != 1 || args[0] != "--check-config" {
		if n, err := io.WriteString(output, configurationCheckUsage); err != nil || n != len(configurationCheckUsage) {
			return true, errOutputUnavailable
		}
		return true, errInvalidRuntimeConfig
	}
	config, err := loadRuntimeConfigFromEnvironment(lookup)
	clear(config.TokenRevealKey)
	if config.AuditExports != nil {
		clear(config.AuditExports.CursorSigningKey)
	}
	message := configurationCheckAccepted
	if err != nil {
		message = configurationCheckRefused
	}
	if n, writeErr := io.WriteString(output, message); writeErr != nil || n != len(message) {
		return true, errOutputUnavailable
	}
	return true, err
}
