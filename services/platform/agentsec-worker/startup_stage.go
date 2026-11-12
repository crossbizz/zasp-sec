package main

import "sync/atomic"

// startupStage records the last construction step a starting worker entered.
// When startup is refused, main reports it, so an operator can tell a missing
// queue from an unreachable database. Stage names are fixed strings in the
// code; they never carry a setting, credential or provider error.
var startupStage atomic.Value

func enterStartupStage(name string) { startupStage.Store(name) }

func currentStartupStage() string {
	if name, ok := startupStage.Load().(string); ok && name != "" {
		return name
	}
	return "unknown"
}
