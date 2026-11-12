package main

import (
	"regexp"
	"sync/atomic"
	"testing"
)

func TestStartupStageIsAFixedName(t *testing.T) {
	startupStage = atomic.Value{}
	t.Cleanup(func() { startupStage = atomic.Value{} })
	if got := currentStartupStage(); got != "unknown" {
		t.Fatalf("stage before any step = %q", got)
	}
	enterStartupStage("discovery-queue")
	if got := currentStartupStage(); got != "discovery-queue" {
		t.Fatalf("stage = %q", got)
	}
	// Stage names are printed to operators; they must stay a closed,
	// value-free vocabulary.
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`).MatchString(currentStartupStage()) {
		t.Fatalf("stage %q is not a plain name", currentStartupStage())
	}
}
