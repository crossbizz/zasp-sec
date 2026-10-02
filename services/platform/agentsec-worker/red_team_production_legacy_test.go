package main

import "testing"

// The active legacy production constructor composes its real runner before
// readiness checks mounted credentials. It must remain constructible without
// the release61-only image pin; Ready and Run still validate the mounted files.
func TestProductionRedTeamDependenciesRemainConstructibleForLegacyV1(t *testing.T) {
	dependencies, err := newProductionRedTeamDependencies(validRedTeamRuntimeConfig())
	if err != nil || dependencies == nil || dependencies.Runner == nil {
		t.Fatal("legacy production dependencies no longer compose", err)
	}
	if err := dependencies.Close(); err != nil {
		t.Fatal(err)
	}
}
