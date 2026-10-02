package main

import (
	"errors"
	"testing"
)

func TestRuntimeServicesRejectPartialEnabledConfig(t *testing.T) {
	values := validDiscoveryRuntimeEnvironment()
	values["ZASP_RUNTIME_SERVICES_ENABLED"] = "true"
	if _, err := loadWorkerRuntimeConfig(mapLookup(values)); err == nil {
		t.Fatal("enabled Temporal/OpenFGA configuration without authority accepted")
	}
}

func TestRuntimeServicesCloseAfterExistingCloseError(t *testing.T) {
	want := errors.New("worker join pending")
	closed := false
	close := closeWorkerRuntimeServices(func() error { return want }, func() error { closed = true; return nil })
	if err := close(); !errors.Is(err, want) || !closed {
		t.Fatal("independent service connections leaked or worker error lost")
	}
}
