package main

import "testing"

func TestComplianceBrowserFailureMarker(t *testing.T) {
	cases := []struct {
		stage complianceBrowserFailureStage
		want  string
	}{
		{complianceBrowserConfigLoad, "config-load"},
		{complianceBrowserOwnedInputs, "owned-inputs"},
		{complianceBrowserStoragePath, "storage-path"},
		{complianceBrowserBoundedDeadline, "bounded-deadline"},
		{complianceBrowserRuntimeBuild, "runtime-build"},
		{complianceBrowserServe, "serve"},
		{0, "unavailable"},
		{7, "unavailable"},
		{255, "unavailable"},
	}
	for _, entry := range cases {
		if got := complianceBrowserFailureMarker(entry.stage); got != "ZASP_COMPLIANCE_API_FAILED_STAGE="+entry.want {
			t.Fatal("closed compliance child stage mismatch")
		}
	}
}
