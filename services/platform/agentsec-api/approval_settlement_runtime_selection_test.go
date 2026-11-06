package main

import (
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/approvalmaintenance"
	"testing"
)

// Constructor selection only. Neither sentinel executor has native authority.
func TestApprovalSettlementRuntimeSelectionHasNoFallback(t *testing.T) {
	original, activated := &approvalmaintenance.Executor{}, &approvalmaintenance.Executor{}
	for _, pin := range []string{"", "explicit-activation"} {
		oldCalls, newCalls := 0, 0
		old := func() (*approvalmaintenance.Executor, error) { oldCalls++; return original, nil }
		selected := func() (*approvalmaintenance.Executor, error) { newCalls++; return activated, nil }
		got, err := selectApprovalMaintenanceExecutor(pin, selected, old)
		if err != nil {
			t.Fatal(err)
		}
		if pin == "" && (got != original || oldCalls != 1 || newCalls != 0) || pin != "" && (got != activated || newCalls != 1 || oldCalls != 0) {
			t.Fatal("explicit constructor selection changed")
		}
		if pin != "" {
			failure := errors.New("additive catalog refused")
			got, err = selectApprovalMaintenanceExecutor(pin, func() (*approvalmaintenance.Executor, error) { return nil, failure }, old)
			if got != nil || !errors.Is(err, failure) || oldCalls != 0 {
				t.Fatal("selected refusal fell back or changed error", err)
			}
			got, err = selectApprovalMaintenanceExecutor(pin, func() (*approvalmaintenance.Executor, error) { return nil, nil }, old)
			if got != nil || !errors.Is(err, errRuntimeUnavailable) || oldCalls != 0 {
				t.Fatal("missing selected executor fell back")
			}
		}
	}
}
