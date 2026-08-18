package m7gate

import (
	"errors"
	"sort"
)

var ErrGate = errors.New("M7 gate rejected")

type Evidence struct {
	DegradedStates                         []string
	Session, Compliance, DataControl       bool
	SystemHealth, AIDegrade, UIAPICoverage bool
}

type Report struct {
	Status         string
	Checks         int
	DegradedChecks int
}

func Evaluate(value Evidence) (Report, error) {
	degraded := append([]string(nil), value.DegradedStates...)
	sort.Strings(degraded)
	expected := []string{"ai", "connector", "event_index", "graph", "remote_otlp"}
	if !equal(degraded, expected) || !value.Session || !value.Compliance || !value.DataControl || !value.SystemHealth || !value.AIDegrade || !value.UIAPICoverage {
		return Report{}, ErrGate
	}
	return Report{Status: "PASS", Checks: 6, DegradedChecks: 5}, nil
}

func equal(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
