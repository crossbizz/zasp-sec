package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"testing"
)

type automaticFindingDatabase struct {
	auditExportRuntimeDatabase
	installed bool
	failure   error
	probes    int
}

func (d *automaticFindingDatabase) RiskAutomaticSourcesAvailable(context.Context) (bool, error) {
	d.probes++
	return d.installed, d.failure
}

func TestTemporalAutomaticFindingDecorator(t *testing.T) {
	inner := &automaticFindingDatabase{}
	traced := &tracedJSONDatabase{next: inner}
	capability, ok := any(traced).(interface {
		RiskAutomaticSourcesAvailable(context.Context) (bool, error)
	})
	if !ok {
		t.Fatal("production tracing drops automatic finding capability")
	}
	for _, installed := range []bool{false, true, false} {
		inner.installed = installed
		got, err := capability.RiskAutomaticSourcesAvailable(context.Background())
		if err != nil || got != installed {
			t.Fatal("changed capability", got, installed, err)
		}
	}
	inner.failure = apiserver.ErrRepositoryUnavailable
	if got, err := capability.RiskAutomaticSourcesAvailable(context.Background()); got || err != inner.failure {
		t.Fatal("invalid installed release downgraded", got, err)
	}
	if inner.probes != 4 {
		t.Fatal("probe cached", inner.probes)
	}
	absent := &tracedJSONDatabase{next: &auditExportRuntimeDatabase{}}
	if probe, ok := any(absent).(interface {
		RiskAutomaticSourcesAvailable(context.Context) (bool, error)
	}); !ok {
		t.Fatal("missing decorator capability")
	} else if got, err := probe.RiskAutomaticSourcesAvailable(context.Background()); got || err != nil {
		t.Fatal("legacy optional capability", got, err)
	}
}
