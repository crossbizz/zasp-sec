package main

import (
	"context"
	"errors"
	"testing"
)

func TestProductionPolicyHistoryOwnsHardenedExplicitAWSAuthority(t *testing.T) {
	config := fixtureRuntimeConfig()
	history, err := newProductionPolicyHistory(config)
	if err != nil {
		t.Fatalf("newProductionPolicyHistory() error = %v", err)
	}
	if history.history == nil || history.schema == nil || history.credentials == nil || history.transport == nil || history.transport.Proxy != nil {
		t.Fatalf("history authority = %#v", history)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := history.Ready(canceled); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("Ready(canceled) error = %v", err)
	}
	if err := history.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := history.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestProductionPolicyHistoryRejectsForeignOrMutableIndexAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*RuntimeConfig){
		"http": func(config *RuntimeConfig) {
			config.PolicyHistoryEndpoint = "http://vpc-zasp.us-east-1.es.amazonaws.com"
		},
		"foreign region": func(config *RuntimeConfig) {
			config.PolicyHistoryEndpoint = "https://vpc-zasp.us-west-2.es.amazonaws.com"
		},
		"path":  func(config *RuntimeConfig) { config.PolicyHistoryEndpoint += "/_search" },
		"index": func(config *RuntimeConfig) { config.PolicyHistoryIndex = "wildcard-*" },
	} {
		t.Run(name, func(t *testing.T) {
			config := fixtureRuntimeConfig()
			mutate(&config)
			if history, err := newProductionPolicyHistory(config); !errors.Is(err, errRuntimeUnavailable) || history != nil {
				t.Fatalf("history/error = (%#v, %v)", history, err)
			}
		})
	}
}
