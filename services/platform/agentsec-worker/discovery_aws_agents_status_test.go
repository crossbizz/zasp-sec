package main

import (
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
)

func TestAccountAgentServiceStatusAcrossRegions(t *testing.T) {
	collected, unavailable, denied := awsdiscovery.AgentServiceCollected, awsdiscovery.AgentServiceUnavailable, awsdiscovery.AgentServiceAccessDenied
	for _, test := range []struct {
		name    string
		regions []string
		want    string
	}{
		{"every region served it", []string{collected, collected}, collected},
		{"some regions do not offer it", []string{unavailable, collected, unavailable}, collected},
		{"no region offers it", []string{unavailable, unavailable}, unavailable},
		{"one region refused", []string{collected, denied, unavailable}, denied},
		{"refused where offered, absent elsewhere", []string{unavailable, denied}, denied},
		{"a single region", []string{unavailable}, unavailable},
	} {
		status := ""
		for _, region := range test.regions {
			status = accountDiscoveryAWSAgentStatus(status, region)
		}
		if status != test.want {
			t.Errorf("%s: status = %q, want %q", test.name, status, test.want)
		}
	}
}
