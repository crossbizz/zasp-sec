package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// Every registered source fragment must affect the checksum used for exact
// readiness. Omitting any fragment from production hashing breaks this test.
func TestSecurityAgentMultistepEveryFragmentBound(t *testing.T) {
	for name, source := range map[string]*string{
		"up": &securityAgentMultistepUpSQL, "down": &securityAgentMultistepDownSQL,
		"promote": &securityAgentMultistepPromoteSQL, "demote": &securityAgentMultistepDemoteSQL,
		"admission": &securityAgentMultistepAdmissionSQL, "progression": &securityAgentMultistepProgressionSQL,
		"legacy_actions": &securityAgentMultistepLegacyActionsSQL, "application": &securityAgentMultistepApplicationSQL,
		"deployment": &securityAgentMultistepDeploymentSQL, "test": &securityAgentMultistepTestSQL,
		"test_artifacts": &securityAgentMultistepTestArtifactsSQL, "test_settlement": &securityAgentMultistepTestSettlementSQL,
		"cleanup": &securityAgentMultistepCleanupSQL, "cleanup_deployment": &securityAgentMultistepCleanupDeploymentSQL,
		"pricing": &securityAgentMultistepPricingSQL, "planning": &securityAgentMultistepPlanningSQL,
		"orchestration": &securityAgentMultistepOrchestrationSQL,
	} {
		t.Run(name, func(t *testing.T) {
			before := ProductionSecurityAgentMultistep().Checksum()
			prior := *source
			defer func() { *source = prior }()
			*source += "\n-- controlled checksum mutation\n"
			if ProductionSecurityAgentMultistep().Checksum() == before {
				t.Fatal("source fragment absent from authority checksum")
			}
		})
	}
}

// The candidate must never silently register itself or rewrite its predecessor.
func TestSecurityAgentMultistepCandidateMetadata(t *testing.T) {
	m := ProductionSecurityAgentMultistep()
	if m.Version() != 61 || m.Name() != "production_security_agent_multistep" {
		t.Fatal("candidate identity")
	}
	template := strings.NewReplacer("-- multistep predecessor checksum", ProductionDiscoveryScheduleReplay().Checksum(), "-- multistep predecessor fingerprint", DiscoveryScheduleReplayFingerprint()).Replace(securityAgentMultistepUpSQL)
	sum := sha256.Sum256([]byte(template + "\x00" + securityAgentMultistepDownSQL + "\x00" + securityAgentMultistepPromoteSQL + "\x00" + securityAgentMultistepDemoteSQL + "\x00" + securityAgentMultistepAdmissionSQL + "\x00" + securityAgentMultistepProgressionSQL + "\x00" + securityAgentMultistepLegacyActionsSQL + "\x00" + securityAgentMultistepApplicationSQL + "\x00" + securityAgentMultistepDeploymentSQL + "\x00" + securityAgentMultistepTestSQL + "\x00" + securityAgentMultistepTestArtifactsSQL + "\x00" + securityAgentMultistepTestSettlementSQL + "\x00" + securityAgentMultistepCleanupSQL + "\x00" + securityAgentMultistepCleanupDeploymentSQL + "\x00" + securityAgentMultistepPricingSQL + "\x00" + securityAgentMultistepPlanningSQL + "\x00" + securityAgentMultistepOrchestrationSQL))
	if m.Checksum() != hex.EncodeToString(sum[:]) || len(SecurityAgentMultistepFingerprint()) != 64 {
		t.Fatal("source identity unbound")
	}
	for _, sql := range []string{m.UpSQL(), m.DownSQL()} {
		if strings.Contains(sql, "-- compiled multistep") || strings.Contains(sql, "-- multistep predecessor") {
			t.Fatal("uncompiled identity")
		}
		if strings.Contains(sql, "INSERT INTO public.zasp_schema_versions") || strings.Contains(sql, "CREATE OR REPLACE") {
			t.Fatal("candidate activated or predecessor mutated")
		}
	}
	if !strings.Contains(m.UpSQL(), ProductionDiscoveryScheduleReplay().Checksum()) || !strings.Contains(m.UpSQL(), DiscoveryScheduleReplayFingerprint()) {
		t.Fatal("predecessor identity absent")
	}
}
