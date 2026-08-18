package reconciliation

import (
	"context"
	"testing"
)

func TestCapabilityGraphQueriesAndEvidenceTransitions(t *testing.T) {
	scope := fixtureScope(t, 1)
	agentID, toolID, identityID := fixtureID(t, 20), fixtureID(t, 21), fixtureID(t, 22)
	graph, err := NewCapabilityGraph([]CapabilityEdge{
		{Scope: scope, AgentID: agentID, TargetID: toolID, TargetKind: TargetTool, Category: CapabilityDataRead, Outcome: "read", EvidenceID: fixtureID(t, 30)},
		{Scope: scope, AgentID: agentID, TargetID: identityID, TargetKind: TargetIdentity, Category: CapabilityDataWrite, Outcome: "write", EvidenceID: fixtureID(t, 31)},
	})
	if err != nil {
		t.Fatal(err)
	}
	values, err := graph.Query(context.Background(), scope, agentID)
	if err != nil || len(values) != 2 || values[0].State != CapabilityReachable || values[1].State != CapabilityReachable {
		t.Fatalf("values=%+v err=%v", values, err)
	}
	if err := graph.ApplyEvidence(context.Background(), scope, CapabilityEvidence{AgentID: agentID, TargetID: toolID, Category: CapabilityDataRead, Kind: EvidenceRuntime, EvidenceID: fixtureID(t, 40)}); err != nil {
		t.Fatal(err)
	}
	if err := graph.ApplyEvidence(context.Background(), scope, CapabilityEvidence{AgentID: agentID, TargetID: toolID, Category: CapabilityDataRead, Kind: EvidenceAttackLab, EvidenceID: fixtureID(t, 41)}); err != nil {
		t.Fatal(err)
	}
	if err := graph.ApplyEvidence(context.Background(), scope, CapabilityEvidence{AgentID: agentID, TargetID: toolID, Category: CapabilityDataRead, Kind: EvidenceRuntimePolicy, EvidenceID: fixtureID(t, 42)}); err != nil {
		t.Fatal(err)
	}
	values, err = graph.Query(context.Background(), scope, agentID)
	if err != nil || values[0].State != CapabilityBlocked || !values[0].Reachable || len(values[0].EvidenceIDs) != 4 {
		t.Fatalf("transitioned=%+v err=%v", values, err)
	}
}

func TestCapabilityEvidenceCannotForgeVerificationOrCrossScope(t *testing.T) {
	scope := fixtureScope(t, 1)
	graph, err := NewCapabilityGraph([]CapabilityEdge{{Scope: scope, AgentID: fixtureID(t, 20), TargetID: fixtureID(t, 21), TargetKind: TargetResource, Category: CapabilityActionExecute, Outcome: "execute", EvidenceID: fixtureID(t, 30)}})
	if err != nil {
		t.Fatal(err)
	}
	for index, evidence := range []CapabilityEvidence{
		{AgentID: fixtureID(t, 20), TargetID: fixtureID(t, 21), Category: CapabilityActionExecute, Kind: EvidenceVerifiedWithoutAuthority, EvidenceID: fixtureID(t, 40)},
		{AgentID: fixtureID(t, 20), TargetID: fixtureID(t, 21), Category: CapabilityDataRead, Kind: EvidenceRuntime, EvidenceID: fixtureID(t, 41)},
	} {
		if err := graph.ApplyEvidence(context.Background(), scope, evidence); err == nil {
			t.Fatalf("forged evidence %d passed", index)
		}
	}
	if _, err := graph.Query(context.Background(), fixtureScope(t, 50), fixtureID(t, 20)); err == nil {
		t.Fatal("cross-scope query passed")
	}
}

func TestCapabilityCategoryRequiresItsExactOutcome(t *testing.T) {
	scope := fixtureScope(t, 1)
	if _, err := NewCapabilityGraph([]CapabilityEdge{{Scope: scope, AgentID: fixtureID(t, 20), TargetID: fixtureID(t, 21), TargetKind: TargetResource, Category: CapabilityDataRead, Outcome: "write", EvidenceID: fixtureID(t, 30)}}); err == nil {
		t.Fatal("mismatched category outcome passed")
	}
}

func TestPostureRulesRequireExactSupportingEvidence(t *testing.T) {
	scope := fixtureScope(t, 1)
	input := PostureInput{Scope: scope, AgentID: fixtureID(t, 20), Owner: "", HumanCredential: true, CredentialFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CredentialAgentCount: 2, UntrustedInput: true, ProductionWrite: true, EvidenceIDs: []PostureEvidence{
		{Rule: RuleOwnerlessAgent, ID: fixtureID(t, 31)},
		{Rule: RuleHumanCredential, ID: fixtureID(t, 32)},
		{Rule: RuleSharedCredential, ID: fixtureID(t, 33)},
		{Rule: RuleUntrustedWrite, ID: fixtureID(t, 34)},
	}}
	findings, err := EvaluatePosture(context.Background(), input)
	if err != nil || len(findings) != 4 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	for _, finding := range findings {
		if finding.AgentID != input.AgentID || finding.Scope != scope || finding.EvidenceID.IsZero() {
			t.Fatalf("unbound finding %+v", finding)
		}
	}
	input.Owner, input.HumanCredential, input.CredentialAgentCount, input.UntrustedInput = "security", false, 1, false
	findings, err = EvaluatePosture(context.Background(), input)
	if err != nil || len(findings) != 0 {
		t.Fatalf("negative fixture findings=%+v err=%v", findings, err)
	}
}
