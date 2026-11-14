package agentsignals

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEgressHostClassifiesModelAPIsAndRemoteMCP(t *testing.T) {
	for name, want := range map[string]string{
		"api.openai.com": "openai", "API.OpenAI.com.": "openai", "myres.openai.azure.com": "azure_openai",
		"api.anthropic.com": "anthropic", "bedrock-runtime.us-east-1.amazonaws.com": "bedrock",
		"bedrock-agent-runtime.eu-west-1.amazonaws.com": "bedrock", "bedrock-agentcore.us-west-2.amazonaws.com": "agentcore",
		"us-central1-aiplatform.googleapis.com": "google", "generativelanguage.googleapis.com": "google",
		"mcp.linear.app": "mcp_remote", "mcp.eu.example.com": "mcp_remote", "api.tavily.com": "tavily",
	} {
		if got, ok := EgressHost(name); !ok || got != want {
			t.Errorf("EgressHost(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{"", "example.com", "openai.com", "evilapi.openai.com.attacker.net", "notapi.anthropic.com", "s3.us-east-1.amazonaws.com", "bedrock.us-east-1.amazonaws.com", "mcp.default.svc.cluster.local", "mcp.internal", "openai.azure.com", "aiplatform.googleapis.com.evil.io"} {
		if got, ok := EgressHost(name); ok {
			t.Errorf("EgressHost(%q) = %q, want no match", name, got)
		}
	}
}

func TestEgressEvidenceStrengthAndUnknownTokens(t *testing.T) {
	var evidence Evidence
	evidence.Egress("not_in_catalog", "tavily")
	if evidence.IsAgent() {
		t.Fatal("one weak egress token must not make an agent")
	}
	evidence.Egress("openai")
	if !evidence.IsAgent() {
		t.Fatal("a model API seen at run time makes an agent")
	}
	if got := evidence.Signals(); len(got) != 2 || got[0] != "egress:openai" || got[1] != "egress:tavily" {
		t.Fatalf("signals = %v", got)
	}
}

func TestEgressObservationsRoundTripAndRefusals(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	document := EgressObservations{Version: EgressObservationsVersion, Node: "ip-10-0-0-1.ec2.internal", GeneratedAt: FormatEgressTime(now), Workloads: []EgressWorkload{
		{Namespace: "shop", Kind: "Deployment", Name: "support-bot", Destinations: []EgressDestination{{Token: "openai", LastSeen: FormatEgressTime(now)}, {Token: "anthropic", LastSeen: FormatEgressTime(now.Add(-8 * 24 * time.Hour))}}},
		{Namespace: "batch", Kind: "CronJob", Name: "summarise", Destinations: []EgressDestination{{Token: "bedrock", LastSeen: FormatEgressTime(now.Add(-time.Hour))}}},
	}}
	document.Normalize()
	body, _ := json.Marshal(document)
	parsed, ok := ParseEgressObservations(body)
	if !ok || len(parsed.Workloads) != 2 || parsed.Workloads[0].Namespace != "batch" {
		t.Fatalf("parse = %+v, %v", parsed, ok)
	}
	if got := parsed.Workloads[1].Current(now); len(got) != 1 || got[0] != "openai" {
		t.Fatalf("current = %v, want only the token inside the retention window", got)
	}
	mutate := func(change func(*EgressObservations)) []byte {
		var copy EgressObservations
		_ = json.Unmarshal(body, &copy)
		change(&copy)
		out, _ := json.Marshal(copy)
		return out
	}
	for name, bad := range map[string][]byte{
		"empty":         nil,
		"version":       mutate(func(d *EgressObservations) { d.Version = "v2" }),
		"unknown token": mutate(func(d *EgressObservations) { d.Workloads[0].Destinations[0].Token = "example" }),
		"unsorted":      mutate(func(d *EgressObservations) { d.Workloads[0], d.Workloads[1] = d.Workloads[1], d.Workloads[0] }),
		"kind":          mutate(func(d *EgressObservations) { d.Workloads[0].Kind = "Pod" }),
		"time":          mutate(func(d *EgressObservations) { d.GeneratedAt = "yesterday" }),
		"no tokens":     mutate(func(d *EgressObservations) { d.Workloads[0].Destinations = nil }),
		"unknown field": []byte(`{"version":"egress-observations-v1","node":"n1","generated_at":"2026-11-14T10:00:00Z","workloads":[],"extra":1}`),
		"trailing":      append(append([]byte{}, body...), []byte(`{}`)...),
	} {
		if _, ok := ParseEgressObservations(bad); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}
