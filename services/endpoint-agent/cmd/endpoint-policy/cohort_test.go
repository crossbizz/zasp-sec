package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

func TestSignCohortPlanForEveryPhase(t *testing.T) {
	now := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "issuer.pem")
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}), 0600); err != nil {
		t.Fatal(err)
	}
	id := uint64(0)
	first := endpointprotocol.Policy{Audience: endpointprotocol.PolicyAudience, Binding: endpointprotocol.Binding{Organization: "organization", Workspace: "workspace", Environment: "staging", Device: "managed-a", Generation: 5}, Revision: 3, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Tool: endpointprotocol.TicketTool, AllowedDestination: "tickets"}
	makePlan := func(phase string) cohortPlan {
		a := first
		a.Mode = "monitor"
		if phase == "canary" || phase == "promote" {
			a.Mode = "enforce"
		}
		b := a
		b.Binding.Device = "managed-b"
		b.Binding.Generation = 7
		return cohortPlan{"ticket-cohort-plan.v1", "staging-team", phase, &id, []planItem{{2, a}, {3, b}}}
	}
	file := filepath.Join(dir, "plan.json")
	run := func(raw []byte) (bytes.Buffer, error) {
		t.Helper()
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err := produce([]string{"--cohort-plan", file, "--key", keyPath}, &out, now)
		return out, err
	}
	for _, phase := range []string{"monitor", "canary", "promote", "rollback"} {
		p := makePlan(phase)
		raw, _ := json.Marshal(p)
		out, err := run(raw)
		if err != nil {
			t.Fatal(err)
		}
		var signed cohortBundle
		if !exactJSON(out.Bytes(), &signed) || signed.Schema != "ticket-cohort-bundle.v1" || signed.Cohort != p.Cohort || signed.Phase != phase || signed.Revision != 0 || len(signed.Items) != 2 {
			t.Fatal("invalid signed plan metadata")
		}
		for i, item := range signed.Items {
			expected := p.Items[i]
			got, ok := item.Bundle.PolicyFor(key.Public().(ed25519.PublicKey), expected.Policy.Binding, now)
			if !ok || got != expected.Policy || item.Version != expected.Version {
				t.Fatal("wrong device envelope or order")
			}
		}
	}
	rejects := []func(*cohortPlan){
		func(p *cohortPlan) { p.Revision = nil }, func(p *cohortPlan) { v := uint64(1000001); p.Revision = &v }, func(p *cohortPlan) { p.Items = nil }, func(p *cohortPlan) { p.Items = append(make([]planItem, 32), p.Items...) }, func(p *cohortPlan) { p.Cohort = "invalid label" }, func(p *cohortPlan) { p.Phase = "all" }, func(p *cohortPlan) { p.Items[1].Version = 0 }, func(p *cohortPlan) { p.Items[1].Policy.Binding = p.Items[0].Policy.Binding }, func(p *cohortPlan) { p.Items[1].Policy.Binding.Environment = "other" }, func(p *cohortPlan) { p.Items[1].Policy.Mode = "enforce" }, func(p *cohortPlan) { p.Items[1].Policy.AllowedDestination = "other" }, func(p *cohortPlan) { p.Items[1].Policy.ExpiresAt = now.Add(25 * time.Hour) }, func(p *cohortPlan) { p.Items[1].Policy.Tool = "another_tool" },
	}
	for _, change := range rejects {
		p := makePlan("monitor")
		change(&p)
		raw, _ := json.Marshal(p)
		if out, err := run(raw); err == nil || out.Len() != 0 {
			t.Fatalf("accepted invalid plan or emitted a partial bundle: %s", raw)
		}
	}
	p := makePlan("canary")
	raw, _ := json.Marshal(p)
	for _, bad := range []string{strings.Replace(string(raw), `"mode":"enforce"`, `"mode":"monitor","mode":"enforce"`, 1), strings.Replace(string(raw), `"credential_generation":`, `"Credential_generation":`, 1), strings.Replace(string(raw), `"phase":`, `"extra":true,"phase":`, 1), strings.Replace(string(raw), `"expected_rollout_revision":0,`, "", 1)} {
		if out, err := run([]byte(bad)); err == nil || out.Len() != 0 {
			t.Fatal("accepted ambiguous or missing JSON fields")
		}
	}
	if err := produce([]string{"--cohort-plan", file, "--policy", file, "--key", keyPath}, &bytes.Buffer{}, now); err == nil {
		t.Fatal("accepted two input files")
	}
}
