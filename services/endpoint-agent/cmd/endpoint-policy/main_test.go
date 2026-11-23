package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

func TestProductionIssuerAndScopedVerifier(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pkcs := filepath.Join(dir, "issuer.pem")
	if err = os.WriteFile(pkcs, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	p := endpointprotocol.Policy{Audience: endpointprotocol.PolicyAudience, Binding: endpointprotocol.Binding{Organization: "o", Workspace: "w", Environment: "e", Device: "d", Generation: 1}, Tool: endpointprotocol.TicketTool, Mode: "monitor", AllowedDestination: "pilot", Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	raw, _ := json.Marshal(p)
	file := filepath.Join(dir, "policy.json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--key", pkcs, "--policy", file}
	var out bytes.Buffer
	if err = produce(args, &out, now); err != nil {
		t.Fatal(err)
	}
	var signed endpointprotocol.Signed
	if err = json.Unmarshal(out.Bytes(), &signed); err != nil {
		t.Fatal(err)
	}
	if _, ok := signed.PolicyFor(pub, p.Binding, now); !ok {
		t.Fatal("issued policy failed verification")
	}
	if err = produce(args, &out, now.Add(48*time.Hour)); err == nil {
		t.Fatal("expired issuance")
	}
	v2 := endpointprotocol.PolicyV2{Audience: endpointprotocol.PolicyAudienceV2, Binding: p.Binding, Revision: 2, Mode: "enforce", FailureMode: "closed", IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt, Rules: []endpointprotocol.PretoolRule{{ID: "files", Type: "file_path_policy", Values: []string{"dotenv"}}}}
	raw, _ = json.Marshal(v2)
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err = produce(args, &out, now); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(out.Bytes(), &signed); err != nil {
		t.Fatal(err)
	}
	if verified, ok := signed.PolicyV2For(pub, p.Binding, now); !ok || verified.Rules[0].ID != "files" {
		t.Fatal("V2 issuer and verifier contract")
	}
	raw = bytes.Replace(raw, []byte(`"failure_mode":"closed"`), []byte(`"failure_mode":"closed","failure_mode":"open"`), 1)
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = produce(args, &out, now); err == nil {
		t.Fatal("duplicate policy property signed")
	}
	if err = os.Chmod(pkcs, 0644); err != nil {
		t.Fatal(err)
	}
	if err = produce(args, &out, now); err == nil {
		t.Fatal("accepted world-readable key")
	}
}
