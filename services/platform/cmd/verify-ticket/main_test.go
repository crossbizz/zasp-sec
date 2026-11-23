package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

func writeExport(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

// Run the real policy evaluator for each synthetic ticket and independently
// persist the writes in a bounded local ledger. Reopen the ledger for target
// readback so a block receipt from the adapter alone cannot prove prevention.
func TestVerifiedTicketLocalEndToEnd(t *testing.T) {
	var scenario redteam.TicketScenario
	if err := readExport("testdata/scenario.json", &scenario); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.Compile(policy.Policy{ID: "ticket-policy", Trigger: "ticket_update", Action: policy.ActionBlock, Conditions: []policy.Condition{{Field: "destination", Operator: "equals", Value: "protected"}}})
	if err != nil {
		t.Fatal(err)
	}
	scenario.PolicyRevision = compiled.Digest
	dir := t.TempDir()
	ledger := filepath.Join(dir, "synthetic-ticket.jsonl")
	f, err := os.OpenFile(ledger, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	adapter := redteam.TicketAdapterEvidence{Version: scenario.Version, TicketRunBinding: scenario.TicketRunBinding, TicketPolicyBinding: scenario.TicketPolicyBinding, Capability: "supported"}
	for i, target := range []struct{ id, destination string }{{scenario.ControlActionID, "allowed"}, {scenario.ProtectedActionID, "protected"}} {
		decision, err := policy.Evaluate(t.Context(), compiled, map[string]string{"destination": target.destination})
		if err != nil {
			t.Fatal(err)
		}
		at := scenario.WindowStart.Add(time.Duration(1+2*i) * time.Second)
		verdict := "block"
		if !(decision.Matched && decision.Action == policy.ActionBlock) {
			verdict = "allow"
			write := redteam.TicketWriteReceipt{ActionID: target.id, ReceiptID: "ticket-" + target.id, RecordedAt: at.Add(time.Second)}
			if err := json.NewEncoder(f).Encode(write); err != nil {
				t.Fatal(err)
			}
			if err := f.Sync(); err != nil {
				t.Fatal(err)
			}
		}
		adapter.Decisions = append(adapter.Decisions, redteam.TicketActionDecision{ActionID: target.id, DecisionID: "decision-" + target.id, Verdict: verdict, Mode: "enforce", Applied: true, DecidedAt: at})
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	var writes []redteam.TicketWriteReceipt
	for _, line := range bytes.FieldsFunc(data, func(r rune) bool { return r == '\n' }) {
		var write redteam.TicketWriteReceipt
		if err := json.Unmarshal(line, &write); err != nil {
			t.Fatal(err)
		}
		writes = append(writes, write)
	}
	if len(writes) != 1 || writes[0].ActionID != scenario.ControlActionID {
		t.Fatalf("unexpected durable writes: %+v", writes)
	}
	recorder := redteam.TicketRecorderEvidence{Version: scenario.Version, TicketRunBinding: scenario.TicketRunBinding, RecorderID: scenario.RecorderID, Healthy: true, CompleteFrom: scenario.WindowStart, CompleteThrough: scenario.WindowEnd, Writes: writes}
	files := []string{filepath.Join(dir, "scenario.json"), filepath.Join(dir, "adapter.json"), filepath.Join(dir, "recorder.json")}
	writeExport(t, files[0], scenario)
	writeExport(t, files[1], adapter)
	writeExport(t, files[2], recorder)
	var stdout, stderr bytes.Buffer
	if code := run(files, &stdout, &stderr, scenario.WindowEnd); code != 0 {
		t.Fatalf("exit %d: %s%s", code, &stdout, &stderr)
	}
	var result redteam.TicketVerification
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Verdict != "passed" || result.ControlReceiptID != writes[0].ReceiptID {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestCLIRejectsInvalidExportsAndProvidesHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	if code := run([]string{"--help"}, &stdout, &stderr, now); code != 0 || !strings.Contains(stdout.String(), "RECORDER.json") {
		t.Fatal(code, stdout.String())
	}
	if code := run(nil, &stdout, &stderr, now); code != 2 {
		t.Fatal(code)
	}
	files := []string{"testdata/scenario.json", "testdata/adapter.json", "testdata/recorder.json"}
	if code := run(files, &stdout, &stderr, now); code != 0 {
		t.Fatal(code, stderr.String())
	}
	file := filepath.Join(t.TempDir(), "bad.json")
	files[1] = file
	for _, data := range []string{`{}`, `null`, `{ "scope":{"run_id":"a","run_id":"b"} }`, `{"Scope":{}}`, `{} []`, `{"unrecognized":true}`, strings.Repeat(" ", 64*1024)} {
		if err := os.WriteFile(file, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		want := 2
		if data == `{}` {
			want = 3
		}
		if code := run(files, &stdout, &stderr, now); code != want {
			t.Fatalf("%q produced %d, wanted %d", data[:min(len(data), 32)], code, want)
		}
	}
}

func TestSourceSignerUsesOneLocalExportAndPrivateKey(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "private.pem")
	if os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600) != nil {
		t.Fatal("key setup")
	}
	var scenario redteam.TicketScenario
	if readExport("testdata/scenario.json", &scenario) != nil {
		t.Fatal("fixture")
	}
	for _, role := range []string{"adapter", "recorder"} {
		args := []string{"sign-source", role, "test-key", keyPath, "testdata/scenario.json", "testdata/" + role + ".json"}
		var out bytes.Buffer
		if code := run(args, &out, io.Discard, scenario.WindowEnd); code != 0 {
			t.Fatal(role, code)
		}
		var source redteam.TicketAttestation
		if redteam.DecodeTicketExport(out.Bytes(), &source) != nil || source.KeyID != "test-key" {
			t.Fatal(out.String())
		}
		args[len(args)-1] = "testdata/scenario.json"
		out.Reset()
		if code := run(args, &out, io.Discard, scenario.WindowEnd); code != 2 || out.Len() != 0 {
			t.Fatal("signed wrong local document")
		}
	}
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := privateTicketKey(keyPath); err == nil {
		t.Fatal("accepted shared private key")
	}
}
