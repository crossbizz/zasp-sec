package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"testing"
	"time"
)

func TestSecurityAgentExportGrantsRepository(t *testing.T) {
	identity, _, pin, _ := agentDownloadFixture(t)
	d := &exportSettlementDatabase{}
	r, err := NewSecurityAgentExportsRepository(d)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("controlled browser credential"))
	token := strings.Repeat("a", 64)
	for _, operation := range []string{"issue", "read", "consume", "integrity_failure"} {
		t.Run(operation, func(t *testing.T) {
			var raw []byte
			var err error
			if operation == "read" {
				raw, err = json.Marshal(pin)
			} else {
				raw, err = json.Marshal(complianceGrantResult{ExpiresAt: time.Now().Add(time.Minute).UTC(), Consumed: operation != "issue"})
			}
			if err != nil {
				t.Fatal(err)
			}
			d.response = raw
			if operation == "read" {
				got, e := r.readGrant(context.Background(), identity, digest[:], pin.Binding.RunID, pin.Binding.StepID, token, "json")
				if e != nil || got.Reference != pin.Reference || len(got.Binding.Selection) != 1 || got.Binding.Selection[0] != pin.Binding.Selection[0] {
					t.Fatalf("read grant rejected: %+v %v", got, e)
				}
			} else {
				got, e := r.grantAction(context.Background(), identity, digest[:], pin.Binding.RunID, pin.Binding.StepID, token, "json", operation)
				if e != nil || got.Consumed != (operation != "issue") {
					t.Fatalf("grant rejected: %+v %v", got, e)
				}
			}
			if d.statement != `SELECT public.zasp_sa_export_grant($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)` || len(d.args) != 13 {
				t.Fatalf("wrong grant SQL: %s", d.statement)
			}
			want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), pin.Binding.RunID, pin.Binding.StepID, identity.PrincipalID.String(), digest[:], identity.CSRFToken, token, "json", operation, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()}
			for i, v := range want {
				if i == 6 {
					if !bytes.Equal(d.args[i].([]byte), digest[:]) {
						t.Fatal("session digest lost")
					}
					continue
				}
				if d.args[i] != v {
					t.Fatalf("argument%d mismatch", i)
				}
			}
		})
	}
}

func TestSecurityAgentExportGrantsRefuseMalformedReadBindings(t *testing.T) {
	identity, _, pin, _ := agentDownloadFixture(t)
	digest := sha256.Sum256([]byte("controlled browser credential"))
	token := strings.Repeat("a", 64)
	encoded, err := json.Marshal(pin)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(encoded)
	for _, mode := range []string{"run", "step", "duplicate_binding", "unknown_selection", "duplicate_selection", "null_selection", "expired", "revision", "zero_size"} {
		t.Run(mode, func(t *testing.T) {
			raw := valid
			switch mode {
			case "run":
				raw = strings.Replace(raw, pin.Binding.RunID, pin.Reference, 1)
			case "step":
				raw = strings.Replace(raw, pin.Binding.StepID, pin.Reference, 1)
			case "duplicate_binding":
				raw = strings.Replace(raw, `"run_id":`, `"run_id":"ignored","run_id":`, 1)
			case "unknown_selection":
				raw = strings.Replace(raw, `"source_kind":`, `"extra":true,"source_kind":`, 1)
			case "duplicate_selection":
				raw = strings.Replace(raw, `"source_version":7`, `"source_version":6,"source_version":7`, 1)
			case "null_selection":
				var v map[string]any
				if json.Unmarshal(encoded, &v) != nil {
					t.Fatal("fixture decode")
				}
				v["binding"].(map[string]any)["selection"] = nil
				b, e := json.Marshal(v)
				if e != nil {
					t.Fatal(e)
				}
				raw = string(b)
			case "expired":
				raw = strings.Replace(raw, pin.ReadExpiresAt.Format(time.RFC3339Nano), "2000-01-01T00:00:00Z", 1)
			case "revision":
				raw = strings.Replace(raw, "security-agent-evidence-envelope-v1", "compliance-envelope-v1", 1)
			case "zero_size":
				var v map[string]any
				if json.Unmarshal(encoded, &v) != nil {
					t.Fatal("fixture decode")
				}
				v["size"] = 0
				b, e := json.Marshal(v)
				if e != nil {
					t.Fatal(e)
				}
				raw = string(b)
			}
			d := &exportSettlementDatabase{response: json.RawMessage(raw)}
			r, _ := NewSecurityAgentExportsRepository(d)
			got, err := r.readGrant(context.Background(), identity, digest[:], pin.Binding.RunID, pin.Binding.StepID, token, "json")
			if !errors.Is(err, ErrRepositoryUnavailable) || got.Reference != "" || d.statement == "" {
				t.Fatalf("malformed read receipt accepted or masked: %+v %v", got, err)
			}
		})
	}
}

func TestSecurityAgentExportGrantsCallerRefusals(t *testing.T) {
	identity, _, pin, _ := agentDownloadFixture(t)
	digest := sha256.Sum256([]byte("controlled browser credential"))
	token := strings.Repeat("a", 64)
	for _, mode := range []string{"csrf", "digest", "run", "token", "format", "operation"} {
		t.Run(mode, func(t *testing.T) {
			i := identity
			dvalue := digest[:]
			run := pin.Binding.RunID
			tok := token
			format, operation := "json", "issue"
			switch mode {
			case "csrf":
				i.CSRFToken = ""
			case "digest":
				dvalue = make([]byte, 32)
			case "run":
				run = "wrong"
			case "token":
				tok = "wrong"
			case "format":
				format = "html"
			case "operation":
				operation = "read"
			}
			d := &exportSettlementDatabase{}
			r, _ := NewSecurityAgentExportsRepository(d)
			if _, err := r.grantAction(context.Background(), i, dvalue, run, pin.Binding.StepID, tok, format, operation); err == nil || d.statement != "" {
				t.Fatal("invalid caller reached SQL")
			}
		})
	}
	d := &exportSettlementDatabase{response: json.RawMessage(`{"expires_at":"2030-01-01T00:00:00Z","consumed":null}`)}
	r, _ := NewSecurityAgentExportsRepository(d)
	if _, err := r.grantAction(context.Background(), identity, digest[:], pin.Binding.RunID, pin.Binding.StepID, token, "json", "issue"); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatal("null consumed accepted")
	}
	d.err = ErrRepositoryConflict
	if _, err := r.grantAction(context.Background(), identity, digest[:], pin.Binding.RunID, pin.Binding.StepID, token, "json", "consume"); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("SQL conflict lost: %v", err)
	}
}
