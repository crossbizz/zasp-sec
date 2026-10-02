package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type agentDownloadReader struct {
	artifact        artifactstore.Artifact
	expectedLocator artifactstore.Locator
	calls           int
	err             error
	duringGet       func(context.Context)
}

func (r *agentDownloadReader) Get(ctx context.Context, locator artifactstore.Locator) (artifactstore.Artifact, error) {
	r.calls++
	if r.duringGet != nil {
		r.duringGet(ctx)
	}
	if locator != r.expectedLocator {
		return artifactstore.Artifact{}, errors.New("unexpected locator")
	}
	return r.artifact, r.err
}

func agentDownloadFixture(t *testing.T) (RequestIdentity, *agentDownloadReader, securityAgentExportReadReceipt, string) {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	const id = "pid_20000001-0000-4000-8000-000000000001"
	const run = "pid_20000002-0000-4000-8000-000000000002"
	const step = "pid_20000003-0000-4000-8000-000000000003"
	const source = "pid_20000004-0000-4000-8000-000000000004"
	content := `{"summary":"persisted evidence"}`
	hash := sha256.Sum256([]byte(content))
	manifest := fmt.Sprintf(`{"mapping_revision":"security-agent-run-evidence-v1","snapshot_at":"2026-09-19T01:02:03Z","organization_id":%q,"workspace_id":%q,"environment_id":%q,"run_id":%q,"step_id":%q,"records":[{"source_kind":"finding","source_id":%q,"source_version":7,"association_digest":%q,"content_sha256":%q,"content_json":%q}],"renderer_revision":"security-agent-evidence-envelope-v1"}`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), run, step, source, "sha256:"+strings.Repeat("a", 64), hex.EncodeToString(hash[:]), content)
	body := []byte(fmt.Sprintf(`{"version":1,"id":%q,"json":%s,"csv":"original,csv\r\n","human":"<p>Original escaped report</p>"}`, id, manifest))
	ref, err := domain.ParseEvidenceRef(id)
	if err != nil {
		t.Fatal(err)
	}
	artifact := artifactstore.Artifact{Locator: artifactstore.Locator{Scope: identity.Scope, Reference: ref, VersionID: "immutable-v1"}, Body: body, Size: int64(len(body)), MediaType: "application/json", SHA256: sha256.Sum256(body)}
	pin := securityAgentExportReadReceipt{complianceReadReceipt: complianceReadReceipt{Reference: id, Version: "immutable-v1", Size: artifact.Size, SHA256: hex.EncodeToString(artifact.SHA256[:]), RendererRevision: "security-agent-evidence-envelope-v1", ReadExpiresAt: time.Now().Add(time.Minute)}, Binding: SecurityAgentExportBinding{RunID: run, StepID: step, Selection: []SecurityAgentExportSelection{{Kind: "finding", ID: source, Version: 7, AssociationDigest: "sha256:" + strings.Repeat("a", 64)}}}}
	return identity, &agentDownloadReader{artifact: artifact, expectedLocator: artifact.Locator}, pin, manifest
}

// Returning current/rerendered formats would change these literal stored bytes.
func TestSecurityAgentExportDownloadOriginalFormats(t *testing.T) {
	for _, format := range []string{"json", "csv", "human"} {
		identity, reader, pin, manifest := agentDownloadFixture(t)
		got, err := readSecurityAgentExportDownload(context.Background(), reader, identity, pin.Reference, format, pin)
		want := map[string]string{"json": manifest, "csv": "original,csv\r\n", "human": "<p>Original escaped report</p>"}[format]
		if err != nil || string(got) != want || reader.calls != 1 {
			t.Fatalf("%s exact bytes: %q %v calls=%d", format, got, err, reader.calls)
		}
	}
}

// Outer hashes are valid in every semantic-tamper case, so they cannot mask a
// missing run/selection/schema check within the manifest.
func TestSecurityAgentExportDownloadManifestBinding(t *testing.T) {
	for _, mode := range []string{"run", "step", "source", "version", "association", "scope", "duplicate", "unknown", "mapping", "renderer", "time", "content_hash", "content_object"} {
		t.Run(mode, func(t *testing.T) {
			identity, reader, pin, _ := agentDownloadFixture(t)
			body := string(reader.artifact.Body)
			switch mode {
			case "run":
				pin.Binding.RunID = pin.Reference
			case "step":
				pin.Binding.StepID = pin.Reference
			case "source":
				pin.Binding.Selection[0].ID = pin.Reference
			case "version":
				pin.Binding.Selection[0].Version++
			case "association":
				pin.Binding.Selection[0].AssociationDigest = "sha256:" + strings.Repeat("b", 64)
			case "scope":
				body = strings.Replace(body, identity.Scope.EnvironmentID().String(), pin.Reference, 1)
			case "duplicate":
				body = strings.Replace(body, `"source_version":7`, `"source_version":6,"source_version":7`, 1)
			case "unknown":
				body = strings.Replace(body, `"source_version":7`, `"source_version":7,"secret":"hidden"`, 1)
			case "mapping":
				body = strings.Replace(body, "security-agent-run-evidence-v1", "product-evidence-v1", 1)
			case "renderer":
				body = strings.Replace(body, "security-agent-evidence-envelope-v1", "compliance-envelope-v1", 1)
			case "time":
				body = strings.Replace(body, "2026-09-19T01:02:03Z", "2026-09-19T01:02:03+00:00", 1)
			case "content_hash":
				body = strings.Replace(body, `"content_sha256":"`, `"content_sha256":"0`, 1)
			case "content_object":
				var v map[string]json.RawMessage
				_ = json.Unmarshal([]byte(body), &v)
				var m map[string]any
				_ = json.Unmarshal(v["json"], &m)
				r := m["records"].([]any)[0].(map[string]any)
				r["content_json"] = "[]"
				h := sha256.Sum256([]byte("[]"))
				r["content_sha256"] = hex.EncodeToString(h[:])
				v["json"], _ = json.Marshal(m)
				b, _ := json.Marshal(v)
				body = string(b)
			}
			reader.artifact.Body = []byte(body)
			reader.artifact.Size = int64(len(body))
			reader.artifact.SHA256 = sha256.Sum256([]byte(body))
			pin.Size = reader.artifact.Size
			pin.SHA256 = hex.EncodeToString(reader.artifact.SHA256[:])
			got, err := readSecurityAgentExportDownload(context.Background(), reader, identity, pin.Reference, "human", pin)
			if len(got) != 0 || !errors.Is(err, artifactstore.ErrIntegrity) {
				t.Fatalf("%s did not fail integrity: %q %v", mode, got, err)
			}
		})
	}
}

func TestSecurityAgentExportDownloadFailsWithoutDisclosure(t *testing.T) {
	for _, mode := range []string{"expired", "missing_selection", "bad_revision", "bad_format", "provider", "bytes", "media", "version", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			identity, reader, pin, _ := agentDownloadFixture(t)
			format := "json"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			preRead := false
			switch mode {
			case "expired":
				pin.ReadExpiresAt = time.Now().Add(-time.Second)
				preRead = true
			case "missing_selection":
				pin.Binding.Selection = nil
				preRead = true
			case "bad_revision":
				pin.RendererRevision = "compliance-envelope-v1"
				preRead = true
			case "bad_format":
				format = "html"
				preRead = true
			case "provider":
				reader.err = errors.New("private provider diagnostic")
			case "bytes":
				reader.artifact.Body = bytes.Clone(reader.artifact.Body)
				reader.artifact.Body[0] = '['
			case "media":
				reader.artifact.MediaType = "text/plain"
			case "version":
				reader.artifact.VersionID = "other"
			case "cancelled":
				cancel()
				preRead = true
			}
			got, err := readSecurityAgentExportDownload(ctx, reader, identity, pin.Reference, format, pin)
			if err == nil || len(got) != 0 || preRead && reader.calls != 0 {
				t.Fatalf("unsafe %s disclosure/call: %q %v calls=%d", mode, got, err, reader.calls)
			}
			if mode == "provider" && errors.Is(err, artifactstore.ErrIntegrity) {
				t.Fatal("provider outage mislabeled corruption")
			}
			if mode == "version" && (!errors.Is(err, artifactstore.ErrIntegrity) || !errors.Is(err, ErrRepositoryUnavailable)) {
				t.Fatal("returned wrong version was not classified as integrity failure")
			}
		})
	}
}

func TestSecurityAgentExportDownloadContentBounds(t *testing.T) {
	for _, content := range []string{"  ", "[]", "{} {}", `{"x":1,"x":2}`, `{"nested":{"x":1,"x":2}}`, strings.Repeat(`{"x":`, 33) + `0` + strings.Repeat(`}`, 33), `{"x":"` + strings.Repeat("a", 65536) + `"}`} {
		if validAgentExportContentJSON(content) {
			t.Fatal("invalid bounded content accepted")
		}
	}
	if !validAgentExportContentJSON(`{"source":"retained","nested":[1,true,null]}`) {
		t.Fatal("valid content refused")
	}
}

// Missing post-I/O cancellation checks would disclose valid bytes here.
func TestSecurityAgentExportDownloadCancelledDuringRead(t *testing.T) {
	identity, reader, pin, _ := agentDownloadFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader.duringGet = func(bounded context.Context) {
		deadline, ok := bounded.Deadline()
		if !ok || !deadline.Equal(pin.ReadExpiresAt) {
			t.Fatal("storage read did not inherit grant deadline")
		}
		cancel()
	}
	got, err := readSecurityAgentExportDownload(ctx, reader, identity, pin.Reference, "json", pin)
	if len(got) != 0 || !errors.Is(err, ErrRepositoryUnavailable) || errors.Is(err, artifactstore.ErrIntegrity) || reader.calls != 1 {
		t.Fatalf("cancelled read disclosed or mislabeled: bytes=%d error=%v calls=%d", len(got), err, reader.calls)
	}
}

// These boundaries protect independent grant authority, not just package shape.
func TestSecurityAgentExportDownloadSelectionBounds(t *testing.T) {
	_, _, pin, _ := agentDownloadFixture(t)
	base := pin.Binding.Selection[0]
	for _, kind := range []string{"finding", "attack_path", "runtime_decision", "run_audit", "existing_test", "attack_lab", "manual"} {
		b := pin.Binding
		s := base
		s.Kind = kind
		if kind == "manual" {
			s.ID = strings.Repeat("a", 64)
		}
		b.Selection = []SecurityAgentExportSelection{s}
		if !validAgentExportDownloadBinding(b) {
			t.Fatalf("valid %s identity refused", kind)
		}
	}
	for _, mode := range []string{"empty", "unknown_kind", "manual_product_id", "zero_version", "unsafe_version", "invalid_digest", "duplicate", "101"} {
		t.Run(mode, func(t *testing.T) {
			b := pin.Binding
			b.Selection = []SecurityAgentExportSelection{base}
			switch mode {
			case "empty":
				b.Selection = nil
			case "unknown_kind":
				b.Selection[0].Kind = "arbitrary"
			case "manual_product_id":
				b.Selection[0].Kind = "manual"
			case "zero_version":
				b.Selection[0].Version = 0
			case "unsafe_version":
				b.Selection[0].Version = 9007199254740992
			case "invalid_digest":
				b.Selection[0].AssociationDigest = strings.Repeat("a", 64)
			case "duplicate":
				b.Selection = append(b.Selection, base)
			case "101":
				b.Selection = nil
				for i := 0; i < 101; i++ {
					s := base
					s.ID = fmt.Sprintf("pid_20000004-0000-4000-8000-%012d", i)
					b.Selection = append(b.Selection, s)
				}
			}
			if validAgentExportDownloadBinding(b) {
				t.Fatal("invalid selection accepted")
			}
			if mode == "101" && !validAgentExportDownloadBinding(SecurityAgentExportBinding{RunID: b.RunID, StepID: b.StepID, Selection: b.Selection[:100]}) {
				t.Fatal("100 valid selections refused")
			}
		})
	}
	if !validAgentExportContentJSON(strings.Repeat(`{"x":`, 32) + `0` + strings.Repeat(`}`, 32)) {
		t.Fatal("depth32 refused")
	}
}

// Keep stored hashes valid so schema, ordered authority and size checks must
// reject the returned package independently of outer checksum verification.
func TestSecurityAgentExportDownloadPackageBoundaries(t *testing.T) {
	for _, mode := range []string{"order", "unknown", "duplicate", "missing", "version", "id", "csv_limit", "human_limit", "package_limit", "foreign_locator"} {
		t.Run(mode, func(t *testing.T) {
			identity, reader, pin, _ := agentDownloadFixture(t)
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(reader.artifact.Body, &envelope); err != nil {
				t.Fatal(err)
			}
			marshal := func(v any) json.RawMessage {
				b, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			switch mode {
			case "order":
				var manifest map[string]json.RawMessage
				if err := json.Unmarshal(envelope["json"], &manifest); err != nil {
					t.Fatal(err)
				}
				var records []map[string]json.RawMessage
				if err := json.Unmarshal(manifest["records"], &records); err != nil {
					t.Fatal(err)
				}
				second := make(map[string]json.RawMessage)
				for k, v := range records[0] {
					second[k] = v
				}
				s := pin.Binding.Selection[0]
				s.ID = pin.Reference
				second["source_id"] = marshal(s.ID)
				manifest["records"] = marshal(append(records, second))
				envelope["json"] = marshal(manifest)
				pin.Binding.Selection = []SecurityAgentExportSelection{s, pin.Binding.Selection[0]}
			case "unknown":
				envelope["extra"] = marshal(true)
			case "missing":
				delete(envelope, "csv")
			case "version":
				envelope["version"] = marshal(2)
			case "id":
				envelope["id"] = marshal(pin.Binding.RunID)
			case "csv_limit":
				envelope["csv"] = marshal(strings.Repeat("x", (4<<20)+1))
			case "human_limit":
				envelope["human"] = marshal(strings.Repeat("x", (4<<20)+1))
			case "package_limit":
				envelope["csv"] = marshal(strings.Repeat("x", 4<<20))
				envelope["human"] = marshal(strings.Repeat("x", 4<<20))
			case "foreign_locator":
				reader.artifact.Reference, _ = domain.ParseEvidenceRef(pin.Binding.RunID)
			}
			reader.artifact.Body = marshal(envelope)
			if mode == "duplicate" {
				reader.artifact.Body = append([]byte(`{"version":1,`), reader.artifact.Body[1:]...)
			}
			reader.artifact.Size = int64(len(reader.artifact.Body))
			reader.artifact.SHA256 = sha256.Sum256(reader.artifact.Body)
			pin.Size = reader.artifact.Size
			pin.SHA256 = hex.EncodeToString(reader.artifact.SHA256[:])
			got, err := readSecurityAgentExportDownload(context.Background(), reader, identity, pin.Reference, "json", pin)
			if len(got) != 0 || !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("invalid package disclosed: %d %v", len(got), err)
			}
			if mode == "package_limit" {
				if reader.calls != 0 {
					t.Fatal("oversize receipt reached storage")
				}
			} else if !errors.Is(err, artifactstore.ErrIntegrity) || reader.calls != 1 {
				t.Fatalf("semantic check masked: %v calls=%d", err, reader.calls)
			}
		})
	}
}
