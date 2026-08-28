package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestBuildManifestCanonicalizesScopeCountsAndPinnedArtifacts(t *testing.T) {
	input := validManifestInput(t)
	manifest, payload, err := BuildManifest(input)
	if err != nil {
		t.Fatalf("BuildManifest() error = %v", err)
	}
	want := `{"schema_version":"recovery_manifest_v1","organization_id":"pid_71000001-0000-4000-8000-000000000001","workspace_id":"pid_71000002-0000-4000-8000-000000000002","environment_id":"pid_71000003-0000-4000-8000-000000000003","backup_id":"pid_71000004-0000-4000-8000-000000000004","captured_at":"2026-08-24T16:00:00Z","expires_at":"2026-09-23T16:00:00Z","neon_project_id":"silent-river-123456","neon_branch_id":"br-falling-sun-123456","postgres_lsn":"0/16B6C50","configuration":{"reference":"pid_71000005-0000-4000-8000-000000000005","version_id":"version-config-0001","sha256":"1111111111111111111111111111111111111111111111111111111111111111","size_bytes":128,"media_type":"application/vnd.zasp.recovery-configuration+json","schema":"recovery_configuration_v1"},"projection_rebuild":{"reference":"pid_71000006-0000-4000-8000-000000000006","version_id":"version-projection-0001","sha256":"2222222222222222222222222222222222222222222222222222222222222222","size_bytes":256,"media_type":"application/vnd.zasp.recovery-projection+json","schema":"recovery_projection_rebuild_v1"},"evidence":[{"reference":"pid_71000007-0000-4000-8000-000000000007","version_id":"version-evidence-0001","sha256":"3333333333333333333333333333333333333333333333333333333333333333","size_bytes":512,"media_type":"application/json","schema":"raw_v1"},{"reference":"pid_71000008-0000-4000-8000-000000000008","version_id":"version-evidence-0002","sha256":"4444444444444444444444444444444444444444444444444444444444444444","size_bytes":1024,"media_type":"application/json","schema":"raw_v1"}],"expected_counts":{"assets":3,"findings":2,"policies":1}}`
	if string(payload) != want {
		t.Fatalf("canonical payload = %s\nwant = %s", payload, want)
	}
	if manifest.Scope != input.Scope || manifest.BackupID != input.BackupID || !reflect.DeepEqual(manifest.Evidence, input.Evidence) {
		t.Fatalf("manifest = %#v", manifest)
	}

	reordered := input
	reordered.Evidence = []ArtifactLocator{input.Evidence[1], input.Evidence[0]}
	reordered.ExpectedCounts = map[string]uint64{"policies": 1, "assets": 3, "findings": 2}
	_, reorderedPayload, err := BuildManifest(reordered)
	if err != nil || !bytes.Equal(payload, reorderedPayload) {
		t.Fatalf("reordered payload = %s, %v", reorderedPayload, err)
	}
}

func TestBuildManifestRejectsAuthorityDriftAndSecretMaterial(t *testing.T) {
	valid := validManifestInput(t)
	tests := []struct {
		name   string
		mutate func(*ManifestInput)
	}{
		{name: "zero scope", mutate: func(value *ManifestInput) { value.Scope = domain.Scope{} }},
		{name: "zero backup", mutate: func(value *ManifestInput) { value.BackupID = domain.ProductID{} }},
		{name: "non utc capture", mutate: func(value *ManifestInput) { value.CapturedAt = value.CapturedAt.In(time.FixedZone("other", 3600)) }},
		{name: "short retention", mutate: func(value *ManifestInput) { value.ExpiresAt = value.CapturedAt.Add(6 * 24 * time.Hour) }},
		{name: "long retention", mutate: func(value *ManifestInput) { value.ExpiresAt = value.CapturedAt.Add(91 * 24 * time.Hour) }},
		{name: "project token", mutate: func(value *ManifestInput) { value.NeonProjectID = "Bearer secret-value" }},
		{name: "branch dsn", mutate: func(value *ManifestInput) { value.NeonBranchID = "postgres://" + "user" + ":" + "pass" + "@host/db" }},
		{name: "noncanonical lsn", mutate: func(value *ManifestInput) { value.PostgresLSN = "0/16b6c50" }},
		{name: "missing version", mutate: func(value *ManifestInput) { value.Configuration.VersionID = "" }},
		{name: "zero checksum", mutate: func(value *ManifestInput) { value.Projection.SHA256 = [sha256.Size]byte{} }},
		{name: "wrong configuration media", mutate: func(value *ManifestInput) { value.Configuration.MediaType = "application/json" }},
		{name: "wrong projection schema", mutate: func(value *ManifestInput) { value.Projection.Schema = "raw_v1" }},
		{name: "duplicate evidence", mutate: func(value *ManifestInput) { value.Evidence[1] = value.Evidence[0] }},
		{name: "foreign scope", mutate: func(value *ManifestInput) { value.Evidence[0].Scope = mustForeignScope(t) }},
		{name: "unknown count", mutate: func(value *ManifestInput) { value.ExpectedCounts["sessions"] = 1 }},
		{name: "missing count", mutate: func(value *ManifestInput) { delete(value.ExpectedCounts, "policies") }},
		{name: "secret version", mutate: func(value *ManifestInput) { value.Evidence[0].VersionID = "token secret-value" }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			input := cloneManifestInput(valid)
			testCase.mutate(&input)
			if manifest, payload, err := BuildManifest(input); !errors.Is(err, ErrManifest) || !reflect.DeepEqual(manifest, Manifest{}) || payload != nil {
				t.Fatalf("BuildManifest() = %#v, %q, %v", manifest, payload, err)
			}
		})
	}
}

func TestSignedManifestVerifiesExactCanonicalPayloadBeforeDecode(t *testing.T) {
	input := validManifestInput(t)
	encoded, err := BuildSignedManifest(context.Background(), input, digestSigner{})
	if err != nil {
		t.Fatalf("BuildSignedManifest() error = %v", err)
	}
	manifest, err := DecodeSignedManifest(context.Background(), bytes.NewReader(encoded), digestVerifier{}, input.CapturedAt)
	if err != nil || manifest.Scope != input.Scope || manifest.BackupID != input.BackupID || manifest.PostgresLSN != input.PostgresLSN {
		t.Fatalf("DecodeSignedManifest() = %#v, %v", manifest, err)
	}

	parts := decodeTestEnvelope(t, encoded)
	payload, err := base64.RawStdEncoding.DecodeString(parts.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.Replace(payload, []byte(`"assets":3`), []byte(`"assets":4`), 1)
	if !bytes.Contains(payload, []byte(`"assets":4`)) {
		t.Fatal("test tamper did not change the canonical payload")
	}
	parts.Payload = base64.RawStdEncoding.EncodeToString(payload)
	tampered := encodeTestEnvelope(parts)
	if manifest, err := DecodeSignedManifest(context.Background(), strings.NewReader(tampered), digestVerifier{}, input.CapturedAt); !errors.Is(err, ErrSignature) || !reflect.DeepEqual(manifest, Manifest{}) {
		t.Fatalf("tampered decode = %#v, %v", manifest, err)
	}
}

func TestDecodeSignedManifestRejectsDuplicateUnknownOversizedAndExpiredData(t *testing.T) {
	input := validManifestInput(t)
	encoded, err := BuildSignedManifest(context.Background(), input, digestSigner{})
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.TrimSuffix(string(encoded), "}") + `,"secret":"must-not-pass"}`
	duplicate := strings.Replace(string(encoded), `"schema_version":"recovery_signed_manifest_v1"`, `"schema_version":"recovery_signed_manifest_v1","schema_version":"recovery_signed_manifest_v1"`, 1)
	oversized := string(encoded) + strings.Repeat(" ", MaximumSignedManifestBytes)
	for name, payload := range map[string]string{"unknown": unknown, "duplicate": duplicate, "oversized": oversized} {
		t.Run(name, func(t *testing.T) {
			if manifest, err := DecodeSignedManifest(context.Background(), strings.NewReader(payload), digestVerifier{}, input.CapturedAt); !errors.Is(err, ErrManifest) || !reflect.DeepEqual(manifest, Manifest{}) {
				t.Fatalf("DecodeSignedManifest() = %#v, %v", manifest, err)
			}
		})
	}
	if manifest, err := DecodeSignedManifest(context.Background(), bytes.NewReader(encoded), digestVerifier{}, input.ExpiresAt.Add(time.Second)); !errors.Is(err, ErrManifest) || !reflect.DeepEqual(manifest, Manifest{}) {
		t.Fatalf("expired decode = %#v, %v", manifest, err)
	}
}

type digestSigner struct{}

func (digestSigner) Sign(_ context.Context, payload []byte) (string, []byte, error) {
	digest := sha256.Sum256(payload)
	return "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-4333-8444-555555555555", digest[:], nil
}

type digestVerifier struct{}

func (digestVerifier) Verify(_ context.Context, keyARN string, payload, signature []byte) error {
	digest := sha256.Sum256(payload)
	if keyARN != "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-4333-8444-555555555555" || !bytes.Equal(signature, digest[:]) {
		return errors.New("invalid signature")
	}
	return nil
}

type testEnvelope struct {
	Schema    string `json:"schema_version"`
	KeyARN    string `json:"signing_key_arn"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func decodeTestEnvelope(t *testing.T, encoded []byte) testEnvelope {
	t.Helper()
	var value testEnvelope
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatalf("envelope = %s: %v", encoded, err)
	}
	return value
}

func encodeTestEnvelope(value testEnvelope) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func validManifestInput(t *testing.T) ManifestInput {
	t.Helper()
	captured := time.Date(2026, 8, 24, 16, 0, 0, 0, time.UTC)
	return ManifestInput{
		Scope:         mustScope(t),
		BackupID:      mustProductID(t, "pid_71000004-0000-4000-8000-000000000004"),
		CapturedAt:    captured,
		ExpiresAt:     captured.Add(30 * 24 * time.Hour),
		NeonProjectID: "silent-river-123456",
		NeonBranchID:  "br-falling-sun-123456",
		PostgresLSN:   "0/16B6C50",
		Configuration: ArtifactLocator{Scope: mustScope(t), Reference: mustEvidenceRef(t, "pid_71000005-0000-4000-8000-000000000005"), VersionID: "version-config-0001", SHA256: repeatedDigest(0x11), SizeBytes: 128, MediaType: "application/vnd.zasp.recovery-configuration+json", Schema: "recovery_configuration_v1"},
		Projection:    ArtifactLocator{Scope: mustScope(t), Reference: mustEvidenceRef(t, "pid_71000006-0000-4000-8000-000000000006"), VersionID: "version-projection-0001", SHA256: repeatedDigest(0x22), SizeBytes: 256, MediaType: "application/vnd.zasp.recovery-projection+json", Schema: "recovery_projection_rebuild_v1"},
		Evidence: []ArtifactLocator{
			{Scope: mustScope(t), Reference: mustEvidenceRef(t, "pid_71000007-0000-4000-8000-000000000007"), VersionID: "version-evidence-0001", SHA256: repeatedDigest(0x33), SizeBytes: 512, MediaType: "application/json", Schema: "raw_v1"},
			{Scope: mustScope(t), Reference: mustEvidenceRef(t, "pid_71000008-0000-4000-8000-000000000008"), VersionID: "version-evidence-0002", SHA256: repeatedDigest(0x44), SizeBytes: 1024, MediaType: "application/json", Schema: "raw_v1"},
		},
		ExpectedCounts: map[string]uint64{"assets": 3, "findings": 2, "policies": 1},
	}
}

func cloneManifestInput(value ManifestInput) ManifestInput {
	value.Evidence = append([]ArtifactLocator(nil), value.Evidence...)
	value.ExpectedCounts = map[string]uint64{
		"assets":   value.ExpectedCounts["assets"],
		"findings": value.ExpectedCounts["findings"],
		"policies": value.ExpectedCounts["policies"],
	}
	return value
}

func mustScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(
		mustProductID(t, "pid_71000001-0000-4000-8000-000000000001"),
		mustProductID(t, "pid_71000002-0000-4000-8000-000000000002"),
		mustProductID(t, "pid_71000003-0000-4000-8000-000000000003"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func mustForeignScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(
		mustProductID(t, "pid_72000001-0000-4000-8000-000000000001"),
		mustProductID(t, "pid_72000002-0000-4000-8000-000000000002"),
		mustProductID(t, "pid_72000003-0000-4000-8000-000000000003"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func mustProductID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustEvidenceRef(t *testing.T, value string) domain.EvidenceRef {
	t.Helper()
	reference, err := domain.ParseEvidenceRef(value)
	if err != nil {
		t.Fatal(err)
	}
	return reference
}

func repeatedDigest(value byte) [sha256.Size]byte {
	var digest [sha256.Size]byte
	for index := range digest {
		digest[index] = value
	}
	return digest
}
