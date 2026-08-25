package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	manifestSchemaVersion       = "recovery_manifest_v1"
	signedManifestSchemaVersion = "recovery_signed_manifest_v1"
	maximumManifestBytes        = 56 << 10
	MaximumSignedManifestBytes  = 64 << 10
	maximumManifestArtifacts    = 4096
	maximumArtifactBytes        = 512 << 20
)

var (
	ErrManifest  = errors.New("invalid recovery manifest")
	ErrSignature = errors.New("invalid recovery manifest signature")
	ErrExpired   = fmt.Errorf("recovery manifest expired: %w", ErrManifest)

	neonProjectPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	neonBranchPattern  = regexp.MustCompile(`^br-[a-z0-9][a-z0-9-]{1,62}$`)
	versionPattern     = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
	mediaTypePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,127}$`)
	schemaPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	kmsKeyARNPattern   = regexp.MustCompile(`^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]{3,32}:[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type ArtifactLocator struct {
	Scope     domain.Scope
	Reference domain.EvidenceRef
	VersionID string
	SHA256    [sha256.Size]byte
	SizeBytes int64
	MediaType string
	Schema    string
}

type ManifestInput struct {
	Scope          domain.Scope
	BackupID       domain.ProductID
	CapturedAt     time.Time
	ExpiresAt      time.Time
	NeonProjectID  string
	NeonBranchID   string
	PostgresLSN    string
	Configuration  ArtifactLocator
	Projection     ArtifactLocator
	Evidence       []ArtifactLocator
	ExpectedCounts map[string]uint64
}

type Manifest struct {
	Scope          domain.Scope
	BackupID       domain.ProductID
	CapturedAt     time.Time
	ExpiresAt      time.Time
	NeonProjectID  string
	NeonBranchID   string
	PostgresLSN    string
	Configuration  ArtifactLocator
	Projection     ArtifactLocator
	Evidence       []ArtifactLocator
	ExpectedCounts map[string]uint64
}

type ManifestSigner interface {
	Sign(context.Context, []byte) (string, []byte, error)
}

type ManifestVerifier interface {
	Verify(context.Context, string, []byte, []byte) error
}

type manifestWire struct {
	SchemaVersion  string             `json:"schema_version"`
	OrganizationID string             `json:"organization_id"`
	WorkspaceID    string             `json:"workspace_id"`
	EnvironmentID  string             `json:"environment_id"`
	BackupID       string             `json:"backup_id"`
	CapturedAt     string             `json:"captured_at"`
	ExpiresAt      string             `json:"expires_at"`
	NeonProjectID  string             `json:"neon_project_id"`
	NeonBranchID   string             `json:"neon_branch_id"`
	PostgresLSN    string             `json:"postgres_lsn"`
	Configuration  artifactWire       `json:"configuration"`
	Projection     artifactWire       `json:"projection_rebuild"`
	Evidence       []artifactWire     `json:"evidence"`
	ExpectedCounts expectedCountsWire `json:"expected_counts"`
}

type artifactWire struct {
	Reference string `json:"reference"`
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	MediaType string `json:"media_type"`
	Schema    string `json:"schema"`
}

type expectedCountsWire struct {
	Assets   uint64 `json:"assets"`
	Findings uint64 `json:"findings"`
	Policies uint64 `json:"policies"`
}

type signedManifestWire struct {
	SchemaVersion string `json:"schema_version"`
	SigningKeyARN string `json:"signing_key_arn"`
	Payload       string `json:"payload"`
	Signature     string `json:"signature"`
}

func BuildManifest(input ManifestInput) (Manifest, []byte, error) {
	manifest, err := validatedManifest(input)
	if err != nil {
		return Manifest{}, nil, err
	}
	payload, err := json.Marshal(manifestToWire(manifest))
	if err != nil || len(payload) == 0 || len(payload) > maximumManifestBytes || !utf8.Valid(payload) {
		return Manifest{}, nil, ErrManifest
	}
	return manifest, payload, nil
}

func BuildSignedManifest(ctx context.Context, input ManifestInput, signer ManifestSigner) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || nilInterface(signer) {
		return nil, ErrSignature
	}
	_, payload, err := BuildManifest(input)
	if err != nil {
		return nil, err
	}
	keyARN, signature, err := signer.Sign(ctx, append([]byte(nil), payload...))
	if err != nil || ctx.Err() != nil || !kmsKeyARNPattern.MatchString(keyARN) || len(signature) < sha256.Size || len(signature) > 512 {
		return nil, ErrSignature
	}
	envelope, err := json.Marshal(signedManifestWire{
		SchemaVersion: signedManifestSchemaVersion,
		SigningKeyARN: keyARN,
		Payload:       base64.RawStdEncoding.EncodeToString(payload),
		Signature:     base64.RawStdEncoding.EncodeToString(signature),
	})
	if err != nil || len(envelope) > MaximumSignedManifestBytes {
		return nil, ErrManifest
	}
	return envelope, nil
}

func DecodeSignedManifest(ctx context.Context, reader io.Reader, verifier ManifestVerifier, now time.Time) (Manifest, error) {
	if ctx == nil || ctx.Err() != nil || reader == nil || nilInterface(verifier) || !validUTCTime(now) {
		return Manifest{}, ErrManifest
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaximumSignedManifestBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > MaximumSignedManifestBytes || !utf8.Valid(encoded) || !uniqueManifestJSON(encoded) {
		return Manifest{}, ErrManifest
	}
	var envelope signedManifestWire
	if err := decodeClosedJSON(encoded, &envelope); err != nil || envelope.SchemaVersion != signedManifestSchemaVersion || !kmsKeyARNPattern.MatchString(envelope.SigningKeyARN) {
		return Manifest{}, ErrManifest
	}
	payload, err := base64.RawStdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > maximumManifestBytes {
		return Manifest{}, ErrManifest
	}
	signature, err := base64.RawStdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) < sha256.Size || len(signature) > 512 {
		return Manifest{}, ErrManifest
	}
	if err := verifier.Verify(ctx, envelope.SigningKeyARN, append([]byte(nil), payload...), append([]byte(nil), signature...)); err != nil || ctx.Err() != nil {
		return Manifest{}, ErrSignature
	}
	if !utf8.Valid(payload) || !uniqueManifestJSON(payload) {
		return Manifest{}, ErrManifest
	}
	var wire manifestWire
	if err := decodeClosedJSON(payload, &wire); err != nil {
		return Manifest{}, ErrManifest
	}
	input, err := wireToManifestInput(wire)
	if err != nil {
		return Manifest{}, err
	}
	manifest, canonical, err := BuildManifest(input)
	if err != nil || !bytes.Equal(canonical, payload) || now.Before(manifest.CapturedAt) {
		return Manifest{}, ErrManifest
	}
	if now.After(manifest.ExpiresAt) {
		return Manifest{}, ErrExpired
	}
	return manifest, nil
}

func validatedManifest(input ManifestInput) (Manifest, error) {
	retention := input.ExpiresAt.Sub(input.CapturedAt)
	if input.Scope.Validate() != nil || input.BackupID.IsZero() || !validUTCTime(input.CapturedAt) || !validUTCTime(input.ExpiresAt) ||
		retention < 7*24*time.Hour || retention > 90*24*time.Hour || retention%(24*time.Hour) != 0 ||
		!neonProjectPattern.MatchString(input.NeonProjectID) || !neonBranchPattern.MatchString(input.NeonBranchID) || !validPostgresLSN(input.PostgresLSN) {
		return Manifest{}, ErrManifest
	}
	if err := validateArtifact(input.Configuration, input.Scope); err != nil ||
		input.Configuration.MediaType != "application/vnd.zasp.recovery-configuration+json" || input.Configuration.Schema != "recovery_configuration_v1" {
		return Manifest{}, ErrManifest
	}
	if err := validateArtifact(input.Projection, input.Scope); err != nil ||
		input.Projection.MediaType != "application/vnd.zasp.recovery-projection+json" || input.Projection.Schema != "recovery_projection_rebuild_v1" {
		return Manifest{}, ErrManifest
	}
	if len(input.Evidence) == 0 || len(input.Evidence) > maximumManifestArtifacts {
		return Manifest{}, ErrManifest
	}
	evidence := append([]ArtifactLocator(nil), input.Evidence...)
	sort.Slice(evidence, func(left, right int) bool {
		if evidence[left].Reference.String() == evidence[right].Reference.String() {
			return evidence[left].VersionID < evidence[right].VersionID
		}
		return evidence[left].Reference.String() < evidence[right].Reference.String()
	})
	for index := range evidence {
		if err := validateArtifact(evidence[index], input.Scope); err != nil ||
			(index > 0 && evidence[index-1].Reference == evidence[index].Reference) {
			return Manifest{}, ErrManifest
		}
	}
	if len(input.ExpectedCounts) != 3 {
		return Manifest{}, ErrManifest
	}
	for _, key := range []string{"assets", "findings", "policies"} {
		if _, ok := input.ExpectedCounts[key]; !ok {
			return Manifest{}, ErrManifest
		}
	}
	counts := map[string]uint64{
		"assets":   input.ExpectedCounts["assets"],
		"findings": input.ExpectedCounts["findings"],
		"policies": input.ExpectedCounts["policies"],
	}
	return Manifest{
		Scope:          input.Scope,
		BackupID:       input.BackupID,
		CapturedAt:     input.CapturedAt,
		ExpiresAt:      input.ExpiresAt,
		NeonProjectID:  input.NeonProjectID,
		NeonBranchID:   input.NeonBranchID,
		PostgresLSN:    input.PostgresLSN,
		Configuration:  input.Configuration,
		Projection:     input.Projection,
		Evidence:       evidence,
		ExpectedCounts: counts,
	}, nil
}

func validateArtifact(locator ArtifactLocator, scope domain.Scope) error {
	if locator.Scope != scope || locator.Reference.Validate() != nil || len(locator.VersionID) > 1024 || !versionPattern.MatchString(locator.VersionID) ||
		locator.SHA256 == ([sha256.Size]byte{}) || locator.SizeBytes <= 0 || locator.SizeBytes > maximumArtifactBytes ||
		!mediaTypePattern.MatchString(locator.MediaType) || !schemaPattern.MatchString(locator.Schema) {
		return ErrManifest
	}
	return nil
}

func manifestToWire(manifest Manifest) manifestWire {
	evidence := make([]artifactWire, len(manifest.Evidence))
	for index := range manifest.Evidence {
		evidence[index] = artifactToWire(manifest.Evidence[index])
	}
	return manifestWire{
		SchemaVersion:  manifestSchemaVersion,
		OrganizationID: manifest.Scope.OrganizationID().String(),
		WorkspaceID:    manifest.Scope.WorkspaceID().String(),
		EnvironmentID:  manifest.Scope.EnvironmentID().String(),
		BackupID:       manifest.BackupID.String(),
		CapturedAt:     manifest.CapturedAt.Format(time.RFC3339),
		ExpiresAt:      manifest.ExpiresAt.Format(time.RFC3339),
		NeonProjectID:  manifest.NeonProjectID,
		NeonBranchID:   manifest.NeonBranchID,
		PostgresLSN:    manifest.PostgresLSN,
		Configuration:  artifactToWire(manifest.Configuration),
		Projection:     artifactToWire(manifest.Projection),
		Evidence:       evidence,
		ExpectedCounts: expectedCountsWire{
			Assets: manifest.ExpectedCounts["assets"], Findings: manifest.ExpectedCounts["findings"], Policies: manifest.ExpectedCounts["policies"],
		},
	}
}

func artifactToWire(locator ArtifactLocator) artifactWire {
	return artifactWire{
		Reference: locator.Reference.String(), VersionID: locator.VersionID, SHA256: hex.EncodeToString(locator.SHA256[:]),
		SizeBytes: locator.SizeBytes, MediaType: locator.MediaType, Schema: locator.Schema,
	}
}

func wireToManifestInput(wire manifestWire) (ManifestInput, error) {
	if wire.SchemaVersion != manifestSchemaVersion {
		return ManifestInput{}, ErrManifest
	}
	organizationID, err := domain.ParseProductID(wire.OrganizationID)
	if err != nil {
		return ManifestInput{}, ErrManifest
	}
	workspaceID, err := domain.ParseProductID(wire.WorkspaceID)
	if err != nil {
		return ManifestInput{}, ErrManifest
	}
	environmentID, err := domain.ParseProductID(wire.EnvironmentID)
	if err != nil {
		return ManifestInput{}, ErrManifest
	}
	scope, err := domain.NewScope(organizationID, workspaceID, environmentID)
	if err != nil {
		return ManifestInput{}, ErrManifest
	}
	backupID, err := domain.ParseProductID(wire.BackupID)
	if err != nil {
		return ManifestInput{}, ErrManifest
	}
	capturedAt, err := parseCanonicalTime(wire.CapturedAt)
	if err != nil {
		return ManifestInput{}, ErrManifest
	}
	expiresAt, err := parseCanonicalTime(wire.ExpiresAt)
	if err != nil {
		return ManifestInput{}, ErrManifest
	}
	configuration, err := wireToArtifact(wire.Configuration, scope)
	if err != nil {
		return ManifestInput{}, err
	}
	projection, err := wireToArtifact(wire.Projection, scope)
	if err != nil {
		return ManifestInput{}, err
	}
	evidence := make([]ArtifactLocator, len(wire.Evidence))
	for index := range wire.Evidence {
		evidence[index], err = wireToArtifact(wire.Evidence[index], scope)
		if err != nil {
			return ManifestInput{}, err
		}
	}
	return ManifestInput{
		Scope: scope, BackupID: backupID, CapturedAt: capturedAt, ExpiresAt: expiresAt,
		NeonProjectID: wire.NeonProjectID, NeonBranchID: wire.NeonBranchID, PostgresLSN: wire.PostgresLSN,
		Configuration: configuration, Projection: projection, Evidence: evidence,
		ExpectedCounts: map[string]uint64{"assets": wire.ExpectedCounts.Assets, "findings": wire.ExpectedCounts.Findings, "policies": wire.ExpectedCounts.Policies},
	}, nil
}

func wireToArtifact(wire artifactWire, scope domain.Scope) (ArtifactLocator, error) {
	reference, err := domain.ParseEvidenceRef(wire.Reference)
	if err != nil {
		return ArtifactLocator{}, ErrManifest
	}
	digestBytes, err := hex.DecodeString(wire.SHA256)
	if err != nil || len(digestBytes) != sha256.Size || wire.SHA256 != strings.ToLower(wire.SHA256) {
		return ArtifactLocator{}, ErrManifest
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	return ArtifactLocator{Scope: scope, Reference: reference, VersionID: wire.VersionID, SHA256: digest, SizeBytes: wire.SizeBytes, MediaType: wire.MediaType, Schema: wire.Schema}, nil
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, ErrManifest
	}
	return parsed, nil
}

func validUTCTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}

func validPostgresLSN(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 8 || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, character := range part {
			if !(character >= '0' && character <= '9') && !(character >= 'A' && character <= 'F') {
				return false
			}
		}
	}
	return true
}

func decodeClosedJSON(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%w: closed JSON", ErrManifest)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("%w: trailing JSON", ErrManifest)
	}
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
