package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery"
)

type recoveryArtifactPublisherConfig struct {
	Store         artifactstore.ObjectReferencingArtifactStore
	Signer        recovery.ManifestSigner
	NeonProjectID string
	NeonBranchID  string
	PostgresLSN   func(context.Context, domain.Scope) (string, error)
	Now           func() time.Time
}

type recoveryArtifactPublisher struct {
	config recoveryArtifactPublisherConfig
}

type recordingRecoverySigner struct {
	delegate  recovery.ManifestSigner
	keyARN    string
	signature []byte
}

func newRecoveryArtifactPublisher(config recoveryArtifactPublisherConfig) (*recoveryArtifactPublisher, error) {
	if config.Store == nil || config.Signer == nil || config.PostgresLSN == nil || config.Now == nil || config.NeonProjectID == "" || config.NeonBranchID == "" {
		return nil, errWorkerExecution
	}
	now := config.Now()
	if now.IsZero() || now.Location() != time.UTC || now.Nanosecond() != 0 {
		return nil, errWorkerExecution
	}
	return &recoveryArtifactPublisher{config: config}, nil
}

func (publisher *recoveryArtifactPublisher) Publish(ctx context.Context, publication recoveryBackupPublication) (apiserver.RecoveryManifestLocator, error) {
	if publisher == nil || ctx == nil || ctx.Err() != nil || !validRecoveryOperationClaim(publication.Claim) || publication.Claim.Kind != "backup" || !exactRecoveryPublicationSections(publication.Sections) {
		return apiserver.RecoveryManifestLocator{}, errWorkerExecution
	}
	capturedAt := publisher.config.Now()
	if capturedAt.IsZero() || capturedAt.Location() != time.UTC || capturedAt.Nanosecond() != 0 {
		return apiserver.RecoveryManifestLocator{}, errWorkerExecution
	}
	postgresLSN, err := publisher.config.PostgresLSN(ctx, publication.Claim.Scope)
	if err != nil {
		return apiserver.RecoveryManifestLocator{}, errWorkerExecution
	}
	configuration, err := publisher.putSection(ctx, publication, "configuration", "application/vnd.zasp.recovery-configuration+json", "recovery_configuration_v1")
	if err != nil {
		return apiserver.RecoveryManifestLocator{}, errWorkerExecution
	}
	projection, err := publisher.putSection(ctx, publication, "projection", "application/vnd.zasp.recovery-projection+json", "recovery_projection_rebuild_v1")
	if err != nil {
		return apiserver.RecoveryManifestLocator{}, errWorkerExecution
	}
	evidence, err := publisher.putSection(ctx, publication, "evidence", "application/vnd.zasp.recovery-evidence+json", "recovery_evidence_v1")
	if err != nil {
		return apiserver.RecoveryManifestLocator{}, errWorkerExecution
	}
	counts, err := recoveryCounts(publication.Sections["counts"])
	if err != nil {
		return apiserver.RecoveryManifestLocator{}, errWorkerExecution
	}
	backupID, err := domain.ParseProductID(publication.Claim.OperationID)
	if err != nil {
		return apiserver.RecoveryManifestLocator{}, errWorkerExecution
	}
	recordingSigner := &recordingRecoverySigner{delegate: publisher.config.Signer}
	envelope, err := recovery.BuildSignedManifest(ctx, recovery.ManifestInput{
		Scope: publication.Claim.Scope, BackupID: backupID, CapturedAt: capturedAt, ExpiresAt: capturedAt.Add(time.Duration(publication.Claim.RetentionDays) * 24 * time.Hour),
		NeonProjectID: publisher.config.NeonProjectID, NeonBranchID: publisher.config.NeonBranchID, PostgresLSN: postgresLSN,
		Configuration: configuration, Projection: projection, Evidence: []recovery.ArtifactLocator{evidence}, ExpectedCounts: counts,
	}, recordingSigner)
	if err != nil || recordingSigner.keyARN == "" || len(recordingSigner.signature) == 0 {
		return apiserver.RecoveryManifestLocator{}, errWorkerExecution
	}
	manifestArtifact, reference, err := publisher.put(ctx, publication, "manifest", "application/vnd.zasp.recovery-manifest+json", envelope)
	if err != nil {
		return apiserver.RecoveryManifestLocator{}, errWorkerExecution
	}
	keyID := recordingSigner.keyARN[strings.LastIndex(recordingSigner.keyARN, "/")+1:]
	return apiserver.RecoveryManifestLocator{
		Reference: reference, VersionID: manifestArtifact.VersionID, SHA256: hex.EncodeToString(manifestArtifact.SHA256[:]), SizeBytes: manifestArtifact.Size,
		MediaType: manifestArtifact.MediaType, Schema: "recovery_signed_manifest_v1", SigningKeyID: keyID, Signature: base64.RawStdEncoding.EncodeToString(recordingSigner.signature),
	}, nil
}

func (publisher *recoveryArtifactPublisher) putSection(ctx context.Context, publication recoveryBackupPublication, section, mediaType, schema string) (recovery.ArtifactLocator, error) {
	body, err := json.Marshal(publication.Sections[section])
	if err != nil || len(body) == 0 || len(body) > recoveryMaximumCapturedBytes {
		return recovery.ArtifactLocator{}, errWorkerExecution
	}
	artifact, _, err := publisher.put(ctx, publication, section, mediaType, body)
	if err != nil {
		return recovery.ArtifactLocator{}, err
	}
	return recovery.ArtifactLocator{Scope: artifact.Scope, Reference: artifact.Reference, VersionID: artifact.VersionID, SHA256: artifact.SHA256, SizeBytes: artifact.Size, MediaType: mediaType, Schema: schema}, nil
}

func (publisher *recoveryArtifactPublisher) put(ctx context.Context, publication recoveryBackupPublication, section, mediaType string, body []byte) (artifactstore.Artifact, string, error) {
	reference, err := recoverySectionReference(publication.Claim.Scope, publication.Claim.OperationID, section)
	if err != nil {
		return artifactstore.Artifact{}, "", errWorkerExecution
	}
	artifact, err := publisher.config.Store.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: publication.Claim.Scope, Reference: reference}, MediaType: mediaType, Body: append([]byte(nil), body...)})
	if err != nil || artifact.Scope != publication.Claim.Scope || artifact.Reference != reference || artifact.VersionID == "" || artifact.MediaType != mediaType || artifact.Size != int64(len(body)) || artifact.SHA256 != sha256.Sum256(body) || !bytes.Equal(artifact.Body, body) {
		return artifactstore.Artifact{}, "", errWorkerExecution
	}
	objectReference, err := publisher.config.Store.ObjectReference(artifact.Locator)
	if err != nil || objectReference == "" {
		return artifactstore.Artifact{}, "", errWorkerExecution
	}
	return artifact, objectReference, nil
}

func (signer *recordingRecoverySigner) Sign(ctx context.Context, payload []byte) (string, []byte, error) {
	keyARN, signature, err := signer.delegate.Sign(ctx, append([]byte(nil), payload...))
	if err == nil {
		signer.keyARN = keyARN
		signer.signature = append([]byte(nil), signature...)
	}
	return keyARN, signature, err
}

func exactRecoveryPublicationSections(sections map[string][]json.RawMessage) bool {
	if len(sections) != 4 {
		return false
	}
	for _, section := range []string{"configuration", "projection", "evidence", "counts"} {
		if sections[section] == nil {
			return false
		}
	}
	return len(sections["counts"]) == 1
}

func recoveryCounts(items []json.RawMessage) (map[string]uint64, error) {
	if len(items) != 1 {
		return nil, errWorkerExecution
	}
	var counts struct {
		Assets   uint64 `json:"assets"`
		Findings uint64 `json:"findings"`
		Policies uint64 `json:"policies"`
	}
	if decodeStrictWorkerJSON(items[0], &counts) != nil {
		return nil, errWorkerExecution
	}
	return map[string]uint64{"assets": counts.Assets, "findings": counts.Findings, "policies": counts.Policies}, nil
}

func recoverySectionReference(scope domain.Scope, backupID, section string) (domain.EvidenceRef, error) {
	identifier, err := apiserver.CanonicalDiscoveryID(scope, "recovery_"+section, backupID)
	if err != nil {
		return domain.EvidenceRef{}, err
	}
	productID, err := domain.ParseProductID(identifier)
	if err != nil {
		return domain.EvidenceRef{}, err
	}
	return domain.NewEvidenceRef(productID)
}

var _ recoveryBackupPublisher = (*recoveryArtifactPublisher)(nil)
