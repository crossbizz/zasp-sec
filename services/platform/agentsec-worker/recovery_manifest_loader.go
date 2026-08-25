package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery"
)

type recoveryManifestLoaderConfig struct {
	Store    artifactstore.ArtifactStore
	Verifier recovery.ManifestVerifier
	Now      func() time.Time
}

type recoveryArtifactManifestLoader struct{ config recoveryManifestLoaderConfig }

type recoverySignedEnvelopeAuthority struct {
	SchemaVersion string `json:"schema_version"`
	SigningKeyARN string `json:"signing_key_arn"`
	Payload       string `json:"payload"`
	Signature     string `json:"signature"`
}

func newRecoveryArtifactManifestLoader(config recoveryManifestLoaderConfig) (*recoveryArtifactManifestLoader, error) {
	if config.Store == nil || config.Verifier == nil || config.Now == nil {
		return nil, errWorkerExecution
	}
	now := config.Now()
	if now.IsZero() || now.Location() != time.UTC || now.Nanosecond() != 0 {
		return nil, errWorkerExecution
	}
	return &recoveryArtifactManifestLoader{config: config}, nil
}

func (loader *recoveryArtifactManifestLoader) Load(ctx context.Context, claim recoveryOperationClaim) (recovery.Manifest, error) {
	if loader == nil || ctx == nil || ctx.Err() != nil || !validRecoveryOperationClaim(claim) || claim.Kind != "restore" || claim.Manifest == nil {
		return recovery.Manifest{}, errRecoveryManifestInvalid
	}
	identifier := claim.Manifest.Reference[strings.LastIndex(claim.Manifest.Reference, "/")+1:]
	productID, err := domain.ParseProductID(identifier)
	if err != nil {
		return recovery.Manifest{}, errRecoveryManifestInvalid
	}
	reference, err := domain.NewEvidenceRef(productID)
	if err != nil {
		return recovery.Manifest{}, errRecoveryManifestInvalid
	}
	artifact, err := loader.config.Store.Get(ctx, artifactstore.Locator{Scope: claim.Scope, Reference: reference, VersionID: claim.Manifest.VersionID})
	if err != nil || artifact.Scope != claim.Scope || artifact.Reference != reference || artifact.VersionID != claim.Manifest.VersionID || artifact.MediaType != claim.Manifest.MediaType || artifact.Size != claim.Manifest.SizeBytes || artifact.Size != int64(len(artifact.Body)) || artifact.SHA256 != sha256.Sum256(artifact.Body) || hex.EncodeToString(artifact.SHA256[:]) != claim.Manifest.SHA256 {
		return recovery.Manifest{}, errRecoveryManifestInvalid
	}
	var envelope recoverySignedEnvelopeAuthority
	if err := decodeStrictWorkerJSON(artifact.Body, &envelope); err != nil || envelope.SchemaVersion != "recovery_signed_manifest_v1" || !strings.HasSuffix(envelope.SigningKeyARN, "/"+claim.Manifest.SigningKeyID) || envelope.Signature != claim.Manifest.Signature {
		return recovery.Manifest{}, errRecoveryManifestInvalid
	}
	publicSignature, err := base64.RawStdEncoding.Strict().DecodeString(claim.Manifest.Signature)
	if err != nil || len(publicSignature) < sha256.Size || len(publicSignature) > 512 {
		return recovery.Manifest{}, errRecoveryManifestInvalid
	}
	envelopeSignature, err := base64.RawStdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || !bytes.Equal(envelopeSignature, publicSignature) {
		return recovery.Manifest{}, errRecoveryManifestInvalid
	}
	manifest, err := recovery.DecodeSignedManifest(ctx, bytes.NewReader(artifact.Body), loader.config.Verifier, loader.config.Now())
	switch {
	case errors.Is(err, recovery.ErrSignature):
		return recovery.Manifest{}, errRecoverySignatureInvalid
	case errors.Is(err, recovery.ErrExpired):
		return recovery.Manifest{}, errRecoveryManifestExpired
	case err != nil:
		return recovery.Manifest{}, errRecoveryManifestInvalid
	case manifest.Scope != claim.Scope:
		return recovery.Manifest{}, errRecoveryManifestInvalid
	default:
		return manifest, nil
	}
}

var _ recoveryManifestLoader = (*recoveryArtifactManifestLoader)(nil)
