package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

const (
	proofSuccess         = "LocalStack storage proof passed: kms=true s3=true secret=true round_trip=true cleanup=true audit=true."
	artifactProofSuccess = "LocalStack artifact store passed: put=true get=true delete=true scoped=true encrypted=true cleanup=true audit=true."
)

func main() {
	artifactMode := len(os.Args) == 2 && os.Args[1] == "artifact-store"
	if len(os.Args) != 1 && !artifactMode {
		failMain("configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	markerBytes := make([]byte, 8)
	if _, err := rand.Read(markerBytes); err != nil {
		failMain("configuration")
	}
	marker := hex.EncodeToString(markerBytes)
	bundle, err := newSDKClients(ctx, os.Getenv("AWS_ENDPOINT_URL"))
	if err != nil {
		failMain("configuration")
	}
	defer bundle.Close()
	if artifactMode {
		result, err := RunArtifactStoreProof(ctx, ArtifactProofOptions{Endpoint: os.Getenv("AWS_ENDPOINT_URL"), Marker: marker, KMS: bundle.KMS, S3: bundle.S3, CleanupTimeout: 20 * time.Second, PollInterval: 100 * time.Millisecond})
		if err != nil {
			failArtifactMain(errorCategory(err))
		}
		auditCtx, auditCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer auditCancel()
		if err := AuditArtifactStore(auditCtx, bundle.KMS, bundle.S3, marker, result.KMSKeyID); err != nil {
			failArtifactMain("operation")
		}
		fmt.Println(artifactProofSuccess)
		return
	}
	result, err := RunProof(ctx, ProofOptions{Endpoint: os.Getenv("AWS_ENDPOINT_URL"), Marker: marker, KMS: bundle.KMS, S3: bundle.S3, Secrets: bundle.Secrets, CleanupTimeout: 20 * time.Second, PollInterval: 100 * time.Millisecond})
	if err != nil {
		failMain(errorCategory(err))
	}
	auditCtx, auditCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer auditCancel()
	if err := AuditStorage(auditCtx, bundle.KMS, bundle.S3, bundle.Secrets, marker, result.KMSKeyID); err != nil {
		failMain("operation")
	}
	fmt.Println(proofSuccess)
}

func failArtifactMain(category string) {
	fmt.Fprintf(os.Stderr, "LocalStack artifact store failed: %s rejected.\n", category)
	os.Exit(1)
}

func failMain(category string) {
	fmt.Fprintf(os.Stderr, "LocalStack storage proof failed: %s rejected.\n", category)
	os.Exit(1)
}
