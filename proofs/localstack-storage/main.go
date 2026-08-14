package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

const proofSuccess = "LocalStack storage proof passed: kms=true s3=true secret=true round_trip=true cleanup=true audit=true."

func main() {
	if len(os.Args) != 1 { failMain("configuration") }
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	markerBytes := make([]byte, 8)
	if _, err := rand.Read(markerBytes); err != nil { failMain("configuration") }
	marker := hex.EncodeToString(markerBytes)
	bundle, err := newSDKClients(ctx, os.Getenv("AWS_ENDPOINT_URL"))
	if err != nil { failMain("configuration") }
	defer bundle.Close()
	result, err := RunProof(ctx, ProofOptions{Endpoint: os.Getenv("AWS_ENDPOINT_URL"), Marker: marker, KMS: bundle.KMS, S3: bundle.S3, Secrets: bundle.Secrets, CleanupTimeout: 20 * time.Second, PollInterval: 100 * time.Millisecond})
	if err != nil { failMain(errorCategory(err)) }
	auditCtx, auditCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer auditCancel()
	if err := AuditStorage(auditCtx, bundle.KMS, bundle.S3, bundle.Secrets, marker, result.KMSKeyID); err != nil { failMain("operation") }
	fmt.Println(proofSuccess)
}

func failMain(category string) {
	fmt.Fprintf(os.Stderr, "LocalStack storage proof failed: %s rejected.\n", category)
	os.Exit(1)
}
