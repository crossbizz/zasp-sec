package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"
)

const proofSuccess = "LocalStack SQS proof passed: queues=true redrive=true batch_events=2 round_trip=true empty=true cleanup=true."

func main() {
	if len(os.Args) == 2 && os.Args[1] == "audit" {
		runAuditMain()
		return
	}
	if len(os.Args) != 1 {
		failMain("configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	markerBytes := make([]byte, 8)
	if _, err := rand.Read(markerBytes); err != nil {
		failMain("configuration")
	}
	marker := hex.EncodeToString(markerBytes)
	client, err := newSDKQueueClient(ctx, os.Getenv("AWS_ENDPOINT_URL"))
	if err != nil {
		failMain("configuration")
	}
	if err := RunProof(ctx, ProofOptions{Endpoint: os.Getenv("AWS_ENDPOINT_URL"), Marker: marker, Client: client, CleanupTimeout: 15 * time.Second, PollInterval: 100 * time.Millisecond}); err != nil {
		failMain(errorCategory(err))
	}
	auditCtx, auditCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer auditCancel()
	if err := AuditNoQueues(auditCtx, client, marker); err != nil {
		failMain("operation")
	}
	fmt.Println(proofSuccess)
}

func errorCategory(err error) string {
	switch {
	case errors.Is(err, errConfiguration):
		return "configuration"
	case errors.Is(err, errOwnership):
		return "ownership"
	case errors.Is(err, errPolicy):
		return "policy"
	case errors.Is(err, errMessage):
		return "message"
	case errors.Is(err, errCleanup):
		return "cleanup"
	default:
		return "operation"
	}
}

func failMain(category string) {
	fmt.Fprintf(os.Stderr, "LocalStack SQS proof failed: %s rejected.\n", category)
	os.Exit(1)
}
