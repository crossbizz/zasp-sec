package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"
)

const (
	proofSuccessLine = "LocalStack IAM compatibility proof passed: namespaces=true assumed=true allowed_read=true explicit_deny=true cleanup=true audit=true container_cleanup=true."
	mainTimeout      = 90 * time.Second
	cleanupTimeout   = 30 * time.Second
)

type mainBoundaryFactory func(context.Context, string, string, string) (IAMBoundary, error)
type mainProofRunner func(context.Context, ProofOptions) (ProofResult, error)

var (
	newMainBoundary mainBoundaryFactory = func(ctx context.Context, endpoint, source, target string) (IAMBoundary, error) {
		return NewSDKBoundary(ctx, endpoint, source, target)
	}
	runMainProof mainProofRunner = RunProof
	mainMarker                   = randomMainMarker
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), mainTimeout)
	defer cancel()
	os.Exit(runMain(ctx, os.Stdout, os.Getenv))
}

func runMain(ctx context.Context, out io.Writer, getenv func(string) string) (code int) {
	defer func() {
		if recover() != nil {
			code = writeMainFailure(out, "operation")
		}
	}()
	if ctx == nil || out == nil || getenv == nil {
		return writeMainFailure(out, "configuration")
	}
	endpoint, path := getenv("AWS_ENDPOINT_URL"), getenv("PATH")
	if endpoint == "" || path == "" {
		return writeMainFailure(out, "configuration")
	}
	marker, err := mainMarker()
	if err != nil || !markerPattern.MatchString(marker) {
		return writeMainFailure(out, "configuration")
	}
	boundary, err := newMainBoundary(ctx, endpoint, sourceNamespace, targetNamespace)
	if err != nil {
		return writeMainFailure(out, "configuration")
	}
	result, err := runMainProof(ctx, ProofOptions{
		Marker: marker, Endpoint: endpoint, SourceAccountID: sourceNamespace, TargetAccountID: targetNamespace,
		Boundary: boundary, CleanupTimeout: cleanupTimeout, PollInterval: 250 * time.Millisecond, Now: time.Now,
	})
	if err != nil || result != (ProofResult{Namespaces: true, Assumed: true, AllowedRead: true, ExplicitDeny: true, Cleanup: true, Audit: true}) {
		return writeMainFailure(out, fixedMainCategory(err))
	}
	_, _ = io.WriteString(out, proofSuccessLine+"\n")
	return 0
}

func randomMainMarker() (string, error) {
	var raw [8]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func writeMainFailure(out io.Writer, category string) int {
	if out != nil {
		_, _ = io.WriteString(out, "LocalStack IAM compatibility proof failed: "+category+" rejected.\n")
	}
	return 1
}

func fixedMainCategory(err error) string {
	switch {
	case errors.Is(err, errConfiguration):
		return "configuration"
	case errors.Is(err, errCapability):
		return "capability"
	case errors.Is(err, errAuthorization):
		return "authorization"
	case errors.Is(err, errOwnership):
		return "ownership"
	case errors.Is(err, errCleanup):
		return "cleanup"
	default:
		return "operation"
	}
}
