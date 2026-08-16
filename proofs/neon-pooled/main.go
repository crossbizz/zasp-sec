package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	proofTimeout          = 30 * time.Second
	migrationProofTimeout = 3 * time.Minute
)

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "migration" || os.Args[1] == "schema-baseline") {
		runMigrationMain(os.Args[1] == "schema-baseline")
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "Neon proof failed: command rejected.")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), proofTimeout)
	defer cancel()

	summary, err := executeProof(ctx, os.Getenv("DATABASE_URL"), openPGXPool)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Neon pooled proof failed: %s.\n", err)
		os.Exit(1)
	}
	fmt.Println(summary)
}

func runMigrationMain(productBaseline bool) {
	failurePrefix := "Neon migration proof failed"
	if productBaseline {
		failurePrefix = "Neon schema baseline failed"
	}
	ctx, cancel := context.WithTimeout(context.Background(), migrationProofTimeout)
	defer cancel()

	markerBytes := make([]byte, 8)
	if _, err := rand.Read(markerBytes); err != nil {
		fmt.Fprintf(os.Stderr, "%s: migration configuration rejected.\n", failurePrefix)
		os.Exit(1)
	}
	apiKey := os.Getenv("NEON_API_KEY")
	projectID := os.Getenv("NEON_PROJECT_ID")
	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       30 * time.Second,
		},
	}
	api, err := newNeonAPIClient(neonOfficialAPIBaseURL, apiKey, httpClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s.\n", failurePrefix, errMigrationConfiguration)
		os.Exit(1)
	}
	opener := openPGXMigrationDatabase
	if productBaseline {
		opener = openPGXProductMigrationDatabase
	}
	summary, err := executeMigrationProof(ctx, migrationRunConfig{
		apiKey:          apiKey,
		databaseURL:     os.Getenv("DATABASE_URL"),
		marker:          hex.EncodeToString(markerBytes),
		projectID:       projectID,
		productBaseline: productBaseline,
	}, migrationDependencies{api: api, openDatabase: opener})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s.\n", failurePrefix, err)
		os.Exit(1)
	}
	fmt.Println(summary)
}
