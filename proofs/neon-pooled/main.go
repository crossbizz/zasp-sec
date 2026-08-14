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
	if len(os.Args) == 2 && os.Args[1] == "migration" {
		runMigrationMain()
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

func runMigrationMain() {
	ctx, cancel := context.WithTimeout(context.Background(), migrationProofTimeout)
	defer cancel()

	markerBytes := make([]byte, 8)
	if _, err := rand.Read(markerBytes); err != nil {
		fmt.Fprintln(os.Stderr, "Neon migration proof failed: migration configuration rejected.")
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
		fmt.Fprintf(os.Stderr, "Neon migration proof failed: %s.\n", errMigrationConfiguration)
		os.Exit(1)
	}
	summary, err := executeMigrationProof(ctx, migrationRunConfig{
		apiKey:      apiKey,
		databaseURL: os.Getenv("DATABASE_URL"),
		marker:      hex.EncodeToString(markerBytes),
		projectID:   projectID,
	}, migrationDependencies{api: api, openDatabase: openPGXMigrationDatabase})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Neon migration proof failed: %s.\n", err)
		os.Exit(1)
	}
	fmt.Println(summary)
}
