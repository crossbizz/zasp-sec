package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func localGraphAuthorityPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local graph authority"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
}

// The graph worker trusts a local certificate authority and accepts a Neo4j
// Community server only with the local cloud emulator, which production
// refuses. Without the emulator the environment is not even read.
func TestGraphDevelopmentSettingsApplyOnlyForLocalEmulator(t *testing.T) {
	t.Parallel()
	authority := localGraphAuthorityPEM(t)
	const path = "/state/tls/neo4j/ca.crt"
	variable := func(value string) func(string) string {
		return func(name string) string {
			if name == localNeo4jCAVariable {
				return value
			}
			return ""
		}
	}
	reads := 0
	read := func(content []byte, err error) func(string) ([]byte, error) {
		return func(name string) ([]byte, error) {
			reads++
			if name != path {
				t.Fatalf("read %q", name)
			}
			return content, err
		}
	}

	for _, test := range []struct{ name, environment, endpoint string }{
		{"production without emulator", "production", ""},
		{"production with a refused emulator", "production", "http://127.0.0.1:4566"},
		{"unset environment", "", "http://127.0.0.1:4566"},
		{"staging", "staging", "http://127.0.0.1:4566"},
		{"development without emulator", "development", ""},
		{"test without emulator", "test", ""},
	} {
		development, err := loadProjectionGraphDevelopment(localCloudSettings(t, test.environment, test.endpoint), variable(path), read(authority, nil))
		if err != nil || development.RootCAs != nil || development.CommunityEdition || reads != 0 {
			t.Fatalf("%s: settings = %#v, %v, reads = %d; want none", test.name, development, err, reads)
		}
	}

	for _, environment := range []string{"development", "test"} {
		emulator := localCloudSettings(t, environment, "http://127.0.0.1:4566")
		// Without a named authority the system trust store stays in use.
		development, err := loadProjectionGraphDevelopment(emulator, variable(""), read(authority, nil))
		if err != nil || development.RootCAs != nil || !development.CommunityEdition {
			t.Fatalf("%s emulator without authority = %#v, %v", environment, development, err)
		}
		if development, err := loadProjectionGraphDevelopment(emulator, nil, nil); err != nil || development.RootCAs != nil || !development.CommunityEdition {
			t.Fatalf("%s emulator without environment = %#v, %v", environment, development, err)
		}
		development, err = loadProjectionGraphDevelopment(emulator, variable(path), read(authority, nil))
		if err != nil || development.RootCAs == nil || !development.CommunityEdition {
			t.Fatalf("%s emulator with authority = %#v, %v", environment, development, err)
		}
		block, _ := pem.Decode(authority)
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if _, verifyErr := certificate.Verify(x509.VerifyOptions{Roots: development.RootCAs}); verifyErr != nil {
			t.Fatalf("%s emulator trust store does not hold the named authority: %v", environment, verifyErr)
		}
	}

	// A named authority that cannot be used refuses the start; it never falls
	// back to another trust store.
	emulator := localCloudSettings(t, "development", "http://127.0.0.1:4566")
	for name, test := range map[string]struct {
		path string
		read func(string) ([]byte, error)
	}{
		"relative path":  {"tls/neo4j/ca.crt", read(authority, nil)},
		"unclean path":   {"/state/tls/../tls/neo4j/ca.crt", read(authority, nil)},
		"unreadable":     {path, read(nil, errors.New("not found"))},
		"empty":          {path, read([]byte{}, nil)},
		"not a PEM file": {path, read([]byte("not a certificate"), nil)},
		"oversized":      {path, read(make([]byte, localNeo4jCAMaximumBytes+1), nil)},
		"no file reader": {path, nil},
	} {
		if development, err := loadProjectionGraphDevelopment(emulator, variable(test.path), test.read); !errors.Is(err, errWorkerConfiguration) || development.RootCAs != nil || development.CommunityEdition {
			t.Fatalf("%s: settings = %#v, %v; want refusal", name, development, err)
		}
	}
}

func TestNeo4jSecretsResolverReportsOnlyAResolvedCredential(t *testing.T) {
	t.Parallel()
	secret := `{"scheme":"basic","principal":"neo4j","credentials":"password-material"}`
	api := &projectionSecretsStub{output: &secretsmanager.GetSecretValueOutput{SecretString: &secret}}
	resolved := 0
	resolver := &projectionNeo4jAuthenticationResolver{client: api, prefix: "zasp-production/projection", resolved: func() { resolved++ }}
	if _, err := resolver.ResolveNeo4jAuthentication(context.Background(), "ref:neo4j/auth/production"); err != nil || resolved != 1 {
		t.Fatalf("resolved = %d, %v", resolved, err)
	}
	malformed := `{"scheme":"basic"}`
	api.output = &secretsmanager.GetSecretValueOutput{SecretString: &malformed}
	if _, err := resolver.ResolveNeo4jAuthentication(context.Background(), "ref:neo4j/auth/production"); !errors.Is(err, errRuntimeUnavailable) || resolved != 1 {
		t.Fatalf("resolved after a malformed secret = %d, %v", resolved, err)
	}
}

// A refused graph start names the step it stopped at, and a local trust store
// that cannot be loaded stops it before any provider is contacted.
func TestGraphProjectionRefusesAnUnusableLocalAuthorityBeforeAnyProvider(t *testing.T) {
	_, err := newProductionGraphProjectionWithDevelopment(context.Background(), workerRuntimeConfig{}, func() (projectionGraphDevelopment, error) {
		return projectionGraphDevelopment{}, errWorkerConfiguration
	})
	if !errors.Is(err, errRuntimeUnavailable) || currentStartupStage() != "projection-graph-local-trust" {
		t.Fatalf("refusal = %v at stage %q", err, currentStartupStage())
	}
	_, err = newProductionGraphProjectionWithDevelopment(context.Background(), workerRuntimeConfig{}, func() (projectionGraphDevelopment, error) {
		return projectionGraphDevelopment{}, nil
	})
	if !errors.Is(err, errRuntimeUnavailable) || currentStartupStage() != "projection-aws-authority" {
		t.Fatalf("refusal = %v at stage %q", err, currentStartupStage())
	}
}
