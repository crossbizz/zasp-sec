package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestComplianceStorageFactoryBoundary(t *testing.T) {
	t.Setenv("HOSTNAME", "compliance-browser-test")
	env := complianceAPIEnvironment()
	config, err := loadRuntimeConfigFromEnvironment(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	db := &complianceRuntimeDatabase{}
	called := false
	_, err = composeRuntimeDependenciesWithStorage(context.Background(), config, db, db, auditFactoryProvider(), newAuditExportStorageClients, func(RuntimeConfig) (complianceStorageResources, error) {
		called = true
		return complianceStorageResources{}, errors.New("controlled boundary failure")
	})
	if !called || err == nil {
		t.Fatal("configured storage factory was bypassed")
	}
}

// Test-only read transport for the exact persisted object emitted by the real
// worker SDK fixture. No request from this transport can reach a network.
type complianceBrowserReadTransport struct{ path string }

func (h complianceBrowserReadTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if _, ok := r.Context().Deadline(); !ok {
		return nil, errors.New("unbounded read")
	}
	if (r.Method != "GET" && r.Method != "HEAD") || r.URL.Host != "controlled.invalid" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" || r.URL.Query().Get("versionId") != "compliance-process-v1" {
		return nil, errors.New("read pins refused")
	}
	raw, err := os.ReadFile(h.path)
	if err != nil {
		return nil, err
	}
	var object struct {
		Body    []byte
		Headers http.Header
		Key     string
	}
	if json.Unmarshal(raw, &object) != nil || object.Key != r.URL.Path {
		return nil, errors.New("object identity refused")
	}
	body := object.Body
	if r.Method == "HEAD" {
		body = nil
	}
	return &http.Response{StatusCode: 200, Header: object.Headers.Clone(), Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
}

func TestComplianceBrowserAPIProcess(t *testing.T) {
	if os.Getenv("ZASP_COMPLIANCE_BROWSER_API") != "true" {
		t.Skip("owned browser fixture not selected")
	}
	config, err := loadRuntimeConfigFromEnvironment(os.LookupEnv)
	if err != nil {
		fmt.Fprintln(os.Stderr, complianceBrowserFailureMarker(complianceBrowserConfigLoad))
		t.Fatal(err)
	}
	legacy := os.Getenv("ZASP_COMPLIANCE_BROWSER_LEGACY") == "true"
	if auditBrowserProcessInputs(config, os.Getenv("ZASP_COMPLIANCE_BROWSER_PG_PORT")) != nil || (config.ComplianceExports == nil) != legacy {
		fmt.Fprintln(os.Stderr, complianceBrowserFailureMarker(complianceBrowserOwnedInputs))
		t.Fatal("owned database/config refused")
	}
	path := os.Getenv("ZASP_COMPLIANCE_BROWSER_OBJECT")
	if !strings.HasPrefix(path, "/tmp/zasp-compliance-browser-") || strings.Contains(path, "..") {
		fmt.Fprintln(os.Stderr, complianceBrowserFailureMarker(complianceBrowserStoragePath))
		t.Fatal("owned storage path refused")
	}
	deadline, err := time.Parse(time.RFC3339Nano, os.Getenv("ZASP_COMPLIANCE_BROWSER_DEADLINE"))
	if err != nil || time.Until(deadline) < time.Second || time.Until(deadline) > 30*time.Minute {
		fmt.Fprintln(os.Stderr, complianceBrowserFailureMarker(complianceBrowserBoundedDeadline))
		t.Fatal("bounded deadline required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	factory := func(c RuntimeConfig) (complianceStorageResources, error) {
		if legacy {
			return complianceStorageResources{}, errors.New("disabled compliance service invoked storage factory")
		}
		provider := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://controlled.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: complianceBrowserReadTransport{path}}})
		p := c.ComplianceExports
		return complianceStorageResources{config: apiserver.ComplianceHandlerConfiguration{Bucket: p.Bucket, ExpectedBucketOwner: p.Owner, KMSKeyARN: p.KMSKey, Client: provider, ProviderTimeout: c.ProviderTimeout}, transport: &http.Transport{}}, nil
	}
	deps, err := buildRuntimeDependenciesWithStorage(ctx, config, newAuditExportStorageClients, factory)
	if err != nil {
		fmt.Fprintln(os.Stderr, complianceBrowserFailureMarker(complianceBrowserRuntimeBuild))
		t.Fatal("compliance browser runtime refused", err)
	}
	if err := serveRuntime(ctx, io.Discard, "compliance-browser", config, deps, net.Listen); err != nil {
		fmt.Fprintln(os.Stderr, complianceBrowserFailureMarker(complianceBrowserServe))
		t.Fatal(err)
	}
}

type complianceBrowserFailureStage uint8

const (
	complianceBrowserConfigLoad complianceBrowserFailureStage = iota + 1
	complianceBrowserOwnedInputs
	complianceBrowserStoragePath
	complianceBrowserBoundedDeadline
	complianceBrowserRuntimeBuild
	complianceBrowserServe
)

func complianceBrowserFailureMarker(stage complianceBrowserFailureStage) string {
	switch stage {
	case complianceBrowserConfigLoad:
		return "ZASP_COMPLIANCE_API_FAILED_STAGE=config-load"
	case complianceBrowserOwnedInputs:
		return "ZASP_COMPLIANCE_API_FAILED_STAGE=owned-inputs"
	case complianceBrowserStoragePath:
		return "ZASP_COMPLIANCE_API_FAILED_STAGE=storage-path"
	case complianceBrowserBoundedDeadline:
		return "ZASP_COMPLIANCE_API_FAILED_STAGE=bounded-deadline"
	case complianceBrowserRuntimeBuild:
		return "ZASP_COMPLIANCE_API_FAILED_STAGE=runtime-build"
	case complianceBrowserServe:
		return "ZASP_COMPLIANCE_API_FAILED_STAGE=serve"
	default:
		return "ZASP_COMPLIANCE_API_FAILED_STAGE=unavailable"
	}
}
