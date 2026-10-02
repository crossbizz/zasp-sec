//go:build darwin || linux

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zasp-ai/zasp-sec/services/platform/auditexportconfig"
)

const auditBrowserAPIPolicy = `[{"schema":"audit-export-policy-v1","policy_id":"pid_7b000001-0000-4000-8000-000000000001","bucket":"owned-audit-browser-fixture","expected_bucket_owner":"123456789012","kms_key_arn":"arn:aws:kms:us-east-1:123456789012:key/7b000002-0000-4000-8000-000000000002","maximum_export_bytes":1073741824,"maximum_retained_bytes":10737418240,"maximum_inflight":2,"capture_timeout_seconds":120}]`
const auditBrowserReaderRole = "arn:aws:iam::123456789012:role/zasp-owned-audit-browser-reader"

func auditBrowserStorageResources(config RuntimeConfig, address, caPath, tokenPath string) (auditExportStorageResources, error) {
	expected, err := auditexportconfig.ParsePolicies([]byte(auditBrowserAPIPolicy))
	host, port, splitErr := net.SplitHostPort(address)
	number, portErr := strconv.Atoi(port)
	ip := net.ParseIP(host)
	if err != nil || !validRuntimeConfig(config) || config.AuditExports == nil || config.AuditExports.ReaderRoleARN != auditBrowserReaderRole || len(config.AuditExports.Policies) != 1 || config.AuditExports.Policies[0] != expected[0] || splitErr != nil || ip == nil || !ip.IsLoopback() || portErr != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port || net.JoinHostPort(ip.String(), port) != address {
		return auditExportStorageResources{}, errRuntimeUnavailable
	}
	ca, err := auditBrowserPrivateFile(caPath, 16384)
	if err != nil {
		return auditExportStorageResources{}, err
	}
	token, err := auditBrowserPrivateFile(tokenPath, 4096)
	if err != nil {
		return auditExportStorageResources{}, err
	}
	validToken := len(token) >= 64 && webIdentityTokenPattern.Match(token) && strings.TrimSpace(string(token)) == string(token)
	clear(token)
	roots := x509.NewCertPool()
	if !validToken || !roots.AppendCertsFromPEM(ca) {
		return auditExportStorageResources{}, errRuntimeUnavailable
	}
	resources, err := newAuditExportStorageResources(config)
	if err != nil {
		return resources, err
	}
	for _, provider := range resources.credentials {
		provider.tokenFile = tokenPath
	}
	resources.transport.TLSClientConfig.RootCAs = roots
	resources.transport.TLSClientConfig.ServerName = "example.com"
	resources.transport.DialContext = func(ctx context.Context, network, destination string) (net.Conn, error) {
		if network != "tcp" || destination != "sts.us-east-1.amazonaws.com:443" && destination != "owned-audit-browser-fixture.s3.us-east-1.amazonaws.com:443" {
			return nil, errors.New("unowned browser provider destination")
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	}
	return resources, nil
}

func auditBrowserPrivateFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > maximum {
		return nil, errRuntimeUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) > maximum {
		return nil, errRuntimeUnavailable
	}
	return raw, nil
}

func auditBrowserAPIConfig(t *testing.T) RuntimeConfig {
	t.Helper()
	config := fixtureAuditExportRuntimeConfig(t)
	policies, err := auditexportconfig.ParsePolicies([]byte(auditBrowserAPIPolicy))
	if err != nil {
		t.Fatal(err)
	}
	config.AuditExports.Policies = policies
	config.AuditExports.ReaderRoleARN = auditBrowserReaderRole
	return config
}

func TestAuditBrowserReaderUsesCachedWebIdentity(t *testing.T) {
	config := auditBrowserAPIConfig(t)
	token := strings.Repeat("owned-browser-token-", 8)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	var assumes, reads atomic.Int32
	front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "sts.us-east-1.amazonaws.com" {
			assumes.Add(1)
			if r.Method != "POST" || r.ParseForm() != nil || r.Form.Get("Action") != "AssumeRoleWithWebIdentity" || r.Form.Get("Version") != "2011-06-15" || r.Form.Get("RoleArn") != auditBrowserReaderRole || r.Form.Get("RoleSessionName") != "zasp-api-audit-read" || r.Form.Get("WebIdentityToken") != token || r.Form.Get("DurationSeconds") != "900" || r.Header.Get("Authorization") != "" {
				t.Error("selected reader STS authority changed")
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIABROWSERREADER</AccessKeyId><SecretAccessKey>owned-browser-reader-secret-not-real</SecretAccessKey><SessionToken>owned-browser-reader-session</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
			return
		}
		if r.Host != "owned-audit-browser-fixture.s3.us-east-1.amazonaws.com" || r.Method != "GET" || r.URL.Query().Get("versionId") != "owned-version" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" || !strings.Contains(r.Header.Get("Authorization"), "Credential=ASIABROWSERREADER/") || r.Header.Get("X-Amz-Security-Token") != "owned-browser-reader-session" {
			t.Error("selected S3 reader authority changed")
			w.WriteHeader(400)
			return
		}
		reads.Add(1)
		w.Header().Set("X-Amz-Version-Id", "owned-version")
		_, _ = io.WriteString(w, "owned-browser-bytes")
	}))
	defer front.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	resources, err := auditBrowserStorageResources(config, front.Listener.Addr().String(), caPath, tokenPath)
	if err != nil {
		t.Fatal("actual selected reader refused", err)
	}
	defer resources.transport.CloseIdleConnections()
	client := resources.entries[0].Client.(*s3.Client)
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("owned-audit-browser-fixture"), Key: aws.String("owned"), VersionId: aws.String("owned-version"), ExpectedBucketOwner: aws.String("123456789012")})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(out.Body)
		closeErr := out.Body.Close()
		cancel()
		if readErr != nil || closeErr != nil || string(body) != "owned-browser-bytes" {
			t.Fatal("actual pinned bytes changed")
		}
	}
	if assumes.Load() != 1 || reads.Load() != 2 {
		t.Fatal("selected cached reader did not reuse actual STS exchange", assumes.Load(), reads.Load())
	}
	for _, change := range []func(*RuntimeConfig){
		func(c *RuntimeConfig) { c.AuditExports.ReaderRoleARN = "arn:aws:iam::123456789012:role/other" },
		func(c *RuntimeConfig) { c.AuditExports.Policies[0].Bucket = "other-bucket" },
		func(c *RuntimeConfig) {
			c.AuditExports.Policies[0].PolicyID = "pid_52000041-0000-4000-8000-000000000041"
		},
	} {
		bad := auditBrowserAPIConfig(t)
		change(&bad)
		if r, e := auditBrowserStorageResources(bad, front.Listener.Addr().String(), caPath, tokenPath); e == nil || r.transport != nil {
			t.Fatal("mismatched selected authority admitted")
		}
	}
	for _, address := range []string{"example.com:443", "127.0.0.1:0443", "192.0.2.1:443", "127.0.0.1:0"} {
		if r, e := auditBrowserStorageResources(config, address, caPath, tokenPath); e == nil || r.transport != nil {
			t.Fatal("foreign/noncanonical provider admitted")
		}
	}
	if err := os.Chmod(tokenPath, 0644); err != nil {
		t.Fatal(err)
	}
	if r, e := auditBrowserStorageResources(config, front.Listener.Addr().String(), caPath, tokenPath); e == nil || r.transport != nil {
		t.Fatal("public token admitted")
	}
}
