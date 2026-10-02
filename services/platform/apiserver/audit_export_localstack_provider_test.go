//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This adapter is test-only. Its owner must verify the broker descriptor and
// create/check the physical policy before constructing it. It owns no Docker.
type auditLocalstackExpected struct {
	Key, Version string
	Body         []byte
	Metadata     map[string]string
}

type auditLocalstackIntent func(context.Context, string) (auditLocalstackExpected, error)
type auditLocalstackPutResult struct {
	Key, Version string
	Status       int
	Header       http.Header
	Body         []byte
}
type auditLocalstackForwarder struct {
	endpoint  *url.URL
	policy    migrations.AuditExportConfiguration
	intent    auditLocalstackIntent
	client    *http.Client
	transport *http.Transport
	timeout   time.Duration
	saved     func(context.Context, auditLocalstackPutResult) error
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	active    sync.WaitGroup
	joined    chan struct{}
}

func newAuditLocalstackForwarder(ctx context.Context, endpoint string, policy migrations.AuditExportConfiguration, intent auditLocalstackIntent, timeout time.Duration, saved func(context.Context, auditLocalstackPutResult) error) (*auditLocalstackForwarder, error) {
	endpointURL, err := url.Parse(endpoint)
	if err != nil || endpointURL.Scheme != "http" || endpointURL.Hostname() != "127.0.0.1" || endpointURL.User != nil || endpointURL.Path != "" || endpointURL.RawQuery != "" || endpointURL.Fragment != "" || endpointURL.ForceQuery {
		return nil, errAuditLocalstack
	}
	port, err := strconv.Atoi(endpointURL.Port())
	if err != nil || port < 1 || port > 65535 || endpointURL.Host != "127.0.0.1:"+strconv.Itoa(port) || ctx == nil || ctx.Err() != nil || intent == nil || timeout <= 0 || timeout > 30*time.Second {
		return nil, errAuditLocalstack
	}
	if _, err := migrations.AuditExportPolicyDigest(policy); err != nil {
		return nil, errAuditLocalstack
	}
	// No inherited default transport, proxy, resolver, redirects or decompression.
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxResponseHeaderBytes: 32 << 10, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 2, ResponseHeaderTimeout: timeout, IdleConnTimeout: time.Second}
	dialer := &net.Dialer{Timeout: timeout}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != endpointURL.Host {
			return nil, errAuditLocalstack
		}
		return dialer.DialContext(ctx, "tcp4", endpointURL.Host)
	}
	life, cancel := context.WithCancel(ctx)
	return &auditLocalstackForwarder{endpoint: endpointURL, policy: policy, intent: intent, transport: transport, client: &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, timeout: timeout, saved: saved, ctx: life, cancel: cancel, joined: make(chan struct{})}, nil
}
func (f *auditLocalstackForwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		panic(http.ErrAbortHandler)
	}
	f.active.Add(1)
	f.mu.Unlock()
	defer f.active.Done()
	ctx, cancel := context.WithTimeout(r.Context(), f.timeout)
	defer cancel()
	stop := context.AfterFunc(f.ctx, cancel)
	defer stop()
	r = r.Clone(ctx)
	// Body.Close alone waits behind an active net/http Body.Read. Move the
	// socket read deadline too, so a partial upload cannot defeat owner join.
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)
	bodyStopped := make(chan struct{})
	stopBody := context.AfterFunc(ctx, func() {
		defer close(bodyStopped)
		_ = controller.SetReadDeadline(time.Now())
		_ = controller.SetWriteDeadline(time.Now())
		_ = r.Body.Close()
	})
	defer func() {
		if !stopBody() {
			<-bodyStopped
		}
	}()
	defer func() {
		// Returning silently lets net/http invent a 200 response. Abort the
		// stream on cancellation so a withheld Put cannot become SDK success.
		if ctx.Err() != nil {
			panic(http.ErrAbortHandler)
		}
	}()
	body, err := f.validate(r)
	if err != nil {
		if ctx.Err() == nil {
			http.Error(w, errAuditLocalstack.Error(), 400)
		}
		return
	}
	localURL := *f.endpoint
	localURL.Path = "/" + f.policy.Bucket + r.URL.Path
	localURL.RawQuery = r.URL.RawQuery
	local, err := http.NewRequestWithContext(ctx, r.Method, localURL.String(), bytes.NewReader(body))
	if err != nil {
		return
	}
	local.Header = r.Header.Clone()
	auditLocalstackStripHop(local.Header)
	for _, key := range []string{"Authorization", "X-Amz-Security-Token", "X-Amz-Date", "X-Amz-Content-Sha256", "Content-Length"} {
		local.Header.Del(key)
	}
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	local.Header.Set("X-Amz-Content-Sha256", payload)
	err = v4.NewSigner().SignHTTP(ctx, aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, local, payload, "s3", "us-east-1", time.Now(), func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	if err != nil {
		return
	}
	response, err := f.client.Do(local)
	if err != nil {
		if ctx.Err() == nil {
			http.Error(w, "owned S3 forwarding failed", 502)
		}
		return
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, audit.ExportMaximumChunkBytes+1))
	if err != nil || len(responseBody) > audit.ExportMaximumChunkBytes || !auditLocalstackHeadersBounded(response.Header) {
		if ctx.Err() == nil {
			http.Error(w, "owned S3 response exceeded bounds", 502)
		}
		return
	}
	if ctx.Err() != nil {
		return
	}
	// This hook receives genuine bytes/headers before ANY downstream write. The
	// owner must independently pin HEAD/GET before signaling its saved-Put
	// barrier, and must return when ctx is canceled. No provider mutex is held.
	if r.Method == "PUT" && response.StatusCode >= 200 && response.StatusCode < 300 && f.saved != nil {
		version := response.Header.Get("X-Amz-Version-Id")
		if !auditLocalstackVersion(version) {
			http.Error(w, "owned S3 version absent", 502)
			return
		}
		if err := f.saved(ctx, auditLocalstackPutResult{Key: strings.TrimPrefix(r.URL.Path, "/"), Version: version, Status: response.StatusCode, Header: response.Header.Clone(), Body: bytes.Clone(responseBody)}); err != nil {
			panic(http.ErrAbortHandler)
		}
	}
	if ctx.Err() != nil {
		return
	}
	// Versions and failed statuses remain provider-owned, even when malformed.
	// The actual driver and independent inventory must detect corrupt values.
	auditLocalstackStripHop(response.Header)
	for key, values := range response.Header {
		w.Header()[key] = append([]string(nil), values...)
	}
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(responseBody)
}
func (f *auditLocalstackForwarder) close(ctx context.Context) error {
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		f.cancel()
		go func() { f.active.Wait(); f.transport.CloseIdleConnections(); close(f.joined) }()
	}
	f.mu.Unlock()
	select {
	case <-f.joined:
		return nil
	case <-ctx.Done():
		return errAuditLocalstack
	}
}

func (f *auditLocalstackForwarder) validate(r *http.Request) ([]byte, error) {
	if r.TLS == nil || r.Host != f.policy.Bucket+".s3.us-east-1.amazonaws.com" || r.URL.RawPath != "" || r.URL.Fragment != "" || len(r.URL.RawQuery) > 2048 || len(r.URL.Path) > 2048 || r.ContentLength > audit.ExportMaximumChunkBytes || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || !auditLocalstackHeadersBounded(r.Header) {
		return nil, errAuditLocalstack
	}
	for key, values := range r.Header {
		if len(values) != 1 {
			return nil, errAuditLocalstack
		}
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-amz-") && !strings.HasPrefix(lower, "x-amz-meta-") {
			switch lower {
			case "x-amz-expected-bucket-owner", "x-amz-content-sha256", "x-amz-date", "x-amz-security-token", "x-amz-checksum-sha256", "x-amz-checksum-mode", "x-amz-sdk-checksum-algorithm", "x-amz-server-side-encryption", "x-amz-server-side-encryption-aws-kms-key-id":
			default:
				return nil, errAuditLocalstack
			}
		}
	}
	if r.Header.Get("Content-Encoding") != "" || r.Header.Get("Range") != "" || r.Header.Get("If-Match") != "" || r.Header.Get("Connection") != "" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != f.policy.ExpectedBucketOwner {
		return nil, errAuditLocalstack
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, errAuditLocalstack
	}
	version := query.Get("versionId")
	switch r.Method {
	case "PUT":
		if !auditExportProcessS3Query("PUT", r.URL.RawQuery, "") {
			return nil, errAuditLocalstack
		}
	case "GET":
		if !auditLocalstackVersion(version) || !auditExportProcessS3Query("GET", r.URL.RawQuery, version) {
			return nil, errAuditLocalstack
		}
	case "HEAD":
		if r.URL.RawQuery != "" && (!auditLocalstackVersion(version) || !auditExportProcessS3Query("HEAD", r.URL.RawQuery, version)) {
			return nil, errAuditLocalstack
		}
	default:
		return nil, errAuditLocalstack
	}
	wanted, err := f.intent(r.Context(), strings.TrimPrefix(r.URL.Path, "/"))
	if err != nil || "/"+wanted.Key != r.URL.Path || len(wanted.Body) == 0 || len(wanted.Body) > audit.ExportMaximumChunkBytes || wanted.Version != "" && version != "" && version != wanted.Version {
		return nil, errAuditLocalstack
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, audit.ExportMaximumChunkBytes+1))
	if err != nil || len(body) > audit.ExportMaximumChunkBytes {
		return nil, errAuditLocalstack
	}
	if r.Method == "PUT" {
		sum := sha256.Sum256(wanted.Body)
		if !bytes.Equal(body, wanted.Body) || r.Header.Get("If-None-Match") != "*" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("X-Amz-Server-Side-Encryption") != "aws:kms" || r.Header.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id") != f.policy.KMSKeyARN || r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(sum[:]) {
			return nil, errAuditLocalstack
		}
		metadata := map[string]string{}
		for key := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") {
				metadata[strings.TrimPrefix(strings.ToLower(key), "x-amz-meta-")] = r.Header.Get(key)
			}
		}
		if len(metadata) != len(wanted.Metadata) {
			return nil, errAuditLocalstack
		}
		for key, value := range wanted.Metadata {
			if metadata[key] != value {
				return nil, errAuditLocalstack
			}
		}
	} else if len(body) != 0 || r.Header.Get("X-Amz-Checksum-Mode") != "ENABLED" || r.Header.Get("If-None-Match") != "" {
		return nil, errAuditLocalstack
	}
	// Recompute the original SDK signature against the original regional host,
	// method, query, headers and payload hash before changing either authority.
	signedAt, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil || time.Since(signedAt) > 15*time.Minute || time.Until(signedAt) > time.Minute || r.Header.Get("X-Amz-Security-Token") != "owned-process-session-worker" {
		return nil, errAuditLocalstack
	}
	sum := sha256.Sum256(body)
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload != "UNSIGNED-PAYLOAD" && payload != hex.EncodeToString(sum[:]) {
		return nil, errAuditLocalstack
	}
	clone := r.Clone(r.Context())
	clone.URL.Scheme = "https"
	clone.URL.Host = r.Host
	authorization := clone.Header.Get("Authorization")
	clone.Header.Del("Authorization")
	err = v4.NewSigner().SignHTTP(r.Context(), aws.Credentials{AccessKeyID: "ASIAPROCESSWORKER", SecretAccessKey: "owned-process-secret-not-real", SessionToken: "owned-process-session-worker"}, clone, payload, "s3", "us-east-1", signedAt, func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	if err != nil || subtle.ConstantTimeCompare([]byte(authorization), []byte(clone.Header.Get("Authorization"))) != 1 {
		return nil, errAuditLocalstack
	}
	return body, nil
}

func auditLocalstackVersion(version string) bool {
	if version == "" || version == "null" || len(version) > 1024 {
		return false
	}
	for _, c := range version {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
func auditLocalstackHeadersBounded(header http.Header) bool {
	size := 0
	for key, values := range header {
		for _, value := range values {
			size += len(key) + len(value) + 4
			if size > 32<<10 {
				return false
			}
		}
	}
	return true
}
func auditLocalstackStripHop(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, key := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(key))
		}
	}
	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(key)
	}
}

var errAuditLocalstack = errors.New("owned S3 forwarding refused")

func newAuditLocalstackIntent(observer *pgx.Conn, policy migrations.AuditExportConfiguration, binding audit.ExportBinding, events []json.RawMessage) auditLocalstackIntent {
	// The owner supplies a dedicated connection and closes it after handler join.
	// This gate serializes PG use without retaining the STS/SQS provider mutex.
	source := make([]json.RawMessage, len(events))
	for index, event := range events {
		source[index] = bytes.Clone(event)
	}
	gate := make(chan struct{}, 1)
	return func(ctx context.Context, key string) (auditLocalstackExpected, error) {
		if observer == nil || len(key) > 2048 {
			return auditLocalstackExpected{}, errAuditLocalstack
		}
		policyDigest, err := migrations.AuditExportPolicyDigest(policy)
		if err != nil {
			return auditLocalstackExpected{}, errAuditLocalstack
		}
		select {
		case gate <- struct{}{}:
		case <-ctx.Done():
			return auditLocalstackExpected{}, errAuditLocalstack
		}
		var kind, id, capture, version string
		var ordinal, size int64
		var digest []byte
		err = observer.QueryRow(ctx, `SELECT i.kind,i.ordinal,i.artifact_id,i.capture_id,i.sha256,i.size_bytes,COALESCE(r.version_id,'') FROM zasp_audit_export_intents i JOIN zasp_audit_export_jobs j ON j.organization_id=i.organization_id AND j.id=i.export_id AND j.capture_id=i.capture_id LEFT JOIN zasp_audit_export_receipts r ON r.organization_id=i.organization_id AND r.export_id=i.export_id AND r.kind=i.kind AND r.ordinal=i.ordinal WHERE i.organization_id=$1 AND i.workspace_id=$2 AND i.environment_id=$3 AND i.export_id=$4 AND i.object_reference=$5 AND j.policy_id=$6 AND j.storage_policy->>'policy_digest'=$7 AND j.captured`, binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, binding.ExportID, "s3://"+policy.Bucket+"/"+key, policy.PolicyID, policyDigest).Scan(&kind, &ordinal, &id, &capture, &digest, &size, &version)
		<-gate
		if err != nil || binding.CaptureID != "" && binding.CaptureID != capture {
			return auditLocalstackExpected{}, errAuditLocalstack
		}
		capturedBinding := binding
		capturedBinding.CaptureID = capture
		expected, err := auditExportProcessExpected(capturedBinding, source)
		if err != nil {
			return auditLocalstackExpected{}, errAuditLocalstack
		}
		body, ok := expected[fmt.Sprintf("%s:%d", kind, ordinal)]
		sum := sha256.Sum256(body)
		wantKey := fmt.Sprintf("organizations/%s/workspaces/%s/environments/%s/exports/%s", binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, id)
		if !ok || key != wantKey || size != int64(len(body)) || !bytes.Equal(digest, sum[:]) {
			return auditLocalstackExpected{}, errAuditLocalstack
		}
		return auditLocalstackExpected{Key: key, Version: version, Body: bytes.Clone(body), Metadata: map[string]string{"organization_id": binding.OrganizationID, "workspace_id": binding.WorkspaceID, "environment_id": binding.EnvironmentID, "artifact_id": id, "media_type": "application/json", "sha256": hex.EncodeToString(sum[:])}}, nil
	}
}

// The caller supplies independently reconstructed bytes/metadata and exact SQL
// receipt versions. List and pinned reads below are the physical authority;
// p.objects is never read or populated. Empty expectations prove an empty bucket.
func (f *auditLocalstackForwarder) inventory(ctx context.Context, expected map[string]auditLocalstackExpected) error {
	if len(expected) > 10000 {
		return errAuditLocalstack
	}
	ctx, finish, err := f.operation(ctx, 30*time.Second)
	if err != nil {
		return err
	}
	defer finish()
	client := f.inventoryClient()
	seen := map[string]bool{}
	markers := map[string]bool{}
	var keyMarker, versionMarker *string
	for page := 0; page < 10001; page++ {
		output, err := client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(f.policy.Bucket), ExpectedBucketOwner: aws.String(f.policy.ExpectedBucketOwner), MaxKeys: aws.Int32(1000), KeyMarker: keyMarker, VersionIdMarker: versionMarker})
		if err != nil || output == nil || len(output.DeleteMarkers) != 0 || len(output.Versions) > 1000 {
			return errAuditLocalstack
		}
		for _, version := range output.Versions {
			key := aws.ToString(version.Key)
			want, ok := expected[key]
			if !ok || key != want.Key || seen[key] || !auditLocalstackVersion(want.Version) || aws.ToString(version.VersionId) != want.Version || !aws.ToBool(version.IsLatest) || aws.ToInt64(version.Size) != int64(len(want.Body)) {
				return errAuditLocalstack
			}
			seen[key] = true
		}
		if !aws.ToBool(output.IsTruncated) {
			if len(seen) != len(expected) {
				return errAuditLocalstack
			}
			for _, want := range expected {
				if err := f.pinned(ctx, want); err != nil {
					return err
				}
			}
			return nil
		}
		key, version := aws.ToString(output.NextKeyMarker), aws.ToString(output.NextVersionIdMarker)
		if key == "" || len(key) > 2048 || !auditLocalstackVersion(version) || len(output.Versions) == 0 {
			return errAuditLocalstack
		}
		marker := key + "\x00" + version
		if markers[marker] {
			return errAuditLocalstack
		}
		markers[marker] = true
		keyMarker, versionMarker = aws.String(key), aws.String(version)
	}
	return errAuditLocalstack
}

// Separate parent-only pinned proof also supports the future saved-Put hook.
func (f *auditLocalstackForwarder) pinned(ctx context.Context, expected auditLocalstackExpected) error {
	if !auditLocalstackVersion(expected.Version) || len(expected.Body) == 0 || len(expected.Body) > audit.ExportMaximumChunkBytes || expected.Key == "" || len(expected.Key) > 2048 {
		return errAuditLocalstack
	}
	ctx, finish, err := f.operation(ctx, f.timeout)
	if err != nil {
		return err
	}
	defer finish()
	client := f.inventoryClient()
	head, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(f.policy.Bucket), Key: aws.String(expected.Key), VersionId: aws.String(expected.Version), ExpectedBucketOwner: aws.String(f.policy.ExpectedBucketOwner), ChecksumMode: "ENABLED"})
	sum := sha256.Sum256(expected.Body)
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	if err != nil || head == nil || aws.ToString(head.VersionId) != expected.Version || aws.ToInt64(head.ContentLength) != int64(len(expected.Body)) || aws.ToString(head.ContentType) != "application/json" || head.ServerSideEncryption != "aws:kms" || aws.ToString(head.SSEKMSKeyId) != f.policy.KMSKeyARN || aws.ToString(head.ChecksumSHA256) != checksum || !reflect.DeepEqual(head.Metadata, expected.Metadata) {
		return errAuditLocalstack
	}
	get, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(f.policy.Bucket), Key: aws.String(expected.Key), VersionId: aws.String(expected.Version), ExpectedBucketOwner: aws.String(f.policy.ExpectedBucketOwner), ChecksumMode: "ENABLED"})
	if err != nil || get == nil || get.Body == nil {
		return errAuditLocalstack
	}
	defer get.Body.Close()
	body, err := io.ReadAll(io.LimitReader(get.Body, audit.ExportMaximumChunkBytes+1))
	if err != nil || ctx.Err() != nil || !bytes.Equal(body, expected.Body) || aws.ToString(get.VersionId) != expected.Version || aws.ToInt64(get.ContentLength) != int64(len(expected.Body)) || aws.ToString(get.ContentType) != "application/json" || get.ServerSideEncryption != "aws:kms" || aws.ToString(get.SSEKMSKeyId) != f.policy.KMSKeyARN || aws.ToString(get.ChecksumSHA256) != checksum || !reflect.DeepEqual(get.Metadata, expected.Metadata) {
		return errAuditLocalstack
	}
	return nil
}

func (f *auditLocalstackForwarder) inventoryClient() *s3.Client {
	client := *f.client
	client.Transport = auditLocalstackInventoryTransport{f.transport}
	return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(f.endpoint.String()), UsePathStyle: true, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
	}), HTTPClient: &client, RetryMaxAttempts: 1})
}

type auditLocalstackInventoryTransport struct{ transport *http.Transport }

func (f *auditLocalstackForwarder) operation(ctx context.Context, timeout time.Duration) (context.Context, func(), error) {
	f.mu.Lock()
	if f.closed || f.ctx.Err() != nil || ctx.Err() != nil {
		f.mu.Unlock()
		return nil, nil, errAuditLocalstack
	}
	f.active.Add(1)
	f.mu.Unlock()
	operation, cancel := context.WithTimeout(ctx, timeout)
	stop := context.AfterFunc(f.ctx, cancel)
	return operation, func() { stop(); cancel(); f.active.Done() }, nil
}

func (t auditLocalstackInventoryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.transport.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	// Bound XML before the SDK's list decoder can allocate an unbounded page.
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, audit.ExportMaximumChunkBytes+1))
	if err != nil || len(body) > audit.ExportMaximumChunkBytes {
		return nil, errAuditLocalstack
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}
