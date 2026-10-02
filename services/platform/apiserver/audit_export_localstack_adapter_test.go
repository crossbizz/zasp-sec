//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
)

// Deterministic transport controls, never actual LocalStack inventory evidence.
// Dropping forwarding, manufacturing versions, or accepting modified signed
// requests must fail these checks against the independent HTTP endpoint.
func auditLocalstackControlExpected() auditLocalstackExpected {
	return auditLocalstackExpected{Key: "organizations/org/workspaces/ws/environments/env/exports/artifact", Body: []byte(`{"fixture":"canonical"}`), Metadata: map[string]string{"organization_id": "org", "workspace_id": "ws", "environment_id": "env", "artifact_id": "artifact", "media_type": "application/json", "sha256": "e672370899cbc3a96d17f78bf5d30132a8dc949b8b75e0cb227f055903ba6b2a"}}
}

// Accepting canned or corrupted versions must fail independent pinned reads
// and inventory comparison. The endpoint is a declared HTTP control, not S3.
func TestAuditExportLocalstackInventoryRejectsCorruptionAndPaginates(t *testing.T) {
	for _, fault := range []string{"", "version", "head version", "get version", "body", "checksum", "kms", "metadata", "size", "extra version", "delete marker", "repeat marker", "missing marker", "unexpected key", "missing key", "oversize list"} {
		t.Run("fault="+fault, func(t *testing.T) {
			var pages, reads atomic.Int32
			first := auditLocalstackControlExpected()
			first.Version = "physical-version-1"
			second := first
			second.Key += "-2"
			second.Version = "physical-version-2"
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Has("versions") {
					page := pages.Add(1)
					w.Header().Set("Content-Type", "application/xml")
					if fault == "oversize list" {
						io.WriteString(w, "<ListVersionsResult>"+strings.Repeat(" ", 1<<20))
						return
					}
					if page == 1 {
						marker := "<NextKeyMarker>next-key</NextKeyMarker><NextVersionIdMarker>next-version</NextVersionIdMarker>"
						if fault == "missing marker" {
							marker = ""
						}
						fmt.Fprintf(w, "<ListVersionsResult><IsTruncated>true</IsTruncated>%s<Version><Key>%s</Key><VersionId>physical-version-1</VersionId><IsLatest>true</IsLatest><Size>23</Size></Version></ListVersionsResult>", marker, first.Key)
						return
					}
					if r.URL.Query().Get("key-marker") != "next-key" || r.URL.Query().Get("version-id-marker") != "next-version" {
						t.Error("pagination lost exact markers")
					}
					key, version, extra, truncated := second.Key, second.Version, "", "<IsTruncated>false</IsTruncated>"
					if fault == "version" {
						version = "fabricated-version"
					}
					if fault == "unexpected key" {
						key = "unexpected"
					}
					if fault == "extra version" {
						extra = fmt.Sprintf("<Version><Key>%s</Key><VersionId>extra</VersionId></Version>", first.Key)
					}
					if fault == "delete marker" {
						extra = "<DeleteMarker><Key>unexpected</Key><VersionId>deleted</VersionId></DeleteMarker>"
					}
					if fault == "repeat marker" {
						truncated = "<IsTruncated>true</IsTruncated><NextKeyMarker>next-key</NextKeyMarker><NextVersionIdMarker>next-version</NextVersionIdMarker>"
					}
					entry := fmt.Sprintf("<Version><Key>%s</Key><VersionId>%s</VersionId><IsLatest>true</IsLatest><Size>23</Size></Version>", key, version)
					if fault == "missing key" {
						entry = ""
					}
					fmt.Fprintf(w, "<ListVersionsResult>%s%s%s</ListVersionsResult>", truncated, entry, extra)
					return
				}
				reads.Add(1)
				expected := first
				if strings.HasSuffix(r.URL.Path, "-2") {
					expected = second
				}
				if r.URL.Query().Get("versionId") != expected.Version || r.Header.Get("X-Amz-Checksum-Mode") != "ENABLED" {
					t.Error("inventory read was not pinned with checksum")
				}
				w.Header().Set("X-Amz-Version-Id", expected.Version)
				w.Header().Set("Content-Length", "23")
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Amz-Server-Side-Encryption", "aws:kms")
				w.Header().Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", auditExportTestPolicy().KMSKeyARN)
				w.Header().Set("X-Amz-Checksum-Sha256", "5nI3CJnLw6ltF/eL9dMBMqjclJuLdeDLIn8FWQO6ayo=")
				for key, value := range expected.Metadata {
					w.Header().Set("X-Amz-Meta-"+key, value)
				}
				if fault == "version" {
					w.Header().Set("X-Amz-Version-Id", "fabricated-version")
				}
				if fault == "head version" && r.Method == "HEAD" || fault == "get version" && r.Method == "GET" {
					w.Header().Set("X-Amz-Version-Id", "fabricated-version")
				}
				if fault == "checksum" {
					w.Header().Set("X-Amz-Checksum-Sha256", "wrong")
				}
				if fault == "kms" {
					w.Header().Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", "wrong")
				}
				if fault == "metadata" {
					w.Header().Set("X-Amz-Meta-Organization_id", "wrong")
				}
				if fault == "size" {
					w.Header().Set("Content-Length", "24")
				}
				if r.Method == "GET" {
					body := bytes.Clone(expected.Body)
					if fault == "body" {
						body[0] = '!'
					}
					_, _ = w.Write(body)
				}
			}))
			defer endpoint.Close()
			f := auditLocalstackControlForwarder(t, endpoint.URL, nil)
			err := f.inventory(context.Background(), map[string]auditLocalstackExpected{first.Key: first, second.Key: second})
			if fault == "" {
				if err != nil || pages.Load() != 2 || reads.Load() != 4 {
					t.Fatalf("complete paginated inventory not checked: %v %d %d", err, pages.Load(), reads.Load())
				}
			} else if err == nil {
				t.Fatal("independent comparison accepted", fault)
			}
		})
	}
}

func TestAuditExportLocalstackForwarderActualSDKShape(t *testing.T) {
	var calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == "HEAD" && r.URL.RawQuery != "" && r.URL.RawQuery != "versionId=physical-version" {
			t.Error("pinned HEAD query changed")
		}
		if r.Method == "GET" && r.URL.Query().Get("versionId") != "physical-version" {
			t.Error("pinned GET version changed")
		}
		w.Header().Set("X-Amz-Version-Id", "physical-version")
		w.WriteHeader(200)
	}))
	defer endpoint.Close()
	f := auditLocalstackControlForwarder(t, endpoint.URL, nil)
	front := httptest.NewTLSServer(f)
	defer front.Close()
	client := front.Client()
	transport := client.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "zasp-audit-export-fixture.s3.us-east-1.amazonaws.com:443" {
			return nil, errAuditLocalstack
		}
		return (&net.Dialer{}).DialContext(ctx, network, front.Listener.Addr().String())
	}
	// The certificate's test DNS name is trusted explicitly, never skip verify.
	transport.TLSClientConfig.ServerName = "example.com"
	sdk := s3.New(s3.Options{Region: "us-east-1", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "ASIAPROCESSWORKER", SecretAccessKey: "owned-process-secret-not-real", SessionToken: "owned-process-session-worker"}, nil
	}), HTTPClient: client, RetryMaxAttempts: 1})
	expected := auditLocalstackControlExpected()
	_, err := sdk.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String(auditExportTestPolicy().Bucket), Key: aws.String(expected.Key), Body: bytes.NewReader(expected.Body), ContentType: aws.String("application/json"), ExpectedBucketOwner: aws.String(auditExportTestPolicy().ExpectedBucketOwner), IfNoneMatch: aws.String("*"), ServerSideEncryption: "aws:kms", SSEKMSKeyId: aws.String(auditExportTestPolicy().KMSKeyARN), ChecksumSHA256: aws.String("5nI3CJnLw6ltF/eL9dMBMqjclJuLdeDLIn8FWQO6ayo="), Metadata: expected.Metadata})
	if err != nil || calls.Load() != 1 {
		t.Fatal("actual SDK first-hop rejected", err, calls.Load())
	}
	for _, version := range []*string{nil, aws.String("physical-version")} {
		if _, err := sdk.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: aws.String(auditExportTestPolicy().Bucket), Key: aws.String(expected.Key), VersionId: version, ExpectedBucketOwner: aws.String(auditExportTestPolicy().ExpectedBucketOwner), ChecksumMode: "ENABLED"}); err != nil {
			t.Fatal("SDK discovery/pinned HEAD rejected", err)
		}
	}
	get, err := sdk.GetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String(auditExportTestPolicy().Bucket), Key: aws.String(expected.Key), VersionId: aws.String("physical-version"), ExpectedBucketOwner: aws.String(auditExportTestPolicy().ExpectedBucketOwner), ChecksumMode: "ENABLED"})
	if err != nil {
		t.Fatal("SDK pinned GET rejected", err)
	}
	get.Body.Close()
	if calls.Load() != 4 {
		t.Fatal("SDK read shapes did not traverse adapter", calls.Load())
	}
}

func TestAuditExportLocalstackForwarderBoundsAndRedirects(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	for _, fault := range []string{"redirect", "body", "headers"} {
		t.Run(fault, func(t *testing.T) {
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch fault {
				case "redirect":
					w.Header().Set("Location", target.URL)
					w.WriteHeader(307)
				case "body":
					io.WriteString(w, strings.Repeat("x", (1<<20)+1))
				case "headers":
					w.Header().Set("X-Large", strings.Repeat("x", (32<<10)+1))
					w.WriteHeader(200)
				}
			}))
			defer endpoint.Close()
			f := auditLocalstackControlForwarder(t, endpoint.URL, nil)
			w := httptest.NewRecorder()
			f.ServeHTTP(w, auditLocalstackControlRequest(t, "PUT", "?x-id=PutObject"))
			want := 502
			if fault == "redirect" {
				want = 307
			}
			if w.Code != want || redirected.Load() != 0 || w.Body.Len() > 1024 {
				t.Fatal("response bound/redirect escaped", w.Code, redirected.Load(), w.Body.Len())
			}
		})
	}
}

func TestAuditExportLocalstackForwarderRequiresOwnedEndpoint(t *testing.T) {
	for _, endpoint := range []string{"https://127.0.0.1:1234", "http://localhost:1234", "http://127.0.0.2:1234", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:01234", "http://127.0.0.1:1234/path", "http://user@127.0.0.1:1234", "http://127.0.0.1:1234?other=1", "http://127.0.0.1:1234#fragment"} {
		f, err := newAuditLocalstackForwarder(context.Background(), endpoint, auditExportTestPolicy(), func(context.Context, string) (auditLocalstackExpected, error) {
			return auditLocalstackExpected{}, errAuditLocalstack
		}, time.Second, nil)
		if err == nil {
			f.close(context.Background())
			t.Fatal("unowned endpoint accepted", endpoint)
		}
	}
}

func TestAuditExportLocalstackDispatchOutsideProviderLock(t *testing.T) {
	p := &auditExportProcessProvider{}
	reached := make(chan struct{}, 1)
	p.forwardS3 = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.mu.TryLock() {
			t.Error("S3 callback retained provider mutex")
			return
		}
		p.mu.Unlock()
		reached <- struct{}{}
		w.WriteHeader(202)
	})
	w := httptest.NewRecorder()
	r := auditLocalstackControlRequest(t, "PUT", "?x-id=PutObject")
	// A non-worker rejection precedes the old storage call, so the stub fails
	// behaviorally without needing an unrelated PostgreSQL fixture.
	r.Header.Set("X-Amz-Security-Token", "owned-process-session-outbox")
	p.serve(w, r)
	select {
	case <-reached:
	case <-time.After(time.Second):
		t.Fatal("S3 callback not dispatched")
	}
	if w.Code != 202 {
		t.Fatal("dispatch failed", w.Code)
	}
}

func TestAuditExportLocalstackQueueUsesTrustedPolicy(t *testing.T) {
	policy := auditExportTestPolicy()
	policy.PolicyID = "pid_52000091-0000-4000-8000-000000000091"
	p := &auditExportProcessProvider{policy: policy, args: []any{"org", "ws", "env", nil, nil, nil, nil, "export"}}
	payload := `{"schema":"audit-export-wakeup-v1","organization_id":"org","workspace_id":"ws","environment_id":"env","export_id":"export","policy_id":"pid_52000091-0000-4000-8000-000000000091"}`
	digest := sha256.Sum256([]byte(payload))
	wire := fmt.Sprintf(`{"version":1,"job_id":"export","organization_id":"org","workspace_id":"ws","environment_id":"env","kind":"audit-export","payload":%s,"authority_digest":%q}`, payload, hex.EncodeToString(digest[:]))
	body, _ := json.Marshal(map[string]any{"QueueUrl": auditExportProcessQueue, "Entries": []any{map[string]string{"Id": "export", "MessageBody": wire, "MessageGroupId": "org"}}})
	r := httptest.NewRequest("POST", "https://sqs.us-east-1.amazonaws.com/", bytes.NewReader(body))
	r.Header.Set("X-Amz-Target", "AmazonSQS.SendMessageBatch")
	w := httptest.NewRecorder()
	p.queue(w, r, "outbox")
	if w.Code != 200 || p.sends != 1 || len(p.messages) != 1 || string(p.messages[0].Body) != wire {
		t.Fatal("trusted policy publication rejected", w.Code)
	}
}

func TestAuditExportLocalstackIntentUsesCommittedRegisteredSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture := auditExportPGFixture(t, ctx)
	fixture.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, fixture)
	policy := auditExportTestPolicy()
	request, common := auditExportClaimForCapture(t, ctx, fixture, worker, policy)
	chunk, canonical := auditExportCaptureSingleRequest(t, ctx, fixture, worker, request, common)
	observer, err := pgx.ConnectConfig(ctx, fixture.admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := observer.Close(closeCtx); err != nil {
			t.Error(err)
		}
	}()
	event, err := audit.EncodeExportEvent(chunk.Events[0])
	if err != nil {
		t.Fatal(err)
	}
	events := []json.RawMessage{event}
	lookup := newAuditLocalstackIntent(observer, policy, chunk.Binding, events)
	if _, err := lookup(ctx, "organizations/uncommitted"); err == nil {
		t.Fatal("uncommitted intent accepted")
	}
	var raw []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_prepare_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), canonical)...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var intent struct {
		ObjectReference string `json:"object_reference"`
		ArtifactID      string `json:"artifact_id"`
	}
	if json.Unmarshal(raw, &intent) != nil {
		t.Fatal("intent decode")
	}
	key := strings.TrimPrefix(intent.ObjectReference, "s3://"+policy.Bucket+"/")
	// The callback owns immutable pre-capture expectations, not caller buffers.
	events[0][0] = '!'
	want, err := lookup(ctx, key)
	if err != nil || want.Key != key || !bytes.Equal(want.Body, canonical) || want.Version != "" || want.Metadata["artifact_id"] != intent.ArtifactID {
		t.Fatal("registered committed intent was not independently reconstructed", err)
	}
	wrongPolicy := policy
	wrongPolicy.PolicyID = "pid_52000091-0000-4000-8000-000000000091"
	if _, err := newAuditLocalstackIntent(observer, wrongPolicy, chunk.Binding, []json.RawMessage{json.RawMessage(`{}`)})(ctx, key); err == nil {
		t.Fatal("unregistered policy accepted")
	}
	wrongBinding := chunk.Binding
	wrongBinding.EnvironmentID = "pid_52000099-0000-4000-8000-000000000099"
	if _, err := newAuditLocalstackIntent(observer, policy, wrongBinding, nil)(ctx, key); err == nil {
		t.Fatal("wrong intent scope accepted")
	}
	changed := chunk.Events[0]
	changed.Action = "changed.source"
	changedEvent, err := audit.EncodeExportEvent(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newAuditLocalstackIntent(observer, policy, chunk.Binding, []json.RawMessage{changedEvent})(ctx, key); err == nil {
		t.Fatal("intent digest differs from source but was accepted")
	}
}

func TestAuditExportLocalstackInventoryCancellationJoins(t *testing.T) {
	reached := make(chan struct{}, 1)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached <- struct{}{}; <-r.Context().Done() }))
	defer endpoint.Close()
	f := auditLocalstackControlForwarder(t, endpoint.URL, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.inventory(ctx, map[string]auditLocalstackExpected{}) }()
	select {
	case <-reached:
	case <-time.After(time.Second):
		t.Fatal("inventory not dispatched")
	}
	closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := f.close(closeCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled inventory claimed success")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("close returned before inventory canceled/joined")
	}
}

func TestAuditExportLocalstackWithheldNetworkResponseIsAborted(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Version-Id", "saved-version")
		w.WriteHeader(200)
	}))
	defer endpoint.Close()
	reached := make(chan struct{})
	f := auditLocalstackControlForwarder(t, endpoint.URL, func(ctx context.Context, _ auditLocalstackPutResult) error {
		close(reached)
		<-ctx.Done()
		return ctx.Err()
	})
	front := httptest.NewTLSServer(f)
	defer front.Close()
	r := auditLocalstackControlRequest(t, "PUT", "?x-id=PutObject")
	r.URL.Scheme = "https"
	r.URL.Host = front.Listener.Addr().String()
	r.RequestURI = ""
	result := make(chan error, 1)
	go func() {
		response, err := front.Client().Do(r)
		if response != nil {
			response.Body.Close()
		}
		result <- err
	}()
	select {
	case <-reached:
	case <-time.After(time.Second):
		t.Fatal("network hook not reached")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("net/http manufactured a success response after canceled withholding")
		}
	case <-ctx.Done():
		t.Fatal("withheld network client not released")
	}
}

func TestAuditExportLocalstackCancellationInterruptsIncomingBody(t *testing.T) {
	f := auditLocalstackControlForwarder(t, "http://127.0.0.1:1", nil)
	reached := make(chan struct{}, 1)
	lookup := f.intent
	f.intent = func(ctx context.Context, key string) (auditLocalstackExpected, error) {
		reached <- struct{}{}
		return lookup(ctx, key)
	}
	front := httptest.NewTLSServer(f)
	defer front.Close()
	r := auditLocalstackControlRequest(t, "PUT", "?x-id=PutObject")
	r.URL.Host = front.Listener.Addr().String()
	r.RequestURI = ""
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	r.Body = reader
	done := make(chan error, 1)
	go func() {
		response, err := front.Client().Do(r)
		if response != nil {
			response.Body.Close()
		}
		done <- err
	}()
	go func() { _, _ = writer.Write([]byte("{")) }()
	select {
	case <-reached:
	case <-time.After(time.Second):
		t.Fatal("incoming body handler not reached")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := f.close(ctx); err != nil {
		t.Fatal("incoming body blocked owner close", err)
	}
	writer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("incoming body client not released")
	}
}

func auditLocalstackControlRequest(t *testing.T, method, query string) *http.Request {
	t.Helper()
	expected := auditLocalstackControlExpected()
	body := expected.Body
	if method != "PUT" {
		body = nil
	}
	r := httptest.NewRequest(method, "https://"+auditExportTestPolicy().Bucket+".s3.us-east-1.amazonaws.com/"+expected.Key+query, bytes.NewReader(body))
	r.Header.Set("Accept-Encoding", "identity")
	r.Header.Set("X-Amz-Expected-Bucket-Owner", auditExportTestPolicy().ExpectedBucketOwner)
	if method == "PUT" {
		r.Header.Set("If-None-Match", "*")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Amz-Server-Side-Encryption", "aws:kms")
		r.Header.Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", auditExportTestPolicy().KMSKeyARN)
		hash := sha256.Sum256(body)
		r.Header.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(hash[:]))
		for key, value := range expected.Metadata {
			r.Header.Set("X-Amz-Meta-"+key, value)
		}
	} else {
		r.Header.Set("X-Amz-Checksum-Mode", "ENABLED")
	}
	auditLocalstackControlSign(t, r, body)
	return r
}

func auditLocalstackControlSign(t *testing.T, r *http.Request, body []byte) {
	t.Helper()
	sum := sha256.Sum256(body)
	r.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(sum[:]))
	err := v4.NewSigner().SignHTTP(r.Context(), aws.Credentials{AccessKeyID: "ASIAPROCESSWORKER", SecretAccessKey: "owned-process-secret-not-real", SessionToken: "owned-process-session-worker"}, r, hex.EncodeToString(sum[:]), "s3", "us-east-1", time.Now(), func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	if err != nil {
		t.Fatal(err)
	}
}

func auditLocalstackControlForwarder(t *testing.T, endpoint string, hook func(context.Context, auditLocalstackPutResult) error) *auditLocalstackForwarder {
	t.Helper()
	f, err := newAuditLocalstackForwarder(context.Background(), endpoint, auditExportTestPolicy(), func(_ context.Context, key string) (auditLocalstackExpected, error) {
		expected := auditLocalstackControlExpected()
		if key != expected.Key {
			return auditLocalstackExpected{}, errAuditLocalstack
		}
		return expected, nil
	}, time.Second, hook)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.close(ctx); err != nil {
			t.Error(err)
		}
	})
	return f
}

func TestAuditExportLocalstackForwarderRelaysProviderResult(t *testing.T) {
	for _, status := range []int{200, 412, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, _ := io.ReadAll(r.Body)
				if r.Method != "PUT" || r.URL.Path != "/zasp-audit-export-fixture/organizations/org/workspaces/ws/environments/env/exports/artifact" || r.URL.RawQuery != "x-id=PutObject" || !bytes.Equal(body, []byte(`{"fixture":"canonical"}`)) || r.Header.Get("If-None-Match") != "*" || !strings.Contains(r.Header.Get("Authorization"), "Credential=test/") || r.Header.Get("X-Amz-Security-Token") != "" {
					t.Error("local hop changed semantics or retained first-hop authority")
				}
				w.Header().Set("X-Amz-Version-Id", "provider-version-7")
				w.Header().Set("X-Amz-Checksum-Sha256", "provider-checksum")
				w.Header().Set("Connection", "X-Private-Hop")
				w.Header().Set("X-Private-Hop", "remove")
				w.WriteHeader(status)
				io.WriteString(w, "provider-body")
			}))
			defer endpoint.Close()
			f := auditLocalstackControlForwarder(t, endpoint.URL, nil)
			w := httptest.NewRecorder()
			f.ServeHTTP(w, auditLocalstackControlRequest(t, "PUT", "?x-id=PutObject"))
			if calls.Load() != 1 || w.Code != status || w.Header().Get("X-Amz-Version-Id") != "provider-version-7" || w.Header().Get("X-Amz-Checksum-Sha256") != "provider-checksum" || w.Body.String() != "provider-body" || w.Header().Get("X-Private-Hop") != "" {
				t.Fatalf("genuine provider result not relayed: calls=%d status=%d body=%q", calls.Load(), w.Code, w.Body.String())
			}
		})
	}
}

func TestAuditExportLocalstackForwarderRejectsTampering(t *testing.T) {
	var calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer endpoint.Close()
	f := auditLocalstackControlForwarder(t, endpoint.URL, nil)
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"method", func(r *http.Request) { r.Method = "DELETE" }},
		{"host", func(r *http.Request) { r.Host = "untrusted.s3.us-east-1.amazonaws.com" }},
		{"scope", func(r *http.Request) { r.URL.Path = strings.Replace(r.URL.Path, "/org/", "/other/", 1) }},
		{"version", func(r *http.Request) { r.URL.RawQuery = "x-id=PutObject&versionId=other" }},
		{"body", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"fixture":"changed"}`)) }},
		{"owner", func(r *http.Request) { r.Header.Set("X-Amz-Expected-Bucket-Owner", "000000000000") }},
		{"kms", func(r *http.Request) { r.Header.Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", "wrong") }},
		{"checksum", func(r *http.Request) { r.Header.Set("X-Amz-Checksum-Sha256", "wrong") }},
		{"metadata", func(r *http.Request) { r.Header.Set("X-Amz-Meta-Organization_id", "other") }},
		{"extra metadata", func(r *http.Request) { r.Header.Set("X-Amz-Meta-untrusted", "other") }},
		{"conditional", func(r *http.Request) { r.Header.Del("If-None-Match") }},
		{"duplicate header", func(r *http.Request) { r.Header.Add("If-None-Match", "*") }},
		{"chunked", func(r *http.Request) { r.Header.Set("Content-Encoding", "aws-chunked") }},
		{"trailer", func(r *http.Request) { r.Trailer = http.Header{"X-Amz-Checksum-Sha256": []string{"untrusted"}} }},
		{"signature", func(r *http.Request) { r.Header.Set("Authorization", r.Header.Get("Authorization")+"0") }},
		{"publisher", func(r *http.Request) { r.Header.Set("X-Amz-Security-Token", "owned-process-session-outbox") }},
		{"oversize headers", func(r *http.Request) { r.Header.Set("User-Agent", strings.Repeat("x", 32769)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := auditLocalstackControlRequest(t, "PUT", "?x-id=PutObject")
			test.mutate(r)
			w := httptest.NewRecorder()
			f.ServeHTTP(w, r)
			if w.Code != 400 || calls.Load() != 0 {
				t.Fatalf("tampered request reached provider or was not refused: %d %d", w.Code, calls.Load())
			}
		})
	}
}

func TestAuditExportLocalstackForwarderCancellationWithholdsAllResponse(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Version-Id", "saved-version")
		io.WriteString(w, "saved")
	}))
	defer endpoint.Close()
	reached := make(chan auditLocalstackPutResult, 1)
	f := auditLocalstackControlForwarder(t, endpoint.URL, func(ctx context.Context, result auditLocalstackPutResult) error {
		reached <- result
		<-ctx.Done()
		return ctx.Err()
	})
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if recovered := recover(); recovered != nil && recovered != http.ErrAbortHandler {
				panic(recovered)
			}
		}()
		f.ServeHTTP(w, auditLocalstackControlRequest(t, "PUT", "?x-id=PutObject"))
	}()
	select {
	case result := <-reached:
		if result.Version != "saved-version" || result.Status != 200 || string(result.Body) != "saved" {
			t.Error("hook lacked genuine result")
		}
	case <-time.After(time.Second):
		t.Fatal("saved-result hook not reached")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("handler did not join")
	}
	if len(w.Header()) != 0 || w.Body.Len() != 0 {
		t.Fatal("withheld response leaked headers/body")
	}
}
