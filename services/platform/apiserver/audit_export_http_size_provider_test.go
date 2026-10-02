package apiserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Catches requests escaping the pre-POST refusal and replacing an installed handler.
func TestAuditHTTPSizeProviderBridge(t *testing.T) {
	b := newAuditHTTPSizeBridge(context.Background())
	r := httptest.NewRequest("GET", "https://example.com/", nil)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("premature bridge request must refuse: status=%d", w.Code)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	if err := b.Install(h); err != nil {
		t.Fatal(err)
	}
	if err := b.Install(h); err == nil {
		t.Fatal("second handler installation accepted")
	}
	w = httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal("installed handler not used", w.Code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Install(h); err == nil {
		t.Fatal("installation after Close accepted")
	}
}

// Catches the admission race where an already-canceled owner can still emit a 2xx.
func TestAuditHTTPSizeProviderCanceledAdmission(t *testing.T) {
	// Keep the asynchronous AfterFunc callback queued until admission has run.
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	ctx, cancel := context.WithCancel(context.Background())
	b := newAuditHTTPSizeBridge(ctx)
	called := false
	if err := b.Install(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(204) })); err != nil {
		t.Fatal(err)
	}
	cancel()
	aborted := false
	func() {
		defer func() {
			if got := recover(); got != nil {
				if got != http.ErrAbortHandler {
					panic(got)
				}
				aborted = true
			}
		}()
		b.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "https://example.com/", nil))
	}()
	if called || !aborted {
		t.Fatal("canceled owner admitted a successful handler", called, aborted)
	}
	closeCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if err := b.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
}

// Catches Body.Close waiting behind Read, missing socket deadlines, and Close
// returning before the active handler leaves its body read.
func TestAuditHTTPSizeProviderPartialBodyJoin(t *testing.T) {
	for _, mode := range []string{"deadline", "owner-cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b := newAuditHTTPSizeBridge(ctx)
			entered, exited := make(chan struct{}), make(chan struct{})
			if err := b.Install(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				defer close(exited)
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(204)
			})); err != nil {
				t.Fatal(err)
			}
			front := httptest.NewTLSServer(b)
			defer front.Close()
			defer func() {
				c, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := b.Close(c); err != nil {
					t.Error(err)
				}
			}()
			tlsConfig := front.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			tlsConfig.ServerName = "example.com"
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", front.Listener.Addr().String(), tlsConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, "PUT / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\n{"); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("partial-body handler did not start")
			}
			if mode == "owner-cancel" {
				cancel()
			}
			closeCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			if mode == "close" {
				if err := b.Close(closeCtx); err != nil {
					t.Fatal(err)
				}
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if response != nil {
				response.Body.Close()
				if response.StatusCode < 400 {
					t.Fatal("partial canceled body returned success", response.StatusCode)
				}
			}
			if err == nil {
				t.Fatal("partial body did not abort its socket")
			}
			if err := b.Close(closeCtx); err != nil {
				t.Fatal(err)
			}
			select {
			case <-exited:
			default:
				t.Fatal("Close returned before handler joined")
			}
		})
	}
}

// Catches an uncancelable serialization wait or advancing the borrowed oracle
// after Close while another handler owns the storage gate. No SQL is reachable.
func TestAuditHTTPSizeProviderCanceledStorageWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := auditHTTPSizeTestOracle(t, 1, auditHTTPSizeTestRow)
	binding := auditHTTPSizeTestBinding()
	p := &auditHTTPSizeProvider{auditHTTPSizeLifetime: newAuditHTTPSizeLifetime(ctx), policy: auditExportTestPolicy(), gate: make(chan struct{}, 1), bound: true, binding: binding, expected: e, objects: map[string]auditExportProcessObject{}, counts: map[string]int{}}
	p.gate <- struct{}{}
	key := "organizations/" + binding.OrganizationID + "/workspaces/" + binding.WorkspaceID + "/environments/" + binding.EnvironmentID + "/exports/" + auditHTTPSizeTestID(9)
	r := auditHTTPSizeRequest(t, "PUT", "worker", key, "?x-id=PutObject", []byte(`{}`), binding)
	entered := make(chan struct{})
	r.Body = &auditHTTPSizeBodySignal{ReadCloser: r.Body, entered: entered}
	done := make(chan error, 1)
	go func() {
		defer func() {
			got := recover()
			if got != http.ErrAbortHandler {
				done <- fmt.Errorf("canceled handler did not abort: %v", got)
			} else {
				done <- nil
			}
		}()
		p.ServeHTTP(httptest.NewRecorder(), r)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("body validation never started")
	}
	closeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := p.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-closeCtx.Done():
		t.Fatal("caller did not join")
	}
	<-p.gate
	if e.summary.Events != 0 || e.read != 0 || e.closed || len(p.objects) != 0 {
		t.Fatal("canceled storage wait changed borrowed source/inventory")
	}
}

type auditHTTPSizeBodySignal struct {
	io.ReadCloser
	entered chan struct{}
	once    sync.Once
}

func (b *auditHTTPSizeBodySignal) Read(value []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	return b.ReadCloser.Read(value)
}

func auditHTTPSizeCredentials(role string) aws.Credentials {
	if role == "reader" {
		return aws.Credentials{AccessKeyID: "OWNEDHTTPSIZEREADER", SecretAccessKey: "owned-http-size-reader-secret-not-real", SessionToken: "owned-http-size-reader-session"}
	}
	return aws.Credentials{AccessKeyID: "ASIAPROCESS" + strings.ToUpper(role), SecretAccessKey: "owned-process-secret-not-real", SessionToken: "owned-process-session-" + role}
}
func auditHTTPSizeSign(t *testing.T, r *http.Request, body []byte, role string) {
	t.Helper()
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	r.Header.Set("X-Amz-Content-Sha256", payload)
	r.Header.Del("Authorization")
	if err := v4.NewSigner().SignHTTP(r.Context(), auditHTTPSizeCredentials(role), r, payload, "s3", "us-east-1", time.Now(), func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true }); err != nil {
		t.Fatal(err)
	}
}
func auditHTTPSizeRequest(t *testing.T, method, role, key, query string, body []byte, binding audit.ExportBinding) *http.Request {
	t.Helper()
	policy := auditExportTestPolicy()
	r := httptest.NewRequest(method, "https://"+policy.Bucket+".s3.us-east-1.amazonaws.com/"+key+query, bytes.NewReader(body))
	r.Header.Set("Accept-Encoding", "identity")
	r.Header.Set("X-Amz-Expected-Bucket-Owner", policy.ExpectedBucketOwner)
	if method == "PUT" {
		r.Header.Set("If-None-Match", "*")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Amz-Server-Side-Encryption", "aws:kms")
		r.Header.Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", policy.KMSKeyARN)
		sum := sha256.Sum256(body)
		r.Header.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum[:]))
		for k, v := range map[string]string{"organization_id": binding.OrganizationID, "workspace_id": binding.WorkspaceID, "environment_id": binding.EnvironmentID, "artifact_id": key[strings.LastIndex(key, "/")+1:], "media_type": "application/json", "sha256": hex.EncodeToString(sum[:])} {
			r.Header.Set("X-Amz-Meta-"+k, v)
		}
	} else {
		r.Header.Set("X-Amz-Checksum-Mode", "ENABLED")
	}
	auditHTTPSizeSign(t, r, body, role)
	return r
}

type auditHTTPSizeReadProbe struct{ reads int }

func (p *auditHTTPSizeReadProbe) Read([]byte) (int, error) { p.reads++; return 0, io.EOF }
func (*auditHTTPSizeReadProbe) Close() error               { return nil }

// Catches authority checks moved after body access, permissive role mixing,
// unchecked SigV4 fields, and open transport/query/metadata bounds.
func TestAuditHTTPSizeProviderAuthority(t *testing.T) {
	binding := auditHTTPSizeTestBinding()
	key := "organizations/" + binding.OrganizationID + "/workspaces/" + binding.WorkspaceID + "/environments/" + binding.EnvironmentID + "/exports/" + auditHTTPSizeTestID(9)
	p := &auditHTTPSizeProvider{policy: auditExportTestPolicy()}
	for _, tc := range []struct {
		name   string
		method string
		role   string
		query  string
		mutate func(*http.Request)
		resign bool
	}{
		{"unknown", "PUT", "unknown", "?x-id=PutObject", nil, false},
		{"mixed", "PUT", "worker", "?x-id=PutObject", func(r *http.Request) {
			r.Header.Set("X-Amz-Security-Token", auditHTTPSizeCredentials("reader").SessionToken)
		}, false},
		{"reader-put", "PUT", "reader", "?x-id=PutObject", nil, false},
		{"outbox", "PUT", "outbox", "?x-id=PutObject", nil, false},
		{"host", "PUT", "worker", "?x-id=PutObject", func(r *http.Request) { r.Host = "wrong.example.com" }, true},
		{"bucket", "PUT", "worker", "?x-id=PutObject", func(r *http.Request) { r.Host = "wrong.s3.us-east-1.amazonaws.com" }, true},
		{"owner", "PUT", "worker", "?x-id=PutObject", func(r *http.Request) { r.Header.Set("X-Amz-Expected-Bucket-Owner", "000000000000") }, true},
		{"prefix", "PUT", "worker", "?x-id=PutObject", func(r *http.Request) { r.URL.Path = "/organizations/wrong/exports/id" }, true},
		{"missing-version", "HEAD", "reader", "", nil, false},
		{"duplicate-version", "GET", "reader", "?versionId=v&versionId=v&x-id=GetObject", nil, false},
		{"null-version", "HEAD", "reader", "?versionId=null", nil, false},
		{"extra-query", "GET", "reader", "?versionId=v&x-id=GetObject&extra=1", nil, false},
		{"queue", "POST", "reader", "", func(r *http.Request) { r.Host = "sqs.us-east-1.amazonaws.com" }, true},
		{"sts", "POST", "reader", "", func(r *http.Request) { r.Host = "sts.us-east-1.amazonaws.com" }, true},
		{"kms", "PUT", "worker", "?x-id=PutObject", func(r *http.Request) { r.Header.Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", "wrong") }, true},
		{"metadata", "PUT", "worker", "?x-id=PutObject", func(r *http.Request) { r.Header.Set("X-Amz-Meta-extra", "wrong") }, true},
		{"metadata-scope", "PUT", "worker", "?x-id=PutObject", func(r *http.Request) { r.Header.Set("X-Amz-Meta-organization_id", "wrong") }, true},
		{"signature", "PUT", "worker", "?x-id=PutObject", func(r *http.Request) { r.Header.Set("Authorization", r.Header.Get("Authorization")+"0") }, false},
		{"duplicate-header", "PUT", "worker", "?x-id=PutObject", func(r *http.Request) {
			r.Header.Add("X-Amz-Expected-Bucket-Owner", auditExportTestPolicy().ExpectedBucketOwner)
		}, false},
		{"unknown-header", "PUT", "worker", "?x-id=PutObject", func(r *http.Request) { r.Header.Set("X-Amz-Website-Redirect-Location", "https://wrong.example") }, true},
		{"oversize-header", "PUT", "worker", "?x-id=PutObject", func(r *http.Request) { r.Header.Set("User-Agent", strings.Repeat("x", 33<<10)) }, true},
		{"oversize-body", "PUT", "worker", "?x-id=PutObject", func(r *http.Request) { r.ContentLength = audit.ExportMaximumChunkBytes + 1 }, true},
		{"range", "GET", "reader", "?versionId=v&x-id=GetObject", func(r *http.Request) { r.Header.Set("Range", "bytes=0-1") }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{}`)
			if tc.method != "PUT" {
				body = nil
			}
			r := auditHTTPSizeRequest(t, tc.method, tc.role, key, tc.query, body, binding)
			if tc.mutate != nil {
				tc.mutate(r)
			}
			if tc.resign {
				auditHTTPSizeSign(t, r, body, tc.role)
			}
			probe := &auditHTTPSizeReadProbe{}
			r.Body = probe
			if _, _, err := p.validate(r, binding); err == nil {
				t.Fatal("invalid signed request accepted")
			}
			if probe.reads != 0 {
				t.Fatal("unauthorized request consumed body", probe.reads)
			}
		})
	}
	for _, method := range []string{"PUT", "HEAD", "GET"} {
		body := []byte(`{}`)
		role, query := "worker", "?x-id=PutObject"
		if method != "PUT" {
			body = nil
			role = "reader"
			query = "?versionId=v"
			if method == "GET" {
				query += "&x-id=GetObject"
			}
		}
		r := auditHTTPSizeRequest(t, method, role, key, query, body, binding)
		got, gotRole, err := p.validate(r, binding)
		if err != nil || gotRole != role || !bytes.Equal(got, body) {
			t.Fatal("valid signed request refused", method, err)
		}
	}
	for _, mode := range []string{"checksum", "payload", "body-length"} {
		t.Run(mode, func(t *testing.T) {
			r := auditHTTPSizeRequest(t, "PUT", "worker", key, "?x-id=PutObject", []byte(`{}`), binding)
			switch mode {
			case "checksum":
				r.Header.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(make([]byte, 32)))
				auditHTTPSizeSign(t, r, []byte(`{}`), "worker")
			case "payload":
				r.Body = io.NopCloser(strings.NewReader(`[]`))
			case "body-length":
				r.ContentLength = 3
				auditHTTPSizeSign(t, r, []byte(`{}`), "worker")
			}
			if _, _, err := p.validate(r, binding); err == nil {
				t.Fatal("invalid payload accepted")
			}
		})
	}
}

type auditHTTPSizeProvider struct {
	*auditHTTPSizeLifetime
	policy             migrations.AuditExportConfiguration
	policyDigest       string
	observer           *pgx.Conn
	gate               chan struct{}
	bindAttempt, bound bool
	binding            audit.ExportBinding
	expected           *auditHTTPSizeExpected
	failure            error
	objects            map[string]auditExportProcessObject
	chunks             int64
	capture            string
	manifest           bool
	counts             map[string]int
	browserReader      bool
}

func newAuditHTTPSizeProvider(ctx context.Context, observer *pgx.Conn, policy migrations.AuditExportConfiguration) (*auditHTTPSizeProvider, error) {
	digest, err := migrations.AuditExportPolicyDigest(policy)
	if err != nil || observer == nil || observer.IsClosed() || ctx.Err() != nil {
		return nil, errAuditHTTPSizeProvider
	}
	return &auditHTTPSizeProvider{auditHTTPSizeLifetime: newAuditHTTPSizeLifetime(ctx), policy: policy, policyDigest: digest, observer: observer, gate: make(chan struct{}, 1), objects: map[string]auditExportProcessObject{}, counts: map[string]int{}}, nil
}
func (p *auditHTTPSizeProvider) Bind(args []any, expected *auditHTTPSizeExpected) error {
	if len(args) != 13 || expected == nil {
		return errAuditHTTPSizeProvider
	}
	var ids [4]string
	for n, index := range []int{0, 1, 2, 7} {
		value, ok := args[index].(string)
		if !ok {
			return errAuditHTTPSizeProvider
		}
		if _, err := domain.ParseProductID(value); err != nil {
			return errAuditHTTPSizeProvider
		}
		ids[n] = value
	}
	var source auditHTTPSizeSnapshotSource
	switch s := expected.source.(type) {
	case *auditHTTPSizePGSource:
		if s != nil && s.organization == ids[0] {
			source = s
		}
	case *auditBrowserMixedSource:
		if s != nil && s.organization == ids[0] {
			source = s
		}
	}
	if source == nil || source.snapshotConnection() == nil || source.snapshotConnection().IsClosed() ||
		source.snapshotConnection().PgConn().TxStatus() != 'T' || source.snapshotConnection() == p.observer ||
		expected.organization != ids[0] || expected.closed {
		return errAuditHTTPSizeProvider
	}
	p.mu.Lock()
	if p.closed || p.bindAttempt || p.ctx.Err() != nil {
		p.mu.Unlock()
		return errAuditHTTPSizeProvider
	}
	p.bindAttempt = true
	p.active++
	p.mu.Unlock()
	defer p.finish()
	ctx, cancel := context.WithTimeout(p.ctx, auditHTTPSizeProviderTimeout)
	defer cancel()
	select {
	case p.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-p.gate }()
	var actual bool
	err := p.observer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_audit_export_jobs WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND policy_id=$5 AND storage_policy->>'policy_digest'=$6 AND status IN ('queued','processing'))`, ids[0], ids[1], ids[2], ids[3], p.policy.PolicyID, p.policyDigest).Scan(&actual)
	if err != nil || !actual || ctx.Err() != nil {
		return errAuditHTTPSizeProvider
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || ctx.Err() != nil {
		return errAuditHTTPSizeProvider
	}
	// Copy only the four immutable identifiers, never retain the caller's slice or digest buffers.
	p.binding = audit.ExportBinding{OrganizationID: ids[0], WorkspaceID: ids[1], EnvironmentID: ids[2], ExportID: ids[3]}
	p.expected = expected
	p.bound = true
	return nil
}
func (p *auditHTTPSizeProvider) Check() error { p.mu.Lock(); defer p.mu.Unlock(); return p.failure }
func (p *auditHTTPSizeProvider) refuse(w http.ResponseWriter, reason string) {
	p.mu.Lock()
	if p.failure == nil {
		p.failure = fmt.Errorf("owned HTTP size provider: %s", reason)
	}
	p.mu.Unlock()
	http.Error(w, errAuditHTTPSizeProvider.Error(), http.StatusBadRequest)
}
func (p *auditHTTPSizeProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.serve(w, r, func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		binding, bound := p.binding, p.bound
		p.mu.Unlock()
		if !bound {
			p.refuse(w, "request before Bind")
			return
		}
		body, role, err := p.validate(r, binding)
		if err != nil {
			p.refuse(w, "request authority/body")
			return
		}
		object, status, err := p.storage(r, binding, role, body)
		if err != nil {
			p.refuse(w, err.Error())
			return
		}
		if r.Context().Err() != nil {
			return
		}
		if status == http.StatusPreconditionFailed {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `<Error><Code>PreconditionFailed</Code></Error>`)
			return
		}
		for k, v := range object.Headers {
			w.Header()[k] = append([]string(nil), v...)
		}
		if r.Method == "PUT" {
			w.Header().Set("Content-Length", "0")
		}
		w.WriteHeader(http.StatusOK)
		if r.Method == "GET" {
			_, _ = w.Write(object.Body)
		}
	})
}
func (p *auditHTTPSizeProvider) storage(r *http.Request, binding audit.ExportBinding, role string, body []byte) (auditExportProcessObject, int, error) {
	fail := func(reason string) (auditExportProcessObject, int, error) {
		return auditExportProcessObject{}, 0, errors.New(reason)
	}
	ctx := r.Context()
	// This gate owns only observer/oracle/inventory sequencing. No body or response I/O occurs here.
	select {
	case p.gate <- struct{}{}:
	case <-ctx.Done():
		return fail("storage gate canceled")
	}
	defer func() { <-p.gate }()
	if ctx.Err() != nil {
		return fail("storage canceled")
	}
	reference := "s3://" + p.policy.Bucket + r.URL.Path
	var kind, id, capture, receiptVersion string
	var ordinal, size int64
	var digest []byte
	err := p.observer.QueryRow(ctx, `SELECT i.kind,i.ordinal,i.artifact_id,i.capture_id,i.sha256,i.size_bytes,COALESCE(r.version_id,'') FROM zasp_audit_export_intents i JOIN zasp_audit_export_jobs j ON j.organization_id=i.organization_id AND j.id=i.export_id AND j.capture_id=i.capture_id LEFT JOIN zasp_audit_export_receipts r ON r.organization_id=i.organization_id AND r.export_id=i.export_id AND r.kind=i.kind AND r.ordinal=i.ordinal WHERE i.organization_id=$1 AND i.workspace_id=$2 AND i.environment_id=$3 AND i.export_id=$4 AND i.object_reference=$5 AND j.policy_id=$6 AND j.storage_policy->>'policy_digest'=$7 AND j.captured`, binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, binding.ExportID, reference, p.policy.PolicyID, p.policyDigest).Scan(&kind, &ordinal, &id, &capture, &digest, &size, &receiptVersion)
	if err != nil || ctx.Err() != nil {
		return fail("committed intent absent")
	}
	wantPath := "/organizations/" + binding.OrganizationID + "/workspaces/" + binding.WorkspaceID + "/environments/" + binding.EnvironmentID + "/exports/" + id
	if r.URL.Path != wantPath || size <= 0 || size > audit.ExportMaximumChunkBytes || len(digest) != 32 || (kind != "chunk" && kind != "manifest") || kind == "chunk" && ordinal < 1 || kind == "manifest" && ordinal != 0 {
		return fail("committed intent shape")
	}
	object, exists := p.objects[reference]
	if exists && receiptVersion != "" && receiptVersion != object.Version {
		return fail("receipt version changed")
	}
	if r.Method != "PUT" {
		if !exists || !auditExportProcessS3Query(r.Method, r.URL.RawQuery, object.Version) {
			return fail("immutable version absent")
		}
		p.counts[role+"-"+r.Method]++
		return object, http.StatusOK, nil
	}
	sum := sha256.Sum256(body)
	if size != int64(len(body)) || !bytes.Equal(digest, sum[:]) {
		return fail("body differs from committed intent")
	}
	if exists {
		if !bytes.Equal(body, object.Body) {
			return fail("repeat changed retained bytes")
		}
		p.counts["worker-repeat-PUT"]++
		return object, http.StatusPreconditionFailed, nil
	}
	if receiptVersion != "" {
		return fail("receipt exists outside continuous inventory")
	}
	if p.manifest {
		return fail("object after manifest")
	}
	if p.capture == "" {
		binding.CaptureID = capture
		if err := p.expected.Reset(ctx, binding); err != nil {
			return fail("original source Reset")
		}
		p.capture = capture
	} else if p.capture != capture {
		return fail("capture changed")
	}
	var wanted []byte
	if kind == "chunk" {
		if ordinal != p.chunks+1 {
			return fail("noncontiguous first chunk")
		}
		wanted, err = p.expected.Next(ctx)
	} else {
		if _, err = p.expected.Next(ctx); !errors.Is(err, io.EOF) {
			return fail("manifest before source EOF")
		}
		var summary auditHTTPSizeSummary
		wanted, summary, err = p.expected.Manifest()
		if err == nil && summary.Chunks != p.chunks {
			return fail("manifest skipped source chunks")
		}
	}
	if err != nil || ctx.Err() != nil || !bytes.Equal(body, wanted) {
		return fail("body differs from original source")
	}
	headers := make(http.Header)
	for key, values := range r.Header {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-amz-meta-") || strings.HasPrefix(lower, "x-amz-server-side-encryption") || lower == "x-amz-checksum-sha256" || lower == "content-type" {
			headers[key] = append([]string(nil), values...)
		}
	}
	object = auditExportProcessObject{Body: bytes.Clone(body), Version: fmt.Sprintf("owned-http-size-version-%d", len(p.objects)+1), Headers: headers}
	object.Headers.Set("X-Amz-Version-Id", object.Version)
	object.Headers.Set("Content-Length", strconv.Itoa(len(body)))
	p.objects[reference] = object
	p.counts["worker-PUT"]++
	if kind == "chunk" {
		p.chunks++
	} else {
		p.manifest = true
	}
	return object, http.StatusOK, nil
}

func auditHTTPSizeSDK(t *testing.T, front *httptest.Server, role string) *s3.Client {
	t.Helper()
	client := front.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != auditExportTestPolicy().Bucket+".s3.us-east-1.amazonaws.com:443" {
			return nil, errAuditHTTPSizeProvider
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, front.Listener.Addr().String())
	}
	client = &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errAuditHTTPSizeProvider }}
	t.Cleanup(transport.CloseIdleConnections)
	return s3.New(s3.Options{Region: "us-east-1", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return auditHTTPSizeCredentials(role), nil }), HTTPClient: client, RetryMaxAttempts: 1})
}
func auditHTTPSizePutInput(binding audit.ExportBinding, key string, body []byte) *s3.PutObjectInput {
	policy := auditExportTestPolicy()
	sum := sha256.Sum256(body)
	return &s3.PutObjectInput{Bucket: aws.String(policy.Bucket), Key: aws.String(key), Body: bytes.NewReader(body), ContentType: aws.String("application/json"), ExpectedBucketOwner: aws.String(policy.ExpectedBucketOwner), IfNoneMatch: aws.String("*"), ServerSideEncryption: "aws:kms", SSEKMSKeyId: aws.String(policy.KMSKeyARN), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:])), Metadata: map[string]string{"organization_id": binding.OrganizationID, "workspace_id": binding.WorkspaceID, "environment_id": binding.EnvironmentID, "artifact_id": key[strings.LastIndex(key, "/")+1:], "media_type": "application/json", "sha256": hex.EncodeToString(sum[:])}}
}

// Catches accepting unissued objects, using SQL canonical bytes as the oracle,
// replacing a retained version, skipping source coverage, and losing reader separation.
func TestAuditHTTPSizeProviderRegisteredPostgres(t *testing.T) {
	for _, binary := range []string{"initdb", "postgres", "pg_isready", "pg_ctl", "node"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Fatal("required owned-PG fixture executable absent", binary)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	policy := auditExportTestPolicy()
	// The live TLS listener and its CA exist before the registered create call.
	b := newAuditHTTPSizeBridge(ctx)
	front := httptest.NewTLSServer(b)
	t.Cleanup(front.Close)
	request, common := auditExportClaimForCapture(t, ctx, f, worker, policy)
	oracleConn, err := pgx.ConnectConfig(ctx, f.admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := oracleConn.Close(c); err != nil {
			t.Error(err)
		}
	})
	observer, err := pgx.ConnectConfig(ctx, f.admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := observer.Close(c); err != nil {
			t.Error(err)
		}
	})
	e, err := newAuditHTTPSizeExpected(ctx, oracleConn, request[0].(string))
	if err != nil {
		t.Fatal(err)
	}
	// A caller's earlier traversal must not supply capture authority to the provider.
	priorBinding := audit.ExportBinding{OrganizationID: request[0].(string), WorkspaceID: request[1].(string), EnvironmentID: request[2].(string), ExportID: request[7].(string), CaptureID: auditHTTPSizeTestID(999)}
	if err := e.Reset(ctx, priorBinding); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := e.Close(c); err != nil {
			t.Error(err)
		}
	})
	p, err := newAuditHTTPSizeProvider(ctx, observer, policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := b.Close(c); err != nil {
			t.Error(err)
		}
		if err := p.Close(c); err != nil {
			t.Error(err)
		}
	})
	args := append([]any(nil), request...)
	if err := p.Bind(args, e); err != nil {
		t.Fatal(err)
	}
	args[0] = "caller-mutated-scope"
	args[7] = "caller-mutated-job"
	process := newAuditExportProcessProviderWithPolicy(t, ctx, f, worker, request, nil, policy, p)
	if err := b.Install(http.HandlerFunc(process.serve)); err != nil {
		t.Fatal(err)
	}
	chunk, canonical := auditExportCaptureSingleRequest(t, ctx, f, worker, request, common)
	binding := chunk.Binding
	var raw []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_prepare_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), canonical)...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var intent struct {
		ObjectReference string `json:"object_reference"`
	}
	if err := json.Unmarshal(raw, &intent); err != nil {
		t.Fatal(err)
	}
	key := strings.TrimPrefix(intent.ObjectReference, "s3://"+policy.Bucket+"/")
	sdk := auditHTTPSizeSDK(t, front, "worker")
	reader := auditHTTPSizeSDK(t, front, "reader")
	original := bytes.Clone(canonical)
	input := auditHTTPSizePutInput(binding, key, canonical)
	put, err := sdk.PutObject(ctx, input)
	if err != nil || put.VersionId == nil || *put.VersionId == "" {
		t.Fatal("actual SDK committed-intent PUT refused", err)
	}
	version := *put.VersionId
	select {
	case p.gate <- struct{}{}:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	beforeSummary, beforeRead := e.summary, e.read
	<-p.gate
	canonical[0] = '!'
	input.Metadata["organization_id"] = "changed"
	*input.ChecksumSHA256 = "changed"
	if err := p.Bind(request, e); err == nil {
		t.Fatal("second Bind accepted")
	}
	if _, err := sdk.PutObject(ctx, auditHTTPSizePutInput(binding, key, original)); err == nil {
		t.Fatal("repeated conditional PUT succeeded")
	}
	select {
	case p.gate <- struct{}{}:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	unchanged := e.summary == beforeSummary && e.read == beforeRead && len(p.objects) == 1 && p.objects["s3://"+policy.Bucket+"/"+key].Version == version && bytes.Equal(p.objects["s3://"+policy.Bucket+"/"+key].Body, original)
	<-p.gate
	if !unchanged {
		t.Fatal("conditional repeat advanced source or replaced inventory")
	}
	head, err := reader.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(policy.Bucket), Key: aws.String(key), VersionId: aws.String(version), ExpectedBucketOwner: aws.String(policy.ExpectedBucketOwner), ChecksumMode: "ENABLED"})
	if err != nil || aws.ToString(head.VersionId) != version || aws.ToInt64(head.ContentLength) != int64(len(original)) || head.Metadata["organization_id"] != binding.OrganizationID || aws.ToString(head.SSEKMSKeyId) != policy.KMSKeyARN {
		t.Fatal("reader HEAD lost retained authority", err)
	}
	head.Metadata["organization_id"] = "changed-response"
	get, err := reader.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(policy.Bucket), Key: aws.String(key), VersionId: aws.String(version), ExpectedBucketOwner: aws.String(policy.ExpectedBucketOwner), ChecksumMode: "ENABLED"})
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(get.Body)
	closeErr := get.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, original) || aws.ToString(get.VersionId) != version || get.Metadata["organization_id"] != binding.OrganizationID {
		t.Fatal("reader GET changed immutable bytes/header/version", readErr, closeErr)
	}
	// Record the actual retained version through the worker capability, then issue a real manifest.
	sum := sha256.Sum256(original)
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_record_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, append(append([]any(nil), common...), int64(1), version, sum[:], int64(len(original)))...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	manifest, err := audit.EncodeExportManifest(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, EventCount: 1, ChunkCount: 1, ChunkBytes: int64(len(original)), ChainRoot: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_prepare_manifest($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(append([]any(nil), common...), manifest)...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &intent); err != nil {
		t.Fatal(err)
	}
	manifestKey := strings.TrimPrefix(intent.ObjectReference, "s3://"+policy.Bucket+"/")
	if result, err := sdk.PutObject(ctx, auditHTTPSizePutInput(binding, manifestKey, manifest)); err != nil || aws.ToString(result.VersionId) == version {
		t.Fatal("complete original-source manifest refused", err)
	}
	if _, err := sdk.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(policy.Bucket), Key: aws.String(key), VersionId: aws.String(version), ExpectedBucketOwner: aws.String(policy.ExpectedBucketOwner), ChecksumMode: "ENABLED"}); err != nil {
		t.Fatal("worker pinned HEAD failed", err)
	}
	// Exercise response ownership without HTTP serialization copying buffers for us.
	for attempt := 0; attempt < 2; attempt++ {
		r := auditHTTPSizeRequest(t, "GET", "reader", key, "?versionId="+version+"&x-id=GetObject", nil, binding)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), original) || w.Header().Get("X-Amz-Meta-Organization_id") != binding.OrganizationID || w.Header().Get("X-Amz-Version-Id") != version {
			t.Fatal("caller response mutation changed retained state")
		}
		w.Body.Bytes()[0] = '!'
		w.Header()["X-Amz-Meta-Organization_id"][0] = "changed-header"
	}
	if err := p.Check(); err != nil {
		t.Fatal("valid provider run failed", err)
	}
	// Requests with real signatures still need a committed intent and exact inventory version.
	for _, bad := range []struct {
		name, method, key, query, role string
		body                           []byte
	}{
		{"missing-intent", "PUT", strings.TrimSuffix(key, key[strings.LastIndex(key, "/")+1:]) + auditHTTPSizeTestID(999), "?x-id=PutObject", "worker", original},
		{"wrong-version", "HEAD", key, "?versionId=wrong-version", "reader", nil},
		{"missing-version", "HEAD", key, "", "reader", nil},
		{"reader-write", "PUT", key, "?x-id=PutObject", "reader", original},
	} {
		t.Run(bad.name, func(t *testing.T) {
			r := auditHTTPSizeRequest(t, bad.method, bad.role, bad.key, bad.query, bad.body, binding)
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if w.Code < 400 {
				t.Fatal("invalid inventory request succeeded", w.Code)
			}
		})
	}
	closeCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if err := b.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	if observer.IsClosed() || oracleConn.IsClosed() || e.closed {
		t.Fatal("provider closed borrowed state")
	}
	_, summary, err := e.Manifest()
	if err != nil || summary.Events != 1 || summary.Chunks != 1 || summary.ChunkBytes != int64(len(original)) {
		t.Fatal("repeat PUT advanced original-source oracle", summary, err)
	}
	var one int
	if err := observer.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatal("observer not reusable after join", err)
	}
	if len(p.objects) != 2 || p.chunks != 1 || !p.manifest || p.counts["worker-PUT"] != 2 || p.counts["worker-repeat-PUT"] != 1 || p.counts["worker-HEAD"] != 1 || p.counts["reader-HEAD"] != 1 || p.counts["reader-GET"] != 3 {
		t.Fatal("continuous inventory or per-role counters changed", p.counts)
	}
	if p.Check() == nil {
		t.Fatal("provider Check lost its negative-request evidence")
	}
	// A new empty provider cannot adopt the issued manifest or the durable receipt
	// as successful object state. It must walk and retain every original chunk itself.
	missing, err := newAuditHTTPSizeProvider(ctx, observer, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := missing.Close(c); err != nil {
			t.Error(err)
		}
	}()
	if err := missing.Bind(request, e); err != nil {
		t.Fatal(err)
	}
	r := auditHTTPSizeRequest(t, "PUT", "worker", manifestKey, "?x-id=PutObject", manifest, binding)
	w := httptest.NewRecorder()
	missing.ServeHTTP(w, r)
	if w.Code < 400 || len(missing.objects) != 0 || missing.Check() == nil || !strings.Contains(missing.Check().Error(), "manifest before source EOF") {
		t.Fatal("manifest skipped original chunks", w.Code, missing.Check())
	}
}

func (p *auditHTTPSizeProvider) validate(r *http.Request, binding audit.ExportBinding) ([]byte, string, error) {
	fail := func() ([]byte, string, error) { return nil, "", errAuditHTTPSizeProvider }
	if r.Context().Err() != nil || r.TLS == nil || r.Host != p.policy.Bucket+".s3.us-east-1.amazonaws.com" || r.URL.RawPath != "" || r.URL.Fragment != "" || r.URL.User != nil || len(r.URL.Path) > 2048 || len(r.URL.RawQuery) > 2048 || r.ContentLength < 0 || r.ContentLength > audit.ExportMaximumChunkBytes || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || !auditLocalstackHeadersBounded(r.Header) {
		return fail()
	}
	prefix := "/organizations/" + binding.OrganizationID + "/workspaces/" + binding.WorkspaceID + "/environments/" + binding.EnvironmentID + "/exports/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return fail()
	}
	id := strings.TrimPrefix(r.URL.Path, prefix)
	if _, err := domain.ParseProductID(id); err != nil {
		return fail()
	}
	seen := map[string]bool{}
	for key, values := range r.Header {
		lower := strings.ToLower(key)
		if len(values) != 1 || seen[lower] {
			return fail()
		}
		seen[lower] = true
		switch lower {
		case "authorization", "accept-encoding", "user-agent", "amz-sdk-invocation-id", "amz-sdk-request", "content-length", "content-type", "if-none-match", "expect",
			"x-amz-expected-bucket-owner", "x-amz-content-sha256", "x-amz-date", "x-amz-security-token", "x-amz-checksum-sha256", "x-amz-checksum-mode", "x-amz-sdk-checksum-algorithm", "x-amz-server-side-encryption", "x-amz-server-side-encryption-aws-kms-key-id",
			"x-amz-meta-organization_id", "x-amz-meta-workspace_id", "x-amz-meta-environment_id", "x-amz-meta-artifact_id", "x-amz-meta-media_type", "x-amz-meta-sha256":
		default:
			return fail()
		}
	}
	if r.Header.Get("X-Amz-Expected-Bucket-Owner") != p.policy.ExpectedBucketOwner {
		return fail()
	}
	role := ""
	for _, candidate := range []string{"worker", "reader"} {
		cred := auditHTTPSizeCredentials(candidate)
		if candidate == "reader" && p.browserReader {
			cred = auditBrowserReaderCredentials()
		}
		if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential="+cred.AccessKeyID+"/") && r.Header.Get("X-Amz-Security-Token") == cred.SessionToken {
			role = candidate
		}
	}
	if role == "" || role == "reader" && r.Method != "HEAD" && r.Method != "GET" {
		return fail()
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return fail()
	}
	if r.Method == "PUT" {
		if !auditExportProcessS3Query(r.Method, r.URL.RawQuery, "") || r.Header.Get("If-None-Match") != "*" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("X-Amz-Server-Side-Encryption") != "aws:kms" || r.Header.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id") != p.policy.KMSKeyARN || r.Header.Get("X-Amz-Checksum-Mode") != "" {
			return fail()
		}
		if value := r.Header.Get("X-Amz-Sdk-Checksum-Algorithm"); value != "" && value != "SHA256" {
			return fail()
		}
		for k, v := range map[string]string{"organization_id": binding.OrganizationID, "workspace_id": binding.WorkspaceID, "environment_id": binding.EnvironmentID, "artifact_id": id, "media_type": "application/json"} {
			if r.Header.Get("X-Amz-Meta-"+k) != v {
				return fail()
			}
		}
		if digest, err := hex.DecodeString(r.Header.Get("X-Amz-Meta-Sha256")); err != nil || len(digest) != 32 {
			return fail()
		}
	} else {
		if !auditLocalstackVersion(query.Get("versionId")) || !auditExportProcessS3Query(r.Method, r.URL.RawQuery, query.Get("versionId")) || r.ContentLength != 0 || r.Header.Get("X-Amz-Checksum-Mode") != "ENABLED" {
			return fail()
		}
		for key := range r.Header {
			lower := strings.ToLower(key)
			if strings.HasPrefix(lower, "x-amz-meta-") || strings.HasPrefix(lower, "x-amz-server-side-encryption") || lower == "x-amz-checksum-sha256" || lower == "x-amz-sdk-checksum-algorithm" || lower == "content-type" || lower == "if-none-match" {
				return fail()
			}
		}
	}
	signedAt, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil || time.Since(signedAt) > 15*time.Minute || time.Until(signedAt) > time.Minute {
		return fail()
	}
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload != "UNSIGNED-PAYLOAD" {
		digest, err := hex.DecodeString(payload)
		if err != nil || len(digest) != 32 {
			return fail()
		}
	}
	clone := r.Clone(r.Context())
	clone.URL.Scheme = "https"
	clone.URL.Host = r.Host
	authorization := clone.Header.Get("Authorization")
	clone.Header.Del("Authorization")
	credentials := auditHTTPSizeCredentials(role)
	if role == "reader" && p.browserReader {
		credentials = auditBrowserReaderCredentials()
	}
	err = v4.NewSigner().SignHTTP(r.Context(), credentials, clone, payload, "s3", "us-east-1", signedAt, func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	if err != nil || subtle.ConstantTimeCompare([]byte(authorization), []byte(clone.Header.Get("Authorization"))) != 1 {
		return fail()
	}
	// Signature/role/scope/query authority is closed before the first body read.
	body, err := io.ReadAll(io.LimitReader(r.Body, audit.ExportMaximumChunkBytes+1))
	if err != nil || r.Context().Err() != nil || int64(len(body)) != r.ContentLength || len(body) > audit.ExportMaximumChunkBytes {
		return fail()
	}
	sum := sha256.Sum256(body)
	if payload != "UNSIGNED-PAYLOAD" && payload != hex.EncodeToString(sum[:]) {
		return fail()
	}
	if r.Method == "PUT" && (len(body) == 0 || r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(sum[:]) || r.Header.Get("X-Amz-Meta-Sha256") != hex.EncodeToString(sum[:])) {
		return fail()
	}
	return body, role, nil
}

var errAuditHTTPSizeProvider = errors.New("owned HTTP size provider rejected request")

const auditHTTPSizeProviderTimeout = 3 * time.Second

// Admission, cancellation and join have one owner. Close never closes borrowed SQL/oracle state.
type auditHTTPSizeLifetime struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	active int
	closed bool
	joined chan struct{}
}

func newAuditHTTPSizeLifetime(ctx context.Context) *auditHTTPSizeLifetime {
	ctx, cancel := context.WithCancel(ctx)
	return &auditHTTPSizeLifetime{ctx: ctx, cancel: cancel, joined: make(chan struct{})}
}
func (l *auditHTTPSizeLifetime) Close(ctx context.Context) error {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		l.cancel()
		if l.active == 0 {
			close(l.joined)
		}
	}
	l.mu.Unlock()
	select {
	case <-l.joined:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (l *auditHTTPSizeLifetime) finish() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active--
	if l.closed && l.active == 0 {
		close(l.joined)
	}
}
func (l *auditHTTPSizeLifetime) serve(w http.ResponseWriter, r *http.Request, h http.HandlerFunc) {
	l.mu.Lock()
	if l.closed || l.ctx.Err() != nil || r.Context().Err() != nil {
		l.mu.Unlock()
		panic(http.ErrAbortHandler)
	}
	l.active++
	l.mu.Unlock()
	defer l.finish()
	ctx, cancel := context.WithTimeout(r.Context(), auditHTTPSizeProviderTimeout)
	defer cancel()
	stop := context.AfterFunc(l.ctx, cancel)
	defer stop()
	r = r.Clone(ctx)
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)
	stopped := make(chan struct{})
	stopBody := context.AfterFunc(ctx, func() {
		defer close(stopped)
		_ = controller.SetReadDeadline(time.Now())
		_ = controller.SetWriteDeadline(time.Now())
		if r.Body != nil {
			_ = r.Body.Close()
		}
	})
	defer func() {
		if !stopBody() {
			<-stopped
		}
	}()
	defer func() {
		if ctx.Err() != nil || l.ctx.Err() != nil || !time.Now().Before(deadline) {
			panic(http.ErrAbortHandler)
		}
	}()
	if ctx.Err() != nil || l.ctx.Err() != nil {
		return
	}
	h(w, r)
}

// Construct the owner's TLS listener with this handler before POST; its address/CA stay fixed.
type auditHTTPSizeBridge struct {
	*auditHTTPSizeLifetime
	handler http.Handler
}

func newAuditHTTPSizeBridge(ctx context.Context) *auditHTTPSizeBridge {
	return &auditHTTPSizeBridge{auditHTTPSizeLifetime: newAuditHTTPSizeLifetime(ctx)}
}
func (b *auditHTTPSizeBridge) Install(h http.Handler) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if h == nil || b.handler != nil || b.closed || b.ctx.Err() != nil {
		return errAuditHTTPSizeProvider
	}
	b.handler = h
	return nil
}
func (b *auditHTTPSizeBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.serve(w, r, func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		h := b.handler
		b.mu.Unlock()
		if h == nil {
			http.Error(w, "owned bridge not installed", http.StatusServiceUnavailable)
			return
		}
		h.ServeHTTP(w, r)
	})
}
