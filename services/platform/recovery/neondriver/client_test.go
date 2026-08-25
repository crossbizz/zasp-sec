package neondriver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testProjectID  = "silent-river-123456"
	testParentID   = "br-falling-sun-123456"
	testBranchID   = "br-recovery-123456"
	testBranchName = "zasp-recovery-71000004"
)

func TestNeonClientCreatesExactBranchAndPrivateEndpoint(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodPost || request.URL.EscapedPath() != "/api/v2/projects/"+testProjectID+"/branches" || request.URL.RawQuery != "" || request.Header.Get("Authorization") != "Bearer neon-test-token-1" || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected request: %s %s headers=%v", request.Method, request.URL.String(), request.Header)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"branch":{"name":"zasp-recovery-71000004","parent_id":"br-falling-sun-123456","parent_lsn":"0/16B6C50"},"endpoints":[{"type":"read_write"}]}`
		if string(body) != want {
			t.Fatalf("unexpected body:\n%s\nwant:\n%s", body, want)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"branch":{"id":"br-recovery-123456","project_id":"silent-river-123456","parent_id":"br-falling-sun-123456","parent_lsn":"0/16B6C50","name":"zasp-recovery-71000004"},"endpoints":[{"id":"ep-recovery-123456","project_id":"silent-river-123456","branch_id":"br-recovery-123456","type":"read_write","host":"ep-recovery-123456.internal"}]}`))
	}))
	defer server.Close()

	client := newNeonTestClient(t, server)
	branch, err := client.CreateBranch(context.Background(), CreateBranchRequest{Name: testBranchName, ParentLSN: "0/16B6C50"})
	if err != nil {
		t.Fatal(err)
	}
	if branch.ID != testBranchID || branch.Name != testBranchName || branch.ParentID != testParentID || branch.ParentLSN != "0/16B6C50" || len(branch.Endpoints) != 1 || branch.Endpoints[0].Type != "read_write" || branch.Endpoints[0].BranchID != branch.ID {
		t.Fatalf("unexpected branch: %#v", branch)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestNeonClientReconcilesLostCreateResponseByExactName(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch calls.Add(1) {
		case 1:
			if request.Method != http.MethodPost {
				t.Fatalf("method=%s", request.Method)
			}
			hijacker, ok := writer.(http.Hijacker)
			if !ok {
				t.Fatal("missing hijacker")
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = connection.Close()
		case 2:
			if request.Method != http.MethodGet || request.URL.EscapedPath() != "/api/v2/projects/"+testProjectID+"/branches" || request.URL.Query().Get("search") != testBranchName || request.URL.Query().Get("limit") != "2" {
				t.Fatalf("unexpected reconciliation request: %s %s", request.Method, request.URL.String())
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"branches":[{"id":"br-recovery-123456","project_id":"silent-river-123456","parent_id":"br-falling-sun-123456","parent_lsn":"0/16B6C50","name":"zasp-recovery-71000004"}],"endpoints":[{"id":"ep-recovery-123456","project_id":"silent-river-123456","branch_id":"br-recovery-123456","type":"read_write","host":"ep-recovery-123456.internal"}]}`))
		default:
			t.Fatalf("unexpected call %d", calls.Load())
		}
	}))
	defer server.Close()

	branch, err := newNeonTestClient(t, server).CreateBranch(context.Background(), CreateBranchRequest{Name: testBranchName, ParentLSN: "0/16B6C50"})
	if err != nil || branch.ID != testBranchID || calls.Load() != 2 {
		t.Fatalf("branch=%#v calls=%d err=%v", branch, calls.Load(), err)
	}
}

func TestNeonClientRejectsProviderFailuresWithoutLeakingBodies(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   error
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, want: ErrDenied},
		{name: "forbidden", status: http.StatusForbidden, want: ErrDenied},
		{name: "locked", status: http.StatusLocked, want: ErrRetryable},
		{name: "unavailable", status: http.StatusServiceUnavailable, want: ErrRetryable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(`{"error":"provider-secret-body"}`))
			}))
			defer server.Close()
			_, err := newNeonTestClient(t, server).CreateBranch(context.Background(), CreateBranchRequest{Name: testBranchName, ParentLSN: "0/16B6C50"})
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), "provider-secret-body") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestNeonClientRejectsMalformedOversizedRedirectedTimedOutAndCancelledResponses(t *testing.T) {
	t.Run("unknown json", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"branch":{"id":"br-recovery-123456","project_id":"silent-river-123456","parent_id":"br-falling-sun-123456","parent_lsn":"0/16B6C50","name":"zasp-recovery-71000004","secret":"forbidden"},"endpoints":[]}`))
		}))
		defer server.Close()
		_, err := newNeonTestClient(t, server).CreateBranch(context.Background(), CreateBranchRequest{Name: testBranchName, ParentLSN: "0/16B6C50"})
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"padding":"` + strings.Repeat("x", maximumResponseBytes) + `"}`))
		}))
		defer server.Close()
		_, err := newNeonTestClient(t, server).CreateBranch(context.Background(), CreateBranchRequest{Name: testBranchName, ParentLSN: "0/16B6C50"})
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("redirect", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, "https://example.invalid/escape", http.StatusTemporaryRedirect)
		}))
		defer server.Close()
		_, err := newNeonTestClient(t, server).CreateBranch(context.Background(), CreateBranchRequest{Name: testBranchName, ParentLSN: "0/16B6C50"})
		if !errors.Is(err, ErrRetryable) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			time.Sleep(50 * time.Millisecond)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{}`))
		}))
		defer server.Close()
		client := newNeonTestClientWithTimeout(t, server, 10*time.Millisecond)
		_, err := client.CreateBranch(context.Background(), CreateBranchRequest{Name: testBranchName, ParentLSN: "0/16B6C50"})
		if !errors.Is(err, ErrRetryable) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		client := newNeonTestClient(t, httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := client.CreateBranch(ctx, CreateBranchRequest{Name: testBranchName, ParentLSN: "0/16B6C50"})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestNeonClientGetsDeletesAndChecksPinnedAuthority(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call := calls.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		switch call {
		case 1:
			if request.Method != http.MethodGet || request.URL.Query().Get("search") != testBranchName {
				t.Fatalf("unexpected get: %s %s", request.Method, request.URL.String())
			}
			_, _ = writer.Write([]byte(`{"branches":[{"id":"br-recovery-123456","project_id":"silent-river-123456","parent_id":"br-falling-sun-123456","parent_lsn":"0/16B6C50","name":"zasp-recovery-71000004"}],"endpoints":[{"id":"ep-recovery-123456","project_id":"silent-river-123456","branch_id":"br-recovery-123456","type":"read_write","host":"ep-recovery-123456.internal"}]}`))
		case 2:
			if request.Method != http.MethodDelete || request.URL.EscapedPath() != "/api/v2/projects/"+testProjectID+"/branches/"+testBranchID {
				t.Fatalf("unexpected delete: %s %s", request.Method, request.URL.String())
			}
			writer.WriteHeader(http.StatusNoContent)
		case 3:
			if request.Method != http.MethodGet || request.URL.EscapedPath() != "/api/v2/projects/"+testProjectID+"/branches/"+testParentID {
				t.Fatalf("unexpected ready: %s %s", request.Method, request.URL.String())
			}
			_, _ = writer.Write([]byte(`{"branch":{"id":"br-falling-sun-123456","project_id":"silent-river-123456","name":"production"}}`))
		default:
			t.Fatalf("unexpected call %d", call)
		}
	}))
	defer server.Close()
	client := newNeonTestClient(t, server)
	branch, err := client.GetBranchByName(context.Background(), testProjectID, testBranchName)
	if err != nil || branch.ID != testBranchID {
		t.Fatalf("branch=%#v err=%v", branch, err)
	}
	if err := client.DeleteBranch(context.Background(), testProjectID, testBranchID); err != nil {
		t.Fatal(err)
	}
	if err := client.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func newNeonTestClient(t *testing.T, server *httptest.Server) *client {
	t.Helper()
	return newNeonTestClientWithTimeout(t, server, time.Second)
}

func newNeonTestClientWithTimeout(t *testing.T, server *httptest.Server, timeout time.Duration) *client {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	certificate := server.Certificate()
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	value, err := newClient(clientConfig{Origin: parsed, APIKey: []byte("neon-test-token-1"), ProjectID: testProjectID, ParentBranchID: testParentID, RootCAs: pool, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = value.Close() })
	return value
}

func TestNeonRequestJSONRemainsCanonical(t *testing.T) {
	encoded, err := json.Marshal(createBranchWire{Branch: createBranchSpec{Name: testBranchName, ParentID: testParentID, ParentLSN: "0/16B6C50"}, Endpoints: []createEndpointSpec{{Type: "read_write"}}})
	if err != nil || string(encoded) != `{"branch":{"name":"zasp-recovery-71000004","parent_id":"br-falling-sun-123456","parent_lsn":"0/16B6C50"},"endpoints":[{"type":"read_write"}]}` {
		t.Fatalf("encoded=%s err=%v", encoded, err)
	}
}
