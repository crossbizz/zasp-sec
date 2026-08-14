package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type staticResolver struct {
	addresses []string
	err       error
}

func (r staticResolver) LookupHost(context.Context, string) ([]string, error) {
	return append([]string(nil), r.addresses...), r.err
}

func TestValidateEndpointAcceptsOnlyExplicitNonPrivilegedLoopbackHTTP(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, valid := range []string{"http://127.0.0.1:49152", "http://[::1]:49153", "http://localhost:49154"} {
		if _, err := validateEndpoint(ctx, valid, staticResolver{addresses: []string{"127.0.0.1", "::1"}}); err != nil {
			t.Errorf("validateEndpoint(%q) rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"", "https://127.0.0.1:49152", "http://127.0.0.1", "http://127.0.0.1:80", "http://0.0.0.0:49152",
		"http://example.com:49152", "http://user@127.0.0.1:49152", "http://127.0.0.1:49152/path",
		"http://127.0.0.1:49152/", "http://127.0.0.1:49152?query=1", "http://127.0.0.1:49152/#fragment",
	} {
		if _, err := validateEndpoint(ctx, invalid, staticResolver{addresses: []string{"203.0.113.10"}}); err == nil {
			t.Errorf("validateEndpoint(%q) accepted", invalid)
		}
	}
}

func TestCreateKeyDoesNotRetryAfterALostResponse(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	var taggedCreates atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts.Add(1)
		var payload struct {
			Description string
			Tags        []struct{ TagKey, TagValue *string }
		}
		if err := json.NewDecoder(io.LimitReader(request.Body, 16_385)).Decode(&payload); err != nil {
			t.Error("test server received an invalid CreateKey request")
			return
		}
		tags := map[string]string{}
		for _, tag := range payload.Tags {
			if tag.TagKey == nil || tag.TagValue == nil {
				t.Error("test server received an incomplete CreateKey tag")
				return
			}
			tags[*tag.TagKey] = *tag.TagValue
		}
		if payload.Description != description(testMarker) || !equalStringMaps(tags, proofTags(testMarker, "kms-key")) {
			t.Error("test server received an unexpected CreateKey ownership marker")
			return
		}
		taggedCreates.Add(1)
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			t.Error("test server cannot close the response connection")
			return
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_ = connection.Close()
	}))
	defer server.Close()
	bundle, err := newSDKClients(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("newSDKClients returned %v", err)
	}
	defer bundle.Close()
	_, _ = bundle.KMS.CreateKey(context.Background(), CreateKeyRequest{Description: description(testMarker), Tags: proofTags(testMarker, "kms-key")})
	if got := attempts.Load(); got != 1 {
		t.Fatalf("CreateKey attempts = %d, want exactly one", got)
	}
	if got := taggedCreates.Load(); got != 1 {
		t.Fatalf("tagged creates = %d, want exactly one", got)
	}
}

func TestLoopbackDialerRejectsRebindingAndTriesOnlyValidatedAddresses(t *testing.T) {
	t.Parallel()
	endpoint := validatedEndpoint{hostname: "localhost", port: "49152"}
	called := []string{}
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		called = append(called, address)
		if strings.HasPrefix(address, "127.0.0.1:") {
			return nil, errors.New("first family unavailable")
		}
		return nil, errors.New("second family unavailable")
	}
	loopback := loopbackDialerWithResolverAndDialer(endpoint, staticResolver{addresses: []string{"127.0.0.1", "::1"}}, dial)
	if _, err := loopback(context.Background(), "tcp", "localhost:49152"); err == nil {
		t.Fatal("dial unexpectedly succeeded")
	}
	if len(called) != 2 || called[0] != "127.0.0.1:49152" || called[1] != "[::1]:49152" {
		t.Fatalf("dialed %v", called)
	}

	rebound := loopbackDialerWithResolverAndDialer(endpoint, staticResolver{addresses: []string{"127.0.0.1", "203.0.113.10"}}, dial)
	before := len(called)
	if _, err := rebound(context.Background(), "tcp", "localhost:49152"); !errors.Is(err, errConfiguration) {
		t.Fatalf("rebound error = %v", err)
	}
	if len(called) != before {
		t.Fatal("dialer attempted a target after non-loopback resolution")
	}
}

func TestSDKUsesPathStyleAndRefusesRedirectsWithoutAmbientConfiguration(t *testing.T) {
	t.Setenv("AWS_PROFILE", "foreign")
	t.Setenv("AWS_ENDPOINT_URL", "http://203.0.113.10:65535")
	t.Setenv("HTTP_PROXY", "http://203.0.113.11:65535")
	t.Setenv("HTTPS_PROXY", "http://203.0.113.12:65535")

	var host, path string
	redirected := false
	foreign := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected = true }))
	defer foreign.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host, path = request.Host, request.URL.EscapedPath()
		writer.Header().Set("Location", foreign.URL)
		writer.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := newSDKClients(context.Background(), "http://"+parsed.Host)
	if err != nil {
		t.Fatalf("newSDKClients returned %v", err)
	}
	defer bundle.Close()
	if err := bundle.S3.CreateBucket(context.Background(), "path-style-bucket"); err == nil {
		t.Fatal("redirect response was accepted")
	}
	if redirected {
		t.Fatal("SDK followed a redirect")
	}
	if host != parsed.Host || path != "/path-style-bucket" {
		t.Fatalf("request destination = host %q path %q", host, path)
	}
}

func TestSecretTagConversionRejectsNilAndDuplicateProviderTags(t *testing.T) {
	t.Parallel()
	for name, tags := range map[string][]secretstypes.Tag{
		"nil key":   {{Key: nil, Value: aws.String("value")}},
		"nil value": {{Key: aws.String("key"), Value: nil}},
		"duplicate": {{Key: aws.String("key"), Value: aws.String("one")}, {Key: aws.String("key"), Value: aws.String("two")}},
	} {
		name, tags := name, tags
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := fromSecretTags(tags); err == nil {
				t.Fatal("provider tags were silently normalized")
			}
		})
	}
	got, err := fromSecretTags([]secretstypes.Tag{{Key: aws.String("one"), Value: aws.String("1")}, {Key: aws.String("two"), Value: aws.String("2")}})
	if err != nil || !equalStringMaps(got, map[string]string{"one": "1", "two": "2"}) {
		t.Fatalf("valid tags = %v, %v", got, err)
	}
}
