package awsclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	platformconfig "github.com/zasp-ai/zasp-sec/services/platform/config"
)

const localEndpoint = "http://localstack.zasp-local.svc.cluster.local:4566"

type capturedRequest struct {
	method        string
	escapedPath   string
	authorization string
	amzDate       string
}

type requestCapture struct {
	mu       sync.Mutex
	requests []capturedRequest
	status   int
}

func (capture *requestCapture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(io.LimitReader(request.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	capture.mu.Lock()
	capture.requests = append(capture.requests, capturedRequest{
		method:        request.Method,
		escapedPath:   request.URL.EscapedPath(),
		authorization: request.Header.Get("Authorization"),
		amzDate:       request.Header.Get("X-Amz-Date"),
	})
	status := capture.status
	capture.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	writer.Header().Set("Content-Type", "application/x-amz-json-1.0")
	writer.WriteHeader(status)
	if request.Method != http.MethodHead {
		_, _ = writer.Write([]byte("{}"))
	}
}

func (capture *requestCapture) snapshot() []capturedRequest {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]capturedRequest(nil), capture.requests...)
}

type staticRoundTripper struct{}

func (staticRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("{}")),
	}, nil
}

type typedNilCredentials struct{}

func (*typedNilCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, errors.New("unreachable")
}

type typedNilHTTPClient struct{}

func (*typedNilHTTPClient) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("unreachable")
}

type explicitCredentials struct{}

func (*explicitCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "production", SecretAccessKey: "explicit", Source: "test"}, nil
}

func mustRegion(t *testing.T, value string) platformconfig.AWSRegion {
	t.Helper()
	region, err := platformconfig.ParseAWSRegion(value)
	if err != nil {
		t.Fatal(err)
	}
	return region
}

func exactLookup(values map[string]string, calls *[]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		*calls = append(*calls, key)
		value, ok := values[key]
		return value, ok
	}
}

func testCredentials() aws.CredentialsProvider {
	return &explicitCredentials{}
}

func TestNewConstructsAllLocalStackClients(t *testing.T) {
	calls := []string{}
	clients, err := New(Options{
		Mode:   ModeCI,
		Region: mustRegion(t, "us-east-1"),
		Lookup: exactLookup(map[string]string{
			"AWS_ENDPOINT_URL":    "http://127.0.0.1:4566",
			"AWS_ENDPOINT_URL_S3": "http://127.0.0.1:4566",
		}, &calls),
	})
	if err != nil {
		t.Fatal(err)
	}

	var _ *sqs.Client = clients.SQS()
	var _ *s3.Client = clients.S3()
	var _ *kms.Client = clients.KMS()
	var _ *secretsmanager.Client = clients.SecretsManager()
	var _ *opensearch.Client = clients.OpenSearch()
	if clients.SQS() == nil || clients.S3() == nil || clients.KMS() == nil ||
		clients.SecretsManager() == nil || clients.OpenSearch() == nil {
		t.Fatal("New returned a nil service client")
	}
	if !reflect.DeepEqual(calls, []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3"}) {
		t.Fatalf("lookup calls = %v", calls)
	}
	clients.Close()
	clients.Close()
}

func TestNewRejectsInvalidAuthority(t *testing.T) {
	region := mustRegion(t, "us-east-1")
	productionClient := &http.Client{Transport: staticRoundTripper{}, Timeout: time.Second}
	validCI := map[string]string{
		"AWS_ENDPOINT_URL":    "http://127.0.0.1:4566",
		"AWS_ENDPOINT_URL_S3": "http://127.0.0.1:4566",
	}
	var nilLookup func(string) (string, bool)
	var nilCredentials *typedNilCredentials
	var nilHTTPClient *typedNilHTTPClient

	tests := []struct {
		name    string
		options Options
	}{
		{name: "zero mode", options: Options{Region: region}},
		{name: "unknown mode", options: Options{Mode: Mode("preview"), Region: region}},
		{name: "zero region", options: Options{Mode: ModeCI, Lookup: exactLookup(validCI, &[]string{})}},
		{name: "wrong local region", options: Options{Mode: ModeLocal, Region: mustRegion(t, "us-west-2"), Lookup: exactLookup(pair(localEndpoint), &[]string{})}},
		{name: "wrong ci region", options: Options{Mode: ModeCI, Region: mustRegion(t, "us-west-2"), Lookup: exactLookup(validCI, &[]string{})}},
		{name: "nil local lookup", options: Options{Mode: ModeLocal, Region: region}},
		{name: "typed nil ci lookup", options: Options{Mode: ModeCI, Region: region, Lookup: nilLookup}},
		{name: "local credentials", options: Options{Mode: ModeLocal, Region: region, Lookup: exactLookup(pair(localEndpoint), &[]string{}), Credentials: testCredentials()}},
		{name: "ci http client", options: Options{Mode: ModeCI, Region: region, Lookup: exactLookup(validCI, &[]string{}), HTTPClient: productionClient}},
		{name: "production lookup", options: Options{Mode: ModeProduction, Region: region, Lookup: exactLookup(validCI, &[]string{}), Credentials: testCredentials(), HTTPClient: productionClient}},
		{name: "production missing credentials", options: Options{Mode: ModeProduction, Region: region, HTTPClient: productionClient}},
		{name: "production typed nil credentials", options: Options{Mode: ModeProduction, Region: region, Credentials: nilCredentials, HTTPClient: productionClient}},
		{name: "production missing http client", options: Options{Mode: ModeProduction, Region: region, Credentials: testCredentials()}},
		{name: "production typed nil http client", options: Options{Mode: ModeProduction, Region: region, Credentials: testCredentials(), HTTPClient: nilHTTPClient}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clients, err := New(test.options)
			if clients != nil {
				clients.Close()
				t.Fatal("New returned clients for invalid authority")
			}
			if !errors.Is(err, ErrConfiguration) || err.Error() != ErrConfiguration.Error() {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestNewRejectsInvalidEndpointPairsAfterExactlyTwoReads(t *testing.T) {
	region := mustRegion(t, "us-east-1")
	tests := []struct {
		name   string
		mode   Mode
		values map[string]string
	}{
		{name: "missing both", mode: ModeCI, values: map[string]string{}},
		{name: "missing s3", mode: ModeCI, values: map[string]string{"AWS_ENDPOINT_URL": "http://127.0.0.1:4566"}},
		{name: "empty", mode: ModeCI, values: map[string]string{"AWS_ENDPOINT_URL": "", "AWS_ENDPOINT_URL_S3": ""}},
		{name: "unequal", mode: ModeCI, values: map[string]string{"AWS_ENDPOINT_URL": "http://127.0.0.1:4566", "AWS_ENDPOINT_URL_S3": "http://127.0.0.1:4567"}},
		{name: "userinfo", mode: ModeCI, values: pair("http://user@127.0.0.1:4566")},
		{name: "path", mode: ModeCI, values: pair("http://127.0.0.1:4566/path")},
		{name: "query", mode: ModeCI, values: pair("http://127.0.0.1:4566?x=1")},
		{name: "fragment", mode: ModeCI, values: pair("http://127.0.0.1:4566#fragment")},
		{name: "escape", mode: ModeCI, values: pair("http://127.0.0.1%3A4566")},
		{name: "trailing slash", mode: ModeCI, values: pair("http://127.0.0.1:4566/")},
		{name: "https", mode: ModeCI, values: pair("https://127.0.0.1:4566")},
		{name: "missing port", mode: ModeCI, values: pair("http://127.0.0.1")},
		{name: "default port", mode: ModeCI, values: pair("http://127.0.0.1:80")},
		{name: "zero port", mode: ModeCI, values: pair("http://127.0.0.1:0")},
		{name: "large port", mode: ModeCI, values: pair("http://127.0.0.1:65536")},
		{name: "leading-zero port", mode: ModeCI, values: pair("http://127.0.0.1:04566")},
		{name: "localhost", mode: ModeCI, values: pair("http://localhost:4566")},
		{name: "ipv6", mode: ModeCI, values: pair("http://[::1]:4566")},
		{name: "wildcard", mode: ModeCI, values: pair("http://0.0.0.0:4566")},
		{name: "private", mode: ModeCI, values: pair("http://10.0.0.1:4566")},
		{name: "public", mode: ModeCI, values: pair("http://198.51.100.1:4566")},
		{name: "wrong local host", mode: ModeLocal, values: pair("http://localstack:4566")},
		{name: "wrong local port", mode: ModeLocal, values: pair("http://localstack.zasp-local.svc.cluster.local:4567")},
		{name: "ci endpoint in local", mode: ModeLocal, values: pair("http://127.0.0.1:4566")},
		{name: "local endpoint in ci", mode: ModeCI, values: pair(localEndpoint)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := []string{}
			clients, err := New(Options{Mode: test.mode, Region: region, Lookup: exactLookup(test.values, &calls)})
			if clients != nil {
				clients.Close()
				t.Fatal("New returned clients for an invalid endpoint")
			}
			if !errors.Is(err, ErrConfiguration) || err.Error() != ErrConfiguration.Error() {
				t.Fatalf("error = %v", err)
			}
			if !reflect.DeepEqual(calls, []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3"}) {
				t.Fatalf("lookup calls = %v", calls)
			}
			for _, value := range test.values {
				if value != "" && strings.Contains(err.Error(), value) {
					t.Fatal("error exposed the rejected endpoint")
				}
			}
		})
	}
}

func pair(value string) map[string]string {
	return map[string]string{"AWS_ENDPOINT_URL": value, "AWS_ENDPOINT_URL_S3": value}
}

func TestProductionPreservesOnlyExplicitAuthority(t *testing.T) {
	credentials := testCredentials()
	httpClient := &http.Client{Transport: staticRoundTripper{}, Timeout: time.Second}
	clients, err := New(Options{Mode: ModeProduction, Region: mustRegion(t, "us-west-2"), Credentials: credentials, HTTPClient: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	defer clients.Close()

	options := []struct {
		region       string
		credentials  aws.CredentialsProvider
		httpClient   aws.HTTPClient
		baseEndpoint *string
	}{
		{clients.SQS().Options().Region, clients.SQS().Options().Credentials, clients.SQS().Options().HTTPClient, clients.SQS().Options().BaseEndpoint},
		{clients.S3().Options().Region, clients.S3().Options().Credentials, clients.S3().Options().HTTPClient, clients.S3().Options().BaseEndpoint},
		{clients.KMS().Options().Region, clients.KMS().Options().Credentials, clients.KMS().Options().HTTPClient, clients.KMS().Options().BaseEndpoint},
		{clients.SecretsManager().Options().Region, clients.SecretsManager().Options().Credentials, clients.SecretsManager().Options().HTTPClient, clients.SecretsManager().Options().BaseEndpoint},
		{clients.OpenSearch().Options().Region, clients.OpenSearch().Options().Credentials, clients.OpenSearch().Options().HTTPClient, clients.OpenSearch().Options().BaseEndpoint},
	}
	for index, option := range options {
		if option.region != "us-west-2" || option.credentials != credentials || option.httpClient != httpClient || option.baseEndpoint != nil {
			t.Fatalf("client %d did not preserve explicit production authority", index)
		}
	}
	if clients.S3().Options().UsePathStyle {
		t.Fatal("production S3 unexpectedly uses LocalStack path-style routing")
	}
}

func TestLocalAndCIAuthorityIsExact(t *testing.T) {
	tests := []struct {
		name     string
		mode     Mode
		endpoint string
	}{
		{name: "local", mode: ModeLocal, endpoint: localEndpoint},
		{name: "ci", mode: ModeCI, endpoint: "http://127.0.0.1:4566"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := []string{}
			clients, err := New(Options{
				Mode:   test.mode,
				Region: mustRegion(t, "us-east-1"),
				Lookup: exactLookup(pair(test.endpoint), &calls),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer clients.Close()

			options := []struct {
				region       string
				credentials  aws.CredentialsProvider
				httpClient   aws.HTTPClient
				baseEndpoint *string
				retryer      aws.Retryer
			}{
				{clients.SQS().Options().Region, clients.SQS().Options().Credentials, clients.SQS().Options().HTTPClient, clients.SQS().Options().BaseEndpoint, clients.SQS().Options().Retryer},
				{clients.S3().Options().Region, clients.S3().Options().Credentials, clients.S3().Options().HTTPClient, clients.S3().Options().BaseEndpoint, clients.S3().Options().Retryer},
				{clients.KMS().Options().Region, clients.KMS().Options().Credentials, clients.KMS().Options().HTTPClient, clients.KMS().Options().BaseEndpoint, clients.KMS().Options().Retryer},
				{clients.SecretsManager().Options().Region, clients.SecretsManager().Options().Credentials, clients.SecretsManager().Options().HTTPClient, clients.SecretsManager().Options().BaseEndpoint, clients.SecretsManager().Options().Retryer},
				{clients.OpenSearch().Options().Region, clients.OpenSearch().Options().Credentials, clients.OpenSearch().Options().HTTPClient, clients.OpenSearch().Options().BaseEndpoint, clients.OpenSearch().Options().Retryer},
			}
			for index, option := range options {
				if option.region != "us-east-1" || option.baseEndpoint == nil || *option.baseEndpoint != test.endpoint || option.httpClient == nil {
					t.Fatalf("client %d local authority mismatch", index)
				}
				credentials, err := option.credentials.Retrieve(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if credentials.AccessKeyID != "test" || credentials.SecretAccessKey != "test" ||
					credentials.SessionToken != "" || credentials.Source != "zasp-localstack-client-factory" {
					t.Fatalf("client %d credential authority mismatch", index)
				}
				if option.retryer == nil || option.retryer.MaxAttempts() != 1 {
					t.Fatalf("client %d retry authority mismatch", index)
				}
			}
			if !clients.S3().Options().UsePathStyle {
				t.Fatal("local S3 does not use path-style routing")
			}
			if !reflect.DeepEqual(calls, []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3"}) {
				t.Fatalf("lookup calls = %v", calls)
			}
		})
	}
}

func TestLocalHTTPClientIsBoundedAndProxyFree(t *testing.T) {
	clients := newCIClients(t, "http://127.0.0.1:4566")
	defer clients.Close()
	httpClient, ok := clients.SQS().Options().HTTPClient.(*http.Client)
	if !ok {
		t.Fatalf("HTTP client type = %T", clients.SQS().Options().HTTPClient)
	}
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", httpClient.Transport)
	}
	if httpClient.Timeout != 20*time.Second || httpClient.CheckRedirect == nil ||
		transport.Proxy != nil || !transport.DisableKeepAlives || transport.ForceAttemptHTTP2 ||
		transport.TLSHandshakeTimeout != 3*time.Second || transport.ResponseHeaderTimeout != 10*time.Second ||
		transport.MaxResponseHeaderBytes != 1<<20 || transport.DialContext == nil {
		t.Fatal("owned HTTP client does not match the bounded proxy-free contract")
	}
	request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(httpClient.CheckRedirect(request, []*http.Request{request}), http.ErrUseLastResponse) {
		t.Fatal("redirect policy did not reject the redirect")
	}
}

func TestFiveSDKClientsRouteOneSignedRequestToCIEndpoint(t *testing.T) {
	capture := &requestCapture{}
	server := httptest.NewServer(capture)
	defer server.Close()
	clients := newCIClients(t, server.URL)
	defer clients.Close()

	invokeReads(t, clients)
	requests := capture.snapshot()
	if len(requests) != 5 {
		t.Fatalf("request count = %d", len(requests))
	}

	credentialPattern := regexp.MustCompile(`Credential=test/\d{8}/us-east-1/([^/]+)/aws4_request`)
	datePattern := regexp.MustCompile(`^\d{8}T\d{6}Z$`)
	services := []string{}
	foundS3 := false
	for _, request := range requests {
		match := credentialPattern.FindStringSubmatch(request.authorization)
		if len(match) != 2 {
			t.Fatalf("authorization = %q", request.authorization)
		}
		services = append(services, match[1])
		if !datePattern.MatchString(request.amzDate) {
			t.Fatalf("X-Amz-Date = %q", request.amzDate)
		}
		if request.method == http.MethodHead {
			foundS3 = request.escapedPath == "/zasp-local-test"
		}
	}
	sort.Strings(services)
	if !reflect.DeepEqual(services, []string{"es", "kms", "s3", "secretsmanager", "sqs"}) {
		t.Fatalf("signing services = %v", services)
	}
	if !foundS3 {
		t.Fatal("S3 did not use exact path-style routing")
	}
}

func TestCIAuthorityIgnoresAmbientAWSAndProxyState(t *testing.T) {
	for key, value := range map[string]string{
		"AWS_ACCESS_KEY_ID":                  "ambient-access",
		"AWS_ENDPOINT_URL":                   "http://198.51.100.1:4566",
		"AWS_ENDPOINT_URL_S3":                "http://198.51.100.1:4566",
		"AWS_SECRET_ACCESS_KEY":              "ambient-secret",
		"AWS_PROFILE":                        "ambient-profile",
		"AWS_SHARED_CREDENTIALS_FILE":        "/untrusted/credentials",
		"AWS_CONFIG_FILE":                    "/untrusted/config",
		"AWS_WEB_IDENTITY_TOKEN_FILE":        "/untrusted/token",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://198.51.100.1/credentials",
		"HTTP_PROXY":                         "http://198.51.100.1:8080",
		"HTTPS_PROXY":                        "http://198.51.100.1:8080",
	} {
		t.Setenv(key, value)
	}
	capture := &requestCapture{}
	server := httptest.NewServer(capture)
	defer server.Close()
	clients := newCIClients(t, server.URL)
	defer clients.Close()

	invokeReads(t, clients)
	for _, request := range capture.snapshot() {
		if !strings.Contains(request.authorization, "Credential=test/") {
			t.Fatalf("authorization used ambient authority: %q", request.authorization)
		}
	}
}

func TestCIHTTPClientDoesNotFollowRedirects(t *testing.T) {
	redirected := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected++
	}))
	defer target.Close()
	originCalls := 0
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		originCalls++
		writer.Header().Set("Location", target.URL)
		writer.WriteHeader(http.StatusFound)
	}))
	defer origin.Close()
	clients := newCIClients(t, origin.URL)
	defer clients.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := clients.SQS().ListQueues(ctx, &sqs.ListQueuesInput{}); err == nil {
		t.Fatal("redirect response unexpectedly succeeded")
	}
	if originCalls != 1 || redirected != 0 {
		t.Fatalf("origin calls = %d, redirected calls = %d", originCalls, redirected)
	}
}

func TestSDKClientsDoNotRetryProviderFailures(t *testing.T) {
	capture := &requestCapture{status: http.StatusInternalServerError}
	server := httptest.NewServer(capture)
	defer server.Close()
	clients := newCIClients(t, server.URL)
	defer clients.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = clients.SQS().ListQueues(ctx, &sqs.ListQueuesInput{})
	_, _ = clients.S3().HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("zasp-local-test")})
	_, _ = clients.KMS().ListKeys(ctx, &kms.ListKeysInput{})
	_, _ = clients.SecretsManager().ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	_, _ = clients.OpenSearch().ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if requests := capture.snapshot(); len(requests) != 5 {
		t.Fatalf("request count = %d, want one per operation", len(requests))
	}
}

func newCIClients(t *testing.T, endpoint string) *Clients {
	t.Helper()
	calls := []string{}
	clients, err := New(Options{Mode: ModeCI, Region: mustRegion(t, "us-east-1"), Lookup: exactLookup(pair(endpoint), &calls)})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3"}) {
		clients.Close()
		t.Fatalf("lookup calls = %v", calls)
	}
	return clients
}

func invokeReads(t *testing.T, clients *Clients) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	operations := []func() error{
		func() error { _, err := clients.SQS().ListQueues(ctx, &sqs.ListQueuesInput{}); return err },
		func() error {
			_, err := clients.S3().HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("zasp-local-test")})
			return err
		},
		func() error { _, err := clients.KMS().ListKeys(ctx, &kms.ListKeysInput{}); return err },
		func() error {
			_, err := clients.SecretsManager().ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
			return err
		},
		func() error {
			_, err := clients.OpenSearch().ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
			return err
		},
	}
	for index, operation := range operations {
		if err := operation(); err != nil {
			t.Fatalf("operation %d: %v", index, err)
		}
	}
}
