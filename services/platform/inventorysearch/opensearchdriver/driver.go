package opensearchdriver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch"
)

const (
	indexName                  = "zasp-inventory-v1"
	maximumConfiguredRequest   = 8 << 20
	maximumConfiguredResponse  = 8 << 20
	maximumConfiguredTimeout   = 30 * time.Second
	maximumResponseHeaderBytes = 1 << 20
)

var (
	regionPattern = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]$`)
	hostPattern   = regexp.MustCompile(`^(?:search|vpc)-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type Config struct {
	Endpoint             string
	Region               string
	RequestTimeout       time.Duration
	MaximumRequestBytes  int
	MaximumResponseBytes int
}

type HTTPSigner interface {
	SignHTTP(context.Context, aws.Credentials, *http.Request, string, string, string, time.Time, ...func(*v4.SignerOptions)) error
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Driver struct {
	config      Config
	endpoint    *url.URL
	credentials aws.CredentialsProvider
	signer      HTTPSigner
	client      HTTPDoer
	clock       func() time.Time
	transport   *http.Transport
}

var _ inventorysearch.Driver = (*Driver)(nil)

func New(config Config, credentials aws.CredentialsProvider, signer HTTPSigner, clock func() time.Time) (*Driver, error) {
	endpoint, err := validateConfig(config, credentials, signer, clock)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname()},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  config.RequestTimeout,
		MaxResponseHeaderBytes: maximumResponseHeaderBytes,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   config.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Driver{config: config, endpoint: endpoint, credentials: credentials, signer: signer, client: client, clock: clock, transport: transport}, nil
}

func newWithClient(config Config, credentials aws.CredentialsProvider, signer HTTPSigner, client HTTPDoer, clock func() time.Time) (*Driver, error) {
	endpoint, err := validateConfig(config, credentials, signer, clock)
	if err != nil || nilInterface(client) {
		return nil, inventorysearch.ErrConfiguration
	}
	return &Driver{config: config, endpoint: endpoint, credentials: credentials, signer: signer, client: client, clock: clock}, nil
}

func validateConfig(config Config, credentials aws.CredentialsProvider, signer HTTPSigner, clock func() time.Time) (*url.URL, error) {
	if nilInterface(credentials) || nilInterface(signer) || clock == nil || !regionPattern.MatchString(config.Region) || config.RequestTimeout < time.Second || config.RequestTimeout > maximumConfiguredTimeout || config.RequestTimeout%time.Second != 0 || config.MaximumRequestBytes < 1 || config.MaximumRequestBytes > maximumConfiguredRequest || config.MaximumResponseBytes < 1 || config.MaximumResponseBytes > maximumConfiguredResponse {
		return nil, inventorysearch.ErrConfiguration
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.String() != config.Endpoint || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Port() != "" || endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return nil, inventorysearch.ErrConfiguration
	}
	hostname := strings.ToLower(endpoint.Hostname())
	suffix := "." + config.Region + ".es.amazonaws.com"
	if strings.HasSuffix(hostname, ".amazonaws.com.cn") {
		suffix += ".cn"
	}
	if !strings.HasSuffix(hostname, suffix) || !hostPattern.MatchString(strings.TrimSuffix(hostname, suffix)) {
		return nil, inventorysearch.ErrConfiguration
	}
	return endpoint, nil
}

func (driver *Driver) Close() {
	if driver != nil && driver.transport != nil {
		driver.transport.CloseIdleConnections()
	}
}

// Ready performs a signed, read-only check against the exact inventory index.
func (driver *Driver) Ready(ctx context.Context) error {
	result, err := driver.request(ctx, http.MethodHead, "/"+indexName, "", nil, false)
	if err != nil {
		return err
	}
	if result.status != http.StatusOK || len(result.body) != 0 {
		return inventorysearch.ErrUnavailable
	}
	return nil
}

type response struct {
	status int
	body   []byte
}

func (driver *Driver) request(ctx context.Context, method, path, contentType string, body []byte, mutation bool) (response, error) {
	if !driver.usable() || ctx == nil || ctx.Err() != nil || len(body) > driver.config.MaximumRequestBytes || !strings.HasPrefix(path, "/") {
		if ctx != nil && ctx.Err() != nil {
			return response{}, inventorysearch.ErrCanceled
		}
		return response{}, inventorysearch.ErrRejected
	}
	relative, parseErr := url.ParseRequestURI(path)
	if parseErr != nil || relative.IsAbs() || relative.Host != "" || relative.Fragment != "" || !strings.HasPrefix(relative.Path, "/") {
		return response{}, inventorysearch.ErrRejected
	}
	requestURL := *driver.endpoint
	requestURL.Path = relative.Path
	requestURL.RawQuery = relative.RawQuery
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return response{}, inventorysearch.ErrRejected
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	request.Header.Set("Accept", "application/json")
	now, clockErr := readClock(driver.clock)
	if clockErr != nil || now.IsZero() || now.Location() != time.UTC {
		return response{}, inventorysearch.ErrDenied
	}
	credentials, err := retrieveCredentials(driver.credentials, ctx)
	if err != nil || !credentials.HasKeys() || credentials.Expired() {
		if ctx.Err() != nil {
			return response{}, inventorysearch.ErrCanceled
		}
		return response{}, inventorysearch.ErrDenied
	}
	payloadDigest := sha256.Sum256(body)
	if err := signRequest(driver.signer, ctx, credentials, request, hex.EncodeToString(payloadDigest[:]), driver.config.Region, now); err != nil || ctx.Err() != nil {
		if ctx.Err() != nil {
			return response{}, inventorysearch.ErrCanceled
		}
		return response{}, inventorysearch.ErrDenied
	}
	returned, err := doRequest(driver.client, request)
	if err != nil || returned == nil {
		if mutation {
			return response{}, inventorysearch.ErrUnknownOutcome
		}
		if ctx.Err() != nil {
			return response{}, inventorysearch.ErrCanceled
		}
		return response{}, inventorysearch.ErrRetryable
	}
	defer returned.Body.Close()
	limited := io.LimitReader(returned.Body, int64(driver.config.MaximumResponseBytes)+1)
	raw, readErr := io.ReadAll(limited)
	if readErr != nil || len(raw) > driver.config.MaximumResponseBytes {
		if mutation {
			return response{}, inventorysearch.ErrUnknownOutcome
		}
		if ctx.Err() != nil {
			return response{}, inventorysearch.ErrCanceled
		}
		return response{}, inventorysearch.ErrRetryable
	}
	return response{status: returned.StatusCode, body: raw}, nil
}

func readClock(clock func() time.Time) (now time.Time, resultErr error) {
	defer func() {
		if recover() != nil {
			now = time.Time{}
			resultErr = inventorysearch.ErrDenied
		}
	}()
	return clock(), nil
}

func retrieveCredentials(provider aws.CredentialsProvider, ctx context.Context) (credentials aws.Credentials, resultErr error) {
	defer func() {
		if recover() != nil {
			credentials = aws.Credentials{}
			resultErr = inventorysearch.ErrDenied
		}
	}()
	return provider.Retrieve(ctx)
}

func signRequest(signer HTTPSigner, ctx context.Context, credentials aws.Credentials, request *http.Request, digest, region string, now time.Time) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = inventorysearch.ErrDenied
		}
	}()
	return signer.SignHTTP(ctx, credentials, request, digest, "es", region, now)
}

func doRequest(client HTTPDoer, request *http.Request) (returned *http.Response, resultErr error) {
	defer func() {
		if recover() != nil {
			returned = nil
			resultErr = inventorysearch.ErrUnavailable
		}
	}()
	return client.Do(request)
}

func decodeExact(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return inventorysearch.ErrUnavailable
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return inventorysearch.ErrUnavailable
	}
	return nil
}

func (driver *Driver) usable() bool {
	return driver != nil && driver.endpoint != nil && !nilInterface(driver.credentials) && !nilInterface(driver.signer) && !nilInterface(driver.client) && driver.clock != nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
