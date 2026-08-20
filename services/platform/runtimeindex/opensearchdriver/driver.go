package opensearchdriver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

const (
	indexName                  = "zasp-runtime-events-v1"
	maximumRequestBytes        = 8 << 20
	maximumResponseBytes       = 8 << 20
	maximumTimeout             = 30 * time.Second
	maximumResponseHeaderBytes = 1 << 20
)

var (
	regionPattern     = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]$`)
	hostPattern       = regexp.MustCompile(`^(?:search|vpc)-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	documentIDPattern = regexp.MustCompile(`^evt_[0-9a-f]{64}$`)
	versionPattern    = regexp.MustCompile(`^[!-~]+$`)
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

var _ runtimeindex.Driver = (*Driver)(nil)

func New(config Config, credentials aws.CredentialsProvider, signer HTTPSigner, clock func() time.Time) (*Driver, error) {
	endpoint, err := validateConfig(config, credentials, signer, clock)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname()}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: config.RequestTimeout, MaxResponseHeaderBytes: maximumResponseHeaderBytes}
	client := &http.Client{Transport: transport, Timeout: config.RequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Driver{config: config, endpoint: endpoint, credentials: credentials, signer: signer, client: client, clock: clock, transport: transport}, nil
}

func newWithClient(config Config, credentials aws.CredentialsProvider, signer HTTPSigner, client HTTPDoer, clock func() time.Time) (*Driver, error) {
	endpoint, err := validateConfig(config, credentials, signer, clock)
	if err != nil || nilInterface(client) {
		return nil, runtimeindex.ErrConfiguration
	}
	return &Driver{config: config, endpoint: endpoint, credentials: credentials, signer: signer, client: client, clock: clock}, nil
}

func validateConfig(config Config, credentials aws.CredentialsProvider, signer HTTPSigner, clock func() time.Time) (*url.URL, error) {
	if nilInterface(credentials) || nilInterface(signer) || clock == nil || !regionPattern.MatchString(config.Region) || config.RequestTimeout < time.Second || config.RequestTimeout > maximumTimeout || config.RequestTimeout%time.Second != 0 || config.MaximumRequestBytes < 1 || config.MaximumRequestBytes > maximumRequestBytes || config.MaximumResponseBytes < 1 || config.MaximumResponseBytes > maximumResponseBytes {
		return nil, runtimeindex.ErrConfiguration
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.String() != config.Endpoint || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Port() != "" || endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return nil, runtimeindex.ErrConfiguration
	}
	hostname := strings.ToLower(endpoint.Hostname())
	suffix := "." + config.Region + ".es.amazonaws.com"
	if strings.HasSuffix(hostname, ".amazonaws.com.cn") {
		suffix += ".cn"
	}
	if !strings.HasSuffix(hostname, suffix) || !hostPattern.MatchString(strings.TrimSuffix(hostname, suffix)) {
		return nil, runtimeindex.ErrConfiguration
	}
	return endpoint, nil
}

func (driver *Driver) Close() {
	if driver != nil && driver.transport != nil {
		driver.transport.CloseIdleConnections()
	}
}

type response struct {
	status int
	body   []byte
}

func (driver *Driver) request(ctx context.Context, method, path, contentType string, body []byte, mutation bool) (response, error) {
	if driver == nil || ctx == nil || ctx.Err() != nil || len(body) > driver.config.MaximumRequestBytes || !strings.HasPrefix(path, "/") {
		if ctx != nil && ctx.Err() != nil {
			return response{}, runtimeindex.ErrCanceled
		}
		return response{}, runtimeindex.ErrRejected
	}
	relative, err := url.ParseRequestURI(path)
	if err != nil || relative.IsAbs() || relative.Host != "" || relative.Fragment != "" {
		return response{}, runtimeindex.ErrRejected
	}
	requestURL := *driver.endpoint
	requestURL.Path, requestURL.RawQuery = relative.Path, relative.RawQuery
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return response{}, runtimeindex.ErrRejected
	}
	request.Header.Set("Accept", "application/json")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	now := driver.clock()
	if now.IsZero() || now.Location() != time.UTC {
		return response{}, runtimeindex.ErrDenied
	}
	credentials, err := driver.credentials.Retrieve(ctx)
	if err != nil || !credentials.HasKeys() || credentials.Expired() {
		if ctx.Err() != nil {
			return response{}, runtimeindex.ErrCanceled
		}
		return response{}, runtimeindex.ErrDenied
	}
	digest := sha256.Sum256(body)
	if err := driver.signer.SignHTTP(ctx, credentials, request, hex.EncodeToString(digest[:]), "es", driver.config.Region, now); err != nil || ctx.Err() != nil {
		if ctx.Err() != nil {
			return response{}, runtimeindex.ErrCanceled
		}
		return response{}, runtimeindex.ErrDenied
	}
	returned, err := driver.client.Do(request)
	if err != nil || returned == nil {
		if mutation {
			return response{}, runtimeindex.ErrUnknownOutcome
		}
		if ctx.Err() != nil {
			return response{}, runtimeindex.ErrCanceled
		}
		return response{}, runtimeindex.ErrRetryable
	}
	defer returned.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(returned.Body, int64(driver.config.MaximumResponseBytes)+1))
	if readErr != nil || len(raw) > driver.config.MaximumResponseBytes {
		if mutation {
			return response{}, runtimeindex.ErrUnknownOutcome
		}
		return response{}, runtimeindex.ErrRetryable
	}
	return response{status: returned.StatusCode, body: raw}, nil
}

type storedDocument struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	BatchID        string `json:"batch_id"`
	Generation     int64  `json:"generation"`
	InputDigest    string `json:"input_digest"`
	ContentDigest  string `json:"content_digest"`
	runtimeindex.DriverDocument
}

type bulkAction struct {
	Create struct {
		Index string `json:"_index"`
		ID    string `json:"_id"`
	} `json:"create"`
}

type responseShards struct {
	Total      int `json:"total"`
	Successful int `json:"successful"`
	Failed     int `json:"failed"`
}

type bulkError struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

type bulkItemResult struct {
	Index         string         `json:"_index"`
	ID            string         `json:"_id"`
	Version       int            `json:"_version,omitempty"`
	Result        string         `json:"result,omitempty"`
	Status        int            `json:"status"`
	Sequence      int64          `json:"_seq_no,omitempty"`
	PrimaryTerm   int64          `json:"_primary_term,omitempty"`
	Shards        responseShards `json:"_shards,omitempty"`
	ForcedRefresh *bool          `json:"forced_refresh,omitempty"`
	Error         *bulkError     `json:"error,omitempty"`
}

type bulkResponse struct {
	Errors bool `json:"errors"`
	Took   int  `json:"took"`
	Items  []struct {
		Create bulkItemResult `json:"create"`
	} `json:"items"`
}

type multiGetResponse struct {
	Documents []struct {
		Index       string         `json:"_index"`
		ID          string         `json:"_id"`
		Version     int            `json:"_version,omitempty"`
		Sequence    int64          `json:"_seq_no,omitempty"`
		PrimaryTerm int64          `json:"_primary_term,omitempty"`
		Found       bool           `json:"found"`
		Source      storedDocument `json:"_source,omitempty"`
	} `json:"docs"`
}

func (driver *Driver) Apply(ctx context.Context, input runtimeindex.DriverBatch) (runtimeindex.DriverResult, error) {
	if ctx == nil || ctx.Err() != nil || !validInput(input) {
		if ctx != nil && ctx.Err() != nil {
			return runtimeindex.DriverResult{}, runtimeindex.ErrCanceled
		}
		return runtimeindex.DriverResult{}, runtimeindex.ErrRejected
	}
	body, expected, ok := bulkBody(input, driver.config.MaximumRequestBytes)
	if !ok {
		return runtimeindex.DriverResult{}, runtimeindex.ErrRejected
	}
	query := url.Values{"refresh": {"wait_for"}, "timeout": {fmt.Sprintf("%ds", int(driver.config.RequestTimeout/time.Second))}}
	result, err := driver.request(ctx, http.MethodPost, "/"+indexName+"/_bulk?"+query.Encode(), "application/x-ndjson", body, true)
	if err != nil {
		if errors.Is(err, runtimeindex.ErrUnknownOutcome) {
			return driver.reconcile(ctx, input, expected)
		}
		return runtimeindex.DriverResult{}, err
	}
	if classified := classifyStatus(result.status, true); classified != nil {
		return runtimeindex.DriverResult{}, classified
	}
	var decoded bulkResponse
	if decodeExact(result.body, &decoded) != nil || decoded.Took < 0 || len(decoded.Items) != len(input.Documents) {
		return driver.reconcile(ctx, input, expected)
	}
	reconcile := decoded.Errors
	for index, item := range decoded.Items {
		value := item.Create
		if value.Index != indexName || value.ID != input.Documents[index].DocumentID {
			reconcile = true
			continue
		}
		switch value.Status {
		case http.StatusCreated:
			if value.Error != nil || value.Version != 1 || value.Result != "created" || value.Sequence < 0 || value.PrimaryTerm < 1 || value.Shards.Total < 1 || value.Shards.Successful != value.Shards.Total || value.Shards.Failed != 0 {
				reconcile = true
			}
		case http.StatusConflict:
			reconcile = true
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return runtimeindex.DriverResult{}, runtimeindex.ErrRetryable
		case http.StatusUnauthorized, http.StatusForbidden:
			return runtimeindex.DriverResult{}, runtimeindex.ErrDenied
		case http.StatusBadRequest, http.StatusNotFound:
			return runtimeindex.DriverResult{}, runtimeindex.ErrRejected
		default:
			reconcile = true
		}
	}
	if reconcile {
		return driver.reconcile(ctx, input, expected)
	}
	return driverResult(input, false), nil
}

func (driver *Driver) reconcile(ctx context.Context, input runtimeindex.DriverBatch, expected []storedDocument) (runtimeindex.DriverResult, error) {
	if ctx.Err() != nil {
		return runtimeindex.DriverResult{}, runtimeindex.ErrUnknownOutcome
	}
	ids := make([]string, len(input.Documents))
	for index, document := range input.Documents {
		ids[index] = document.DocumentID
	}
	body, _ := json.Marshal(struct {
		IDs []string `json:"ids"`
	}{IDs: ids})
	result, err := driver.request(ctx, http.MethodPost, "/"+indexName+"/_mget", "application/json", body, false)
	if err != nil || result.status != http.StatusOK {
		return runtimeindex.DriverResult{}, runtimeindex.ErrUnknownOutcome
	}
	var decoded multiGetResponse
	if decodeExact(result.body, &decoded) != nil || len(decoded.Documents) != len(expected) {
		return runtimeindex.DriverResult{}, runtimeindex.ErrUnknownOutcome
	}
	for index, document := range decoded.Documents {
		if document.Index != indexName || document.ID != ids[index] || !document.Found {
			return runtimeindex.DriverResult{}, runtimeindex.ErrUnknownOutcome
		}
		if document.Version < 1 || document.Sequence < 0 || document.PrimaryTerm < 1 || !reflect.DeepEqual(document.Source, expected[index]) {
			return runtimeindex.DriverResult{}, runtimeindex.ErrDrift
		}
	}
	return driverResult(input, true), nil
}

func validInput(input runtimeindex.DriverBatch) bool {
	if input.Scope.Validate() != nil || input.BatchID == "" || input.Generation < 1 || input.InputDigest == ([sha256.Size]byte{}) || input.ContentDigest == ([sha256.Size]byte{}) || len(input.Documents) < 1 || len(input.Documents) > 1000 || !strings.HasPrefix(input.ArchiveReference, "s3://") || !validVersion(input.ArchiveVersionID) {
		return false
	}
	if _, err := domain.ParseProductID(input.BatchID); err != nil {
		return false
	}
	previous := ""
	for _, document := range input.Documents {
		if !validDocument(document, input) || document.EventID <= previous {
			return false
		}
		previous = document.EventID
	}
	return true
}

func validDocument(document runtimeindex.DriverDocument, input runtimeindex.DriverBatch) bool {
	if document.RecordType != "runtime_event" || !documentIDPattern.MatchString(document.DocumentID) || document.ArchiveReference != input.ArchiveReference || document.ArchiveVersionID != input.ArchiveVersionID || document.Source != "tetragon" && document.Source != "otlp" || document.EventClass == "" || document.Action == "" || document.EventTime == "" || document.TraceID == "" || document.SpanID == "" {
		return false
	}
	_, eventErr := domain.ParseProductID(document.EventID)
	_, evidenceErr := domain.ParseProductID(document.EvidenceID)
	return eventErr == nil && evidenceErr == nil
}

func validVersion(value string) bool {
	return len(value) >= 1 && len(value) <= 1024 && versionPattern.MatchString(value)
}

func bulkBody(input runtimeindex.DriverBatch, maximum int) ([]byte, []storedDocument, bool) {
	var body bytes.Buffer
	expected := make([]storedDocument, len(input.Documents))
	for index, document := range input.Documents {
		action := bulkAction{}
		action.Create.Index, action.Create.ID = indexName, document.DocumentID
		source := expectedStoredDocument(input, document)
		actionJSON, actionErr := json.Marshal(action)
		sourceJSON, sourceErr := json.Marshal(source)
		if actionErr != nil || sourceErr != nil || body.Len()+len(actionJSON)+len(sourceJSON)+2 > maximum {
			return nil, nil, false
		}
		body.Write(actionJSON)
		body.WriteByte('\n')
		body.Write(sourceJSON)
		body.WriteByte('\n')
		expected[index] = source
	}
	return body.Bytes(), expected, true
}

func expectedStoredDocument(input runtimeindex.DriverBatch, document runtimeindex.DriverDocument) storedDocument {
	return storedDocument{OrganizationID: input.Scope.OrganizationID().String(), WorkspaceID: input.Scope.WorkspaceID().String(), EnvironmentID: input.Scope.EnvironmentID().String(), BatchID: input.BatchID, Generation: input.Generation, InputDigest: hex.EncodeToString(input.InputDigest[:]), ContentDigest: hex.EncodeToString(input.ContentDigest[:]), DriverDocument: document}
}

func driverResult(input runtimeindex.DriverBatch, replayed bool) runtimeindex.DriverResult {
	ids := make([]string, len(input.Documents))
	for index, document := range input.Documents {
		ids[index] = document.DocumentID
	}
	return runtimeindex.DriverResult{BatchID: input.BatchID, Generation: input.Generation, InputDigest: input.InputDigest, ContentDigest: input.ContentDigest, DocumentIDs: ids, Replayed: replayed}
}

func decodeExact(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return runtimeindex.ErrRejected
	}
	return nil
}

func classifyStatus(status int, mutation bool) error {
	switch status {
	case http.StatusOK, http.StatusCreated:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return runtimeindex.ErrDenied
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return runtimeindex.ErrRetryable
	case http.StatusBadRequest, http.StatusNotFound, http.StatusRequestEntityTooLarge:
		return runtimeindex.ErrRejected
	default:
		if mutation {
			return runtimeindex.ErrUnknownOutcome
		}
		return runtimeindex.ErrRetryable
	}
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
