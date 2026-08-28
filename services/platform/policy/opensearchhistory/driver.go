package opensearchhistory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	platformpolicy "github.com/zasp-ai/zasp-sec/services/platform/policy"
)

var ErrHistory = errors.New("policy history unavailable")

const historyIndex = "zasp-runtime-events-v1"

var (
	historyRegionPattern   = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]$`)
	historyHostPattern     = regexp.MustCompile(`^(?:search|vpc)-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	historyDocumentPattern = regexp.MustCompile(`^evt_[0-9a-f]{64}$`)
)

type SignerOptions = v4.SignerOptions

type Config struct {
	Endpoint             string
	Region               string
	RequestTimeout       time.Duration
	MaximumResponseBytes int64
	AllowTestLoopback    bool
}

type Signer interface {
	SignHTTP(context.Context, aws.Credentials, *http.Request, string, string, string, time.Time, ...func(*v4.SignerOptions)) error
}

type SchemaReadiness interface{ Ready(context.Context) error }
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Driver struct {
	config      Config
	endpoint    *url.URL
	credentials aws.CredentialsProvider
	signer      Signer
	client      HTTPDoer
	readiness   SchemaReadiness
	clock       func() time.Time
	transport   *http.Transport
}

func New(config Config, credentials aws.CredentialsProvider, signer Signer, readiness SchemaReadiness, clock func() time.Time) (*Driver, error) {
	endpoint, err := validConfig(config, credentials, signer, readiness, clock)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname()}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: config.RequestTimeout, MaxResponseHeaderBytes: 1 << 20}
	client := &http.Client{Transport: transport, Timeout: config.RequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Driver{config: config, endpoint: endpoint, credentials: credentials, signer: signer, client: client, readiness: readiness, clock: clock, transport: transport}, nil
}

func newWithClient(config Config, credentials aws.CredentialsProvider, signer Signer, client HTTPDoer, readiness SchemaReadiness, clock func() time.Time) (*Driver, error) {
	endpoint, err := validConfig(config, credentials, signer, readiness, clock)
	if err != nil || client == nil {
		return nil, ErrHistory
	}
	return &Driver{config: config, endpoint: endpoint, credentials: credentials, signer: signer, client: client, readiness: readiness, clock: clock}, nil
}

func validConfig(config Config, credentials aws.CredentialsProvider, signer Signer, readiness SchemaReadiness, clock func() time.Time) (*url.URL, error) {
	if credentials == nil || signer == nil || readiness == nil || clock == nil || !historyRegionPattern.MatchString(config.Region) || config.RequestTimeout < time.Second || config.RequestTimeout > 30*time.Second || config.RequestTimeout%time.Second != 0 || config.MaximumResponseBytes < 1 || config.MaximumResponseBytes > 8<<20 {
		return nil, ErrHistory
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.String() != config.Endpoint || endpoint.User != nil || endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return nil, ErrHistory
	}
	if config.AllowTestLoopback {
		ip := net.ParseIP(endpoint.Hostname())
		if endpoint.Scheme != "http" || endpoint.Port() == "" || ip == nil || !ip.IsLoopback() {
			return nil, ErrHistory
		}
		return endpoint, nil
	}
	if endpoint.Scheme != "https" || endpoint.Port() != "" {
		return nil, ErrHistory
	}
	host := strings.ToLower(endpoint.Hostname())
	suffix := "." + config.Region + ".es.amazonaws.com"
	if strings.HasSuffix(host, ".amazonaws.com.cn") {
		suffix += ".cn"
	}
	if !strings.HasSuffix(host, suffix) || !historyHostPattern.MatchString(strings.TrimSuffix(host, suffix)) {
		return nil, ErrHistory
	}
	return endpoint, nil
}

func (driver *Driver) Close() error {
	if driver != nil && driver.transport != nil {
		driver.transport.CloseIdleConnections()
	}
	return nil
}

func (driver *Driver) Ready(ctx context.Context) error {
	if driver == nil || ctx == nil || ctx.Err() != nil || driver.readiness.Ready(ctx) != nil {
		return ErrHistory
	}
	return nil
}

type historySearchResponse struct {
	TimedOut bool `json:"timed_out"`
	Hits     struct {
		Hits []struct {
			ID     string                `json:"_id"`
			Sort   []string              `json:"sort"`
			Source historyStoredDocument `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type historyStoredDocument struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	RecordType     string `json:"record_type"`
	EventID        string `json:"event_id"`
	EventClass     string `json:"event_class"`
	Action         string `json:"action"`
	AgentID        string `json:"agent_id"`
	SessionID      string `json:"session_id"`
	ToolID         string `json:"tool_id,omitempty"`
	WorkloadID     string `json:"workload_id,omitempty"`
	SourceEventID  string `json:"source_event_id"`
	EventTime      string `json:"event_time"`
}

func (driver *Driver) SearchPolicyActions(ctx context.Context, scope domain.Scope, trigger string, limit int) ([]platformpolicy.ActionContext, error) {
	if driver == nil || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !historyTrigger(trigger) || limit < 1 || limit > 100 {
		return nil, ErrHistory
	}
	body, err := historyQuery(scope, trigger, limit)
	if err != nil {
		return nil, ErrHistory
	}
	query := url.Values{"filter_path": {"hits.hits._id,hits.hits._source,hits.hits.sort,timed_out"}}
	response, err := driver.request(ctx, "/"+historyIndex+"/_search?"+query.Encode(), body)
	if err != nil {
		return nil, ErrHistory
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !validJSONMediaType(response.Header.Get("Content-Type")) {
		return nil, ErrHistory
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, driver.config.MaximumResponseBytes+1))
	if readErr != nil || int64(len(raw)) > driver.config.MaximumResponseBytes {
		return nil, ErrHistory
	}
	var decoded historySearchResponse
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || decoder.Decode(&struct{}{}) != io.EOF || decoded.TimedOut || len(decoded.Hits.Hits) > limit {
		return nil, ErrHistory
	}
	values := make([]platformpolicy.ActionContext, len(decoded.Hits.Hits))
	seen := make(map[string]struct{}, len(values))
	var previousTime time.Time
	previousID := ""
	for index, hit := range decoded.Hits.Hits {
		value, instant, ok := actionContext(scope, trigger, hit.ID, hit.Sort, hit.Source)
		if !ok || index > 0 && (instant.After(previousTime) || instant.Equal(previousTime) && hit.ID <= previousID) {
			return nil, ErrHistory
		}
		if _, exists := seen[hit.ID]; exists {
			return nil, ErrHistory
		}
		seen[hit.ID] = struct{}{}
		values[index], previousTime, previousID = value, instant, hit.ID
	}
	return values, nil
}

func validJSONMediaType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || mediaType != "application/json" || len(parameters) > 1 {
		return false
	}
	charset, present := parameters["charset"]
	return !present || strings.EqualFold(charset, "utf-8")
}

func historyQuery(scope domain.Scope, trigger string, limit int) ([]byte, error) {
	return json.Marshal(map[string]any{
		"_source": []string{"organization_id", "workspace_id", "environment_id", "record_type", "event_id", "event_class", "action", "agent_id", "session_id", "tool_id", "workload_id", "source_event_id", "event_time"},
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]string{"organization_id": scope.OrganizationID().String()}},
			map[string]any{"term": map[string]string{"workspace_id": scope.WorkspaceID().String()}},
			map[string]any{"term": map[string]string{"environment_id": scope.EnvironmentID().String()}},
			map[string]any{"term": map[string]string{"record_type": "runtime_event"}},
			map[string]any{"term": map[string]string{"event_class": trigger}},
			map[string]any{"exists": map[string]string{"field": "agent_id"}},
			map[string]any{"exists": map[string]string{"field": "session_id"}},
		}}},
		"size": limit, "sort": []any{map[string]any{"event_time": map[string]string{"order": "desc"}}, map[string]any{"document_id": map[string]string{"order": "asc"}}}, "track_total_hits": false,
	})
}

func (driver *Driver) request(ctx context.Context, path string, body []byte) (*http.Response, error) {
	relative, err := url.ParseRequestURI(path)
	if err != nil || relative.IsAbs() || relative.Host != "" || relative.Fragment != "" {
		return nil, ErrHistory
	}
	target := *driver.endpoint
	target.Path, target.RawQuery = relative.Path, relative.RawQuery
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrHistory
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	credentials, err := driver.credentials.Retrieve(ctx)
	now := driver.clock()
	if err != nil || !credentials.HasKeys() || credentials.Expired() || now.IsZero() || now.Location() != time.UTC {
		return nil, ErrHistory
	}
	digest := sha256.Sum256(body)
	if driver.signer.SignHTTP(ctx, credentials, request, hex.EncodeToString(digest[:]), "es", driver.config.Region, now) != nil || ctx.Err() != nil {
		return nil, ErrHistory
	}
	response, err := driver.client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return nil, ErrHistory
	}
	return response, nil
}

func actionContext(scope domain.Scope, trigger, documentID string, sortValues []string, source historyStoredDocument) (platformpolicy.ActionContext, time.Time, bool) {
	if !historyDocumentPattern.MatchString(documentID) || len(sortValues) != 2 || sortValues[1] != documentID || source.OrganizationID != scope.OrganizationID().String() || source.WorkspaceID != scope.WorkspaceID().String() || source.EnvironmentID != scope.EnvironmentID().String() || source.RecordType != "runtime_event" || source.EventClass != trigger || source.Action == "" || len(source.Action) > 64 {
		return platformpolicy.ActionContext{}, time.Time{}, false
	}
	if _, err := domain.ParseProductID(source.EventID); err != nil {
		return platformpolicy.ActionContext{}, time.Time{}, false
	}
	if _, err := domain.ParseProductID(source.AgentID); err != nil {
		return platformpolicy.ActionContext{}, time.Time{}, false
	}
	if _, err := domain.ParseProductID(source.SessionID); err != nil {
		return platformpolicy.ActionContext{}, time.Time{}, false
	}
	instant, err := time.Parse("2006-01-02T15:04:05.000Z", source.EventTime)
	if err != nil || sortValues[0] != source.EventTime {
		return platformpolicy.ActionContext{}, time.Time{}, false
	}
	resource := source.ToolID
	if resource == "" {
		resource = source.WorkloadID
	}
	if resource == "" {
		resource = source.SourceEventID
	}
	value := platformpolicy.ActionContext{PrincipalID: source.AgentID, AgentID: source.AgentID, SessionID: source.SessionID, Action: source.EventClass, Resource: resource, EnvironmentID: source.EnvironmentID, Metadata: map[string]string{"action": source.Action, "resource": resource, "principal_id": source.AgentID, "agent_id": source.AgentID, "session_id": source.SessionID, "environment_id": source.EnvironmentID}}
	if _, err := platformpolicy.NormalizeActionContext(value); err != nil {
		return platformpolicy.ActionContext{}, time.Time{}, false
	}
	return value, instant, true
}

func historyTrigger(value string) bool {
	return value == "tool" || value == "runtime" || value == "network" || value == "file" || value == "credential"
}

var _ interface {
	SearchPolicyActions(context.Context, domain.Scope, string, int) ([]platformpolicy.ActionContext, error)
	Ready(context.Context) error
} = (*Driver)(nil)
