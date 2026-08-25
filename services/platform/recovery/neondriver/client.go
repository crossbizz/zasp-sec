package neondriver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	productionOrigin     = "https://console.neon.tech"
	maximumRequestBytes  = 8 << 10
	maximumResponseBytes = 1 << 20
)

var (
	ErrInvalid   = errors.New("invalid neon request")
	ErrDenied    = errors.New("neon authority denied")
	ErrRetryable = errors.New("neon operation retryable")
	ErrNotFound  = errors.New("neon resource not found")
	ErrConflict  = errors.New("neon operation conflict")
	ErrMalformed = errors.New("invalid neon response")

	projectPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	branchIDPattern   = regexp.MustCompile(`^br-[a-z0-9][a-z0-9-]{1,62}$`)
	branchNamePattern = regexp.MustCompile(`^zasp-recovery-[a-z0-9]{8,32}$`)
	endpointIDPattern = regexp.MustCompile(`^ep-[a-z0-9][a-z0-9-]{1,62}$`)
	lsnPattern        = regexp.MustCompile(`^[0-9A-F]{1,8}/[0-9A-F]{1,16}$`)
	hostPattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

type Client interface {
	CreateBranch(context.Context, CreateBranchRequest) (Branch, error)
	GetBranchByName(context.Context, string, string) (Branch, error)
	DeleteBranch(context.Context, string, string) error
	Ready(context.Context) error
}

type CreateBranchRequest struct {
	Name      string
	ParentLSN string
}

type Endpoint struct {
	ID       string
	BranchID string
	Type     string
	Host     string
}

type Branch struct {
	ID        string
	ProjectID string
	ParentID  string
	ParentLSN string
	Name      string
	Endpoints []Endpoint
}

type clientConfig struct {
	Origin         *url.URL
	APIKey         []byte
	ProjectID      string
	ParentBranchID string
	RootCAs        *x509.CertPool
	Timeout        time.Duration
}

type client struct {
	origin         *url.URL
	apiKey         []byte
	projectID      string
	parentBranchID string
	timeout        time.Duration
	httpClient     *http.Client
	transport      *http.Transport
	closeOnce      sync.Once
}

type createBranchWire struct {
	Branch    createBranchSpec     `json:"branch"`
	Endpoints []createEndpointSpec `json:"endpoints"`
}

type createBranchSpec struct {
	Name      string `json:"name"`
	ParentID  string `json:"parent_id"`
	ParentLSN string `json:"parent_lsn"`
}

type createEndpointSpec struct {
	Type string `json:"type"`
}

type branchWire struct {
	ID               string          `json:"id"`
	ProjectID        string          `json:"project_id"`
	ParentID         string          `json:"parent_id,omitempty"`
	ParentLSN        string          `json:"parent_lsn,omitempty"`
	Name             string          `json:"name"`
	CurrentState     json.RawMessage `json:"current_state,omitempty"`
	PendingState     json.RawMessage `json:"pending_state,omitempty"`
	LogicalSize      json.RawMessage `json:"logical_size,omitempty"`
	CreationSource   json.RawMessage `json:"creation_source,omitempty"`
	Primary          json.RawMessage `json:"primary,omitempty"`
	Default          json.RawMessage `json:"default,omitempty"`
	CreatedAt        json.RawMessage `json:"created_at,omitempty"`
	UpdatedAt        json.RawMessage `json:"updated_at,omitempty"`
	InitSource       json.RawMessage `json:"init_source,omitempty"`
	Protected        json.RawMessage `json:"protected,omitempty"`
	CPUUsedSec       json.RawMessage `json:"cpu_used_sec,omitempty"`
	ComputeTime      json.RawMessage `json:"compute_time_seconds,omitempty"`
	ActiveTime       json.RawMessage `json:"active_time_seconds,omitempty"`
	WrittenDataBytes json.RawMessage `json:"written_data_bytes,omitempty"`
	DataTransfer     json.RawMessage `json:"data_transfer_bytes,omitempty"`
}

type endpointWire struct {
	ID                    string          `json:"id"`
	ProjectID             string          `json:"project_id"`
	BranchID              string          `json:"branch_id"`
	Type                  string          `json:"type"`
	Host                  string          `json:"host"`
	AutoscalingMin        json.RawMessage `json:"autoscaling_limit_min_cu,omitempty"`
	AutoscalingMax        json.RawMessage `json:"autoscaling_limit_max_cu,omitempty"`
	RegionID              json.RawMessage `json:"region_id,omitempty"`
	CurrentState          json.RawMessage `json:"current_state,omitempty"`
	PendingState          json.RawMessage `json:"pending_state,omitempty"`
	Settings              json.RawMessage `json:"settings,omitempty"`
	PoolerEnabled         json.RawMessage `json:"pooler_enabled,omitempty"`
	PoolerMode            json.RawMessage `json:"pooler_mode,omitempty"`
	Disabled              json.RawMessage `json:"disabled,omitempty"`
	PasswordlessAccess    json.RawMessage `json:"passwordless_access,omitempty"`
	CreatedAt             json.RawMessage `json:"created_at,omitempty"`
	UpdatedAt             json.RawMessage `json:"updated_at,omitempty"`
	ProxyHost             json.RawMessage `json:"proxy_host,omitempty"`
	SuspendTimeoutSeconds json.RawMessage `json:"suspend_timeout_seconds,omitempty"`
	Provisioner           json.RawMessage `json:"provisioner,omitempty"`
}

type createResponseWire struct {
	Branch    branchWire     `json:"branch"`
	Endpoints []endpointWire `json:"endpoints"`
}

type listResponseWire struct {
	Branches  []branchWire   `json:"branches"`
	Endpoints []endpointWire `json:"endpoints"`
}

type getResponseWire struct {
	Branch branchWire `json:"branch"`
}

func NewProductionClient(apiKey []byte, projectID, parentBranchID string, timeout time.Duration) (Client, error) {
	origin, err := url.Parse(productionOrigin)
	if err != nil {
		return nil, ErrInvalid
	}
	return newClient(clientConfig{Origin: origin, APIKey: apiKey, ProjectID: projectID, ParentBranchID: parentBranchID, Timeout: timeout})
}

func newClient(config clientConfig) (*client, error) {
	if config.Origin == nil || config.Origin.Scheme != "https" || config.Origin.Host == "" || config.Origin.User != nil || config.Origin.Path != "" || config.Origin.RawQuery != "" || config.Origin.Fragment != "" ||
		len(config.APIKey) < 16 || len(config.APIKey) > 4096 || bytes.ContainsAny(config.APIKey, "\r\n\x00") || !projectPattern.MatchString(config.ProjectID) || !branchIDPattern.MatchString(config.ParentBranchID) || config.Timeout < time.Millisecond || config.Timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: config.Timeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: config.RootCAs, ServerName: config.Origin.Hostname()},
		TLSHandshakeTimeout:    config.Timeout,
		ResponseHeaderTimeout:  config.Timeout,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &client{
		origin: cloneURL(config.Origin), apiKey: append([]byte(nil), config.APIKey...), projectID: config.ProjectID, parentBranchID: config.ParentBranchID, timeout: config.Timeout,
		httpClient: &http.Client{Transport: transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }}, transport: transport,
	}, nil
}

func (value *client) CreateBranch(ctx context.Context, request CreateBranchRequest) (Branch, error) {
	if err := value.validContext(ctx); err != nil {
		return Branch{}, err
	}
	if !branchNamePattern.MatchString(request.Name) || !lsnPattern.MatchString(request.ParentLSN) {
		return Branch{}, ErrInvalid
	}
	body, err := json.Marshal(createBranchWire{Branch: createBranchSpec{Name: request.Name, ParentID: value.parentBranchID, ParentLSN: request.ParentLSN}, Endpoints: []createEndpointSpec{{Type: "read_write"}}})
	if err != nil || len(body) > maximumRequestBytes {
		return Branch{}, ErrInvalid
	}
	var response createResponseWire
	status, err := value.call(ctx, http.MethodPost, "/api/v2/projects/"+url.PathEscape(value.projectID)+"/branches", nil, body, &response)
	if err == nil && status == http.StatusCreated {
		return value.branch(response.Branch, response.Endpoints, request.Name, request.ParentLSN)
	}
	if ctx.Err() != nil {
		return Branch{}, ctx.Err()
	}
	if err != nil || status == http.StatusConflict {
		reconciled, reconcileErr := value.GetBranchByName(ctx, value.projectID, request.Name)
		if reconcileErr == nil && reconciled.ParentID == value.parentBranchID && reconciled.ParentLSN == request.ParentLSN {
			return reconciled, nil
		}
		if err != nil && !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrDenied) {
			return Branch{}, ErrRetryable
		}
		if status == http.StatusConflict {
			return Branch{}, ErrConflict
		}
		return Branch{}, err
	}
	return Branch{}, classifyStatus(status)
}

func (value *client) GetBranchByName(ctx context.Context, projectID, name string) (Branch, error) {
	if err := value.validContext(ctx); err != nil {
		return Branch{}, err
	}
	if projectID != value.projectID || !branchNamePattern.MatchString(name) {
		return Branch{}, ErrInvalid
	}
	query := url.Values{"limit": {"2"}, "search": {name}}
	var response listResponseWire
	status, err := value.call(ctx, http.MethodGet, "/api/v2/projects/"+url.PathEscape(projectID)+"/branches", query, nil, &response)
	if err != nil {
		return Branch{}, err
	}
	if status != http.StatusOK {
		return Branch{}, classifyStatus(status)
	}
	matched := make([]branchWire, 0, 1)
	for _, branch := range response.Branches {
		if branch.Name == name {
			matched = append(matched, branch)
		}
	}
	if len(matched) == 0 {
		return Branch{}, ErrNotFound
	}
	if len(matched) != 1 {
		return Branch{}, ErrConflict
	}
	endpoints := make([]endpointWire, 0, 1)
	for _, endpoint := range response.Endpoints {
		if endpoint.BranchID == matched[0].ID {
			endpoints = append(endpoints, endpoint)
		}
	}
	return value.branch(matched[0], endpoints, name, matched[0].ParentLSN)
}

func (value *client) DeleteBranch(ctx context.Context, projectID, branchID string) error {
	if err := value.validContext(ctx); err != nil {
		return err
	}
	if projectID != value.projectID || !branchIDPattern.MatchString(branchID) || branchID == value.parentBranchID {
		return ErrInvalid
	}
	status, err := value.call(ctx, http.MethodDelete, "/api/v2/projects/"+url.PathEscape(projectID)+"/branches/"+url.PathEscape(branchID), nil, nil, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNoContent || status == http.StatusNotFound {
		return nil
	}
	return classifyStatus(status)
}

func (value *client) Ready(ctx context.Context) error {
	if err := value.validContext(ctx); err != nil {
		return err
	}
	var response getResponseWire
	status, err := value.call(ctx, http.MethodGet, "/api/v2/projects/"+url.PathEscape(value.projectID)+"/branches/"+url.PathEscape(value.parentBranchID), nil, nil, &response)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return classifyStatus(status)
	}
	if response.Branch.ID != value.parentBranchID || response.Branch.ProjectID != value.projectID || response.Branch.Name == "" {
		return ErrMalformed
	}
	return nil
}

func (value *client) Close() error {
	if value == nil {
		return nil
	}
	value.closeOnce.Do(func() {
		clear(value.apiKey)
		if value.transport != nil {
			value.transport.CloseIdleConnections()
		}
	})
	return nil
}

func (value *client) call(ctx context.Context, method, path string, query url.Values, body []byte, output any) (int, error) {
	requestURL := cloneURL(value.origin)
	requestURL.Path = path
	requestURL.RawQuery = query.Encode()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), reader)
	if err != nil {
		return 0, ErrInvalid
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(value.apiKey))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := value.httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, ErrRetryable
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumResponseBytes+1))
		return response.StatusCode, nil
	}
	if output == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumResponseBytes+1))
		return response.StatusCode, nil
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return response.StatusCode, ErrMalformed
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumResponseBytes || decodeClosedJSON(encoded, output) != nil {
		return response.StatusCode, ErrMalformed
	}
	return response.StatusCode, nil
}

func (value *client) branch(wire branchWire, endpointWires []endpointWire, expectedName, expectedLSN string) (Branch, error) {
	if !branchIDPattern.MatchString(wire.ID) || wire.ProjectID != value.projectID || wire.ParentID != value.parentBranchID || wire.Name != expectedName || wire.ParentLSN != expectedLSN || len(endpointWires) != 1 {
		return Branch{}, ErrMalformed
	}
	endpoint := endpointWires[0]
	if !endpointIDPattern.MatchString(endpoint.ID) || endpoint.ProjectID != value.projectID || endpoint.BranchID != wire.ID || endpoint.Type != "read_write" || !hostPattern.MatchString(endpoint.Host) {
		return Branch{}, ErrMalformed
	}
	return Branch{ID: wire.ID, ProjectID: wire.ProjectID, ParentID: wire.ParentID, ParentLSN: wire.ParentLSN, Name: wire.Name, Endpoints: []Endpoint{{ID: endpoint.ID, BranchID: endpoint.BranchID, Type: endpoint.Type, Host: endpoint.Host}}}, nil
}

func (value *client) validContext(ctx context.Context) error {
	if value == nil || value.httpClient == nil || value.origin == nil || len(value.apiKey) == 0 || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func classifyStatus(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrDenied
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		return ErrConflict
	case http.StatusLocked, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return ErrRetryable
	default:
		return ErrMalformed
	}
}

func decodeClosedJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("trailing json")
	}
	return nil
}

func cloneURL(value *url.URL) *url.URL {
	clone := *value
	return &clone
}

func validOpaqueText(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

var _ Client = (*client)(nil)
