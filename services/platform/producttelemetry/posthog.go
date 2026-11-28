package producttelemetry

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/config"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	WorkflowAction EventName = "workflow_action"
	WorkflowUsage  EventName = "workflow_usage"

	WorkspaceCreated         = "workspace_created"
	EnvironmentCreated       = "environment_created"
	SensorEnrollmentCreated  = "sensor_enrollment_created"
	IntegrationCreated       = "integration_created"
	PolicyCreated            = "policy_created"
	PolicyRolledOut          = "policy_rolled_out"
	FindingUpdated           = "finding_updated"
	MemberInvited            = "member_invited"
	IntegrationSyncRequested = "integration_sync_requested"

	HomeSummaryRead        = "home_summary_read"
	FindingDetailRead      = "finding_detail_read"
	AuditLogRead           = "audit_log_read"
	ComplianceCoverageRead = "compliance_coverage_read"

	postHogMaxInFlight = 8
	postHogTimeout     = 2 * time.Second
)

var projectTokenPattern = regexp.MustCompile(`^phc_[A-Za-z0-9_-]{1,192}$`)

// WorkflowKind returns the event family for a registered workflow source.
func WorkflowKind(source string) EventName {
	switch source {
	case WorkspaceCreated, EnvironmentCreated, SensorEnrollmentCreated, IntegrationCreated,
		PolicyCreated, PolicyRolledOut, FindingUpdated, MemberInvited, IntegrationSyncRequested:
		return WorkflowAction
	case HomeSummaryRead, FindingDetailRead, AuditLogRead, ComplianceCoverageRead:
		return WorkflowUsage
	default:
		return ""
	}
}

type captureProperties struct {
	DistinctID           string `json:"distinct_id"`
	Source               string `json:"source"`
	Success              bool   `json:"success"`
	ProcessPersonProfile bool   `json:"$process_person_profile"`
	GeoIPDisable         bool   `json:"$geoip_disable"`
}

type postHogCapture struct {
	ProjectKey string            `json:"api_key"`
	Event      EventName         `json:"event"`
	Properties captureProperties `json:"properties"`
}

type PostHog struct {
	captureURL string
	projectKey string
	client     *http.Client
	mu         sync.Mutex
	inFlight   int
	closed     bool
	sends      sync.WaitGroup
}

// ValidatePostHogConfig checks a cloud or self-hosted HTTPS ingestion origin
// and a PostHog project token. Validation never contacts the provider.
func ValidatePostHogConfig(endpoint, projectKey string) error {
	_, err := config.ParseDependencyEndpoint(endpoint)
	host, isHTTPS := strings.CutPrefix(strings.TrimSuffix(endpoint, "/"), "https://")
	if err != nil || !isHTTPS || strings.ContainsAny(host, "/?#") || strings.HasSuffix(host, ":") ||
		!projectTokenPattern.MatchString(projectKey) {
		return ErrConfiguration
	}
	return nil
}

func NewPostHog(endpoint, projectKey string) (*PostHog, error) {
	if err := ValidatePostHogConfig(endpoint, projectKey); err != nil {
		return nil, err
	}
	return &PostHog{
		captureURL: strings.TrimSuffix(endpoint, "/") + "/i/v0/e/",
		projectKey: projectKey,
		client: &http.Client{
			Timeout: postHogTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// TryTrack drops invalid events and events beyond the in-flight limit. A request
// can complete independently of the analytics provider.
func (p *PostHog) TryTrack(scope domain.Scope, event Event) {
	if p == nil || p.client == nil || scope.Validate() != nil {
		return
	}
	source, success, err := sourceAndSuccess(event.Fields)
	kind := WorkflowKind(source)
	if err != nil || kind == "" || event.Name != kind {
		return
	}

	p.mu.Lock()
	if p.closed || p.inFlight >= postHogMaxInFlight {
		p.mu.Unlock()
		return
	}
	p.inFlight++
	p.sends.Add(1)
	p.mu.Unlock()

	// Pass validated values across the async boundary, never the caller's fields.
	go p.send(scope.OrganizationID().String(), kind, source, success)
}

func (p *PostHog) send(organization string, kind EventName, source string, success bool) {
	defer func() {
		p.mu.Lock()
		p.inFlight--
		p.mu.Unlock()
		p.sends.Done()
	}()
	mac := hmac.New(sha256.New, []byte(p.projectKey))
	mac.Write([]byte(organization))
	capture := postHogCapture{
		ProjectKey: p.projectKey,
		Event:      kind,
		Properties: captureProperties{
			DistinctID:   hex.EncodeToString(mac.Sum(nil)),
			Source:       source,
			Success:      success,
			GeoIPDisable: true,
		},
	}
	body, err := json.Marshal(capture)
	if err != nil {
		return
	}
	request, err := http.NewRequest(http.MethodPost, p.captureURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	// A small successful response can reuse its connection. Never store
	// provider response data or retry a failed capture.
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
}

// Close drops future events and lets outstanding requests finish within their
// HTTP deadline. Repeated and concurrent calls are safe.
func (p *PostHog) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.sends.Wait()
	return nil
}
