package apiserver

import (
	"context"
	"net/http"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/producttelemetry"
)

// WorkflowTelemetry accepts best-effort events without waiting for network delivery.
type WorkflowTelemetry interface {
	TryTrack(domain.Scope, producttelemetry.Event)
}

// Keys are registered operation IDs. Neither a URL nor user-supplied data becomes an event label.
var workflowSources = map[string]string{
	"createWorkspace":        producttelemetry.WorkspaceCreated,
	"createEnvironment":      producttelemetry.EnvironmentCreated,
	"inviteMember":           producttelemetry.MemberInvited,
	"createSensorEnrollment": producttelemetry.SensorEnrollmentCreated,
	"createIntegration":      producttelemetry.IntegrationCreated,
	"syncIntegration":        producttelemetry.IntegrationSyncRequested,
	"createPolicy":           producttelemetry.PolicyCreated,
	"rolloutPolicy":          producttelemetry.PolicyRolledOut,
	"updateFinding":          producttelemetry.FindingUpdated,
	"getHomeSummary":         producttelemetry.HomeSummaryRead,
	"getFinding":             producttelemetry.FindingDetailRead,
	"listAuditEvents":        producttelemetry.AuditLogRead,
	"listComplianceCoverage": producttelemetry.ComplianceCoverageRead,
}

type workflowTelemetryKey struct{}
type workflowCapture struct {
	tracker WorkflowTelemetry
	scope   domain.Scope
	source  string
}

func withWorkflowTelemetry(op Operation, tracker WorkflowTelemetry) http.Handler {
	source, tracked := workflowSources[op.OperationID]
	if !tracked || tracker == nil {
		return op.Handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := IdentityFromRequest(r)
		// Composite reports and assistant tools can dispatch subsidiary requests with
		// the same browser identity. Only the outer browser operation represents usage.
		if ok && identity.CredentialKind == CredentialBrowserSession && r.Context().Value(productRouterContextKey{}) == nil &&
			!prefetchedWorkflow(r) && !(source == producttelemetry.AuditLogRead && r.URL.Query().Has("cursor")) {
			capture := &workflowCapture{tracker: tracker, scope: identity.Scope, source: source}
			r = r.WithContext(context.WithValue(r.Context(), workflowTelemetryKey{}, capture))
		}
		op.Handler.ServeHTTP(w, r)
	})
}

func prefetchedWorkflow(r *http.Request) bool {
	purpose, _, _ := strings.Cut(r.Header.Get("Sec-Purpose"), ";")
	return strings.EqualFold(strings.TrimSpace(purpose), "prefetch") || strings.EqualFold(r.Header.Get("Purpose"), "prefetch")
}

// An idempotent replay still returns its original success response to the caller.
func suppressReplayedWorkflow(ctx context.Context) {
	if capture, ok := ctx.Value(workflowTelemetryKey{}).(*workflowCapture); ok {
		capture.tracker = nil
	}
}

// Invoked only when a selected API response has been successfully written.
func recordWorkflowResponse(r *http.Request, status int) {
	if r == nil || status < http.StatusOK || status >= http.StatusMultipleChoices {
		return
	}
	capture, ok := r.Context().Value(workflowTelemetryKey{}).(*workflowCapture)
	if !ok || capture.tracker == nil {
		return
	}
	capture.tracker.TryTrack(capture.scope, producttelemetry.Event{
		Name: producttelemetry.WorkflowKind(capture.source),
		Fields: []producttelemetry.Field{
			producttelemetry.TextField("source", capture.source),
			producttelemetry.BooleanField("success", true),
		},
	})
	capture.tracker = nil
}
