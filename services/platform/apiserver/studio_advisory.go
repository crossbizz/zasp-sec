package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

const studioAdvisorySQL = `SELECT zasp_authorization80.studio_advisory($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb)`

// Bound in-flight jobs in addition to the durable per-Environment reservation.
var studioAdvisorySlots = make(chan struct{}, 4)

func configuredStudioAdvisory() *analystChat {
	return configuredPrivateModel(aigateway.PurposeRemediate, "ZASP_BEDROCK_REMEDIATION_")
}

func init() {
	productStatementRules[studioAdvisorySQL] = productStatementRule{operations: []string{"getStudioRemediationAdvisory", "requestStudioRemediationAdvisory"}, arguments: 12, scope: 1, actor: 4, browserOnly: true, check: func(g RequestAuthorization, args []any) bool {
		s, ok := args[4].(string)
		return ok && authorizationNativeTargetAllowed(g, "session", s) && args[5] == g.PathParameters["id"] && args[8] == g.OperationID
	}}
}

type studioCandidate struct {
	Action   string `json:"action"`
	Target   string `json:"target_id"`
	Rollback string `json:"rollback"`
}
type advisoryRecord struct {
	State     string           `json:"state"`
	Session   string           `json:"session_id"`
	Approval  string           `json:"approval_id"`
	Message   string           `json:"message_id"`
	Candidate *studioCandidate `json:"candidate,omitempty"`
	// These fields are returned only by the operator-owned SQL function.
	// They are removed from every HTTP response.
	Lease string          `json:"lease_id,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type studioAdvisoryJob struct {
	db                                 JSONDatabase
	model                              *analystChat
	op                                 RoutedOperation
	thread, session, message, approval string
}

func (j studioAdvisoryJob) query(r *http.Request, phase, lease string, output json.RawMessage) (json.RawMessage, error) {
	ctx, err := refreshChatAuthorization(r, j.op)
	if err != nil {
		return nil, ErrRepositoryAuthorization
	}
	i, ok := IdentityFromRequest(r)
	if !ok {
		return nil, ErrRepositoryAuthorization
	}
	grant, err := secondaryRequestAuthorization(ctx, i, RoutedOperation{OperationID: "getSecurityAgentApproval", PathParameters: map[string]string{"id": j.approval}})
	if err != nil {
		return nil, secondaryAuthorizationError(err)
	}
	proof, err := authorizationProofJSON(grant)
	if err != nil {
		return nil, ErrRepositoryAuthorization
	}
	var binding json.RawMessage
	if j.model != nil && j.model.driver != nil {
		binding, _ = json.Marshal(j.model.binding)
	}
	req, _ := json.Marshal(map[string]any{"phase": phase, "lease_id": lease, "output": output})
	sc := i.Scope
	return j.db.QueryJSON(ctx, studioAdvisorySQL, sc.OrganizationID().String(), sc.WorkspaceID().String(), sc.EnvironmentID().String(), i.PrincipalID.String(), j.session, j.thread, j.message, j.approval, j.op.OperationID, string(proof), req, binding)
}
func (j studioAdvisoryJob) record(raw json.RawMessage) (advisoryRecord, bool) {
	var v advisoryRecord
	if decodeStrictDiscovery(raw, &v) != nil || v.Session != j.session || v.Message != j.message || v.Approval != j.approval || !stringIn(v.State, "available", "pending", "reviewed", "no_recommendation", "unavailable") || (v.Candidate != nil) != (v.State == "reviewed") {
		return v, false
	}
	return v, v.Candidate == nil || *v.Candidate == (studioCandidate{Action: "isolate_session", Target: j.session, Rollback: "ttl_release"})
}

func serveStudioAdvisory(db JSONDatabase, model *analystChat, w http.ResponseWriter, r *http.Request, op RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	if nilInterface(db) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	i, ok := IdentityFromRequest(r)
	post := op.OperationID == "requestStudioRemediationAdvisory"
	if !ok || i.CredentialKind != CredentialBrowserSession || post && !i.FreshAuthenticated {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	q, ok := exactWorkflowQuery(r.URL.RawQuery, map[string]int{"session_id": 40, "message_id": 40, "approval_id": 40})
	j := studioAdvisoryJob{db: db, model: model, op: op, thread: op.PathParameters["id"], session: q.Get("session_id"), message: q.Get("message_id"), approval: q.Get("approval_id")}
	var empty struct{}
	if !ok || !validProductID(j.thread) || !validProductID(j.session) || !validProductID(j.message) || !validProductID(j.approval) || post && (r.Method != "POST" || decodeProductionJSON(r, &empty) != nil) || !post && r.Method != "GET" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	phase, lease := "get", ""
	release := false
	if post {
		var err error
		lease, err = newWorkflowProductID()
		if err != nil {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		select {
		case studioAdvisorySlots <- struct{}{}:
			release = true
		default:
			writeProductionStatusError(w, r, http.StatusTooManyRequests, "advisory_busy", "Private reviews are busy. Try again shortly.", true)
			return
		}
		defer func() {
			if release {
				<-studioAdvisorySlots
			}
		}()
		phase = "reserve"
	}
	raw, err := j.query(r, phase, lease, nil)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	if chatError(w, r, raw, nil) {
		return
	}
	result, ok := j.record(raw)
	if !ok || result.Input != nil || (result.Lease != "" && (!post || result.Lease != lease || result.State != "pending" || model == nil)) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	if result.Lease != "" {
		detached := r.Clone(context.WithoutCancel(r.Context()))
		release = false
		go func() { defer func() { <-studioAdvisorySlots }(); j.run(detached, lease) }()
	}
	result.Lease = ""
	public, _ := json.Marshal(result)
	status := http.StatusOK
	if post && result.State == "pending" {
		status = http.StatusAccepted
	}
	writeProductionResponse(w, r, status, public, nil)
}

func (j studioAdvisoryJob) run(r *http.Request, lease string) {
	// The process never retries an uncertain dispatch. An expired lease reads
	// as unavailable, retaining the conservative reservation.
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	raw, err := j.query(r, "dispatch", lease, nil)
	record, ok := j.record(raw)
	if err != nil || !ok || record.State != "pending" || !aigateway.ValidateRemediationProposal(record.Input, json.RawMessage(`{"steps":[]}`)) {
		return
	}
	providerContext, stop := context.WithTimeout(ctx, 30*time.Second)
	output, err := j.model.driver.Evaluate(providerContext, aigateway.PurposeRemediate, record.Input)
	stop()
	if err != nil || !aigateway.ValidateRemediationProposal(record.Input, output) {
		_, _ = j.query(r, "fail", lease, nil)
		return
	}
	_, _ = j.query(r, "finish", lease, output)
}
