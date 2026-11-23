package main

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/delegation"
)

// Tier: 1 | Purpose: enforce a pinned task grant before cached or live policy.
// Model: none.
// Authority: deployment-bound child identity and exact tool/resource or HTTP method/target.
// Fallback: a missing or invalid grant cannot use an open policy cache.
func (r *gatewayRuntime) delegated(q gatewayEvaluationRequest, now time.Time) *gatewayEvaluationResult {
	if r.delegation == nil && q.Delegation == "" {
		return nil
	}
	op := q.Attributes["tool.name"]
	if q.ActionKind == "http" {
		op = q.Attributes["http.method"]
	}
	d := r.delegation.Decide(q.Delegation, op, q.Attributes["resource"], now)
	if r.delegation != nil && q.Attributes["agent_id"] != r.delegation.Agent {
		d = delegation.Decision{Status: "denied"}
	}
	if !d.Allowed {
		return &gatewayEvaluationResult{Decision: "block", CacheState: d.Status, MatchedPolicyIDs: []string{"task.delegation"}}
	}
	return nil
}

// Check wire routing independently of caller-supplied classification labels.
func (r *gatewayRuntime) delegatedProxy(q *gatewayEvaluationRequest, req *http.Request, body []byte, target *url.URL) bool {
	values := req.Header.Values(delegation.Header)
	if r.delegation == nil && len(values) == 0 {
		return true
	}
	if len(values) > 1 || len(values) == 1 && (values[0] == "" || len(values[0]) > 16384) {
		return false
	}
	if len(values) == 1 {
		q.Delegation = values[0]
	}
	if q.ActionKind == "mcp" {
		return delegation.MCPOperation(body) == q.Attributes["tool.name"] && q.Attributes["action"] == q.Attributes["tool.name"]
	}
	resource := "https://" + target.Host + target.EscapedPath()
	return target.RawQuery == "" && !target.ForceQuery && !strings.Contains(target.EscapedPath(), "%") &&
		q.Attributes["resource"] == resource && q.Attributes["action"] == req.Method
}
