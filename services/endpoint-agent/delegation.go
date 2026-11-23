package main

import "github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/pretool"

// Tier: 1 | Purpose: narrow the supervised ticket adapter before normal hook policy.
// Model: none.
// Authority: broker configuration pins the agent and task; the adapter reads the actual destination.
// Fallback: missing tokens and tools without a known resource mapping are denied.
func (b *broker) checkDelegated(req request) *result {
	if b.delegation == nil && !req.RequireDelegation && req.Delegation == "" {
		return nil
	}
	now := b.now().UTC()
	if now.Before(b.store.state.Latest) {
		now = b.store.state.Latest
	}
	d := pretool.VerifyTicketDelegation(b.delegation, req.Delegation, req.Hook, now)
	if d.Allowed {
		return nil
	}
	if d.Status == "delegation_unverified" {
		return &result{Verdict: "deny", Reason: d.Status}
	}
	return &result{Verdict: "deny", Reason: "delegation_denied"}
}
