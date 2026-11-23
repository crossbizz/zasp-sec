package pretool

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/inventoryreport"
	"github.com/zasp-ai/zasp-sec/services/platform/delegation"
)

// Reject ambiguous case variants when decoding a harness event: the broker and
// the managed callback must agree about the tool and destination being checked.
func exactHookFields(raw []byte, fields ...string) (map[string]json.RawMessage, bool) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return nil, false
	}
	for _, field := range fields {
		if _, ok := obj[field]; !ok {
			return nil, false
		}
		for k := range obj {
			if k != field && strings.EqualFold(k, field) {
				return nil, false
			}
		}
	}
	return obj, true
}

// VerifyTicketDelegation binds the managed adapter to the actual supervised
// tool invocation. Other tools require an independently verified resource map.
func VerifyTicketDelegation(v *delegation.Verifier, token string, hook []byte, now time.Time) delegation.Decision {
	deny := delegation.Decision{Status: "denied"}
	if v == nil || !inventoryreport.UniqueJSON(hook) {
		return deny
	}
	e, ok := exactHookFields(hook, "hook_event_name", "session_id", "tool_use_id", "tool_name", "tool_input")
	var name, tool, destination, session, call string
	if !ok || json.Unmarshal(e["hook_event_name"], &name) != nil || name != "PreToolUse" ||
		json.Unmarshal(e["session_id"], &session) != nil || !delegation.ValidIdentifier(session) ||
		json.Unmarshal(e["tool_use_id"], &call) != nil || !delegation.ValidIdentifier(call) ||
		json.Unmarshal(e["tool_name"], &tool) != nil || tool != "mcp__pilot__update_ticket" {
		return deny
	}
	args, ok := exactHookFields(e["tool_input"], "destination")
	if !ok || json.Unmarshal(args["destination"], &destination) != nil || !delegation.ValidIdentifier(destination) {
		return deny
	}
	return v.Decide(token, tool, destination, now)
}
