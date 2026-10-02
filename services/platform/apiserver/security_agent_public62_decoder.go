package apiserver

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"unicode/utf8"
)

// Validate against the DTO's exact JSON schema before decoding. Unlike the
// standard decoder this rejects missing fields, duplicate keys, case aliases,
// and null non-pointer values at every nesting level.
func public62Decode(raw json.RawMessage, destination any) error {
	if len(raw) > 65536 || !utf8.Valid(raw) || !public62Shape(raw, reflect.TypeOf(destination).Elem(), 0) || json.Unmarshal(raw, destination) != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}
func public62Shape(raw json.RawMessage, t reflect.Type, depth int) bool {
	if depth > 8 {
		return false
	}
	if t.Kind() == reflect.Pointer {
		return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || public62Shape(raw, t.Elem(), depth+1)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	switch t.Kind() {
	case reflect.Struct:
		d := json.NewDecoder(bytes.NewReader(raw))
		token, err := d.Token()
		if err != nil || token != json.Delim('{') {
			return false
		}
		seen := map[string]bool{}
		for d.More() {
			token, err = d.Token()
			key, ok := token.(string)
			if err != nil || !ok || seen[key] {
				return false
			}
			seen[key] = true
			var field reflect.Type
			for i := 0; i < t.NumField(); i++ {
				if t.Field(i).Tag.Get("json") == key {
					field = t.Field(i).Type
					break
				}
			}
			var value json.RawMessage
			if field == nil || d.Decode(&value) != nil || !public62Shape(value, field, depth+1) {
				return false
			}
		}
		token, err = d.Token()
		if err != nil || token != json.Delim('}') || len(seen) != t.NumField() {
			return false
		}
		_, err = d.Token()
		return err == io.EOF
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || len(values) > 10 {
			return false
		}
		for _, value := range values {
			if !public62Shape(value, t.Elem(), depth+1) {
				return false
			}
		}
		return true
	case reflect.String:
		var value string
		return json.Unmarshal(raw, &value) == nil && len(value) <= 128
	default:
		return json.Unmarshal(raw, reflect.New(t).Interface()) == nil
	}
}

var public62Digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func public62OneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
func public62Terminal(state string) bool {
	return public62OneOf(state, "contained", "remediated", "needs_human", "failed", "inconclusive", "cancelled")
}
func public62ValidRun(v SecurityAgentPublicRun, id RequestIdentity) bool {
	if v.ContractVersion != 62 || v.OrganizationID != id.Scope.OrganizationID().String() || v.WorkspaceID != id.Scope.WorkspaceID().String() || v.EnvironmentID != id.Scope.EnvironmentID().String() || !public62ID(v.RunID) || !public62ID(v.DefinitionID) || !public62Version(v.DefinitionVersion) || !public62Version(v.Version) {
		return false
	}
	terminal := public62Terminal(v.State)
	if terminal && v.Verification != v.State || !terminal && v.Verification != "pending" {
		return false
	}
	if !v.Admitted {
		return len(v.Steps) == 0 && public62OneOf(v.State, "queued", "planning", "needs_human", "cancelled", "failed", "inconclusive") && (v.State != "queued" || v.Version == 1) && (v.State != "planning" || v.Version >= 2)
	}
	if len(v.Steps) != 2 || v.Version < 3 || !terminal && !public62OneOf(v.State, "waiting_approval", "running", "verifying") {
		return false
	}
	application := v.Steps[0].Receipt != nil
	for i, s := range v.Steps {
		expected, _ := CanonicalDiscoveryID(id.Scope, "security_agent_step", v.RunID+"\x1f"+strconv.Itoa(i))
		action, kind := "create_temporary_policy", "temporary_policy_applied.v1"
		if i == 1 {
			action, kind = "run_test", "existing_test_settled.v1"
		}
		if s.Index != i || s.StepID != expected || s.Action != action || !public62Version(s.Version) || s.Version > v.Version || s.Authorization != "approval_required" || !public62OneOf(s.State, "blocked", "waiting_approval", "authorized", "executing", "verifying", "succeeded", "failed", "inconclusive", "cancelled") {
			return false
		}
		d := s.Dependency
		if i == 0 {
			if d.PredecessorStepID != nil || d.RequiredReceiptKind != nil || !d.Satisfied || d.Blocked || s.State == "blocked" {
				return false
			}
		} else {
			if d.PredecessorStepID == nil || *d.PredecessorStepID != v.Steps[0].StepID || d.RequiredReceiptKind == nil || *d.RequiredReceiptKind != "temporary_policy_applied.v1" || d.Satisfied != application || d.Blocked != (s.State == "blocked") || !application && !public62OneOf(s.State, "blocked", "cancelled") {
				return false
			}
		}
		// False readiness can reflect a live stop authority not disclosed in the
		// projection. True readiness must still satisfy all public prerequisites.
		if d.Ready && (terminal || !d.Satisfied || d.Blocked || !public62OneOf(s.State, "authorized", "waiting_approval")) {
			return false
		}
		if !public62ValidApproval(s, v, id) {
			return false
		}
		if s.State == "waiting_approval" && v.State != "waiting_approval" {
			return false
		}
		if (s.Receipt != nil) != (s.State == "succeeded") {
			return false
		}
		if s.Receipt != nil {
			receipt := s.Receipt
			ref, _ := CanonicalDiscoveryID(id.Scope, "public62_evidence", v.RunID+"\x1f"+s.StepID+"\x1f"+kind)
			if receipt.Kind != kind || receipt.Version != 1 || !public62Digest.MatchString(receipt.Digest) || receipt.Reference != ref {
				return false
			}
		}
		if i == 0 && s.Settlement != "not_applicable" || i == 1 && (s.Receipt == nil && s.Settlement != "pending" || s.Receipt != nil && !public62OneOf(s.Settlement, "not_reproduced", "reproduced", "unknown")) {
			return false
		}
		if !public62ValidCleanup(s.Cleanup, i, application, terminal, v.State) {
			return false
		}
	}
	if v.State == "waiting_approval" && v.Steps[0].State != "waiting_approval" && v.Steps[1].State != "waiting_approval" {
		return false
	}
	if !terminal && v.Steps[1].Receipt != nil {
		return false
	}
	if public62OneOf(v.State, "contained", "remediated") && (!application || v.Steps[1].Settlement != "not_reproduced") {
		return false
	}
	if v.State == "remediated" && (!v.Steps[0].Cleanup.Cleaned || v.Steps[0].Cleanup.Partial) {
		return false
	}
	if v.State == "contained" && v.Steps[0].Cleanup.Cleaned {
		return false
	}
	return true
}

func public62ValidApproval(s SecurityAgentPublicStep, v SecurityAgentPublicRun, id RequestIdentity) bool {
	a := s.Approval
	if a.State == "absent" {
		return s.Index == 1 && public62OneOf(s.State, "blocked", "cancelled") && a.Version == 0 && a.ApprovalID == nil
	}
	expected, _ := CanonicalDiscoveryID(id.Scope, "security_agent_ordered_approval", v.RunID+"\x1f"+s.StepID)
	if a.ApprovalID == nil || *a.ApprovalID != expected || !public62OneOf(a.State, "pending", "approved", "rejected", "expired", "cancelled") {
		return false
	}
	if a.Version > s.Version || a.State == "pending" && a.Version != 1 || a.State != "pending" && a.Version != 2 {
		return false
	}
	if s.State == "blocked" || s.State == "waiting_approval" && a.State != "pending" || public62OneOf(s.State, "authorized", "executing", "verifying", "succeeded") && a.State != "approved" {
		return false
	}
	if a.State == "pending" && s.State != "waiting_approval" {
		return false
	}
	return true
}

func public62ValidCleanup(c SecurityAgentPublicCleanup, index int, application, terminal bool, state string) bool {
	if index == 1 {
		return c == (SecurityAgentPublicCleanup{State: "not_applicable"})
	}
	if c.State == "not_started" {
		return !application && c == (SecurityAgentPublicCleanup{State: "not_started"})
	}
	if c.State == "pending" {
		return application && c == (SecurityAgentPublicCleanup{State: "pending"})
	}
	if !public62OneOf(c.State, "leased", "retryable", "cleaned") || !terminal || c.Version < 1 || c.Version > 999999 || c.Attempt < 1 || c.Attempt > 100 || c.Cleaned != (c.State == "cleaned") {
		return false
	}
	if !application && (!c.Partial || !public62OneOf(state, "cancelled", "needs_human")) {
		return false
	}
	if c.Partial && !public62OneOf(state, "cancelled", "needs_human") {
		return false
	}
	// Initial claim is version 1. Each later attempt requires reconcile and
	// recovery claim (+2). Heartbeats/stores can raise, never lower, this floor.
	minimumVersion := 2*c.Attempt - 1
	if c.Attempt > 1 && !public62OneOf(state, "cancelled", "needs_human") {
		return false
	}
	switch c.State {
	case "retryable":
		minimumVersion++ // Reconcile increments the current attempt's version.
		if !public62OneOf(state, "cancelled", "needs_human") {
			return false
		}
	case "cleaned":
		// At least one removal source must have been stored across all attempts,
		// and completion itself increments the version once more.
		minimumVersion += 2
		if !public62OneOf(state, "remediated", "needs_human", "cancelled") {
			return false
		}
	}
	return c.Version >= minimumVersion
}
