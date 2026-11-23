package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/inventoryreport"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

const (
	policyAudience  = "zasp.endpoint-policy.v1"
	receiptAudience = "zasp.endpoint-observation.v1"
	ticketTool      = "mcp__pilot__update_ticket"
	wireLimit       = 256 << 10
)

var (
	toolName       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$`)
	safeID         = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)
	errInvalid     = errors.New("invalid endpoint input")
	errUnavailable = errors.New("endpoint control unavailable")
)

type Binding struct {
	Organization string `json:"organization_id"`
	Workspace    string `json:"workspace_id"`
	Environment  string `json:"environment_id"`
	Device       string `json:"device_id"`
	Generation   uint64 `json:"credential_generation"`
}

func (b Binding) valid() bool {
	return safeID.MatchString(b.Organization) && safeID.MatchString(b.Workspace) && safeID.MatchString(b.Environment) && safeID.MatchString(b.Device) && b.Generation > 0
}

type Policy struct {
	pretool            *endpointprotocol.PolicyV2
	Audience           string    `json:"audience"`
	Binding            Binding   `json:"binding"`
	Revision           uint64    `json:"revision"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	Mode               string    `json:"mode"`
	Tool               string    `json:"tool"`
	AllowedDestination string    `json:"allowed_destination"`
}

type Signed struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func sign(v any, key ed25519.PrivateKey) (Signed, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return Signed{}, err
	}
	return Signed{Payload: body, Signature: ed25519.Sign(key, body)}, nil
}

func (s Signed) policy(key ed25519.PublicKey, binding Binding, now time.Time) (Policy, error) {
	var p Policy
	if binding.valid() {
		if signed, ok := (endpointprotocol.Signed(s)).AuthenticatedPolicyV2For(key, endpointprotocol.Binding(binding), now); ok {
			return Policy{pretool: &signed, Audience: signed.Audience, Binding: binding, Revision: signed.Revision, IssuedAt: signed.IssuedAt, ExpiresAt: signed.ExpiresAt, Mode: signed.Mode}, nil
		}
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, s.Payload, s.Signature) || strictJSON(s.Payload, &p) != nil {
		return Policy{}, errInvalid
	}
	if p.Audience != policyAudience || !binding.valid() || p.Binding != binding || p.Revision == 0 || !safeID.MatchString(p.AllowedDestination) || p.Tool != ticketTool || (p.Mode != "enforce" && p.Mode != "monitor") {
		return Policy{}, errInvalid
	}
	if p.IssuedAt.IsZero() || p.IssuedAt.After(now) || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > 24*time.Hour {
		return Policy{}, errInvalid
	}
	return p, nil
}

func strictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errInvalid
	}
	if dec.Decode(new(any)) != io.EOF {
		return errInvalid
	}
	return nil
}

func boundedRead(r io.Reader, limit int64) ([]byte, error) {
	value, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(value)) > limit {
		return nil, errInvalid
	}
	return value, nil
}

type HookEvent struct {
	CWD     string          `json:"cwd,omitempty"`
	Name    string          `json:"hook_event_name"`
	Session string          `json:"session_id"`
	Tool    string          `json:"tool_name"`
	Call    string          `json:"tool_use_id"`
	Input   json.RawMessage `json:"tool_input"`
}

// Claude may add unrelated event fields. Only the ticket destination may influence
// the rule. Session and tool-call references are local client claims.
func parseHook(raw []byte) (HookEvent, string, error) {
	var e HookEvent
	var envelope map[string]json.RawMessage
	// Ignore unrelated harness extensions, and reject ambiguous JSON field names.
	if !inventoryreport.UniqueJSON(raw) || json.Unmarshal(raw, &envelope) != nil {
		return e, "", errInvalid
	}
	for name, dst := range map[string]*string{"hook_event_name": &e.Name, "session_id": &e.Session, "tool_name": &e.Tool, "tool_use_id": &e.Call} {
		if json.Unmarshal(envelope[name], dst) != nil {
			return e, "", errInvalid
		}
	}
	if e.Name != "PreToolUse" || !safeID.MatchString(e.Session) || !safeID.MatchString(e.Call) || !toolName.MatchString(e.Tool) {
		return e, "", errInvalid
	}
	if rawCWD, has := envelope["cwd"]; has && (json.Unmarshal(rawCWD, &e.CWD) != nil || len(e.CWD) > 4096) {
		return e, "", errInvalid
	}
	e.Input = envelope["tool_input"]
	if len(e.Input) == 0 {
		e.Input = json.RawMessage("null")
	}
	var args map[string]json.RawMessage
	var destination string
	if json.Unmarshal(e.Input, &args) == nil {
		_ = json.Unmarshal(args["destination"], &destination)
	}
	return e, destination, nil
}
