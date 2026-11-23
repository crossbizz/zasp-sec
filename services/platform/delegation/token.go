// Package delegation verifies short-lived, task-scoped grants offline. Token
// claims are matched against the verifier's own tenant, task and agent binding.
package delegation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	MaxDepth   = 8
	MaxTTL     = 300
	maxToken   = 16384
	Header     = "X-Zasp-Delegation"
	TaskHeader = "X-Zasp-Parent-Task-Id"
)

var ErrDenied = errors.New("task delegation denied")
var label = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$`)
var encoding = base64.RawURLEncoding.Strict()
var protected = encoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"zasp-task-delegation.v1+jwt"}`))

type Tenant struct {
	Organization string `json:"organization_id"`
	Workspace    string `json:"workspace_id"`
	Environment  string `json:"environment_id"`
}

type Scope struct {
	Operations []string `json:"allowed_operations"`
	Resources  []string `json:"allowed_resources"`
}

type Claims struct {
	Tenant
	Scope
	Task     string `json:"parent_task_id"`
	Parent   string `json:"parent_agent_id"`
	Child    string `json:"child_agent_id"`
	Depth    int    `json:"depth"`
	MaxDepth int    `json:"max_depth"`
	Issued   int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

// Binding is obtained from authenticated deployment configuration.
type Binding struct {
	Tenant
	Task  string `json:"parent_task_id"`
	Agent string `json:"agent_id"`
}

func (t Tenant) Valid() bool {
	return label.MatchString(t.Organization) && label.MatchString(t.Workspace) && label.MatchString(t.Environment)
}

func (b Binding) Valid() bool {
	return b.Tenant.Valid() && label.MatchString(b.Task) && label.MatchString(b.Agent)
}

func ValidIdentifier(value string) bool { return label.MatchString(value) }

func validList(values []string) bool {
	if len(values) < 1 || len(values) > 32 {
		return false
	}
	seen := make(map[string]bool, len(values))
	for _, v := range values {
		if !label.MatchString(v) || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

func (s Scope) Valid() bool { return validList(s.Operations) && validList(s.Resources) }

func subset(values, ceiling []string) bool {
	for _, v := range values {
		if !slices.Contains(ceiling, v) {
			return false
		}
	}
	return true
}

func (s Scope) Within(ceiling Scope) bool {
	return subset(s.Operations, ceiling.Operations) && subset(s.Resources, ceiling.Resources)
}

func (c Claims) Valid(now int64) bool {
	return c.Tenant.Valid() && c.Scope.Valid() && label.MatchString(c.Task) &&
		label.MatchString(c.Parent) && label.MatchString(c.Child) && c.Child != c.Parent &&
		c.Depth > 0 && c.Depth <= c.MaxDepth && c.MaxDepth <= MaxDepth &&
		c.Issued > 0 && c.Issued <= now && c.Expires > now && c.Expires-c.Issued <= MaxTTL
}

func strict(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(new(any)) != io.EOF {
		return ErrDenied
	}
	return nil
}

// Tier: 1 | Purpose: verify task attenuation before dispatch.
// Model: none.
// Authority: a pinned key and locally trusted binding, with an exact operation and resource.
// Fallback: missing, malformed, expired or overbroad grants never permit dispatch.
func Verify(key ed25519.PublicKey, token string, b Binding, now time.Time) (Claims, error) {
	if len(key) != ed25519.PublicKeySize || len(token) > maxToken || !b.Valid() {
		return Claims{}, ErrDenied
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != protected || strings.ContainsAny(token, "\r\n") {
		return Claims{}, ErrDenied
	}
	sig, err := encoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, ErrDenied
	}
	raw, err := encoding.DecodeString(parts[1])
	var c Claims
	if err != nil || strict(raw, &c) != nil || !c.Valid(now.Unix()) || c.Tenant != b.Tenant || c.Task != b.Task || c.Child != b.Agent {
		return Claims{}, ErrDenied
	}
	return c, nil
}

type Decision struct {
	Status  string `json:"status"`
	Allowed bool   `json:"allowed"`
}

func Check(key ed25519.PublicKey, token string, b Binding, operation, resource string, now time.Time) Decision {
	if token == "" {
		return Decision{Status: "delegation_unverified"}
	}
	c, err := Verify(key, token, b, now)
	if err != nil || !slices.Contains(c.Operations, operation) || !slices.Contains(c.Resources, resource) {
		return Decision{Status: "denied"}
	}
	return Decision{Status: "verified", Allowed: true}
}
