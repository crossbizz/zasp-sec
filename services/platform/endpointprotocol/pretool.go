package endpointprotocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"
)

var wireField = regexp.MustCompile(`^[a-z_]+$`)

// StrictPolicyJSON rejects alias casing, repeated properties and unknown fields in signed wire messages.
func StrictPolicyJSON(raw []byte, out any) bool {
	if !Strict(raw, out) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) bool
	value = func(depth int) bool {
		token, err := d.Token()
		if err != nil || depth > 12 {
			return false
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				name, ok := k.(string)
				if err != nil || !ok || !wireField.MatchString(name) || seen[name] {
					return false
				}
				seen[name] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case json.Delim('['):
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return true
		}
	}
	return value(0)
}

const PolicyAudienceV2 = "zasp.endpoint-policy.v2"

type PretoolRule struct {
	ID                  string   `json:"id"`
	Type                string   `json:"type"`
	Match               string   `json:"match,omitempty"`
	Values              []string `json:"values"`
	AllowedDestinations []string `json:"allowed_destinations,omitempty"`
}

type PolicyV2 struct {
	Audience    string        `json:"audience"`
	Binding     Binding       `json:"binding"`
	Revision    uint64        `json:"revision"`
	IssuedAt    time.Time     `json:"issued_at"`
	ExpiresAt   time.Time     `json:"expires_at"`
	Mode        string        `json:"mode"`
	FailureMode string        `json:"failure_mode"`
	Rules       []PretoolRule `json:"rules"`
}

var (
	ruleName  = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	mcpName   = regexp.MustCompile(`^mcp__[A-Za-z0-9_-]{1,64}__(?:[A-Za-z0-9_-]{1,80}|\*)$`)
	hostLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

func validHost(pattern string) bool {
	if len(pattern) > 253 || strings.ToLower(pattern) != pattern {
		return false
	}
	host := strings.TrimPrefix(pattern, "*.")
	if strings.HasPrefix(pattern, "*.") && !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func valuesValid(values []string, allow func(string) bool) bool {
	if len(values) == 0 || len(values) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range values {
		if seen[v] || !allow(v) {
			return false
		}
		seen[v] = true
	}
	return true
}

func ValidPretoolRules(mode, failure string, rules []PretoolRule) bool {
	if (mode != "monitor" && mode != "enforce") || (failure != "open" && failure != "closed") || len(rules) == 0 || len(rules) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if !ruleName.MatchString(r.ID) || seen[r.ID] {
			return false
		}
		seen[r.ID] = true
		if r.Type != "mcp_tool_policy" && r.AllowedDestinations != nil {
			return false
		}
		switch r.Type {
		case "mcp_tool_policy", "destination_domain_policy":
			if r.Match != "allowlist" && r.Match != "denylist" {
				return false
			}
			if r.Type == "mcp_tool_policy" {
				if !valuesValid(r.Values, mcpName.MatchString) || (r.AllowedDestinations != nil && !valuesValid(r.AllowedDestinations, validHost)) {
					return false
				}
			} else if !valuesValid(r.Values, validHost) {
				return false
			}
		case "shell_command_policy":
			if r.Match != "" || !valuesValid(r.Values, func(v string) bool {
				return slices.Contains([]string{"shell_pipe", "secret_transfer", "reverse_shell", "privileged_mode", "encoded_execution"}, v)
			}) {
				return false
			}
		case "file_path_policy":
			if r.Match != "" || !valuesValid(r.Values, func(v string) bool {
				return slices.Contains([]string{"ssh", "aws", "gcloud", "dotenv", "pem", "identity_key"}, v)
			}) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validPretoolBinding(b Binding) bool {
	return b.Generation > 0 && b.Generation <= 1<<53 && Label.MatchString(b.Organization) && Label.MatchString(b.Workspace) && Label.MatchString(b.Environment) && Label.MatchString(b.Device)
}

func (s Signed) PolicyV2For(key []byte, binding Binding, now time.Time) (PolicyV2, bool) {
	p, ok := s.AuthenticatedPolicyV2For(key, binding, now)
	return p, ok && p.ExpiresAt.After(now)
}

// AuthenticatedPolicyV2For retains the signed failure mode and revision of a
// stale policy. Call PolicyV2For when admitting a new active policy.
func (s Signed) AuthenticatedPolicyV2For(key []byte, binding Binding, now time.Time) (PolicyV2, bool) {
	var p PolicyV2
	valid := len(key) == ed25519.PublicKeySize && len(s.Payload) > 0 && len(s.Payload) <= 32768 && ed25519.Verify(key, s.Payload, s.Signature) && StrictPolicyJSON(s.Payload, &p)
	return p, valid && p.Audience == PolicyAudienceV2 && p.Binding == binding && validPretoolBinding(binding) && p.Revision > 0 && p.Revision <= 1<<53 && !p.IssuedAt.IsZero() && !p.IssuedAt.After(now) && p.ExpiresAt.After(p.IssuedAt) && p.ExpiresAt.Sub(p.IssuedAt) <= 24*time.Hour && ValidPretoolRules(p.Mode, p.FailureMode, p.Rules)
}

const ReceiptAudienceV2 = "zasp.endpoint-observation.v2"

type ObservationV2 struct {
	Audience       string    `json:"audience"`
	Binding        Binding   `json:"binding"`
	Action         string    `json:"action_id"`
	Session        string    `json:"session_ref"`
	ObservedAt     time.Time `json:"observed_at"`
	PolicyRevision uint64    `json:"policy_revision"`
	Mode           string    `json:"mode"`
	Adapter        string    `json:"adapter"`
	Tool           string    `json:"tool"`
	RuleID         string    `json:"rule_id,omitempty"`
	Reason         string    `json:"reason_code"`
	Verdict        string    `json:"verdict"`
	WouldBlock     bool      `json:"would_block"`
	TargetClass    string    `json:"target_class"`
	SkillUsage     string    `json:"skill_usage"`
	TargetEffect   string    `json:"target_effect"`
}

func PretoolAdapter(value string) bool {
	return slices.Contains([]string{"macos_claude_pretool_v2", "linux_claude_pretool_v2_test", "macos_codex_pretool_v2", "windows_claude_pretool_v2"}, value)
}
func ToolClass(name string) string {
	switch {
	case strings.HasPrefix(name, "mcp__"):
		return "mcp"
	case name == "Bash":
		return "shell"
	case name == "WebFetch":
		return "web"
	case slices.Contains([]string{"Read", "Write", "Edit", "MultiEdit", "Glob", "Grep", "apply_patch"}, name):
		return "file"
	default:
		return "other"
	}
}
func (s Signed) ObservationV2For(key []byte, binding Binding, now time.Time) (ObservationV2, bool) {
	var o ObservationV2
	ok := len(key) == ed25519.PublicKeySize && len(s.Payload) > 0 && len(s.Payload) < 4096 && ed25519.Verify(key, s.Payload, s.Signature) && StrictPolicyJSON(s.Payload, &o)
	if !ok || o.Audience != ReceiptAudienceV2 || o.Binding != binding || !validPretoolBinding(binding) || !Digest.MatchString(o.Action) || !Digest.MatchString(o.Session) || o.ObservedAt.IsZero() || o.ObservedAt.After(now.Add(30*time.Second)) || !PretoolAdapter(o.Adapter) || !slices.Contains([]string{"shell", "mcp", "file", "web", "other"}, o.Tool) || o.TargetClass != "unknown" || o.SkillUsage != "unknown" || o.TargetEffect != "unknown" {
		return o, false
	}
	if o.PolicyRevision > 1<<53 || (o.Mode != "" && o.Mode != "enforce" && o.Mode != "monitor") || (o.RuleID != "" && !ruleName.MatchString(o.RuleID)) {
		return o, false
	}
	switch o.Reason {
	case "policy_expired", "policy_unavailable", "state_unavailable", "input_unavailable", "spool_full":
		return o, slices.Contains([]string{"continue", "deny", "unavailable"}, o.Verdict) && (!o.WouldBlock || o.Mode == "enforce") && (o.Verdict != "deny" || (o.Mode == "enforce" && o.WouldBlock))
	case "within_scope":
		return o, o.PolicyRevision > 0 && o.Mode != "" && o.RuleID == "" && o.Verdict == "continue" && !o.WouldBlock
	case "mcp_tool_restricted", "destination_restricted", "shell_pipe", "secret_transfer", "reverse_shell", "privileged_mode", "encoded_execution", "ssh", "aws", "gcloud", "dotenv", "pem", "identity_key", "unverifiable_path":
		return o, o.PolicyRevision > 0 && o.RuleID != "" && o.WouldBlock && ((o.Mode == "monitor" && o.Verdict == "continue") || (o.Mode == "enforce" && o.Verdict == "deny"))
	}
	return o, false
}
