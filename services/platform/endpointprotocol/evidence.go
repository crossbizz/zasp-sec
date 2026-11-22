package endpointprotocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"time"
)

const (
	PolicyAudience  = "zasp.endpoint-policy.v1"
	ReceiptAudience = "zasp.endpoint-observation.v1"
	TicketTool      = "mcp__pilot__update_ticket"
)

type Signed struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}
type Policy struct {
	Audience           string    `json:"audience"`
	Binding            Binding   `json:"binding"`
	Revision           uint64    `json:"revision"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	Mode               string    `json:"mode"`
	Tool               string    `json:"tool"`
	AllowedDestination string    `json:"allowed_destination"`
}
type Observation struct {
	Audience       string    `json:"audience"`
	Binding        Binding   `json:"binding"`
	PeerUID        int       `json:"local_uid"`
	Action         string    `json:"action_id"`
	Session        string    `json:"session_ref"`
	ObservedAt     time.Time `json:"observed_at"`
	PolicyRevision uint64    `json:"policy_revision"`
	Mode           string    `json:"mode"`
	Tool           string    `json:"tool"`
	TargetClass    string    `json:"target_class"`
	Verdict        string    `json:"verdict"`
	WouldBlock     bool      `json:"would_block"`
	Reason         string    `json:"reason"`
	SkillUsage     string    `json:"skill_usage"`
	TargetEffect   string    `json:"target_effect"`
}

func Strict(raw []byte, value any) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(value) == nil && d.Decode(new(any)) == io.EOF
}

func (s Signed) PolicyFor(key []byte, binding Binding, now time.Time) (Policy, bool) {
	var p Policy
	ok := len(key) == ed25519.PublicKeySize && len(s.Payload) < 4096 && ed25519.Verify(key, s.Payload, s.Signature) && Strict(s.Payload, &p)
	return p, ok && p.Binding == binding && p.Audience == PolicyAudience && p.Tool == TicketTool && p.Revision > 0 && p.Revision <= 1<<53 && (p.Mode == "monitor" || p.Mode == "enforce") && Label.MatchString(p.AllowedDestination) && !p.IssuedAt.IsZero() && !p.IssuedAt.After(now) && p.ExpiresAt.After(now) && p.ExpiresAt.Sub(p.IssuedAt) <= 24*time.Hour
}

func (s Signed) ObservationFor(key []byte, binding Binding, now time.Time) (Observation, bool) {
	var o Observation
	ok := len(key) == ed25519.PublicKeySize && len(s.Payload) < 4096 && ed25519.Verify(key, s.Payload, s.Signature) && Strict(s.Payload, &o)
	if !ok || o.Binding != binding || o.Audience != ReceiptAudience || !Digest.MatchString(o.Action) || !Digest.MatchString(o.Session) || o.PeerUID < 0 || o.PeerUID > 1<<31-1 || o.ObservedAt.IsZero() || o.ObservedAt.After(now.Add(30*time.Second)) || o.Tool != TicketTool || o.SkillUsage != "unknown" || o.TargetEffect != "unknown" {
		return o, false
	}
	switch o.Verdict {
	case "continue", "deny":
		return o, (o.Mode == "enforce" || o.Mode == "monitor") && o.PolicyRevision > 0 && (o.TargetClass == "allowed_destination" || o.TargetClass == "outside_allowed_destination" || o.TargetClass == "unknown") && o.WouldBlock == (o.TargetClass != "allowed_destination") && (o.Verdict == "deny") == (o.Mode == "enforce" && o.WouldBlock) && ((o.WouldBlock && o.Reason == "destination_not_approved") || (!o.WouldBlock && o.Reason == "within_scope"))
	case "unavailable":
		return o, (o.Mode == "" || o.Mode == "enforce" || o.Mode == "monitor") && !o.WouldBlock && o.TargetClass == "unknown" && (o.Reason == "policy_unavailable" || o.Reason == "policy_expired" || o.Reason == "state_unavailable")
	default:
		return o, false
	}
}

type Installation struct {
	ID     string `json:"installation_id"`
	Digest string `json:"manifest_digest,omitempty"`
}
type Inventory struct {
	Partition  string         `json:"partition_id"`
	Generation uint64         `json:"snapshot_generation"`
	Complete   *bool          `json:"complete"`
	Items      []Installation `json:"installations"`
}

func (i Inventory) Valid() bool {
	if !Digest.MatchString(i.Partition) || i.Generation == 0 || i.Generation > 1<<53 || i.Complete == nil || i.Items == nil || len(i.Items) > 128 {
		return false
	}
	seen := make(map[string]bool, len(i.Items))
	for _, item := range i.Items {
		if !Digest.MatchString(item.ID) || seen[item.ID] || (item.Digest != "" && (len(item.Digest) != 71 || item.Digest[:7] != "sha256:" || !Digest.MatchString(item.Digest[7:]))) {
			return false
		}
		seen[item.ID] = true
	}
	return true
}
