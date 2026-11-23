// Package providerhooks authenticates external provider callbacks before reducing
// them to bounded metadata for a separately authenticated Zasp workload action.
package providerhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const ClaudePath = "/api/v1/runtime/provider-hooks/claude-enterprise/"
const Deadline = 400 * time.Millisecond
const maxFrame = 64 << 20

type Scope struct{ Organization, Workspace, Environment, Credential string }
type bindingKey struct{}

func Binding(ctx context.Context) (Scope, bool) {
	s, ok := ctx.Value(bindingKey{}).(Scope)
	return s, ok
}

type Config struct {
	Integration, Tenant, Secret, ReferenceKey string
	Scope                                     Scope
}
type Action struct {
	Schema    string `json:"schema_version"`
	ID        string `json:"action_id"`
	Kind      string `json:"action_kind"`
	Operation string `json:"operation"`
	Resource  struct {
		Kind           string `json:"kind"`
		Classification string `json:"classification"`
	} `json:"resource"`
	Session string `json:"source_session_ref,omitempty"`
	Call    string `json:"source_call_ref"`
}
type Decision struct{ ActionID, DecisionID, Mode, Verdict string }
type Admit func(context.Context, Action) (Decision, error)

var ErrConflict = errors.New("provider delivery already bound to another frame")
var ErrIncompatible = errors.New("incompatible provider policy")
var productID = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Claude struct {
	scope               Scope
	integration, tenant string
	secret, refs        []byte
	admit               Admit
	now                 func() time.Time
	slots               chan struct{}
}

func NewClaude(cfg Config, admit Admit) (*Claude, error) {
	if admit == nil || cfg.Tenant == "" || len(cfg.Tenant) > 512 || !strings.HasPrefix(cfg.Secret, "whsec_") {
		return nil, errors.New("invalid provider configuration")
	}
	for _, id := range []string{cfg.Integration, cfg.Scope.Organization, cfg.Scope.Workspace, cfg.Scope.Environment, cfg.Scope.Credential} {
		if !productID.MatchString(id) {
			return nil, errors.New("invalid provider scope")
		}
	}
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(cfg.Secret, "whsec_"))
	refs, errRef := base64.StdEncoding.Strict().DecodeString(cfg.ReferenceKey)
	if err != nil || len(key) < 16 || len(key) > 128 || errRef != nil || len(refs) != 32 || hmac.Equal(key, refs) {
		return nil, errors.New("invalid provider signing or reference key")
	}
	return &Claude{scope: cfg.Scope, integration: cfg.Integration, tenant: cfg.Tenant, secret: key, refs: refs, admit: admit, now: time.Now, slots: make(chan struct{}, 2)}, nil
}
func (h *Claude) reference(class string, data []byte) string {
	m := hmac.New(sha256.New, h.refs)
	_, _ = io.WriteString(m, "zasp.claude-enterprise.v1\x00"+h.integration+"\x00"+class+"\x00")
	_, _ = m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

func singleton(headers http.Header, name string) string {
	v := headers.Values(name)
	if len(v) != 1 {
		return ""
	}
	return v[0]
}
func (h *Claude) signature(body []byte, id, stamp, sig string) bool {
	if id == "" || len(id) > 512 || strings.ContainsAny(id, "\r\n") || len(sig) > 4096 || len(stamp) > 16 {
		return false
	}
	ts, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil || strconv.FormatInt(ts, 10) != stamp {
		return false
	}
	now := h.now().Unix()
	if ts < now-300 || ts > now+300 {
		return false
	}
	m := hmac.New(sha256.New, h.secret)
	_, _ = io.WriteString(m, id+"."+stamp+".")
	_, _ = m.Write(body)
	wanted := m.Sum(nil)
	for _, field := range strings.Fields(sig) {
		prefix, value, ok := strings.Cut(field, ",")
		if !ok || prefix != "v1" {
			continue
		}
		mac, err := base64.StdEncoding.Strict().DecodeString(value)
		if err == nil && hmac.Equal(wanted, mac) {
			return true
		}
	}
	return false
}

type frame struct {
	Type    string  `json:"type"`
	ID      string  `json:"request_id"`
	Tenant  *string `json:"tenant_id"`
	Session *string `json:"session_id"`
	Source  struct {
		Application string `json:"application"`
	} `json:"source"`
	Messages []json.RawMessage `json:"messages"`
}
type toolMessage struct {
	Role    string `json:"role"`
	Content []struct {
		Type string `json:"type"`
		Info struct {
			Type string `json:"type"`
		} `json:"tool_info"`
	} `json:"content"`
}

func classify(f frame) (string, bool) {
	if f.Type == "prompt" {
		return "claude.prompt", f.Messages != nil
	}
	if len(f.Messages) == 0 {
		return "", false
	}
	var msg toolMessage
	if json.Unmarshal(f.Messages[len(f.Messages)-1], &msg) != nil || msg.Role != "assistant" {
		return "", false
	}
	kinds := map[string]bool{}
	for _, b := range msg.Content {
		if b.Type != "tool_use" {
			continue
		}
		v := b.Info.Type
		switch v {
		case "platform", "application", "third_party", "client":
		default:
			v = "unknown"
		}
		kinds[v] = true
	}
	if len(kinds) == 0 {
		return "", false
	}
	var parts []string
	for _, kind := range []string{"platform", "application", "third_party", "client", "unknown"} {
		if kinds[kind] {
			parts = append(parts, kind)
		}
	}
	if len(parts) > 1 {
		return "claude.tool_frame.mixed." + strings.Join(parts, "."), true
	}
	return "claude.tool_frame." + parts[0], true
}

// MatchesClass evaluates each constituent of a mixed tool frame. A rule
// covering a single origin also covers that origin inside a multi-tool call.
func MatchesClass(observed, required string) bool {
	if observed == required {
		return true
	}
	const group = "claude.tool_frame.mixed"
	rest, mixed := strings.CutPrefix(observed, group+".")
	if !mixed {
		return false
	}
	if required == group {
		return true
	}
	for _, origin := range strings.Split(rest, ".") {
		if required == "claude.tool_frame."+origin {
			return true
		}
	}
	return false
}
func writeHookError(w http.ResponseWriter, status int, code, message string) {
	id, err := domain.NewProductID()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": message, "correlation_id": id.String(), "retryable": false})
}

func writeVerdict(w http.ResponseWriter, deny bool, id string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if !deny {
		_, _ = io.WriteString(w, `{"action":"allow"}`)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"action": "deny", "deny_reason": "Your organization's Zasp policy blocked this request.", "reference_id": id})
}
func (h *Claude) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	controller := http.NewResponseController(w)
	if controller.SetReadDeadline(time.Now().Add(Deadline)) == nil {
		defer controller.SetReadDeadline(time.Time{})
	}
	http.TimeoutHandler(http.HandlerFunc(h.handle), Deadline, "").ServeHTTP(w, r)
}
func (h *Claude) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != ClaudePath+h.integration || r.URL.RawPath != "" || r.URL.RawQuery != "" {
		w.WriteHeader(404)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(405)
		return
	}
	typ, _, e := mime.ParseMediaType(singleton(r.Header, "Content-Type"))
	if e != nil || typ != "application/json" || r.Header.Get("Content-Encoding") != "" {
		w.WriteHeader(415)
		return
	}
	id, stamp, sig := singleton(r.Header, "webhook-id"), singleton(r.Header, "webhook-timestamp"), singleton(r.Header, "webhook-signature")
	if id == "" || stamp == "" || sig == "" {
		writeHookError(w, 401, "authentication_required", "Webhook authentication failed")
		return
	}
	if r.ContentLength > maxFrame {
		writeHookError(w, 413, "request_too_large", "Webhook body exceeds the frame limit")
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.WriteHeader(503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), Deadline)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = r.Body.Close() })
	defer stop()

	body, err := io.ReadAll(io.LimitReader(r.Body, maxFrame+1))
	if ctx.Err() != nil {
		w.WriteHeader(504)
		return
	}
	if err != nil {
		w.WriteHeader(400)
		return
	}
	if len(body) > maxFrame {
		writeHookError(w, 413, "request_too_large", "Webhook body exceeds the frame limit")
		return
	}
	if !h.signature(body, id, stamp, sig) {
		writeHookError(w, 401, "authentication_required", "Webhook authentication failed")
		return
	}
	var f frame
	if json.Unmarshal(body, &f) != nil || f.ID != id || f.Type == "" {
		w.WriteHeader(400)
		return
	}
	// A configuration probe uses the tenant-dedicated signing secret and is
	// subject to the very same prompt policy as other frames. The provider
	// documents source.application as advisory, so it never selects a weaker rule.
	if f.Tenant == nil && (f.Type != "prompt" || f.Source.Application != "config-test") || f.Tenant != nil && *f.Tenant != h.tenant {
		w.WriteHeader(403)
		return
	}
	if ctx.Err() != nil {
		w.WriteHeader(504)
		return
	}
	if f.Type != "tool_call" && f.Type != "prompt" {
		// The published protocol requests an allow verdict for unknown future
		// event types. These frames produce no Zasp coverage or action receipt.
		writeVerdict(w, false, "")
		return
	}
	class, ok := classify(f)
	if !ok {
		w.WriteHeader(400)
		return
	}
	action := Action{Schema: "action.v1", ID: h.reference("delivery", []byte(id)), Kind: "provider_prompt", Operation: "claude.prompt", Call: h.reference("frame", body)}
	action.Resource.Kind = "claude_enterprise"
	action.Resource.Classification = class
	if f.Type == "tool_call" {
		action.Kind = "provider_tool_frame"
		action.Operation = "claude.tool_frame"
	}
	if f.Session != nil && *f.Session != "" {
		action.Session = h.reference("session", []byte(*f.Session))
	}
	// Discard the transcript before entering the scoped product decision path.
	body = nil
	f.Messages = nil
	d, err := h.admit(context.WithValue(ctx, bindingKey{}, h.scope), action)
	switch {
	case ctx.Err() != nil:
		w.WriteHeader(504)
	case errors.Is(err, ErrConflict):
		writeHookError(w, 409, "action_id_conflict", "The delivery identifier was already used with different inputs")
	case errors.Is(err, ErrIncompatible):
		writeHookError(w, 422, "policy_context_unavailable", "Policy requires unavailable context")
	case err != nil || d.ActionID != action.ID || !productID.MatchString(d.DecisionID) ||
		(d.Mode != "monitor" && d.Mode != "enforce") || (d.Verdict != "allow" && !(d.Verdict == "block" && d.Mode == "enforce")):
		w.WriteHeader(503)
	default:
		writeVerdict(w, d.Verdict == "block", d.DecisionID)
	}
}
