package identity

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumWebhookBytes   = 16 * 1024
	maximumWebhookEvents  = 10_000
	maximumSignatureBytes = 4 * 1024
)

type WebhookHeaders struct {
	MessageID string
	Timestamp string
	Signature string
}

type WebhookEvent struct {
	ProjectID   string          `json:"project_id"`
	EventID     string          `json:"event_id"`
	Action      string          `json:"action"`
	ObjectType  string          `json:"object_type"`
	Source      string          `json:"source"`
	ObjectID    string          `json:"id"`
	Timestamp   string          `json:"timestamp"`
	Vertical    string          `json:"vertical"`
	WorkspaceID string          `json:"workspace_id"`
	Details     WebhookDetails  `json:"details"`
	Member      json.RawMessage `json:"member,omitempty"`
}

type WebhookDetails struct {
	OrganizationReference string `json:"organization_id"`
}

func (event WebhookEvent) Kind() string {
	return strings.ToLower(event.Source + "." + event.ObjectType + "." + event.Action)
}

type WebhookVerifier struct {
	mu         sync.Mutex
	projectID  string
	secret     []byte
	now        func() time.Time
	tolerance  time.Duration
	seenEvents map[string]time.Time
}

func NewWebhookVerifier(projectID, secret string, now func() time.Time, tolerance time.Duration) (*WebhookVerifier, error) {
	if !validReference(projectID, "project-") || !strings.HasPrefix(secret, "whsec_") || now == nil || tolerance <= 0 || tolerance > 15*time.Minute {
		return nil, ErrConfiguration
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(secret, "whsec_"))
	current, clockOK := readWebhookClock(now)
	if err != nil || len(decoded) != sha256.Size || !clockOK || !canonicalTime(current) {
		return nil, ErrConfiguration
	}
	return &WebhookVerifier{projectID: projectID, secret: decoded, now: now, tolerance: tolerance, seenEvents: map[string]time.Time{}}, nil
}

func (verifier *WebhookVerifier) Verify(body []byte, headers WebhookHeaders) (WebhookEvent, bool, error) {
	if verifier == nil || len(body) == 0 || len(body) > maximumWebhookBytes || !validWebhookMessageID(headers.MessageID) ||
		len(headers.Signature) == 0 || len(headers.Signature) > maximumSignatureBytes {
		return WebhookEvent{}, false, ErrWebhookVerification
	}
	seconds, err := strconv.ParseInt(headers.Timestamp, 10, 64)
	if err != nil || strconv.FormatInt(seconds, 10) != headers.Timestamp {
		return WebhookEvent{}, false, ErrWebhookVerification
	}
	now, clockOK := readWebhookClock(verifier.now)
	sentAt := time.Unix(seconds, 0).UTC()
	if !clockOK || !canonicalTime(now) || sentAt.Before(now.Add(-verifier.tolerance)) || sentAt.After(now.Add(verifier.tolerance)) ||
		!verifier.validSignature(body, headers) || validateUniqueJSON(body) != nil {
		return WebhookEvent{}, false, ErrWebhookVerification
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var event WebhookEvent
	if err := decoder.Decode(&event); err != nil {
		return WebhookEvent{}, false, ErrWebhookVerification
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) || !validWebhookEvent(event, verifier.projectID, now, verifier.tolerance) {
		return WebhookEvent{}, false, ErrWebhookVerification
	}

	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	for eventID, timestamp := range verifier.seenEvents {
		if timestamp.Before(now.Add(-verifier.tolerance)) {
			delete(verifier.seenEvents, eventID)
		}
	}
	if _, exists := verifier.seenEvents[event.EventID]; exists {
		return event, true, nil
	}
	if len(verifier.seenEvents) >= maximumWebhookEvents {
		return WebhookEvent{}, false, ErrWebhookVerification
	}
	verifier.seenEvents[event.EventID] = now
	return event, false, nil
}

func (verifier *WebhookVerifier) validSignature(body []byte, headers WebhookHeaders) bool {
	mac := hmac.New(sha256.New, verifier.secret)
	_, _ = io.WriteString(mac, headers.MessageID+"."+headers.Timestamp+".")
	_, _ = mac.Write(body)
	want := mac.Sum(nil)
	matched := 0
	for _, candidate := range strings.Fields(headers.Signature) {
		parts := strings.Split(candidate, ",")
		if len(parts) != 2 || parts[0] != "v1" {
			continue
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(parts[1])
		if err == nil && len(decoded) == len(want) {
			matched |= subtle.ConstantTimeCompare(decoded, want)
		}
	}
	return matched == 1
}

func readWebhookClock(clock func() time.Time) (value time.Time, ok bool) {
	defer func() {
		if recover() != nil {
			value = time.Time{}
			ok = false
		}
	}()
	return clock(), true
}

func (verifier *WebhookVerifier) Release(eventID string) {
	if verifier == nil || !validWebhookEventID(eventID) {
		return
	}
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	delete(verifier.seenEvents, eventID)
}

type DeprovisionAuditEvent struct {
	EventID         string
	OrganizationID  domain.ProductID
	PrincipalID     domain.ProductID
	MemberReference string
	GrantIDs        []domain.ProductID
}

type DeprovisionAuditor interface {
	Record(context.Context, DeprovisionAuditEvent) error
}

type DeprovisionReconciler struct {
	store    *MemoryStore
	verifier *WebhookVerifier
	auditor  DeprovisionAuditor
}

type WebhookHTTPHandler struct {
	reconciler WebhookReconciler
	path       string
}

type WebhookReconciler interface {
	Handle(context.Context, []byte, WebhookHeaders) (bool, error)
}

func NewWebhookHTTPHandler(reconciler *DeprovisionReconciler) (*WebhookHTTPHandler, error) {
	return NewWebhookHTTPHandlerForPath(reconciler, "/internal/v1/stytch/webhooks")
}

func NewWebhookHTTPHandlerForPath(reconciler WebhookReconciler, path string) (*WebhookHTTPHandler, error) {
	if nilInterface(reconciler) || path != "/internal/v1/stytch/webhooks" && path != "/api/v1/webhooks/stytch" {
		return nil, ErrConfiguration
	}
	return &WebhookHTTPHandler{reconciler: reconciler, path: path}, nil
}

func (handler *WebhookHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.reconciler == nil || request == nil || request.URL == nil {
		http.Error(writer, "", http.StatusInternalServerError)
		return
	}
	if request.Method != http.MethodPost || request.URL.Path != handler.path ||
		request.URL.EscapedPath() != request.URL.Path || request.URL.RawQuery != "" {
		http.NotFound(writer, request)
		return
	}
	if request.Header.Get("Content-Type") != "application/json" || request.Body == nil || request.ContentLength > maximumWebhookBytes ||
		len(request.Header.Values("Svix-Id")) != 1 || len(request.Header.Values("Svix-Timestamp")) != 1 ||
		len(request.Header.Values("Svix-Signature")) != 1 {
		writeWebhookResult(writer, http.StatusUnauthorized, false, true)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumWebhookBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumWebhookBytes {
		writeWebhookResult(writer, http.StatusUnauthorized, false, true)
		return
	}
	processed, err := handleWebhookSafely(handler.reconciler, request.Context(), body, WebhookHeaders{
		MessageID: request.Header.Get("Svix-Id"), Timestamp: request.Header.Get("Svix-Timestamp"),
		Signature: request.Header.Get("Svix-Signature"),
	})
	if err != nil {
		if errors.Is(err, ErrWebhookVerification) {
			writeWebhookResult(writer, http.StatusUnauthorized, false, true)
			return
		}
		writeWebhookUnavailable(writer)
		return
	}
	writeWebhookResult(writer, http.StatusAccepted, processed, false)
}

func handleWebhookSafely(reconciler WebhookReconciler, ctx context.Context, body []byte, headers WebhookHeaders) (processed bool, resultErr error) {
	defer func() {
		if recover() != nil {
			processed = false
			resultErr = ErrDeprovision
		}
	}()
	return reconciler.Handle(ctx, body, headers)
}

func writeWebhookResult(writer http.ResponseWriter, status int, processed, rejected bool) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	if rejected {
		_, _ = io.WriteString(writer, "{\"code\":\"webhook_rejected\"}\n")
		return
	}
	if processed {
		_, _ = io.WriteString(writer, "{\"processed\":true}\n")
		return
	}
	_, _ = io.WriteString(writer, "{\"processed\":false}\n")
}

func writeWebhookUnavailable(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Retry-After", "5")
	writer.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(writer, "{\"code\":\"webhook_unavailable\"}\n")
}

func NewDeprovisionReconciler(store *MemoryStore, verifier *WebhookVerifier, auditor DeprovisionAuditor) (*DeprovisionReconciler, error) {
	if store == nil || verifier == nil || nilInterface(auditor) {
		return nil, ErrConfiguration
	}
	return &DeprovisionReconciler{store: store, verifier: verifier, auditor: auditor}, nil
}

func (reconciler *DeprovisionReconciler) Handle(ctx context.Context, body []byte, headers WebhookHeaders) (bool, error) {
	if reconciler == nil || reconciler.store == nil || reconciler.verifier == nil || nilInterface(reconciler.auditor) || !validContext(ctx) {
		return false, ErrDeprovision
	}
	event, replay, err := reconciler.verifier.Verify(body, headers)
	if err != nil {
		return false, ErrDeprovision
	}
	if replay {
		return false, nil
	}
	if event.Kind() != "scim.member.delete" {
		reconciler.verifier.Release(event.EventID)
		return false, ErrDeprovision
	}
	if err := reconciler.store.deprovisionMember(ctx, event.EventID, event.ObjectID, reconciler.auditor); err != nil {
		reconciler.verifier.Release(event.EventID)
		return false, ErrDeprovision
	}
	return true, nil
}

func (store *MemoryStore) deprovisionMember(ctx context.Context, eventID, memberReference string, auditor DeprovisionAuditor) error {
	if store == nil || !validContext(ctx) || !validWebhookEventID(eventID) || !validReference(memberReference, "member-") || nilInterface(auditor) {
		return ErrDeprovision
	}
	store.mu.RLock()
	key, principal, grantIDs, err := store.deprovisionSnapshotLocked(memberReference)
	store.mu.RUnlock()
	if err != nil {
		return ErrDeprovision
	}
	auditEvent := DeprovisionAuditEvent{EventID: eventID, OrganizationID: principal.organizationID, PrincipalID: principal.id,
		MemberReference: memberReference, GrantIDs: append([]domain.ProductID(nil), grantIDs...)}
	if err := recordDeprovisionAudit(auditor, ctx, auditEvent); err != nil || ctx.Err() != nil {
		return ErrDeprovision
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	currentKey, currentPrincipal, currentGrantIDs, err := store.deprovisionSnapshotLocked(memberReference)
	if err != nil || currentKey != key || currentPrincipal != principal || !equalProductIDs(currentGrantIDs, grantIDs) {
		return ErrDeprovision
	}
	currentPrincipal.active = false
	store.principals[currentKey] = currentPrincipal
	for _, id := range currentGrantIDs {
		delete(store.grants, id)
	}
	return nil
}

func (store *MemoryStore) deprovisionSnapshotLocked(memberReference string) (string, Principal, []domain.ProductID, error) {
	var key string
	var principal Principal
	for candidateKey, candidate := range store.principals {
		if candidate.memberReference == memberReference {
			if key != "" {
				return "", Principal{}, nil, ErrDeprovision
			}
			key, principal = candidateKey, candidate
		}
	}
	if key == "" || !principal.validRecord() || !principal.active {
		return "", Principal{}, nil, ErrDeprovision
	}
	grants := make([]WorkspaceGrant, 0)
	for _, grant := range store.grants {
		if grant.organizationID == principal.organizationID && grant.principalID == principal.id {
			grants = append(grants, grant)
		}
	}
	sort.Slice(grants, func(first, second int) bool { return grants[first].id.String() < grants[second].id.String() })
	grantIDs := make([]domain.ProductID, len(grants))
	for index, grant := range grants {
		grantIDs[index] = grant.id
	}
	return key, principal, grantIDs, nil
}

func equalProductIDs(first, second []domain.ProductID) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func recordDeprovisionAudit(auditor DeprovisionAuditor, ctx context.Context, event DeprovisionAuditEvent) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrDeprovision
		}
	}()
	return auditor.Record(ctx, event)
}

func validWebhookEvent(event WebhookEvent, projectID string, now time.Time, tolerance time.Duration) bool {
	parsed, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != event.Timestamp ||
		parsed.Before(now.Add(-tolerance)) || parsed.After(now.Add(tolerance)) || event.ProjectID != projectID || !validWebhookEventID(event.EventID) || event.Source != "SCIM" || event.Vertical != "B2B" || !validReference(event.WorkspaceID, "workspace-") || !validReference(event.Details.OrganizationReference, "organization-") {
		return false
	}
	return event.ObjectType == "member" && validReference(event.ObjectID, "member-") && validWebhookMember(event)
}

func validWebhookMember(event WebhookEvent) bool {
	if event.Action == "DELETE" {
		return len(event.Member) == 0
	}
	if event.Action != "CREATE" && event.Action != "UPDATE" || len(event.Member) == 0 || len(event.Member) > maximumWebhookBytes {
		return false
	}
	var member struct {
		MemberReference       string `json:"member_id"`
		OrganizationReference string `json:"organization_id"`
	}
	return json.Unmarshal(event.Member, &member) == nil && member.MemberReference == event.ObjectID &&
		member.OrganizationReference == event.Details.OrganizationReference
}

func validWebhookMessageID(value string) bool {
	return len(value) > 4 && len(value) <= 128 && strings.HasPrefix(value, "msg_") && validTokenCharacters(value)
}

func validWebhookEventID(value string) bool {
	return len(value) >= 24 && len(value) <= 128 && (strings.HasPrefix(value, "webhook-event-live-") || strings.HasPrefix(value, "webhook-event-test-")) && validTokenCharacters(value)
}

func validTokenCharacters(value string) bool {
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validateUniqueJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrWebhookVerification
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrWebhookVerification
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return ErrWebhookVerification
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrWebhookVerification
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return ErrWebhookVerification
	}
	closing, err := decoder.Token()
	if err != nil || closing != map[json.Delim]json.Delim{'{': '}', '[': ']'}[delimiter] {
		return ErrWebhookVerification
	}
	return nil
}
