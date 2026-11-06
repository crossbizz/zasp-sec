package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"reflect"
	"strconv"
	"time"
	"unicode/utf8"

	assoc "github.com/zasp-ai/zasp-sec/services/platform/gatewayassociationwire"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type AgentDeviceAssociationMutation struct {
	AgentID, DeviceID, AssociationID, ChallengeID, IdempotencyKey string
	ExpectedVersion                                               int64
	TTLSeconds                                                    int32
	RequestDigest, ChallengeSHA256, Nonce                         []byte
}
type AgentDeviceAssociationAuthority interface {
	MutateAssociation(context.Context, RequestIdentity, string, AgentDeviceAssociationMutation) (json.RawMessage, error)
	ListAssociations(context.Context, RequestIdentity, string, string, int) (json.RawMessage, error)
}
type AgentDeviceAssociationHandlerConfig struct {
	NewProductID func() (string, error)
	NewNonce     func() ([]byte, error)
	Clock        func() time.Time
	SigningKey   []byte
}
type agentDeviceAssociationHandler struct {
	repository AgentDeviceAssociationAuthority
	config     AgentDeviceAssociationHandlerConfig
}

func NewAgentDeviceAssociationHTTPHandler(repository AgentDeviceAssociationAuthority, c AgentDeviceAssociationHandlerConfig) (http.Handler, error) {
	if nilInterface(repository) || c.NewProductID == nil || c.NewNonce == nil || c.Clock == nil || len(c.SigningKey) < 32 {
		return nil, ErrRepositoryConfiguration
	}
	c.SigningKey = append([]byte(nil), c.SigningKey...)
	return &agentDeviceAssociationHandler{repository, c}, nil
}
func agentAssociationTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && t.Location() == time.UTC && t.Nanosecond()%1000 == 0
}
func agentAssociationNowFresh(i RequestIdentity, now time.Time) bool {
	return !now.IsZero() && now.Year() >= 1 && now.Year() <= 9999 && now.Location() == time.UTC && i.CredentialKind == CredentialBrowserSession && i.FreshAuthenticated && agentAssociationTime(i.FreshAuthExpiresAt) && i.FreshAuthExpiresAt.After(now) && !i.FreshAuthExpiresAt.After(now.Add(5*time.Minute))
}
func (h *agentDeviceAssociationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	identity, ok := IdentityFromRequest(r)
	route, routed := RoutedOperationFromRequest(r)
	if !ok || !routed || r.Context().Err() != nil {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	op := route.OperationID
	agent := route.PathParameters["id"]
	if !validProductID(agent) || !stringIn(op, "createAgentDeviceIntent", "activateAgentDeviceAssociation", "revokeAgentDeviceAssociation", "listAgentDeviceAssociations") {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	if grant, present := requestAuthorizationFromContext(r.Context()); present && !agentAssociationGrantMatches(grant, identity, op, agent) {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	if op == "listAgentDeviceAssociations" {
		h.list(w, r, identity, agent)
		return
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Body == nil || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" || !agentAssociationNowFresh(identity, h.config.Clock()) || !validSensorFreshAuthority(r, identity) {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	key, valid := sensorMutationHeaders(r, false)
	if !valid {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 16385))
	if e != nil || len(raw) > 16384 {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	in := AgentDeviceAssociationMutation{AgentID: agent, IdempotencyKey: key}
	semantic := map[string]any{}
	switch op {
	case "createAgentDeviceIntent":
		if len(route.PathParameters) != 1 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		var body struct {
			DeviceID        string `json:"device_id"`
			ExpectedVersion int64  `json:"expected_association_version"`
			TTL             int32  `json:"ttl_seconds"`
		}
		if decodeGatewayBootstrapJSON(raw, &body) != nil || !validProductID(body.DeviceID) || body.ExpectedVersion < 0 || body.TTL < 60 || body.TTL > 300 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		in.DeviceID = body.DeviceID
		in.ExpectedVersion = body.ExpectedVersion
		in.TTLSeconds = body.TTL
		semantic = map[string]any{"device_id": body.DeviceID, "expected_association_version": body.ExpectedVersion, "ttl_seconds": body.TTL}
		in.ChallengeID, e = h.config.NewProductID()
		if e != nil || !validProductID(in.ChallengeID) {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		in.Nonce, e = h.config.NewNonce()
		if e != nil || len(in.Nonce) != 32 {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
	case "activateAgentDeviceAssociation":
		var body struct {
			ChallengeID     string `json:"challenge_id"`
			ChallengeSHA256 string `json:"challenge_sha256"`
			ExpectedVersion int64  `json:"expected_association_version"`
		}
		if decodeGatewayBootstrapJSON(raw, &body) != nil || !validProductID(body.ChallengeID) || !agentAssociationDigest(body.ChallengeSHA256) || body.ExpectedVersion < 0 || body.ExpectedVersion == math.MaxInt64 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		in.AssociationID = route.PathParameters["associationId"]
		in.ChallengeID = body.ChallengeID
		in.ExpectedVersion = body.ExpectedVersion
		in.ChallengeSHA256, _ = hex.DecodeString(body.ChallengeSHA256)
		semantic = map[string]any{"challenge_id": body.ChallengeID, "challenge_sha256": body.ChallengeSHA256, "expected_association_version": body.ExpectedVersion}
	case "revokeAgentDeviceAssociation":
		var body struct {
			ExpectedVersion int64 `json:"expected_association_version"`
		}
		if decodeGatewayBootstrapJSON(raw, &body) != nil || body.ExpectedVersion < 0 || body.ExpectedVersion == math.MaxInt64 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		in.AssociationID = route.PathParameters["associationId"]
		in.ExpectedVersion = body.ExpectedVersion
		semantic["expected_association_version"] = body.ExpectedVersion
	}
	if op != "createAgentDeviceIntent" && (!validProductID(in.AssociationID) || len(route.PathParameters) != 2) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	canonical, e := json.Marshal(map[string]any{"scope": map[string]string{"organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String()}, "actor": identity.PrincipalID.String(), "operation": op, "agent_id": agent, "association_id": in.AssociationID, "idempotency_key": key, "body": semantic})
	if e != nil {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	digest := sha256.Sum256(canonical)
	in.RequestDigest = digest[:]
	result, e := h.repository.MutateAssociation(r.Context(), identity, op, in)
	if e != nil {
		writeProductionError(w, r, e)
		return
	}
	public, newMutation, e := validateAgentDeviceAssociationMutationResult(result, op, identity, in)
	if e != nil || r.Context().Err() != nil || !agentAssociationNowFresh(identity, h.config.Clock()) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	status := http.StatusOK
	if op == "createAgentDeviceIntent" && newMutation {
		status = http.StatusCreated
	}
	writeJSONValue(w, r, status, public, nil)
}
func agentAssociationGrantMatches(g RequestAuthorization, i RequestIdentity, op, agent string) bool {
	if g.OperationID != op || g.Identity.PrincipalID != i.PrincipalID || g.Identity.Scope != i.Scope || g.Credential.Kind != i.CredentialKind || g.Credential.ID == "" || g.Collection || len(g.Targets) != 1 || len(g.Allowed) != 1 || g.Targets[0] != g.Allowed[0] {
		return false
	}
	target := g.Allowed[0]
	return target.Scope == i.Scope && target.Kind == "agent" && target.ID == agent && (target.SourceID == "" || target.SourceID == agent) && target.Version > 0
}
func agentAssociationDigest(v string) bool {
	if len(v) != 64 {
		return false
	}
	decoded, e := hex.DecodeString(v)
	return e == nil && hex.EncodeToString(decoded) == v
}
func agentAssociationObject(raw json.RawMessage, keys ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if decodeGatewayBootstrapJSON(raw, &fields) != nil || len(fields) != len(keys) {
		return nil, ErrRepositoryUnavailable
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return nil, ErrRepositoryUnavailable
		}
	}
	return fields, nil
}
func agentAssociationString(raw json.RawMessage) (string, bool) {
	var s string
	e := json.Unmarshal(raw, &s)
	return s, e == nil && !bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
func agentAssociationInteger(raw json.RawMessage) (int64, bool) {
	var n int64
	if json.Unmarshal(raw, &n) != nil || strconv.FormatInt(n, 10) != string(raw) || n < 0 {
		return 0, false
	}
	return n, true
}
func agentAssociationTimestamp(raw json.RawMessage) (time.Time, bool) {
	s, ok := agentAssociationString(raw)
	if !ok {
		return time.Time{}, false
	}
	v, e := time.Parse(time.RFC3339Nano, s)
	return v, e == nil && agentAssociationTime(v) && v.Format(time.RFC3339Nano) == s
}
func validateAgentDeviceAssociationMutationResult(raw json.RawMessage, op string, identity RequestIdentity, in AgentDeviceAssociationMutation) (json.RawMessage, bool, error) {
	fail := func() (json.RawMessage, bool, error) { return nil, false, ErrRepositoryUnavailable }
	fields, e := agentAssociationObject(raw, "receipt", "challenge", "replayed", "new_mutation")
	if e != nil {
		return fail()
	}
	var replayed, newMutation bool
	if json.Unmarshal(fields["replayed"], &replayed) != nil || json.Unmarshal(fields["new_mutation"], &newMutation) != nil || bytes.Equal(fields["replayed"], []byte("null")) || bytes.Equal(fields["new_mutation"], []byte("null")) || replayed == newMutation {
		return fail()
	}
	receipt, e := agentAssociationObject(fields["receipt"], "operation", "association_id", "challenge_id", "version", "recorded_state", "recorded_at")
	if e != nil {
		return fail()
	}
	operation, _ := agentAssociationString(receipt["operation"])
	pair, _ := agentAssociationString(receipt["association_id"])
	state, _ := agentAssociationString(receipt["recorded_state"])
	version, validVersion := agentAssociationInteger(receipt["version"])
	_, validTime := agentAssociationTimestamp(receipt["recorded_at"])
	if operation != op || !validProductID(pair) || !validVersion || !validTime || in.AssociationID != "" && pair != in.AssociationID {
		return fail()
	}
	expectedVersion := in.ExpectedVersion
	if op != "createAgentDeviceIntent" {
		if expectedVersion == math.MaxInt64 {
			return fail()
		}
		expectedVersion++
	}
	if version != expectedVersion {
		return fail()
	}
	if op == "createAgentDeviceIntent" {
		if state != "intent_created" {
			return fail()
		}
		envelope, e := assoc.ParseChallengeEnvelope(fields["challenge"])
		if e != nil {
			return fail()
		}
		challenge, e := assoc.ChallengeFromEnvelope(envelope)
		challengeID, _ := agentAssociationString(receipt["challenge_id"])
		if e != nil || challengeID != challenge.ChallengeID || challenge.AssociationID != pair || challenge.AgentID != in.AgentID || challenge.DeviceID != in.DeviceID || challenge.OrganizationID != identity.Scope.OrganizationID().String() || challenge.WorkspaceID != identity.Scope.WorkspaceID().String() || challenge.EnvironmentID != identity.Scope.EnvironmentID().String() || challenge.ExpectedAssociationVersion != uint64(in.ExpectedVersion) || newMutation && (challenge.ChallengeID != in.ChallengeID || challenge.Nonce != base64.RawURLEncoding.EncodeToString(in.Nonce)) {
			return fail()
		}
	} else {
		if !bytes.Equal(bytes.TrimSpace(fields["challenge"]), []byte("null")) {
			return fail()
		}
		if op == "activateAgentDeviceAssociation" {
			id, _ := agentAssociationString(receipt["challenge_id"])
			if state != "activated" || id != in.ChallengeID {
				return fail()
			}
		} else if op == "revokeAgentDeviceAssociation" {
			if state != "revoked" || !bytes.Equal(bytes.TrimSpace(receipt["challenge_id"]), []byte("null")) {
				return fail()
			}
		} else {
			return fail()
		}
	}
	public, e := json.Marshal(struct {
		Receipt   json.RawMessage `json:"receipt"`
		Challenge json.RawMessage `json:"challenge"`
		Replayed  bool            `json:"replayed"`
	}{fields["receipt"], fields["challenge"], replayed})
	return public, newMutation, e
}

// The page can contain up to100 individually bounded items. Keep the
// existing16KiB mutation/bootstrap boundary while admitting the API1MiB page.
func agentAssociationPageObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) || !gatewayBootstrapSurrogatesValid(raw) {
		return nil, ErrRepositoryUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if !gatewayBootstrapScanJSON(decoder, 0) {
		return nil, ErrRepositoryUnavailable
	}
	if _, e := decoder.Token(); e != io.EOF {
		return nil, ErrRepositoryUnavailable
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 2 || fields["items"] == nil || fields["next_association_id"] == nil {
		return nil, ErrRepositoryUnavailable
	}
	return fields, nil
}

func validateAgentDeviceAssociationList(raw json.RawMessage, agent string, limit int) ([]json.RawMessage, string, error) {
	fail := func() ([]json.RawMessage, string, error) { return nil, "", ErrRepositoryUnavailable }
	fields, e := agentAssociationPageObject(raw)
	if e != nil {
		return fail()
	}
	var items []json.RawMessage
	if json.Unmarshal(fields["items"], &items) != nil || items == nil || len(items) > limit {
		return fail()
	}
	last := ""
	for _, item := range items {
		id, e := validateAgentAssociationItem(item, agent)
		if e != nil || id <= last {
			return fail()
		}
		last = id
	}
	next := ""
	if !bytes.Equal(bytes.TrimSpace(fields["next_association_id"]), []byte("null")) {
		var ok bool
		next, ok = agentAssociationString(fields["next_association_id"])
		if !ok || !validProductID(next) || next != last || len(items) != limit {
			return fail()
		}
	}
	return items, next, nil
}
func validateAgentAssociationCredential(raw json.RawMessage) (time.Time, error) {
	fields, e := agentAssociationObject(raw, "credential_id", "credential_generation", "expires_at")
	if e != nil {
		return time.Time{}, e
	}
	id, _ := agentAssociationString(fields["credential_id"])
	generation, ok := agentAssociationInteger(fields["credential_generation"])
	expiry, valid := agentAssociationTimestamp(fields["expires_at"])
	if !validProductID(id) || !ok || generation < 1 || !valid {
		return time.Time{}, ErrRepositoryUnavailable
	}
	return expiry, nil
}
func validateAgentAssociationAcceptance(raw json.RawMessage, challenge assoc.Challenge, envelope assoc.ChallengeEnvelope) error {
	fields, e := agentAssociationObject(raw, "request_sha256", "credential", "accepted_at", "expires_at")
	if e != nil {
		return e
	}
	digest, _ := agentAssociationString(fields["request_sha256"])
	// This metadata DTO retains the original raw-body hash, but not those
	// original outer bytes. Native acceptance/confirmation validates that hash;
	// reserializing the envelope here would reject valid original JSON layouts.
	if !agentAssociationDigest(digest) {
		return ErrRepositoryUnavailable
	}
	credentialExpiry, e := validateAgentAssociationCredential(fields["credential"])
	accepted, ok := agentAssociationTimestamp(fields["accepted_at"])
	expires, valid := agentAssociationTimestamp(fields["expires_at"])
	expected := challenge.ExpiresAt
	if credentialExpiry.Before(expected) {
		expected = credentialExpiry
	}
	if e != nil || !ok || !valid || !accepted.Before(expires) || !expires.Equal(expected) {
		return ErrRepositoryUnavailable
	}
	return nil
}
func validateAgentAssociationItem(raw json.RawMessage, agent string) (string, error) {
	fail := func() (string, error) { return "", ErrRepositoryUnavailable }
	fields, e := agentAssociationObject(raw, "association_id", "agent_id", "device_id", "version", "state", "unavailable_reason", "source_identity", "admission_snapshot", "device_credential", "created_by", "activated_by", "created_at", "activated_at", "revoked_at", "pending_intent")
	if e != nil {
		return fail()
	}
	id, _ := agentAssociationString(fields["association_id"])
	agentID, _ := agentAssociationString(fields["agent_id"])
	device, _ := agentAssociationString(fields["device_id"])
	creator, _ := agentAssociationString(fields["created_by"])
	state, _ := agentAssociationString(fields["state"])
	reason, _ := agentAssociationString(fields["unavailable_reason"])
	version, validVersion := agentAssociationInteger(fields["version"])
	if !validProductID(id) || agentID != agent || !validProductID(device) || !validProductID(creator) || !validVersion || !stringIn(state, "none", "admitted", "revoked", "unavailable") || !stringIn(reason, "none", "source_stale", "source_removed", "source_identity_changed", "device_unavailable", "credential_expired", "credential_rotated", "credential_revoked") {
		return fail()
	}
	if _, ok := agentAssociationTimestamp(fields["created_at"]); !ok {
		return fail()
	}
	isNull := func(key string) bool { return bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) }
	for _, key := range []string{"activated_at", "revoked_at"} {
		if !isNull(key) {
			if _, ok := agentAssociationTimestamp(fields[key]); !ok {
				return fail()
			}
		}
	}
	if !isNull("activated_by") {
		actor, _ := agentAssociationString(fields["activated_by"])
		if !validProductID(actor) {
			return fail()
		}
	}
	if state == "none" && (version != 0 || !isNull("source_identity") || !isNull("admission_snapshot") || !isNull("device_credential") || !isNull("activated_by") || !isNull("activated_at") || !isNull("revoked_at")) {
		return fail()
	}
	if state == "admitted" && (reason != "none" || isNull("source_identity") || isNull("admission_snapshot") || isNull("device_credential") || isNull("activated_by") || isNull("activated_at")) {
		return fail()
	}
	if state == "unavailable" && reason == "none" || state != "unavailable" && reason != "none" {
		return fail()
	}
	if !isNull("source_identity") {
		source, e := agentAssociationObject(fields["source_identity"], "integration_id", "provider", "source", "identity_namespace", "source_native_id", "rule_version", "agent_id")
		if e != nil {
			return fail()
		}
		integration, _ := agentAssociationString(source["integration_id"])
		sourceAgent, _ := agentAssociationString(source["agent_id"])
		rule, ok := agentAssociationInteger(source["rule_version"])
		if !validProductID(integration) || sourceAgent != agent || !ok || rule < 1 {
			return fail()
		}
		for _, key := range []string{"provider", "source", "identity_namespace", "source_native_id"} {
			text, ok := agentAssociationString(source[key])
			if !ok || len(text) == 0 || len(text) > 4096 {
				return fail()
			}
		}
	}
	if !isNull("admission_snapshot") {
		snapshot, e := agentAssociationObject(fields["admission_snapshot"], "snapshot_id", "evidence_id", "generation", "content_sha256", "observed_at", "fresh_until")
		if e != nil {
			return fail()
		}
		for _, key := range []string{"snapshot_id", "evidence_id"} {
			value, _ := agentAssociationString(snapshot[key])
			if !validProductID(value) {
				return fail()
			}
		}
		generation, ok := agentAssociationInteger(snapshot["generation"])
		digest, _ := agentAssociationString(snapshot["content_sha256"])
		observed, valid := agentAssociationTimestamp(snapshot["observed_at"])
		fresh, validFresh := agentAssociationTimestamp(snapshot["fresh_until"])
		if !ok || generation < 1 || !agentAssociationDigest(digest) || !valid || !validFresh || !fresh.After(observed) {
			return fail()
		}
	}
	if !isNull("device_credential") {
		if _, e := validateAgentAssociationCredential(fields["device_credential"]); e != nil {
			return fail()
		}
	}
	if !isNull("pending_intent") {
		pending, e := agentAssociationObject(fields["pending_intent"], "challenge_id", "challenge_wire", "challenge_sha256", "created_by", "created_at", "expires_at", "state", "acceptance")
		if e != nil {
			return fail()
		}
		wireText, _ := agentAssociationString(pending["challenge_wire"])
		digest, _ := agentAssociationString(pending["challenge_sha256"])
		envelope := assoc.ChallengeEnvelope{Schema: assoc.EnvelopeSchema, ChallengeWire: wireText, ChallengeSHA256: digest}
		challenge, e := assoc.ChallengeFromEnvelope(envelope)
		challengeID, _ := agentAssociationString(pending["challenge_id"])
		pendingCreator, _ := agentAssociationString(pending["created_by"])
		pendingState, _ := agentAssociationString(pending["state"])
		created, valid := agentAssociationTimestamp(pending["created_at"])
		expires, validExpiry := agentAssociationTimestamp(pending["expires_at"])
		if e != nil || challenge.ChallengeID != challengeID || challenge.AssociationID != id || challenge.AgentID != agent || challenge.DeviceID != device || !validProductID(pendingCreator) || !stringIn(pendingState, "pending_device", "pending_human", "expired", "superseded") || !valid || !validExpiry || !expires.Equal(challenge.ExpiresAt) || !created.Before(expires) {
			return fail()
		}
		if !bytes.Equal(bytes.TrimSpace(pending["acceptance"]), []byte("null")) {
			if validateAgentAssociationAcceptance(pending["acceptance"], challenge, envelope) != nil {
				return fail()
			}
		} else if pendingState == "pending_human" {
			return fail()
		}
	}
	return id, nil
}

type agentAssociationCursor struct {
	Version         int            `json:"v"`
	OrganizationID  string         `json:"organization_id"`
	WorkspaceID     string         `json:"workspace_id"`
	EnvironmentID   string         `json:"environment_id"`
	PrincipalID     string         `json:"principal_id"`
	CredentialKind  CredentialKind `json:"credential_kind"`
	CredentialID    string         `json:"credential_id"`
	AgentID         string         `json:"agent_id"`
	AgentVersion    int64          `json:"agent_version"`
	DesiredRevision int64          `json:"desired_revision"`
	Generation      int64          `json:"generation"`
	StoreID         string         `json:"store_id"`
	ModelID         string         `json:"model_id"`
	Limit           int            `json:"limit"`
	AfterID         string         `json:"after_association_id"`
	ProfileChecksum string         `json:"profile_checksum"`
	ExpiresAt       time.Time      `json:"expires_at"`
}

func (h *agentDeviceAssociationHandler) list(w http.ResponseWriter, r *http.Request, identity RequestIdentity, agent string) {
	if r.Method != http.MethodGet || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.URL.ForceQuery || len(r.Header.Values("Idempotency-Key")) != 0 || len(r.Header.Values("If-Match")) != 0 || len(r.Header.Values("X-Zasp-Fresh-Auth")) != 0 {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	query, ok := exactWorkflowQuery(r.URL.RawQuery, map[string]int{"limit": 3, "cursor": 4096})
	if !ok {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	limit := 20
	if values, present := query["limit"]; present {
		v, e := strconv.Atoi(values[0])
		if e != nil || v < 1 || v > 100 || strconv.Itoa(v) != values[0] {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		limit = v
	}
	grant, present := requestAuthorizationFromContext(r.Context())
	profile, hasProfile := h.repository.(interface{ AgentDeviceAssociationProfileChecksum() string })
	if !present || !hasProfile || !agentAssociationGrantMatches(grant, identity, "listAgentDeviceAssociations", agent) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	pin := profile.AgentDeviceAssociationProfileChecksum()
	now := h.config.Clock().UTC().Truncate(time.Microsecond)
	if !migrations.IsAgentDeviceAssociationProfileChecksum(pin) || !agentAssociationTime(now) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	binding := agentAssociationCursor{Version: 1, OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), PrincipalID: identity.PrincipalID.String(), CredentialKind: grant.Credential.Kind, CredentialID: grant.Credential.ID, AgentID: agent, AgentVersion: grant.Allowed[0].Version, DesiredRevision: grant.Revision.Desired, Generation: grant.Revision.Generation, StoreID: grant.Revision.StoreID, ModelID: grant.Revision.ModelID, Limit: limit, ProfileChecksum: pin}
	after := ""
	if values, present := query["cursor"]; present {
		decoded, e := base64.RawURLEncoding.DecodeString(values[0])
		if e != nil || base64.RawURLEncoding.EncodeToString(decoded) != values[0] || len(decoded) <= sha256.Size {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		payload, signature := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
		mac := hmac.New(sha256.New, h.config.SigningKey)
		_, _ = mac.Write(payload)
		var cursor agentAssociationCursor
		if !hmac.Equal(signature, mac.Sum(nil)) || decodeGatewayBootstrapJSON(payload, &cursor) != nil || !validProductID(cursor.AfterID) || !agentAssociationTime(cursor.ExpiresAt) || !cursor.ExpiresAt.After(now) || cursor.ExpiresAt.After(now.Add(5*time.Minute)) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		canonical, _ := json.Marshal(cursor)
		if !bytes.Equal(canonical, payload) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		after = cursor.AfterID
		cursor.AfterID = ""
		cursor.ExpiresAt = time.Time{}
		if !reflect.DeepEqual(cursor, binding) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
	}
	raw, e := h.repository.ListAssociations(r.Context(), identity, agent, after, limit)
	if e != nil {
		writeProductionError(w, r, e)
		return
	}
	items, next, e := validateAgentDeviceAssociationList(raw, agent, limit)
	if e != nil || r.Context().Err() != nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	for _, item := range items {
		fields, _ := agentAssociationObject(item, "association_id", "agent_id", "device_id", "version", "state", "unavailable_reason", "source_identity", "admission_snapshot", "device_credential", "created_by", "activated_by", "created_at", "activated_at", "revoked_at", "pending_intent")
		id, _ := agentAssociationString(fields["association_id"])
		if id <= after {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
	}
	var cursor *string
	if next != "" {
		binding.AfterID = next
		binding.ExpiresAt = now.Add(5 * time.Minute)
		payload, _ := json.Marshal(binding)
		mac := hmac.New(sha256.New, h.config.SigningKey)
		_, _ = mac.Write(payload)
		encoded := base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
		cursor = &encoded
	}
	response := struct {
		Items        []json.RawMessage `json:"items"`
		NextCursor   *string           `json:"next_cursor"`
		Capabilities struct {
			CanManage bool `json:"can_manage"`
		} `json:"capabilities"`
	}{Items: items, NextCursor: cursor}
	response.Capabilities.CanManage = grant.AssociationCanManage
	writeJSONValue(w, r, http.StatusOK, response, nil)
}
