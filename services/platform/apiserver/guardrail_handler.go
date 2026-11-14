package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/guardrail"
)

// The guardrail decision API (completion.sql, section V7). A gateway the
// customer already runs sends one interaction and is told to allow it, redact
// it or block it:
//
//	POST /api/v1/guardrails/decisions   createGuardrailDecision (API token)
//	GET  /api/v1/guardrails/policy      getGuardrailPolicy
//	PUT  /api/v1/guardrails/policy      putGuardrailPolicy
//
// The interaction text exists only in this process for the duration of the
// request. It is not logged, not sent to PostgreSQL and not stored: the
// decision statement receives the matched rule identifiers, the size and the
// SHA-256 digest of the text, and nothing else of it.

const (
	currentGuardrailDecideSQL    = `SELECT zasp_authorization80.guardrail_decide($1,$2,$3,$4,$5::jsonb)`
	currentGuardrailPolicySQL    = `SELECT zasp_authorization80.guardrail_policy($1,$2,$3)`
	currentGuardrailSetPolicySQL = `SELECT zasp_authorization80.guardrail_set_policy($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`

	// The request body is the text with JSON escaping (at most six bytes
	// for one byte of text) plus the other members.
	guardrailMaxBodyBytes = 6*guardrail.MaxTextBytes + 4096
)

var guardrailIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

// GuardrailMatchedRule is one rule that matched an interaction.
type GuardrailMatchedRule struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Mode     string `json:"mode"`
	Count    int    `json:"count"`
}

// GuardrailDecision is the answer to one interaction. RedactedText is
// present only when Decision is redact.
type GuardrailDecision struct {
	DecisionID    string                 `json:"decision_id"`
	Decision      string                 `json:"decision"`
	RedactedText  *string                `json:"redacted_text,omitempty"`
	MatchedRules  []GuardrailMatchedRule `json:"matched_rules"`
	PolicyVersion int64                  `json:"policy_version"`
}

// GuardrailPolicyRule is one rule of the catalog with the Environment's mode.
type GuardrailPolicyRule struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Mode        string `json:"mode"`
	DefaultMode string `json:"default_mode"`
	Redactable  bool   `json:"redactable"`
}

// GuardrailPolicy is the guardrail policy of an Environment: every rule of
// the catalog with its mode. Version is 0 while the defaults apply.
type GuardrailPolicy struct {
	EnvironmentID string                `json:"environment_id"`
	Version       int64                 `json:"version"`
	UpdatedAt     *time.Time            `json:"updated_at"`
	Rules         []GuardrailPolicyRule `json:"rules"`
}

type guardrailHTTPHandler struct {
	database     JSONDatabase
	newProductID func() (string, error)
}

// guardrailSurface serves the guardrail operations and passes every other
// operation to the surface it wraps.
type guardrailSurface struct {
	next      http.Handler
	guardrail *guardrailHTTPHandler
}

func newGuardrailSurface(next http.Handler, database JSONDatabase, newProductID func() (string, error)) (http.Handler, error) {
	if nilInterface(next) || nilInterface(database) || newProductID == nil {
		return nil, ErrRepositoryConfiguration
	}
	return &guardrailSurface{next: next, guardrail: &guardrailHTTPHandler{database: database, newProductID: newProductID}}, nil
}

func (surface *guardrailSurface) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	routed, ok := RoutedOperationFromRequest(request)
	if ok && stringIn(routed.OperationID, "createGuardrailDecision", "getGuardrailPolicy", "putGuardrailPolicy") {
		surface.guardrail.ServeHTTP(writer, request, routed.OperationID)
		return
	}
	surface.next.ServeHTTP(writer, request)
}

func (handler *guardrailHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request, operation string) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	switch operation {
	case "createGuardrailDecision":
		handler.decide(writer, request, identity)
	case "getGuardrailPolicy":
		handler.getPolicy(writer, request, identity)
	case "putGuardrailPolicy":
		handler.putPolicy(writer, request, identity)
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
	}
}

type guardrailDecisionInput struct {
	Direction string  `json:"direction"`
	Text      *string `json:"text"`
	AgentID   *string `json:"agent_id"`
	ToolName  *string `json:"tool_name"`
}

type guardrailMatchedInput struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	DefaultMode string `json:"default_mode"`
	Redactable  bool   `json:"redactable"`
	Count       int    `json:"count"`
}

// guardrailDecisionRecord is everything of an interaction that reaches the
// database. It has no member that could hold the text.
type guardrailDecisionRecord struct {
	ID            string                  `json:"id"`
	Direction     string                  `json:"direction"`
	InputBytes    int                     `json:"input_bytes"`
	ContentDigest string                  `json:"content_digest"`
	AgentID       *string                 `json:"agent_id"`
	ToolName      *string                 `json:"tool_name"`
	Matched       []guardrailMatchedInput `json:"matched"`
}

func (handler *guardrailHTTPHandler) decide(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	// The gateway authenticates with an API token.
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || identity.CredentialKind != CredentialBearerToken || request.Body == nil || request.Header.Get("Content-Type") != "application/json" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, guardrailMaxBodyBytes+1))
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	if len(raw) > guardrailMaxBodyBytes {
		writeProductionStatusError(writer, request, http.StatusRequestEntityTooLarge, "interaction_too_large", "The interaction text is limited to 32768 bytes", false)
		return
	}
	var input guardrailDecisionInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.Text == nil || !stringIn(input.Direction, string(guardrail.DirectionInput), string(guardrail.DirectionOutput)) ||
		input.AgentID != nil && !guardrailIdentifierPattern.MatchString(*input.AgentID) || input.ToolName != nil && !guardrailIdentifierPattern.MatchString(*input.ToolName) || !utf8.ValidString(*input.Text) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	text := *input.Text
	if len(text) > guardrail.MaxTextBytes {
		writeProductionStatusError(writer, request, http.StatusRequestEntityTooLarge, "interaction_too_large", "The interaction text is limited to 32768 bytes", false)
		return
	}
	matches, ok := guardrail.Detect(text, guardrail.Direction(input.Direction))
	if !ok {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	id, err := handler.newProductID()
	if err != nil || !validProductID(id) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	counts := map[string]int{}
	for _, match := range matches {
		counts[match.RuleID]++
	}
	digest := sha256.Sum256([]byte(text))
	record := guardrailDecisionRecord{ID: id, Direction: input.Direction, InputBytes: len(text), ContentDigest: "sha256:" + hex.EncodeToString(digest[:]), AgentID: input.AgentID, ToolName: input.ToolName, Matched: []guardrailMatchedInput{}}
	for _, rule := range guardrail.Rules() {
		if count := counts[rule.ID]; count > 0 {
			record.Matched = append(record.Matched, guardrailMatchedInput{ID: rule.ID, Category: rule.Category, DefaultMode: string(rule.DefaultMode), Redactable: rule.Redactable, Count: count})
		}
	}
	result, err := handler.recordDecision(request.Context(), identity, record)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	// The decision is PostgreSQL's. The redaction applies exactly the modes
	// it returned, and must come to the same decision.
	modes := map[string]guardrail.Mode{}
	for _, rule := range guardrail.Rules() {
		modes[rule.ID] = guardrail.ModeOff
	}
	for _, rule := range result.MatchedRules {
		modes[rule.ID] = guardrail.Mode(rule.Mode)
	}
	local := guardrail.Decide(text, matches, modes)
	if local.Decision != result.Decision || len(local.Rules) != len(result.MatchedRules) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	if result.Decision == guardrail.DecisionRedact {
		result.RedactedText = &local.RedactedText
	}
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}

func (handler *guardrailHTTPHandler) recordDecision(ctx context.Context, identity RequestIdentity, record guardrailDecisionRecord) (GuardrailDecision, error) {
	payload, err := json.Marshal(record)
	if err != nil {
		return GuardrailDecision{}, ErrRepositoryOperation
	}
	raw, err := handler.database.QueryJSON(ctx, currentGuardrailDecideSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), json.RawMessage(payload))
	if err != nil {
		return GuardrailDecision{}, discoveryProviderError(err)
	}
	var wire struct {
		ID            string                 `json:"id"`
		Decision      string                 `json:"decision"`
		Rules         []GuardrailMatchedRule `json:"rules"`
		PolicyVersion int64                  `json:"policy_version"`
	}
	if !exactJSONFields(raw, "decision", "id", "policy_version", "rules") || decodeStrictDiscovery(raw, &wire) != nil || wire.ID != record.ID || !stringIn(wire.Decision, guardrail.DecisionAllow, guardrail.DecisionRedact, guardrail.DecisionBlock) || wire.PolicyVersion < 0 || wire.PolicyVersion > 1000000 || wire.Rules == nil || len(wire.Rules) > len(record.Matched) {
		return GuardrailDecision{}, ErrRepositoryUnavailable
	}
	matched := map[string]guardrailMatchedInput{}
	for _, rule := range record.Matched {
		matched[rule.ID] = rule
	}
	seen := map[string]bool{}
	for _, applied := range wire.Rules {
		rule, known := guardrail.RuleByID(applied.ID)
		sent, found := matched[applied.ID]
		if !known || !found || seen[applied.ID] || applied.Category != rule.Category || applied.Count != sent.Count || applied.Mode == string(guardrail.ModeOff) || !guardrail.ValidMode(rule, guardrail.Mode(applied.Mode)) {
			return GuardrailDecision{}, ErrRepositoryUnavailable
		}
		seen[applied.ID] = true
	}
	return GuardrailDecision{DecisionID: wire.ID, Decision: wire.Decision, MatchedRules: wire.Rules, PolicyVersion: wire.PolicyVersion}, nil
}

// decodeGuardrailPolicy turns the stored modes into the full catalog view.
func decodeGuardrailPolicy(raw json.RawMessage, environmentID string, extra ...string) (GuardrailPolicy, error) {
	var wire struct {
		EnvironmentID string            `json:"environment_id"`
		Rules         map[string]string `json:"rules"`
		Version       int64             `json:"version"`
		UpdatedAt     *time.Time        `json:"updated_at"`
		AuditID       string            `json:"audit_id"`
		CorrelationID string            `json:"correlation_id"`
	}
	fields := append([]string{"environment_id", "rules", "updated_at", "version"}, extra...)
	if !exactJSONFields(raw, fields...) || decodeStrictDiscovery(raw, &wire) != nil || wire.EnvironmentID != environmentID || wire.Rules == nil || wire.Version < 0 || wire.Version > 1000000 || (wire.Version == 0) != (wire.UpdatedAt == nil) || wire.Version == 0 && len(wire.Rules) != 0 {
		return GuardrailPolicy{}, ErrRepositoryUnavailable
	}
	policy := GuardrailPolicy{EnvironmentID: wire.EnvironmentID, Version: wire.Version, UpdatedAt: wire.UpdatedAt, Rules: []GuardrailPolicyRule{}}
	for _, rule := range guardrail.Rules() {
		mode := rule.DefaultMode
		if stored, ok := wire.Rules[rule.ID]; ok {
			if !guardrail.ValidMode(rule, guardrail.Mode(stored)) {
				return GuardrailPolicy{}, ErrRepositoryUnavailable
			}
			mode = guardrail.Mode(stored)
			delete(wire.Rules, rule.ID)
		}
		policy.Rules = append(policy.Rules, GuardrailPolicyRule{ID: rule.ID, Category: rule.Category, Description: rule.Description, Mode: string(mode), DefaultMode: string(rule.DefaultMode), Redactable: rule.Redactable})
	}
	// A stored rule the catalog does not have is not served.
	if len(wire.Rules) != 0 {
		return GuardrailPolicy{}, ErrRepositoryUnavailable
	}
	return policy, nil
}

func (handler *guardrailHTTPHandler) getPolicy(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	environment := identity.Scope.EnvironmentID().String()
	raw, err := handler.database.QueryJSON(request.Context(), currentGuardrailPolicySQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), environment)
	if err != nil {
		writeProductionError(writer, request, discoveryProviderError(err))
		return
	}
	policy, err := decodeGuardrailPolicy(raw, environment)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", quoteVersion(policy.Version))
	writeJSONValue(writer, request, http.StatusOK, policy, nil)
}

func (handler *guardrailHTTPHandler) putPolicy(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	// The optimistic version makes a repeated request safe: the second one
	// names a version that is no longer current and is refused.
	_, expectedVersion, valid := discoveryMutationHeaders(request, true)
	var input struct {
		Rules map[string]string `json:"rules"`
	}
	if request.Method != http.MethodPut || request.URL.RawQuery != "" || !valid || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || decodeProductionJSON(request, &input) != nil || input.Rules == nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	for id, mode := range input.Rules {
		rule, known := guardrail.RuleByID(id)
		if !known || !guardrail.ValidMode(rule, guardrail.Mode(mode)) {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
	}
	rules, err := json.Marshal(input.Rules)
	auditID, idErr := handler.newProductID()
	correlationID := correlationIDFromContext(request.Context())
	if err != nil || idErr != nil || !validProductID(auditID) || !validProductID(correlationID) || auditID == correlationID {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	environment := identity.Scope.EnvironmentID().String()
	raw, err := handler.database.QueryJSON(request.Context(), currentGuardrailSetPolicySQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), environment, identity.PrincipalID.String(), json.RawMessage(rules), expectedVersion, auditID, correlationID)
	if err != nil {
		writeProductionError(writer, request, discoveryProviderError(err))
		return
	}
	policy, err := decodeGuardrailPolicy(raw, environment, "audit_id", "correlation_id")
	if err != nil || policy.Version != expectedVersion+1 {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeDiscoveryMutationHeaders(writer, policy.Version, auditID, "")
	writeJSONValue(writer, request, http.StatusOK, policy, nil)
}

// guardrailStatementAllowed admits the three guardrail statements for the
// checked request they belong to. PostgreSQL compares the same values with
// the attested proof.
func guardrailStatementAllowed(g RequestAuthorization, q string, args []any) (handled, allowed bool) {
	var operation string
	var count int
	actor := false
	switch q {
	case currentGuardrailDecideSQL:
		operation, count, actor = "createGuardrailDecision", 5, true
	case currentGuardrailPolicySQL:
		operation, count = "getGuardrailPolicy", 3
	case currentGuardrailSetPolicySQL:
		operation, count, actor = "putGuardrailPolicy", 8, true
	default:
		return false, false
	}
	bearer, browser := g.Identity.CredentialKind == CredentialBearerToken, g.Identity.CredentialKind == CredentialBrowserSession
	if g.OperationID != operation || g.Collection || len(args) != count || !bearer && (!browser || operation == "createGuardrailDecision") {
		return true, false
	}
	e := g.Identity.Scope.EnvironmentID().String()
	expected := []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), e}
	if actor {
		expected = append(expected, g.Identity.PrincipalID.String())
	}
	for index, want := range expected {
		value, ok := args[index].(string)
		if !ok || value == "" || value != want {
			return true, false
		}
	}
	if operation == "createGuardrailDecision" {
		// The record has a closed shape with no member for the text.
		raw, ok := args[4].(json.RawMessage)
		var record guardrailDecisionRecord
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if !ok || len(raw) > 16384 || decoder.Decode(&record) != nil || decoder.More() || !validProductID(record.ID) || record.InputBytes < 0 || record.InputBytes > guardrail.MaxTextBytes {
			return true, false
		}
	}
	return true, authorizationNativeTargetAllowed(g, "environment", e)
}
