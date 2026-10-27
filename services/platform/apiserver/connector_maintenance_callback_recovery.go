package apiserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

type connectorCallbackRecoveryOperation uint8

const (
	callbackRecoveryClaim connectorCallbackRecoveryOperation = iota + 1
	callbackRecoveryBefore
	callbackRecoverySettle
)

type connectorCallbackRecoveryExecutor interface {
	invokeCallbackRecovery(context.Context, connectorCallbackRecoveryOperation, json.RawMessage, json.RawMessage) (json.RawMessage, error)
}
type connectorCallbackRecoverySecrets interface {
	Delete(context.Context, string) error
}
type connectorCallbackRecoveryItem struct {
	OrganizationID    string          `json:"organization_id"`
	WorkspaceID       string          `json:"workspace_id"`
	EnvironmentID     string          `json:"environment_id"`
	AttemptID         string          `json:"attempt_id"`
	IntegrationID     string          `json:"integration_id"`
	AuthorizeEffectID string          `json:"authorize_effect_id"`
	CleanupEffectID   string          `json:"cleanup_effect_id"`
	PKCEReference     string          `json:"pkce_reference"`
	LeaseOwner        string          `json:"lease_owner"`
	LeaseToken        string          `json:"lease_token"`
	LeaseExpiresAt    time.Time       `json:"lease_expires_at"`
	Phase             string          `json:"phase"`
	SecretSettled     bool            `json:"secret_settled"`
	CapturedProof     json.RawMessage `json:"captured_proof,omitempty"`
}

// runConnectorCallbackRecovery has no workflow reader or provider capability.
// Native SQL alone authenticates receipts and admits exact expired callbacks.
func runConnectorCallbackRecovery(ctx context.Context, e connectorCallbackRecoveryExecutor, s connectorCallbackRecoverySecrets, owner string, seconds, limit int) (int, error) {
	if ctx == nil || ctx.Err() != nil || nilInterface(e) || nilInterface(s) || len(owner) < 3 || len(owner) > 128 || seconds < 5 || seconds > 300 || limit < 1 || limit > 10 {
		return 0, ErrRepositoryOperation
	}
	request, _ := json.Marshal(struct {
		Owner   string `json:"owner"`
		Seconds int    `json:"seconds"`
		Limit   int    `json:"limit"`
	}{owner, seconds, limit})
	raw, err := e.invokeCallbackRecovery(ctx, callbackRecoveryClaim, request, nil)
	if err != nil {
		return 0, err
	}
	items, err := decodeConnectorCallbackRecovery(raw, owner, seconds, limit)
	if err != nil {
		return 0, err
	}
	completed := 0
	var failures error
	for _, item := range items {
		deletionDeadline := item.LeaseExpiresAt.Add(-2100 * time.Millisecond)
		if ctx.Err() != nil || !deletionDeadline.After(time.Now()) {
			return completed, errors.Join(failures, ErrRepositoryUnavailable)
		}
		proof := append(json.RawMessage(nil), item.CapturedProof...)
		item.CapturedProof = nil
		q, _ := json.Marshal(item)
		deletion, stop := context.WithDeadline(ctx, deletionDeadline)
		before, callErr := e.invokeCallbackRecovery(deletion, callbackRecoveryBefore, q, proof)
		if callErr == nil && !callbackRecoveryTrue(before, "valid") {
			callErr = ErrRepositoryUnavailable
		}
		if callErr == nil && deletion.Err() != nil {
			callErr = ErrRepositoryUnavailable
		}
		if callErr == nil && !item.SecretSettled {
			callErr = s.Delete(deletion, item.PKCEReference)
		}
		stop()
		if callErr != nil {
			failures = errors.Join(failures, callErr)
			continue
		}
		// Confirmed deletion can settle despite request cancellation, within this
		// captured lease. A lost commit response is never counted as completion.
		settlement, finish := context.WithDeadline(context.WithoutCancel(ctx), item.LeaseExpiresAt.Add(-100*time.Millisecond))
		settled, callErr := e.invokeCallbackRecovery(settlement, callbackRecoverySettle, q, proof)
		if callErr == nil && (!callbackRecoveryTrue(settled, "settled") || settlement.Err() != nil) {
			callErr = ErrRepositoryUnavailable
		}
		finish()
		if callErr != nil {
			failures = errors.Join(failures, callErr)
			continue
		}
		completed++
	}
	return completed, failures
}

func decodeConnectorCallbackRecovery(raw json.RawMessage, owner string, seconds, limit int) ([]connectorCallbackRecoveryItem, error) {
	if len(raw) == 0 || len(raw) > 131072 {
		return nil, ErrRepositoryUnavailable
	}
	fields, ok := callbackRecoveryObject(raw, "items")
	if !ok || len(bytes.TrimSpace(fields["items"])) == 0 || bytes.TrimSpace(fields["items"])[0] != '[' {
		return nil, ErrRepositoryUnavailable
	}
	var wire []json.RawMessage
	if json.Unmarshal(fields["items"], &wire) != nil || len(wire) > limit || len(wire) > 10 {
		return nil, ErrRepositoryUnavailable
	}
	items := make([]connectorCallbackRecoveryItem, 0, len(wire))
	seen := map[string]bool{}
	now := time.Now()
	for _, entry := range wire {
		if _, ok := callbackRecoveryObject(entry, "organization_id", "workspace_id", "environment_id", "attempt_id", "integration_id", "authorize_effect_id", "cleanup_effect_id", "pkce_reference", "lease_owner", "lease_token", "lease_expires_at", "phase", "secret_settled", "captured_proof"); !ok {
			return nil, ErrRepositoryUnavailable
		}
		var item connectorCallbackRecoveryItem
		if decodeStrictDiscovery(entry, &item) != nil || !validProductID(item.OrganizationID) || !validProductID(item.WorkspaceID) || !validProductID(item.EnvironmentID) || !validProductID(item.AttemptID) || !validProductID(item.IntegrationID) || !validProductID(item.AuthorizeEffectID) || !validProductID(item.CleanupEffectID) || item.AuthorizeEffectID == item.CleanupEffectID || item.LeaseOwner != owner || !callbackRecoveryDigest(item.LeaseToken) || !validOpaqueReference(item.PKCEReference) || !strings.HasPrefix(item.PKCEReference, "ref:oauth/pkce/") || len(item.PKCEReference) <= len("ref:oauth/pkce/") || !item.LeaseExpiresAt.After(now.Add(2100*time.Millisecond)) || item.LeaseExpiresAt.After(now.Add(time.Duration(seconds)*time.Second+time.Second)) || !stringIn(item.Phase, "consumed", "secret", "rejection_secret", "secret_settled", "rejection_secret_settled") || item.SecretSettled != stringIn(item.Phase, "secret_settled", "rejection_secret_settled") || !validCallbackRecoveryProof(item.CapturedProof) {
			return nil, ErrRepositoryUnavailable
		}
		scope := item.OrganizationID + "/" + item.WorkspaceID + "/" + item.EnvironmentID + "/"
		for _, key := range []string{scope + "attempt/" + item.AttemptID, scope + "effect/" + item.AuthorizeEffectID, scope + "effect/" + item.CleanupEffectID} {
			if seen[key] {
				return nil, ErrRepositoryUnavailable
			}
			seen[key] = true
		}
		items = append(items, item)
	}
	return items, nil
}
func validCallbackRecoveryProof(raw json.RawMessage) bool {
	if len(raw) == 0 || len(raw) > 65536 {
		return false
	}
	if _, ok := callbackRecoveryObject(raw, "body", "version", "mac"); !ok {
		return false
	}
	var envelope struct {
		Body    string `json:"body"`
		Version string `json:"version"`
		MAC     string `json:"mac"`
	}
	if decodeStrictDiscovery(raw, &envelope) != nil || !callbackRecoveryDigest(envelope.Version) || !callbackRecoveryDigest(envelope.MAC) {
		return false
	}
	body, err := base64.StdEncoding.Strict().DecodeString(envelope.Body)
	return err == nil && len(body) > 0 && len(body) <= 65536
}
func callbackRecoveryDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}
func callbackRecoveryTrue(raw json.RawMessage, key string) bool {
	if len(raw) > 131072 {
		return false
	}
	fields, ok := callbackRecoveryObject(raw, key)
	return ok && bytes.Equal(bytes.TrimSpace(fields[key]), []byte("true"))
}

// Each response object has an exact case-sensitive grammar. Reject aliases,
// omitted/null fields and duplicate keys before ordinary JSON decoding.
func callbackRecoveryObject(raw json.RawMessage, names ...string) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	fields := make(map[string]json.RawMessage, len(names))
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || fields[key] != nil {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
		fields[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || len(fields) != len(names) {
		return nil, false
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, false
	}
	return fields, true
}
