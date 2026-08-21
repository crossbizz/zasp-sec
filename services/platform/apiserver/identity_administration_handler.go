package apiserver

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"time"

	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
)

const identityAdministrationMutationLeaseSeconds = 60
const identityAdministrationSecretLifetime = 10 * time.Minute

type identityAdministrationStore interface {
	identityProviderOrganization(context.Context, RequestIdentity) (string, error)
	reserveIdentityProviderMutation(context.Context, RequestIdentity, identityProviderMutation) (identityMutationReservation, json.RawMessage, error)
	markIdentityProviderMutationUnknown(context.Context, RequestIdentity, identityProviderMutation) error
	completeIdentityProviderMutation(context.Context, RequestIdentity, identityProviderCompletion) (json.RawMessage, error)
	revealIdentityProviderSecret(context.Context, RequestIdentity, string) (json.RawMessage, error)
	acknowledgeIdentityProviderSecret(context.Context, RequestIdentity, string) error
}

type identityAdministrationCoordinatorConfig struct {
	Clock         func() time.Time
	RevealKey     []byte
	NewProductID  func() (string, error)
	NewOwnerToken func() ([]byte, error)
}

type identityAdministrationCoordinator struct {
	store         identityAdministrationStore
	provider      IdentityConnectionProvider
	now           func() time.Time
	revealKey     []byte
	newProductID  func() (string, error)
	newOwnerToken func() ([]byte, error)
}

type identityAdministrationResult struct {
	Status   int
	Body     json.RawMessage
	Version  int64
	Replayed bool
}

type identityAdministrationConnection struct {
	Reference        string  `json:"reference"`
	Kind             string  `json:"kind"`
	Protocol         *string `json:"protocol"`
	Status           string  `json:"status"`
	DisplayName      string  `json:"display_name"`
	IdentityProvider string  `json:"identity_provider"`
	BaseURL          *string `json:"base_url"`
	Deleted          *bool   `json:"deleted,omitempty"`
}

type identityAdministrationCompletionEnvelope struct {
	Body          json.RawMessage `json:"body"`
	Version       int64           `json:"version"`
	MutationID    string          `json:"mutation_id"`
	AuditID       string          `json:"audit_id"`
	CorrelationID string          `json:"correlation_id"`
	ReceiptID     string          `json:"receipt_id"`
	Replayed      bool            `json:"replayed"`
	SecretGrantID *string         `json:"secret_grant_id"`
}

type identityAdministrationSecretEnvelope struct {
	Ciphertext        string `json:"ciphertext"`
	Nonce             string `json:"nonce"`
	AuthenticationTag string `json:"authentication_tag"`
	ExpiresAt         string `json:"expires_at"`
}

func newIdentityAdministrationCoordinator(store identityAdministrationStore, provider IdentityConnectionProvider, config identityAdministrationCoordinatorConfig) (*identityAdministrationCoordinator, error) {
	if nilInterface(store) || nilInterface(provider) || config.Clock == nil || config.NewProductID == nil || config.NewOwnerToken == nil || len(config.RevealKey) != 32 || !canonicalIdentityAdministrationTime(config.Clock()) {
		return nil, ErrRepositoryConfiguration
	}
	return &identityAdministrationCoordinator{
		store: store, provider: provider, now: config.Clock, revealKey: append([]byte(nil), config.RevealKey...),
		newProductID: config.NewProductID, newOwnerToken: config.NewOwnerToken,
	}, nil
}

func (coordinator *identityAdministrationCoordinator) List(ctx context.Context, identity RequestIdentity, operation, after string, limit int) (json.RawMessage, error) {
	if coordinator == nil || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, true) || identity.CredentialKind != CredentialBrowserSession || !stringIn(operation, "listSSOConnections", "listSCIMConnections") || limit < 1 || limit > 100 {
		return nil, ErrRepositoryOperation
	}
	organization, err := coordinator.store.identityProviderOrganization(ctx, identity)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0)
	if operation == "listSSOConnections" {
		connections, listErr := coordinator.provider.ListSSO(ctx, organization)
		if listErr != nil {
			return nil, ErrRepositoryUnavailable
		}
		for _, connection := range connections {
			if connection.Reference() > after {
				items = append(items, publicSSOConnection(connection, ""))
			}
		}
	} else {
		connections, listErr := coordinator.provider.ListSCIM(ctx, organization)
		if listErr != nil {
			return nil, ErrRepositoryUnavailable
		}
		for _, connection := range connections {
			if connection.Reference() > after {
				items = append(items, publicSCIMConnection(connection, "", ""))
			}
		}
	}
	sort.Slice(items, func(left, right int) bool { return items[left]["id"].(string) < items[right]["id"].(string) })
	if len(items) > limit+1 {
		items = items[:limit+1]
	}
	payload, err := json.Marshal(map[string]any{"items": items})
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	return payload, nil
}

func (coordinator *identityAdministrationCoordinator) Mutate(ctx context.Context, identity RequestIdentity, operation, idempotencyKey string, intent json.RawMessage) (identityAdministrationResult, error) {
	if coordinator == nil || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, true) || identity.CredentialKind != CredentialBrowserSession || !identity.FreshAuthenticated || !validAdministrationIdempotencyKey(idempotencyKey) || !validIdentityAdministrationIntent(operation, intent) {
		return identityAdministrationResult{}, ErrRepositoryOperation
	}
	ids := make([]string, 3)
	for index := range ids {
		value, err := coordinator.newProductID()
		if err != nil || !validProductID(value) {
			return identityAdministrationResult{}, ErrRepositoryUnavailable
		}
		ids[index] = value
	}
	ownerToken, err := coordinator.newOwnerToken()
	if err != nil || len(ownerToken) != 32 {
		return identityAdministrationResult{}, ErrRepositoryUnavailable
	}
	mutation := identityProviderMutation{
		Operation: operation, IdempotencyKey: idempotencyKey, MutationID: ids[0], AuditID: ids[1],
		CorrelationID: correlationIDFromContext(ctx), ReceiptID: ids[2], Intent: append(json.RawMessage(nil), intent...),
		OwnerToken: append([]byte(nil), ownerToken...), LeaseSeconds: identityAdministrationMutationLeaseSeconds,
	}
	reservation, _, err := coordinator.store.reserveIdentityProviderMutation(ctx, identity, mutation)
	if err != nil {
		return identityAdministrationResult{}, err
	}
	if len(reservation.Body) > 0 {
		return coordinator.publicCompletion(ctx, identity, operation, reservation.Body, reservation.Version, reservation.AuditID, reservation.Replayed, reservation.SecretGrantID, reservation.MutationID)
	}
	mutation.MutationID, mutation.AuditID, mutation.CorrelationID, mutation.ReceiptID = reservation.MutationID, reservation.AuditID, reservation.CorrelationID, reservation.ReceiptID
	return coordinator.executeProviderMutation(ctx, identity, reservation.ProviderOrganizationReference, reservation.State, mutation)
}

func (handler *identityHTTPHandler) mutateIdentityConnection(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	if handler == nil || handler.identityAdministration == nil || request.URL.RawQuery != "" || identity.CredentialKind != CredentialBrowserSession || !identity.FreshAuthenticated || !exactHeaderValue(request.Header.Values("X-Zasp-Fresh-Auth"), "confirmed") {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	idempotencyValues := request.Header.Values("Idempotency-Key")
	if len(idempotencyValues) != 1 || !validAdministrationIdempotencyKey(idempotencyValues[0]) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	var intent json.RawMessage
	var err error
	switch routed.OperationID {
	case "createSSOConnection":
		var input struct {
			DisplayName      string `json:"display_name"`
			Protocol         string `json:"protocol"`
			IdentityProvider string `json:"identity_provider"`
		}
		if decodeProductionJSON(request, &input) == nil {
			intent, err = json.Marshal(map[string]string{"display_name": input.DisplayName, "protocol": input.Protocol, "identity_provider": input.IdentityProvider})
		} else {
			err = ErrRepositoryOperation
		}
	case "createSCIMConnection":
		var input struct {
			DisplayName      string `json:"display_name"`
			IdentityProvider string `json:"identity_provider"`
		}
		if decodeProductionJSON(request, &input) == nil {
			intent, err = json.Marshal(map[string]string{"display_name": input.DisplayName, "identity_provider": input.IdentityProvider})
		} else {
			err = ErrRepositoryOperation
		}
	case "deleteSSOConnection", "deleteSCIMConnection":
		if requireZeroByteInput(request) != nil {
			err = ErrRepositoryOperation
		}
		intent, _ = json.Marshal(map[string]string{"reference": routed.PathParameters["id"]})
	case "testSSOConnection":
		if decodeEmptyInput(request) != nil {
			err = ErrRepositoryOperation
		}
		intent, _ = json.Marshal(map[string]string{"reference": routed.PathParameters["id"]})
	default:
		err = ErrRepositoryNotFound
	}
	if err != nil || !validIdentityAdministrationIntent(routed.OperationID, intent) {
		writeProductionError(writer, request, errOrOperation(err))
		return
	}
	result, err := handler.identityAdministration.Mutate(request.Context(), identity, routed.OperationID, idempotencyValues[0], intent)
	if err != nil {
		writeWorkflowMutationError(writer, request, err)
		return
	}
	if result.Version > 0 {
		writer.Header().Set("ETag", quoteVersion(result.Version))
	}
	if routed.OperationID == "createSCIMConnection" {
		writer.Header().Set("Cache-Control", "no-store")
	}
	writeProductionResponse(writer, request, result.Status, result.Body, nil)
}

func (coordinator *identityAdministrationCoordinator) executeProviderMutation(ctx context.Context, identity RequestIdentity, organization, state string, mutation identityProviderMutation) (identityAdministrationResult, error) {
	var intent struct {
		DisplayName      string `json:"display_name"`
		Protocol         string `json:"protocol"`
		IdentityProvider string `json:"identity_provider"`
		Reference        string `json:"reference"`
	}
	if decodeStrictIdentityAdministration(mutation.Intent, &intent) != nil {
		return identityAdministrationResult{}, ErrRepositoryOperation
	}
	var connection json.RawMessage
	var rawSecret string
	switch mutation.Operation {
	case "createSSOConnection":
		if state == "provider_unknown" {
			matches, err := coordinator.matchSSO(ctx, organization, intent)
			if err != nil || len(matches) > 1 {
				coordinator.releaseUnknown(identity, mutation)
				return identityAdministrationResult{}, ErrRepositoryUnavailable
			}
			if len(matches) == 1 {
				connection, err = internalSSOConnection(matches[0])
				if err != nil {
					return identityAdministrationResult{}, err
				}
			} else {
				created, createErr := coordinator.provider.CreateSSO(ctx, organization, platformidentity.SSOConfig{DisplayName: intent.DisplayName, Protocol: intent.Protocol, IdentityProvider: intent.IdentityProvider})
				if createErr != nil {
					coordinator.releaseUnknown(identity, mutation)
					return identityAdministrationResult{}, ErrRepositoryUnavailable
				}
				connection, err = internalSSOConnection(created)
			}
		} else {
			matches, listErr := coordinator.matchSSO(ctx, organization, intent)
			if listErr != nil {
				coordinator.releaseUnknown(identity, mutation)
				return identityAdministrationResult{}, ErrRepositoryUnavailable
			}
			if len(matches) != 0 {
				return identityAdministrationResult{}, ErrRepositoryConflict
			}
			created, err := coordinator.provider.CreateSSO(ctx, organization, platformidentity.SSOConfig{DisplayName: intent.DisplayName, Protocol: intent.Protocol, IdentityProvider: intent.IdentityProvider})
			if err != nil {
				coordinator.releaseUnknown(identity, mutation)
				return identityAdministrationResult{}, ErrRepositoryUnavailable
			}
			connection, err = internalSSOConnection(created)
			if err != nil {
				return identityAdministrationResult{}, err
			}
		}
	case "deleteSSOConnection":
		if state == "provider_unknown" {
			values, err := coordinator.provider.ListSSO(ctx, organization)
			if err != nil {
				coordinator.releaseUnknown(identity, mutation)
				return identityAdministrationResult{}, ErrRepositoryUnavailable
			}
			present := false
			for _, value := range values {
				present = present || value.Reference() == intent.Reference
			}
			if present && coordinator.provider.DeleteSSO(ctx, organization, intent.Reference) != nil {
				coordinator.releaseUnknown(identity, mutation)
				return identityAdministrationResult{}, ErrRepositoryUnavailable
			}
		} else if coordinator.provider.DeleteSSO(ctx, organization, intent.Reference) != nil {
			coordinator.releaseUnknown(identity, mutation)
			return identityAdministrationResult{}, ErrRepositoryUnavailable
		}
		connection, _ = json.Marshal(map[string]any{"reference": intent.Reference, "kind": "sso", "deleted": true})
	case "testSSOConnection":
		if coordinator.provider.TestSSO(ctx, organization, intent.Reference) != nil {
			coordinator.releaseUnknown(identity, mutation)
			return identityAdministrationResult{}, ErrRepositoryUnavailable
		}
		values, err := coordinator.provider.ListSSO(ctx, organization)
		if err != nil {
			coordinator.releaseUnknown(identity, mutation)
			return identityAdministrationResult{}, ErrRepositoryUnavailable
		}
		for _, value := range values {
			if value.Reference() == intent.Reference && value.Status() == "active" {
				connection, _ = internalSSOConnection(value)
			}
		}
		if len(connection) == 0 {
			coordinator.releaseUnknown(identity, mutation)
			return identityAdministrationResult{}, ErrRepositoryUnavailable
		}
	case "createSCIMConnection":
		matches, listErr := coordinator.matchSCIM(ctx, organization, intent)
		if listErr != nil || len(matches) > 1 {
			coordinator.releaseUnknown(identity, mutation)
			return identityAdministrationResult{}, ErrRepositoryUnavailable
		}
		if state != "provider_unknown" && len(matches) != 0 {
			return identityAdministrationResult{}, ErrRepositoryConflict
		}
		if state == "provider_unknown" && len(matches) == 1 {
			if coordinator.provider.DeleteSCIM(ctx, organization, matches[0].Reference()) != nil {
				coordinator.releaseUnknown(identity, mutation)
				return identityAdministrationResult{}, ErrRepositoryUnavailable
			}
		}
		credential, err := coordinator.provider.CreateSCIM(ctx, organization, platformidentity.SCIMConfig{DisplayName: intent.DisplayName, IdentityProvider: intent.IdentityProvider})
		if err != nil {
			coordinator.releaseUnknown(identity, mutation)
			return identityAdministrationResult{}, ErrRepositoryUnavailable
		}
		connection, err = internalSCIMConnection(credential.Connection)
		if err != nil {
			return identityAdministrationResult{}, err
		}
		rawSecret = credential.BearerToken()
	case "deleteSCIMConnection":
		if state == "provider_unknown" {
			values, err := coordinator.provider.ListSCIM(ctx, organization)
			if err != nil {
				coordinator.releaseUnknown(identity, mutation)
				return identityAdministrationResult{}, ErrRepositoryUnavailable
			}
			present := false
			for _, value := range values {
				present = present || value.Reference() == intent.Reference
			}
			if present && coordinator.provider.DeleteSCIM(ctx, organization, intent.Reference) != nil {
				coordinator.releaseUnknown(identity, mutation)
				return identityAdministrationResult{}, ErrRepositoryUnavailable
			}
		} else if coordinator.provider.DeleteSCIM(ctx, organization, intent.Reference) != nil {
			coordinator.releaseUnknown(identity, mutation)
			return identityAdministrationResult{}, ErrRepositoryUnavailable
		}
		connection, _ = json.Marshal(map[string]any{"reference": intent.Reference, "kind": "scim", "deleted": true})
	default:
		return identityAdministrationResult{}, ErrRepositoryOperation
	}
	completion := identityProviderCompletion{identityProviderMutation: mutation, Connection: connection}
	if rawSecret != "" {
		grantID, err := coordinator.newProductID()
		if err != nil || !validProductID(grantID) {
			coordinator.releaseUnknown(identity, mutation)
			return identityAdministrationResult{}, ErrRepositoryUnavailable
		}
		completion.GrantID = grantID
		completion.GrantExpiresAt = coordinator.now().UTC().Add(identityAdministrationSecretLifetime).Truncate(time.Second)
		completion.Ciphertext, completion.Nonce, completion.AuthenticationTag, err = encryptIdentityAdministrationSecret(coordinator.revealKey, identity, mutation.MutationID, grantID, completion.GrantExpiresAt, rawSecret)
		if err != nil {
			coordinator.releaseUnknown(identity, mutation)
			return identityAdministrationResult{}, err
		}
	}
	payload, err := coordinator.store.completeIdentityProviderMutation(ctx, identity, completion)
	if err != nil {
		coordinator.releaseUnknown(identity, mutation)
		return identityAdministrationResult{}, err
	}
	return coordinator.publicCompletion(ctx, identity, mutation.Operation, payload, 0, "", false, nil, mutation.MutationID, rawSecret)
}

func (coordinator *identityAdministrationCoordinator) publicCompletion(ctx context.Context, identity RequestIdentity, operation string, payload json.RawMessage, version int64, auditID string, replayed bool, grantID *string, mutationID string, rawSecret ...string) (identityAdministrationResult, error) {
	var envelope identityAdministrationCompletionEnvelope
	if decodeStrictIdentityAdministration(payload, &envelope) == nil && len(envelope.Body) > 0 {
		payload, version, auditID, replayed, grantID = envelope.Body, envelope.Version, envelope.AuditID, envelope.Replayed, envelope.SecretGrantID
		mutationID = envelope.MutationID
	}
	if !validProductID(auditID) || version < 1 || !json.Valid(payload) {
		return identityAdministrationResult{}, ErrRepositoryUnavailable
	}
	secret := ""
	if len(rawSecret) == 1 {
		secret = rawSecret[0]
	}
	if operation == "createSCIMConnection" && secret == "" {
		if grantID == nil || !validProductID(*grantID) {
			return identityAdministrationResult{}, ErrRepositoryUnavailable
		}
		value, err := coordinator.store.revealIdentityProviderSecret(ctx, identity, *grantID)
		if err != nil {
			return identityAdministrationResult{}, err
		}
		secret, err = decryptIdentityAdministrationSecret(coordinator.revealKey, identity, mutationID, *grantID, coordinator.now(), value)
		if err != nil {
			return identityAdministrationResult{}, err
		}
	}
	public, status, err := publicIdentityAdministrationResult(operation, payload, auditID, secret)
	if err != nil {
		return identityAdministrationResult{}, err
	}
	return identityAdministrationResult{Status: status, Body: public, Version: version, Replayed: replayed}, nil
}

func (coordinator *identityAdministrationCoordinator) matchSSO(ctx context.Context, organization string, intent struct {
	DisplayName      string `json:"display_name"`
	Protocol         string `json:"protocol"`
	IdentityProvider string `json:"identity_provider"`
	Reference        string `json:"reference"`
}) ([]platformidentity.SSOConnection, error) {
	values, err := coordinator.provider.ListSSO(ctx, organization)
	if err != nil {
		return nil, err
	}
	matches := make([]platformidentity.SSOConnection, 0, 1)
	for _, value := range values {
		if value.DisplayName() == intent.DisplayName && value.Protocol() == intent.Protocol && value.IdentityProvider() == intent.IdentityProvider {
			matches = append(matches, value)
		}
	}
	return matches, nil
}

func (coordinator *identityAdministrationCoordinator) matchSCIM(ctx context.Context, organization string, intent struct {
	DisplayName      string `json:"display_name"`
	Protocol         string `json:"protocol"`
	IdentityProvider string `json:"identity_provider"`
	Reference        string `json:"reference"`
}) ([]platformidentity.SCIMConnection, error) {
	values, err := coordinator.provider.ListSCIM(ctx, organization)
	if err != nil {
		return nil, err
	}
	matches := make([]platformidentity.SCIMConnection, 0, 1)
	for _, value := range values {
		if value.DisplayName() == intent.DisplayName && value.IdentityProvider() == intent.IdentityProvider {
			matches = append(matches, value)
		}
	}
	return matches, nil
}

func (coordinator *identityAdministrationCoordinator) releaseUnknown(identity RequestIdentity, mutation identityProviderMutation) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = coordinator.store.markIdentityProviderMutationUnknown(ctx, identity, mutation)
}

func validIdentityAdministrationIntent(operation string, payload json.RawMessage) bool {
	var value map[string]json.RawMessage
	if decodeStrictIdentityAdministration(payload, &value) != nil {
		return false
	}
	switch operation {
	case "createSSOConnection":
		var input struct {
			DisplayName      string `json:"display_name"`
			Protocol         string `json:"protocol"`
			IdentityProvider string `json:"identity_provider"`
		}
		return len(value) == 3 && decodeStrictIdentityAdministration(payload, &input) == nil && validAdministrationName(input.DisplayName) && stringIn(input.Protocol, "saml", "oidc") && validSSOIdentityProvider(input.IdentityProvider)
	case "createSCIMConnection":
		var input struct {
			DisplayName      string `json:"display_name"`
			IdentityProvider string `json:"identity_provider"`
		}
		return len(value) == 2 && decodeStrictIdentityAdministration(payload, &input) == nil && validAdministrationName(input.DisplayName) && validSCIMIdentityProvider(input.IdentityProvider)
	case "deleteSSOConnection", "testSSOConnection", "deleteSCIMConnection":
		var input struct {
			Reference string `json:"reference"`
		}
		return len(value) == 1 && decodeStrictIdentityAdministration(payload, &input) == nil && ((operation == "deleteSCIMConnection" && validIdentitySCIMReference(input.Reference)) || (operation != "deleteSCIMConnection" && validIdentitySSOReference(input.Reference)))
	default:
		return false
	}
}

func internalSSOConnection(value platformidentity.SSOConnection) (json.RawMessage, error) {
	protocol := value.Protocol()
	return json.Marshal(identityAdministrationConnection{Reference: value.Reference(), Kind: "sso", Protocol: &protocol, Status: value.Status(), DisplayName: value.DisplayName(), IdentityProvider: value.IdentityProvider()})
}

func internalSCIMConnection(value platformidentity.SCIMConnection) (json.RawMessage, error) {
	baseURL := value.BaseURL()
	return json.Marshal(identityAdministrationConnection{Reference: value.Reference(), Kind: "scim", Status: value.Status(), DisplayName: value.DisplayName(), IdentityProvider: value.IdentityProvider(), BaseURL: &baseURL})
}

func publicIdentityAdministrationResult(operation string, payload json.RawMessage, auditID, secret string) (json.RawMessage, int, error) {
	var value identityAdministrationConnection
	if decodeStrictIdentityAdministration(payload, &value) != nil {
		return nil, 0, ErrRepositoryUnavailable
	}
	var body map[string]any
	switch operation {
	case "createSSOConnection":
		if value.Kind != "sso" || value.Protocol == nil || value.Deleted != nil {
			return nil, 0, ErrRepositoryUnavailable
		}
		body = map[string]any{"id": value.Reference, "status": value.Status, "display_name": value.DisplayName, "protocol": *value.Protocol, "identity_provider": value.IdentityProvider, "audit_correlation_id": auditID}
	case "createSCIMConnection":
		if value.Kind != "scim" || value.BaseURL == nil || value.Deleted != nil || secret == "" {
			return nil, 0, ErrRepositoryUnavailable
		}
		body = map[string]any{"id": value.Reference, "status": value.Status, "display_name": value.DisplayName, "identity_provider": value.IdentityProvider, "base_url": *value.BaseURL, "bearer_token": secret, "audit_correlation_id": auditID}
	case "deleteSSOConnection", "deleteSCIMConnection":
		if value.Deleted == nil || !*value.Deleted {
			return nil, 0, ErrRepositoryUnavailable
		}
		body = map[string]any{"id": value.Reference, "audit_correlation_id": auditID}
	case "testSSOConnection":
		if value.Kind != "sso" || value.Status != "active" {
			return nil, 0, ErrRepositoryUnavailable
		}
		body = map[string]any{"healthy": true, "audit_correlation_id": auditID}
	default:
		return nil, 0, ErrRepositoryOperation
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, 0, ErrRepositoryUnavailable
	}
	status := http.StatusOK
	if operation == "createSSOConnection" || operation == "createSCIMConnection" {
		status = http.StatusCreated
	}
	return encoded, status, nil
}

func publicSSOConnection(value platformidentity.SSOConnection, auditID string) map[string]any {
	result := map[string]any{"id": value.Reference(), "status": value.Status(), "display_name": value.DisplayName(), "protocol": value.Protocol(), "identity_provider": value.IdentityProvider()}
	if auditID != "" {
		result["audit_correlation_id"] = auditID
	}
	return result
}

func publicSCIMConnection(value platformidentity.SCIMConnection, auditID, token string) map[string]any {
	result := map[string]any{"id": value.Reference(), "status": value.Status(), "display_name": value.DisplayName(), "identity_provider": value.IdentityProvider(), "base_url": value.BaseURL()}
	if auditID != "" {
		result["audit_correlation_id"] = auditID
	}
	if token != "" {
		result["bearer_token"] = token
	}
	return result
}

func encryptIdentityAdministrationSecret(key []byte, identity RequestIdentity, mutationID, grantID string, expires time.Time, raw string) ([]byte, []byte, []byte, error) {
	if len(key) != 32 || !validProductID(mutationID) || !validProductID(grantID) || raw == "" || expires.IsZero() || expires.Location() != time.UTC {
		return nil, nil, nil, ErrRepositoryOperation
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, ErrRepositoryConfiguration
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, ErrRepositoryConfiguration
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, ErrRepositoryUnavailable
	}
	sealed := aead.Seal(nil, nonce, []byte(raw), identityAdministrationSecretAAD(identity, mutationID, grantID, expires))
	tagStart := len(sealed) - aead.Overhead()
	return append([]byte(nil), sealed[:tagStart]...), nonce, append([]byte(nil), sealed[tagStart:]...), nil
}

func decryptIdentityAdministrationSecret(key []byte, identity RequestIdentity, mutationID, grantID string, now time.Time, payload json.RawMessage) (string, error) {
	var envelope identityAdministrationSecretEnvelope
	if decodeStrictIdentityAdministration(payload, &envelope) != nil || len(key) != 32 {
		return "", ErrRepositoryNotFound
	}
	expires, err := time.Parse(time.RFC3339Nano, envelope.ExpiresAt)
	if err != nil || expires.Format(time.RFC3339Nano) != envelope.ExpiresAt || expires.Location() != time.UTC || !canonicalIdentityAdministrationTime(now) || !expires.After(now) || expires.After(now.Add(15*time.Minute)) {
		return "", ErrRepositoryNotFound
	}
	decode := func(value string) ([]byte, error) {
		decoded, decodeErr := base64.StdEncoding.DecodeString(value)
		if decodeErr != nil {
			return nil, ErrRepositoryNotFound
		}
		return decoded, nil
	}
	ciphertext, cipherErr := decode(envelope.Ciphertext)
	nonce, nonceErr := decode(envelope.Nonce)
	tag, tagErr := decode(envelope.AuthenticationTag)
	block, blockErr := aes.NewCipher(key)
	if cipherErr != nil || nonceErr != nil || tagErr != nil || blockErr != nil || len(ciphertext) == 0 || len(nonce) != 12 || len(tag) != 16 {
		return "", ErrRepositoryNotFound
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrRepositoryNotFound
	}
	opened, err := aead.Open(nil, nonce, append(ciphertext, tag...), identityAdministrationSecretAAD(identity, mutationID, grantID, expires))
	if err != nil || len(opened) < len("scim_bearer_token_")+1 || string(opened[:len("scim_bearer_token_")]) != "scim_bearer_token_" {
		return "", ErrRepositoryNotFound
	}
	return string(opened), nil
}

func identityAdministrationSecretAAD(identity RequestIdentity, mutationID, grantID string, expires time.Time) []byte {
	value, _ := json.Marshal([]string{"zasp-identity-administration-secret-v1", identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), mutationID, grantID, expires.UTC().Format(time.RFC3339Nano)})
	return value
}

func randomIdentityAdministrationOwnerToken() ([]byte, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return nil, err
	}
	return value, nil
}

func canonicalIdentityAdministrationTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}

func validIdentitySSOReference(value string) bool {
	return validExactIdentityReference(value, 18, "saml-connection-", "oidc-connection-", "external-connection-")
}

func validIdentitySCIMReference(value string) bool {
	return validExactIdentityReference(value, 20, "scim-connection-")
}

func validExactIdentityReference(value string, minimum int, prefixes ...string) bool {
	if len(value) < minimum || len(value) > 128 {
		return false
	}
	for _, prefix := range prefixes {
		if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
			continue
		}
		for _, character := range value[len(prefix):] {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
				continue
			}
			return false
		}
		return true
	}
	return false
}

func validSSOIdentityProvider(value string) bool {
	return stringIn(value, "classlink", "cyberark", "duo", "generic", "google-workspace", "jumpcloud", "keycloak", "miniorange", "microsoft-entra", "okta", "onelogin", "pingfederate", "rippling", "salesforce", "shibboleth")
}

func validSCIMIdentityProvider(value string) bool {
	return stringIn(value, "generic", "okta", "microsoft-entra", "cyberark", "jumpcloud", "onelogin", "pingfederate", "rippling")
}
