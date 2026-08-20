package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/idpdiscovery"
)

type connectorProviderSecrets struct {
	driver *connectorSecretsDriver
	root   string
	kmsKey string
}

func (store *connectorProviderSecrets) resolve(ctx context.Context, reference string) ([]byte, error) {
	name, ok := store.name(reference)
	if !ok {
		return nil, errRuntimeUnavailable
	}
	value, err := store.driver.Read(ctx, name)
	if errors.Is(err, apiserver.ErrOAuthSecretNotFound) {
		return nil, apiserver.ErrOAuthSecretNotFound
	}
	if err != nil || len(value) < 8 || len(value) > 16384 {
		return nil, errRuntimeUnavailable
	}
	return value, nil
}

func (store *connectorProviderSecrets) put(ctx context.Context, reference string, value []byte) error {
	name, ok := store.name(reference)
	if !ok || len(value) < 16 || len(value) > 16384 {
		return errRuntimeUnavailable
	}
	if err := store.driver.Create(ctx, name, store.kmsKey, value); err == nil {
		return nil
	}
	existing, err := store.driver.Read(ctx, name)
	if err != nil || !bytes.Equal(existing, value) {
		return errRuntimeUnavailable
	}
	return nil
}

func (store *connectorProviderSecrets) delete(ctx context.Context, reference string) error {
	name, ok := store.name(reference)
	if !ok {
		return errRuntimeUnavailable
	}
	return store.driver.Delete(ctx, name)
}

func (store *connectorProviderSecrets) ready(ctx context.Context, reference string) error {
	value, err := store.resolve(ctx, reference)
	clear(value)
	return err
}

func (store *connectorProviderSecrets) name(reference string) (string, bool) {
	if store == nil || store.driver == nil || !connectorReferencePattern.MatchString(reference) || strings.Contains(reference, "..") {
		return "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(reference, "ref:"), "/", 2)
	if len(parts) != 2 {
		return "", false
	}
	return store.root + "/" + parts[0] + "/" + parts[1], true
}

type githubExchangeClient struct {
	http                *http.Client
	secrets             *connectorProviderSecrets
	appID               string
	privateKeyReference string
}

type githubEffectManifest struct {
	ClientID              string `json:"client_id"`
	ClientSecretReference string `json:"client_secret_reference"`
}

type githubEffectOutcome struct {
	Manifest   githubEffectManifest       `json:"manifest"`
	Connection githubdiscovery.Connection `json:"connection"`
}

type githubRevocationProof struct {
	Reference string `json:"reference"`
	Revoked   bool   `json:"revoked"`
}

func (client *githubExchangeClient) Exchange(ctx context.Context, request githubdiscovery.ExchangeRequest) (githubdiscovery.Connection, error) {
	manifestReference, _, outcomeReference, ok := connectorEffectReferences("github", request.EffectID)
	if !ok {
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	manifest := githubEffectManifest{ClientID: request.ClientID, ClientSecretReference: request.ClientSecretReference}
	manifestJSON, _ := json.Marshal(manifest)
	if err := client.secrets.put(ctx, manifestReference, manifestJSON); err != nil {
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	secret, err := client.secrets.resolve(ctx, request.ClientSecretReference)
	if err != nil {
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	form := url.Values{"client_id": {request.ClientID}, "client_secret": {string(secret)}, "code": {request.Code}, "redirect_uri": {request.CallbackURL}, "code_verifier": {string(request.PKCEVerifier)}}
	clear(secret)
	tokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	tokenRequest.Header.Set("Accept", "application/json")
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	if performConnectorJSON(client.http, tokenRequest, &token, 32<<10) != nil || len(token.AccessToken) < 20 || len(token.AccessToken) > 4096 || !strings.EqualFold(token.TokenType, "bearer") {
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	installationsRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/installations?per_page=2", nil)
	installationsRequest.Header.Set("Accept", "application/vnd.github+json")
	installationsRequest.Header.Set("Authorization", "Bearer "+token.AccessToken)
	installationsRequest.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	var page struct {
		TotalCount    int `json:"total_count"`
		Installations []struct {
			ID      int64 `json:"id"`
			Account struct {
				Login string `json:"login"`
			} `json:"account"`
			RepositorySelection string            `json:"repository_selection"`
			Permissions         map[string]string `json:"permissions"`
		} `json:"installations"`
	}
	if performConnectorJSON(client.http, installationsRequest, &page, 128<<10) != nil || page.TotalCount != 1 || len(page.Installations) != 1 {
		_ = client.revokeOAuthGrant(ctx, manifest, token.AccessToken)
		token.AccessToken = ""
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	installation := page.Installations[0]
	connection := githubdiscovery.Connection{Reference: "ref:github/installation/" + strconv.FormatInt(installation.ID, 10), InstallationID: installation.ID, AccountLogin: installation.Account.Login, RepositorySelection: installation.RepositorySelection, Permissions: installation.Permissions}
	outcomeJSON, _ := json.Marshal(githubEffectOutcome{Manifest: manifest, Connection: connection})
	if client.revokeOAuthGrant(ctx, manifest, token.AccessToken) != nil {
		token.AccessToken = ""
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	token.AccessToken = ""
	if client.secrets.put(ctx, outcomeReference, outcomeJSON) != nil {
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	return connection, nil
}

func (client *githubExchangeClient) Recover(ctx context.Context, effectID string) (githubdiscovery.Connection, error) {
	manifestReference, _, outcomeReference, ok := connectorEffectReferences("github", effectID)
	if !ok {
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	manifest, manifestErr := readGitHubManifest(ctx, client.secrets, manifestReference)
	if manifestErr != nil {
		return githubdiscovery.Connection{}, manifestErr
	}
	outcomeBytes, err := client.secrets.resolve(ctx, outcomeReference)
	if errors.Is(err, apiserver.ErrOAuthSecretNotFound) {
		return githubdiscovery.Connection{}, githubdiscovery.ErrOutcomeNotFound
	}
	var outcome githubEffectOutcome
	if err != nil || decodeConnectorSecretJSON(outcomeBytes, &outcome) != nil || outcome.Manifest != manifest {
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	return outcome.Connection, nil
}

func (client *githubExchangeClient) Discard(ctx context.Context, effectID string, revoke bool) error {
	manifestReference, _, outcomeReference, ok := connectorEffectReferences("github", effectID)
	if !ok {
		return errRuntimeUnavailable
	}
	if revoke {
		outcome, err := client.Recover(ctx, effectID)
		if err != nil || client.Revoke(ctx, outcome.Reference) != nil {
			return errRuntimeUnavailable
		}
	}
	if deleteConnectorSecret(ctx, client.secrets, outcomeReference) != nil || deleteConnectorSecret(ctx, client.secrets, manifestReference) != nil {
		return errRuntimeUnavailable
	}
	return nil
}

func (client *githubExchangeClient) Revoke(ctx context.Context, reference string) error {
	const prefix = "ref:github/installation/"
	proofReference, proofOK := githubRevocationProofReference(reference)
	if !proofOK {
		return errRuntimeUnavailable
	}
	if proofBytes, proofErr := client.secrets.resolve(ctx, proofReference); proofErr == nil {
		var proof githubRevocationProof
		if decodeConnectorSecretJSON(proofBytes, &proof) == nil && proof.Revoked && proof.Reference == reference {
			return nil
		}
		return errRuntimeUnavailable
	} else if !errors.Is(proofErr, apiserver.ErrOAuthSecretNotFound) {
		return errRuntimeUnavailable
	}
	installationID, err := strconv.ParseInt(strings.TrimPrefix(reference, prefix), 10, 64)
	if err != nil || !strings.HasPrefix(reference, prefix) || installationID < 1 || client.deleteInstallation(ctx, installationID) != nil {
		return errRuntimeUnavailable
	}
	proofJSON, _ := json.Marshal(githubRevocationProof{Reference: reference, Revoked: true})
	if client.secrets.put(ctx, proofReference, proofJSON) != nil {
		return errRuntimeUnavailable
	}
	return nil
}

func githubRevocationProofReference(reference string) (string, bool) {
	const prefix = "ref:github/"
	if !strings.HasPrefix(reference, prefix) {
		return "", false
	}
	path := strings.TrimPrefix(reference, prefix)
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", false
	}
	switch parts[0] {
	case "installation":
		return prefix + "revoked-installation/" + parts[1], true
	default:
		return "", false
	}
}

func (client *githubExchangeClient) revokeOAuthGrant(ctx context.Context, manifest githubEffectManifest, accessToken string) error {
	secret, err := client.secrets.resolve(ctx, manifest.ClientSecretReference)
	if err != nil {
		return errRuntimeUnavailable
	}
	payload, _ := json.Marshal(map[string]string{"access_token": accessToken})
	request, _ := http.NewRequestWithContext(ctx, http.MethodDelete, "https://api.github.com/applications/"+url.PathEscape(manifest.ClientID)+"/grant", bytes.NewReader(payload))
	request.SetBasicAuth(manifest.ClientID, string(secret))
	clear(secret)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return performConnectorRevocation(client.http, request)
}

func (client *githubExchangeClient) deleteInstallation(ctx context.Context, installationID int64) error {
	token, err := client.appJWT(ctx)
	if err != nil {
		return err
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodDelete, "https://api.github.com/app/installations/"+strconv.FormatInt(installationID, 10), nil)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return performConnectorRevocation(client.http, request)
}

func (client *githubExchangeClient) MintInstallationToken(ctx context.Context, reference string) ([]byte, time.Time, error) {
	const prefix = "ref:github/installation/"
	if client == nil || ctx == nil || ctx.Err() != nil || !strings.HasPrefix(reference, prefix) {
		return nil, time.Time{}, errRuntimeUnavailable
	}
	installationID, err := strconv.ParseInt(strings.TrimPrefix(reference, prefix), 10, 64)
	if err != nil || installationID < 1 {
		return nil, time.Time{}, errRuntimeUnavailable
	}
	appToken, err := client.appJWT(ctx)
	if err != nil {
		return nil, time.Time{}, errRuntimeUnavailable
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.github.com/app/installations/"+strconv.FormatInt(installationID, 10)+"/access_tokens", strings.NewReader(`{}`))
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+appToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	var response struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if performConnectorJSON(client.http, request, &response, 32<<10) != nil || len(response.Token) < 20 || len(response.Token) > 4096 || !response.ExpiresAt.After(time.Now().Add(time.Minute)) || response.ExpiresAt.After(time.Now().Add(65*time.Minute)) {
		response.Token = ""
		return nil, time.Time{}, errRuntimeUnavailable
	}
	result := []byte(response.Token)
	response.Token = ""
	return result, response.ExpiresAt.UTC(), nil
}

func (client *githubExchangeClient) appJWT(ctx context.Context) (string, error) {
	if client == nil || client.secrets == nil || client.appID == "" || !connectorReferencePattern.MatchString(client.privateKeyReference) {
		return "", errRuntimeUnavailable
	}
	keyBytes, err := client.secrets.resolve(ctx, client.privateKeyReference)
	if err != nil {
		return "", errRuntimeUnavailable
	}
	block, _ := pem.Decode(keyBytes)
	clear(keyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return "", errRuntimeUnavailable
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	clear(block.Bytes)
	if err != nil || key.N.BitLen() < 2048 {
		return "", errRuntimeUnavailable
	}
	now := time.Now().UTC()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(map[string]any{"iat": now.Add(-30 * time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix(), "iss": client.appID})
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsigned := header + "." + payload
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", errRuntimeUnavailable
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

type oktaExchangeClient struct {
	http    *http.Client
	secrets *connectorProviderSecrets
}

type oktaEffectManifest struct {
	Issuer                string `json:"issuer"`
	ClientID              string `json:"client_id"`
	ClientSecretReference string `json:"client_secret_reference"`
}

type oktaEffectOutcome struct {
	Manifest   oktaEffectManifest      `json:"manifest"`
	Connection idpdiscovery.Connection `json:"connection"`
}

type oktaRevocationProof struct {
	Reference string `json:"reference"`
	Revoked   bool   `json:"revoked"`
}

func (client *oktaExchangeClient) Exchange(ctx context.Context, request idpdiscovery.ExchangeRequest) (idpdiscovery.Connection, error) {
	manifestReference, accessReference, outcomeReference, ok := connectorEffectReferences("okta", request.EffectID)
	if !ok {
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	refreshReference := "ref:okta/refresh/" + strings.TrimPrefix(request.EffectID, "pid_")
	manifest := oktaEffectManifest{Issuer: request.Issuer, ClientID: request.ClientID, ClientSecretReference: request.ClientSecretReference}
	manifestJSON, _ := json.Marshal(manifest)
	if err := client.secrets.put(ctx, manifestReference, manifestJSON); err != nil {
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	secret, err := client.secrets.resolve(ctx, request.ClientSecretReference)
	if err != nil {
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {request.Code}, "redirect_uri": {request.CallbackURL}, "code_verifier": {string(request.PKCEVerifier)}}
	tokenRequest, _ := http.NewRequestWithContext(ctx, http.MethodPost, request.Issuer+"/oauth2/v1/token", strings.NewReader(form.Encode()))
	tokenRequest.SetBasicAuth(request.ClientID, string(secret))
	clear(secret)
	tokenRequest.Header.Set("Accept", "application/json")
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if performConnectorJSON(client.http, tokenRequest, &token, 64<<10) != nil || len(token.AccessToken) < 20 || len(token.AccessToken) > 4096 || len(token.RefreshToken) < 20 || len(token.RefreshToken) > 4096 || !strings.EqualFold(token.TokenType, "bearer") || token.ExpiresIn < 1 || token.ExpiresIn > 3600 {
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	if client.secrets.put(ctx, accessReference, []byte(token.AccessToken)) != nil || client.secrets.put(ctx, refreshReference, []byte(token.RefreshToken)) != nil {
		_ = client.revokeToken(ctx, manifest, token.AccessToken, "access_token")
		_ = client.revokeToken(ctx, manifest, token.RefreshToken, "refresh_token")
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	profileRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, request.Issuer+"/oauth2/v1/userinfo", nil)
	profileRequest.Header.Set("Accept", "application/json")
	profileRequest.Header.Set("Authorization", "Bearer "+token.AccessToken)
	var profile struct {
		Subject string `json:"sub"`
	}
	if performConnectorJSON(client.http, profileRequest, &profile, 32<<10) != nil {
		_ = client.revokeToken(ctx, manifest, token.AccessToken, "access_token")
		_ = client.revokeToken(ctx, manifest, token.RefreshToken, "refresh_token")
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	issuer, _ := url.Parse(request.Issuer)
	scopes := strings.Fields(token.Scope)
	sort.Strings(scopes)
	connection := idpdiscovery.Connection{Reference: refreshReference, Subject: profile.Subject, Tenant: issuer.Hostname(), Scopes: scopes}
	outcomeJSON, _ := json.Marshal(oktaEffectOutcome{Manifest: manifest, Connection: connection})
	if client.secrets.put(ctx, outcomeReference, outcomeJSON) != nil || client.revokeToken(ctx, manifest, token.AccessToken, "access_token") != nil || client.secrets.delete(ctx, accessReference) != nil {
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	return connection, nil
}

func (client *oktaExchangeClient) Recover(ctx context.Context, effectID string) (idpdiscovery.Connection, error) {
	manifestReference, accessReference, outcomeReference, ok := connectorEffectReferences("okta", effectID)
	if !ok {
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	manifest, manifestErr := readOktaManifest(ctx, client.secrets, manifestReference)
	if manifestErr != nil {
		return idpdiscovery.Connection{}, manifestErr
	}
	outcomeBytes, err := client.secrets.resolve(ctx, outcomeReference)
	if errors.Is(err, apiserver.ErrOAuthSecretNotFound) {
		_ = client.cleanupToken(ctx, manifest, accessReference, "access_token")
		_ = client.cleanupToken(ctx, manifest, "ref:okta/refresh/"+strings.TrimPrefix(effectID, "pid_"), "refresh_token")
		return idpdiscovery.Connection{}, idpdiscovery.ErrOutcomeNotFound
	}
	var outcome oktaEffectOutcome
	if err != nil || decodeConnectorSecretJSON(outcomeBytes, &outcome) != nil || outcome.Manifest != manifest {
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	if client.cleanupToken(ctx, manifest, accessReference, "access_token") != nil {
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	return outcome.Connection, nil
}

func (client *oktaExchangeClient) Discard(ctx context.Context, effectID string, revoke bool) error {
	manifestReference, accessReference, outcomeReference, ok := connectorEffectReferences("okta", effectID)
	if !ok {
		return errRuntimeUnavailable
	}
	manifest, err := readOktaManifest(ctx, client.secrets, manifestReference)
	if err != nil && !errors.Is(err, apiserver.ErrOAuthSecretNotFound) {
		return errRuntimeUnavailable
	}
	if err == nil {
		if client.cleanupToken(ctx, manifest, accessReference, "access_token") != nil {
			return errRuntimeUnavailable
		}
		if revoke && client.cleanupToken(ctx, manifest, "ref:okta/refresh/"+strings.TrimPrefix(effectID, "pid_"), "refresh_token") != nil {
			return errRuntimeUnavailable
		}
	}
	if deleteConnectorSecret(ctx, client.secrets, outcomeReference) != nil || deleteConnectorSecret(ctx, client.secrets, manifestReference) != nil {
		return errRuntimeUnavailable
	}
	return nil
}

func (client *oktaExchangeClient) Revoke(ctx context.Context, reference string, config idpdiscovery.Config) error {
	manifest := oktaEffectManifest{Issuer: config.Issuer, ClientID: config.ClientID, ClientSecretReference: config.ClientSecretReference}
	found, err := client.revokePersistedToken(ctx, manifest, reference)
	if err != nil || !found {
		return errRuntimeUnavailable
	}
	return nil
}

func (client *oktaExchangeClient) revokePersistedToken(ctx context.Context, manifest oktaEffectManifest, reference string) (bool, error) {
	proofReference, ok := oktaRevocationProofReference(reference)
	if !ok {
		return false, errRuntimeUnavailable
	}
	token, err := client.secrets.resolve(ctx, reference)
	if errors.Is(err, apiserver.ErrOAuthSecretNotFound) {
		proofBytes, proofErr := client.secrets.resolve(ctx, proofReference)
		var proof oktaRevocationProof
		if proofErr != nil || decodeConnectorSecretJSON(proofBytes, &proof) != nil || !proof.Revoked || proof.Reference != reference {
			return false, nil
		}
		return true, nil
	}
	if err != nil || client.revokeToken(ctx, manifest, string(token), "refresh_token") != nil {
		clear(token)
		return true, errRuntimeUnavailable
	}
	clear(token)
	proofJSON, _ := json.Marshal(oktaRevocationProof{Reference: reference, Revoked: true})
	if client.secrets.put(ctx, proofReference, proofJSON) != nil || client.secrets.delete(ctx, reference) != nil {
		return true, errRuntimeUnavailable
	}
	return true, nil
}

func oktaRevocationProofReference(reference string) (string, bool) {
	const prefix = "ref:okta/refresh/"
	if !strings.HasPrefix(reference, prefix) || len(reference) <= len(prefix) {
		return "", false
	}
	return "ref:okta/revoked-refresh/" + strings.TrimPrefix(reference, prefix), true
}

func (client *oktaExchangeClient) cleanupToken(ctx context.Context, manifest oktaEffectManifest, reference, hint string) error {
	token, err := client.secrets.resolve(ctx, reference)
	if errors.Is(err, apiserver.ErrOAuthSecretNotFound) {
		return nil
	}
	if err != nil || client.revokeToken(ctx, manifest, string(token), hint) != nil {
		clear(token)
		return errRuntimeUnavailable
	}
	clear(token)
	return client.secrets.delete(ctx, reference)
}

func (client *oktaExchangeClient) revokeToken(ctx context.Context, manifest oktaEffectManifest, token, hint string) error {
	secret, err := client.secrets.resolve(ctx, manifest.ClientSecretReference)
	if err != nil {
		return errRuntimeUnavailable
	}
	form := url.Values{"token": {token}, "token_type_hint": {hint}}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, manifest.Issuer+"/oauth2/v1/revoke", strings.NewReader(form.Encode()))
	request.SetBasicAuth(manifest.ClientID, string(secret))
	clear(secret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return performConnectorEmpty(client.http, request)
}

func connectorEffectReferences(provider, effectID string) (string, string, string, bool) {
	if !strings.HasPrefix(effectID, "pid_") || len(effectID) != 40 {
		return "", "", "", false
	}
	suffix := strings.TrimPrefix(effectID, "pid_")
	for _, character := range suffix {
		if !strings.ContainsRune("0123456789abcdef-", character) {
			return "", "", "", false
		}
	}
	return "ref:" + provider + "/effect-manifest/" + suffix, "ref:" + provider + "/effect-token/" + suffix, "ref:" + provider + "/effect-outcome/" + suffix, true
}

func readGitHubManifest(ctx context.Context, store *connectorProviderSecrets, reference string) (githubEffectManifest, error) {
	value, err := store.resolve(ctx, reference)
	var result githubEffectManifest
	if err != nil || decodeConnectorSecretJSON(value, &result) != nil || result.ClientID == "" || !strings.HasPrefix(result.ClientSecretReference, "ref:") {
		return githubEffectManifest{}, errRuntimeUnavailable
	}
	return result, nil
}

func readOktaManifest(ctx context.Context, store *connectorProviderSecrets, reference string) (oktaEffectManifest, error) {
	value, err := store.resolve(ctx, reference)
	var result oktaEffectManifest
	if err != nil || decodeConnectorSecretJSON(value, &result) != nil || result.Issuer == "" || result.ClientID == "" || !strings.HasPrefix(result.ClientSecretReference, "ref:") {
		return oktaEffectManifest{}, errRuntimeUnavailable
	}
	return result, nil
}

func decodeConnectorSecretJSON(value []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return errRuntimeUnavailable
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errRuntimeUnavailable
	}
	return nil
}

func deleteConnectorSecret(ctx context.Context, store *connectorProviderSecrets, reference string) error {
	if _, err := store.resolve(ctx, reference); errors.Is(err, apiserver.ErrOAuthSecretNotFound) {
		return nil
	} else if err != nil {
		return errRuntimeUnavailable
	}
	return store.delete(ctx, reference)
}

func performConnectorJSON(client *http.Client, request *http.Request, target any, maximum int64) error {
	if client == nil || request == nil || maximum < 1 || maximum > 1<<20 {
		return errRuntimeUnavailable
	}
	response, err := client.Do(request)
	if err != nil {
		return errRuntimeUnavailable
	}
	defer response.Body.Close()
	mediaType, parameters, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode < 200 || response.StatusCode > 299 || response.Header.Get("Location") != "" || mediaErr != nil || strings.ToLower(mediaType) != "application/json" || len(parameters) > 1 || len(parameters) == 1 && !strings.EqualFold(parameters["charset"], "utf-8") {
		return errRuntimeUnavailable
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		return errRuntimeUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return errRuntimeUnavailable
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errRuntimeUnavailable
	}
	return nil
}

func performConnectorEmpty(client *http.Client, request *http.Request) error {
	if client == nil || request == nil {
		return errRuntimeUnavailable
	}
	response, err := client.Do(request)
	if err != nil {
		return errRuntimeUnavailable
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
	if response.StatusCode < 200 || response.StatusCode > 299 || response.Header.Get("Location") != "" || readErr != nil || len(payload) != 0 {
		return errRuntimeUnavailable
	}
	return nil
}

func performConnectorRevocation(client *http.Client, request *http.Request) error {
	if client == nil || request == nil {
		return errRuntimeUnavailable
	}
	response, err := client.Do(request)
	if err != nil {
		return errRuntimeUnavailable
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
	if response.StatusCode != http.StatusNotFound && (response.StatusCode < 200 || response.StatusCode > 299) || response.Header.Get("Location") != "" || readErr != nil || len(payload) != 0 {
		return errRuntimeUnavailable
	}
	return nil
}

type githubOAuthProvider struct{ adapter *githubdiscovery.Adapter }

func (provider *githubOAuthProvider) AuthorizationURL(state, challenge string) (string, error) {
	return provider.adapter.AuthorizationURL(state, challenge)
}
func (provider *githubOAuthProvider) Complete(ctx context.Context, effectID, code string, verifier []byte) (apiserver.ConnectorOAuthGrant, error) {
	value, err := provider.adapter.Complete(ctx, effectID, code, verifier)
	if err != nil {
		return apiserver.ConnectorOAuthGrant{}, errRuntimeUnavailable
	}
	metadata, err := json.Marshal(map[string]any{"account_login": value.AccountLogin, "installation_id": value.InstallationID, "permissions": value.Permissions, "repository_selection": value.RepositorySelection})
	return apiserver.ConnectorOAuthGrant{ConnectionReference: value.Reference, ProviderSubject: "installation:" + strconv.FormatInt(value.InstallationID, 10), CredentialClass: "github_installation_reference", Metadata: metadata}, err
}
func (provider *githubOAuthProvider) Recover(ctx context.Context, effectID string) (apiserver.ConnectorOAuthGrant, error) {
	value, err := provider.adapter.Recover(ctx, effectID)
	if err != nil {
		if errors.Is(err, githubdiscovery.ErrOutcomeNotFound) {
			return apiserver.ConnectorOAuthGrant{}, apiserver.ErrConnectorOutcomeNotFound
		}
		return apiserver.ConnectorOAuthGrant{}, errRuntimeUnavailable
	}
	metadata, err := json.Marshal(map[string]any{"account_login": value.AccountLogin, "installation_id": value.InstallationID, "permissions": value.Permissions, "repository_selection": value.RepositorySelection})
	return apiserver.ConnectorOAuthGrant{ConnectionReference: value.Reference, ProviderSubject: "installation:" + strconv.FormatInt(value.InstallationID, 10), CredentialClass: "github_installation_reference", Metadata: metadata}, err
}
func (provider *githubOAuthProvider) Discard(ctx context.Context, effectID string, revoke bool) error {
	if err := provider.adapter.Discard(ctx, effectID, revoke); err != nil {
		return errRuntimeUnavailable
	}
	return nil
}
func (provider *githubOAuthProvider) Revoke(ctx context.Context, reference string) error {
	if err := provider.adapter.Revoke(ctx, reference); err != nil {
		return errRuntimeUnavailable
	}
	return nil
}

type oktaOAuthProvider struct{ adapter *idpdiscovery.OktaAdapter }

func (provider *oktaOAuthProvider) AuthorizationURL(state, challenge string) (string, error) {
	return provider.adapter.AuthorizationURL(state, challenge)
}
func (provider *oktaOAuthProvider) Complete(ctx context.Context, effectID, code string, verifier []byte) (apiserver.ConnectorOAuthGrant, error) {
	value, err := provider.adapter.Complete(ctx, effectID, code, verifier)
	if err != nil {
		return apiserver.ConnectorOAuthGrant{}, errRuntimeUnavailable
	}
	metadata, err := json.Marshal(map[string]any{"scopes": value.Scopes, "subject": value.Subject, "tenant": value.Tenant})
	return apiserver.ConnectorOAuthGrant{ConnectionReference: value.Reference, ProviderSubject: value.Subject, CredentialClass: "okta_refresh_reference", Metadata: metadata}, err
}
func (provider *oktaOAuthProvider) Recover(ctx context.Context, effectID string) (apiserver.ConnectorOAuthGrant, error) {
	value, err := provider.adapter.Recover(ctx, effectID)
	if err != nil {
		if errors.Is(err, idpdiscovery.ErrOutcomeNotFound) {
			return apiserver.ConnectorOAuthGrant{}, apiserver.ErrConnectorOutcomeNotFound
		}
		return apiserver.ConnectorOAuthGrant{}, errRuntimeUnavailable
	}
	metadata, err := json.Marshal(map[string]any{"scopes": value.Scopes, "subject": value.Subject, "tenant": value.Tenant})
	return apiserver.ConnectorOAuthGrant{ConnectionReference: value.Reference, ProviderSubject: value.Subject, CredentialClass: "okta_refresh_reference", Metadata: metadata}, err
}
func (provider *oktaOAuthProvider) Discard(ctx context.Context, effectID string, revoke bool) error {
	if err := provider.adapter.Discard(ctx, effectID, revoke); err != nil {
		return errRuntimeUnavailable
	}
	return nil
}
func (provider *oktaOAuthProvider) Revoke(ctx context.Context, reference string) error {
	if err := provider.adapter.Revoke(ctx, reference); err != nil {
		return errRuntimeUnavailable
	}
	return nil
}

type oktaOAuthFactory struct {
	clientID, secretReference, callback string
	exchange                            idpdiscovery.ExchangeClient
	timeout                             time.Duration
}

func (factory *oktaOAuthFactory) Provider(configuration map[string]string) (apiserver.ConnectorOAuthProvider, error) {
	if factory == nil || len(configuration) != 1 {
		return nil, errRuntimeUnavailable
	}
	adapter, err := idpdiscovery.NewOktaAdapter(idpdiscovery.Config{Issuer: configuration["issuer"], ClientID: factory.clientID, ClientSecretReference: factory.secretReference, CallbackURL: factory.callback}, factory.exchange, factory.timeout)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	return &oktaOAuthProvider{adapter: adapter}, nil
}

func newConnectorHTTPClient(timeout time.Duration) (*http.Client, error) {
	if timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil, errRuntimeUnavailable
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 1 << 20}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

var _ githubdiscovery.ExchangeClient = (*githubExchangeClient)(nil)
var _ idpdiscovery.ExchangeClient = (*oktaExchangeClient)(nil)
var _ apiserver.ConnectorOAuthProvider = (*githubOAuthProvider)(nil)
var _ apiserver.ConnectorOAuthProviderFactory = (*oktaOAuthFactory)(nil)
