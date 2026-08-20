package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

const discoveryCredentialEnvelopeVersion = "discovery_credential_v1"

var (
	errDiscoveryCredentialUnavailable = errors.New("discovery credential unavailable")
	discoveryAWSRolePattern           = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,128}$`)
	discoveryRegionPattern            = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]?$`)
	discoveryGitHubAppIDPattern       = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	discoveryOktaClientIDPattern      = regexp.MustCompile(`^0oa[A-Za-z0-9_-]{13,125}$`)
	discoveryReferencePattern         = regexp.MustCompile(`^ref:(aws|kubernetes|github|okta)/[A-Za-z0-9][A-Za-z0-9._/:-]{7,507}$`)
	discoveryOktaIssuerPattern        = regexp.MustCompile(`^https://([a-z0-9][a-z0-9-]{1,61}[a-z0-9]\.okta\.com)$`)
)

type discoverySecretReader interface {
	ResolveDiscoverySecret(context.Context, string) ([]byte, error)
}

type discoveryAssumeRoleAPI interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

type discoveryGitHubInstallationToken struct {
	Token          []byte
	InstallationID int64
	ExpiresAt      time.Time
}

type discoveryGitHubTokenAPI interface {
	MintDiscoveryInstallationToken(context.Context, string, []byte, int64) (discoveryGitHubInstallationToken, error)
}

type discoveryOktaAccessToken struct {
	Token     []byte
	Tenant    string
	Scopes    []string
	ExpiresAt time.Time
}

type discoveryOktaTokenAPI interface {
	ExchangeDiscoveryRefreshToken(context.Context, string, string, []byte, []byte) (discoveryOktaAccessToken, error)
}

type productionDiscoveryCredentialConfig struct {
	Secrets                   discoverySecretReader
	AssumeRole                discoveryAssumeRoleAPI
	GitHub                    discoveryGitHubTokenAPI
	Okta                      discoveryOktaTokenAPI
	GitHubAppID               string
	GitHubPrivateKeyReference string
	OktaClientID              string
	OktaClientSecretReference string
	Clock                     func() time.Time
}

type productionDiscoveryCredentialResolver struct {
	config productionDiscoveryCredentialConfig
}

func newProductionDiscoveryCredentialResolver(config productionDiscoveryCredentialConfig) (*productionDiscoveryCredentialResolver, error) {
	if nilDiscoveryCredentialDependency(config.Secrets) || nilDiscoveryCredentialDependency(config.AssumeRole) || nilDiscoveryCredentialDependency(config.GitHub) || nilDiscoveryCredentialDependency(config.Okta) || config.Clock == nil ||
		!discoveryGitHubAppIDPattern.MatchString(config.GitHubAppID) || !validDiscoveryCredentialReference(config.GitHubPrivateKeyReference, "ref:github/") ||
		!discoveryOktaClientIDPattern.MatchString(config.OktaClientID) || !validDiscoveryCredentialReference(config.OktaClientSecretReference, "ref:okta/") {
		return nil, errDiscoveryCredentialUnavailable
	}
	now := config.Clock()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errDiscoveryCredentialUnavailable
	}
	return &productionDiscoveryCredentialResolver{config: config}, nil
}

func (resolver *productionDiscoveryCredentialResolver) ResolveDiscoveryCredential(ctx context.Context, bound discoveryCredentialMaterialRequest) (*collection.CredentialMaterial, error) {
	if resolver == nil || ctx == nil || ctx.Err() != nil || !validDiscoveryCredentialBinding(bound) {
		return nil, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	now := resolver.config.Clock()
	if now.IsZero() || now.Location() != time.UTC || !bound.Input.LeaseExpiresAt.After(now) {
		return nil, discoveryCredentialFailure(ctx, collection.FailureCancelled)
	}

	var envelope discoveryCredentialEnvelope
	var err error
	switch bound.Input.Provider {
	case collection.ProviderAWS:
		envelope, err = resolver.resolveAWS(ctx, bound, now)
	case collection.ProviderKubernetes:
		envelope, err = resolver.resolveKubernetes(ctx, bound, now)
	case collection.ProviderGitHub:
		envelope, err = resolver.resolveGitHub(ctx, bound, now)
	case collection.ProviderOkta:
		envelope, err = resolver.resolveOkta(ctx, bound, now)
	default:
		err = discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	if err != nil {
		envelope.Destroy()
		return nil, err
	}
	encoded, err := encodeDiscoveryCredentialEnvelope(envelope)
	expiresAt := envelope.ExpiresAt
	envelope.Destroy()
	if err != nil {
		clear(encoded)
		return nil, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	material, err := collection.NewCredentialMaterial(bound.Credential, encoded, expiresAt)
	clear(encoded)
	if err != nil {
		return nil, discoveryCredentialFailure(ctx, collection.FailureOutcomeUnknown)
	}
	return material, nil
}

func (resolver *productionDiscoveryCredentialResolver) resolveAWS(ctx context.Context, bound discoveryCredentialMaterialRequest, now time.Time) (discoveryCredentialEnvelope, error) {
	var config struct {
		ExternalIDReference string `json:"external_id_reference"`
		Region              string `json:"region"`
		RoleARN             string `json:"role_arn"`
	}
	if !decodeCanonicalDiscoveryCredentialJSON(bound.Input.Configuration, &config, 4096) {
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	match := discoveryAWSRolePattern.FindStringSubmatch(config.RoleARN)
	if len(match) != 2 || match[1] != bound.Input.SubjectID || !discoveryRegionPattern.MatchString(config.Region) || config.ExternalIDReference != bound.Credential.Reference || !validDiscoveryCredentialReference(config.ExternalIDReference, "ref:aws/external-id/") {
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	externalID, err := resolver.config.Secrets.ResolveDiscoverySecret(ctx, config.ExternalIDReference)
	if err != nil || !validDiscoveryOpaqueSecret(externalID, 16, 256) {
		clear(externalID)
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, err)
	}
	duration := int32(900)
	sessionDigest := sha256.Sum256([]byte(bound.Scope.OrganizationID().String() + "\x1f" + bound.Scope.WorkspaceID().String() + "\x1f" + bound.Scope.EnvironmentID().String() + "\x1f" + bound.Input.JobID + "\x1f" + strconv.Itoa(bound.Input.Attempt)))
	sessionName := "zasp-discovery-" + hex.EncodeToString(sessionDigest[:12])
	externalIDText := string(externalID)
	output, assumeErr := resolver.config.AssumeRole.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: aws.String(config.RoleARN), RoleSessionName: aws.String(sessionName), ExternalId: aws.String(externalIDText), DurationSeconds: &duration}, func(options *sts.Options) { options.Retryer = aws.NopRetryer{} })
	externalIDText = ""
	clear(externalID)
	if assumeErr != nil || ctx.Err() != nil {
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, assumeErr)
	}
	if output == nil || output.Credentials == nil || output.Credentials.AccessKeyId == nil || output.Credentials.SecretAccessKey == nil || output.Credentials.SessionToken == nil || output.Credentials.Expiration == nil {
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureOutcomeUnknown)
	}
	accessKey := []byte(*output.Credentials.AccessKeyId)
	secretKey := []byte(*output.Credentials.SecretAccessKey)
	sessionToken := []byte(*output.Credentials.SessionToken)
	expiresAt := boundedDiscoveryCredentialExpiry(now, bound.Input.LeaseExpiresAt, output.Credentials.Expiration.UTC())
	if !validAWSDiscoveryMaterial(accessKey, secretKey, sessionToken, expiresAt, now) {
		clear(accessKey)
		clear(secretKey)
		clear(sessionToken)
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureOutcomeUnknown)
	}
	return newDiscoveryCredentialEnvelope(bound, expiresAt, func(value *discoveryCredentialEnvelope) {
		value.Region, value.AccessKeyID, value.SecretAccessKey, value.SessionToken = config.Region, accessKey, secretKey, sessionToken
	}), nil
}

func (resolver *productionDiscoveryCredentialResolver) resolveKubernetes(ctx context.Context, bound discoveryCredentialMaterialRequest, now time.Time) (discoveryCredentialEnvelope, error) {
	var config struct {
		ConnectionReference string `json:"connection_reference"`
	}
	if !decodeCanonicalDiscoveryCredentialJSON(bound.Input.Configuration, &config, 4096) || config.ConnectionReference != bound.Credential.Reference || !validDiscoveryCredentialReference(config.ConnectionReference, "ref:kubernetes/connection/") {
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	descriptorBytes, err := resolver.config.Secrets.ResolveDiscoverySecret(ctx, config.ConnectionReference)
	if err != nil {
		clear(descriptorBytes)
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, err)
	}
	defer clear(descriptorBytes)
	var descriptor struct {
		Endpoint            string `json:"endpoint"`
		Context             string `json:"context"`
		CAReference         string `json:"ca_reference"`
		CredentialReference string `json:"credential_reference"`
	}
	if !decodeCanonicalDiscoveryCredentialJSON(descriptorBytes, &descriptor, 4096) || !validDiscoveryCredentialReference(descriptor.CAReference, "ref:kubernetes/ca/") || !validDiscoveryCredentialReference(descriptor.CredentialReference, "ref:kubernetes/credential/") || !validKubernetesDiscoveryBinding(descriptor.Endpoint, descriptor.Context, bound.Input.SubjectID) {
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	caBundle, caErr := resolver.config.Secrets.ResolveDiscoverySecret(ctx, descriptor.CAReference)
	if caErr != nil || !validDiscoveryCABundle(caBundle) {
		clear(caBundle)
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, caErr)
	}
	token, tokenErr := resolver.config.Secrets.ResolveDiscoverySecret(ctx, descriptor.CredentialReference)
	if tokenErr != nil || !validDiscoveryOpaqueSecret(token, 16, 16_384) {
		clear(caBundle)
		clear(token)
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, tokenErr)
	}
	expiresAt := bound.Input.LeaseExpiresAt.UTC()
	if !expiresAt.After(now) {
		clear(caBundle)
		clear(token)
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureCancelled)
	}
	return newDiscoveryCredentialEnvelope(bound, expiresAt, func(value *discoveryCredentialEnvelope) {
		value.Endpoint, value.Context, value.CABundlePEM, value.BearerToken = descriptor.Endpoint, descriptor.Context, caBundle, token
	}), nil
}

func (resolver *productionDiscoveryCredentialResolver) resolveGitHub(ctx context.Context, bound discoveryCredentialMaterialRequest, now time.Time) (discoveryCredentialEnvelope, error) {
	var config struct {
		AuthorizationMode string `json:"authorization_mode"`
	}
	const referencePrefix = "ref:github/installation/"
	installationID, parseErr := strconv.ParseInt(strings.TrimPrefix(bound.Credential.Reference, referencePrefix), 10, 64)
	if !decodeCanonicalDiscoveryCredentialJSON(bound.Input.Configuration, &config, 4096) || config.AuthorizationMode != "github_app" || !strings.HasPrefix(bound.Credential.Reference, referencePrefix) || parseErr != nil || installationID < 1 || strconv.FormatInt(installationID, 10) != bound.Input.SubjectID {
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	key, err := resolver.config.Secrets.ResolveDiscoverySecret(ctx, resolver.config.GitHubPrivateKeyReference)
	if err != nil || len(key) < 16 || len(key) > 16_384 {
		clear(key)
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, err)
	}
	result, mintErr := resolver.config.GitHub.MintDiscoveryInstallationToken(ctx, resolver.config.GitHubAppID, key, installationID)
	clear(key)
	if mintErr != nil || ctx.Err() != nil {
		result.Destroy()
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, mintErr)
	}
	expiresAt := boundedDiscoveryCredentialExpiry(now, bound.Input.LeaseExpiresAt, result.ExpiresAt)
	if result.InstallationID != installationID || !validDiscoveryOpaqueSecret(result.Token, 16, 8192) || !expiresAt.After(now) {
		result.Destroy()
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureDenied)
	}
	token := bytes.Clone(result.Token)
	result.Destroy()
	return newDiscoveryCredentialEnvelope(bound, expiresAt, func(value *discoveryCredentialEnvelope) { value.BearerToken = token }), nil
}

func (resolver *productionDiscoveryCredentialResolver) resolveOkta(ctx context.Context, bound discoveryCredentialMaterialRequest, now time.Time) (discoveryCredentialEnvelope, error) {
	var config struct {
		Issuer string `json:"issuer"`
	}
	if !decodeCanonicalDiscoveryCredentialJSON(bound.Input.Configuration, &config, 4096) {
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	issuerMatch := discoveryOktaIssuerPattern.FindStringSubmatch(config.Issuer)
	if len(issuerMatch) != 2 || issuerMatch[1] != bound.Input.SubjectID || !validDiscoveryCredentialReference(bound.Credential.Reference, "ref:okta/refresh/") {
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	clientSecret, clientErr := resolver.config.Secrets.ResolveDiscoverySecret(ctx, resolver.config.OktaClientSecretReference)
	if clientErr != nil || !validDiscoveryOpaqueSecret(clientSecret, 8, 16_384) {
		clear(clientSecret)
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, clientErr)
	}
	refreshToken, refreshErr := resolver.config.Secrets.ResolveDiscoverySecret(ctx, bound.Credential.Reference)
	if refreshErr != nil || !validDiscoveryOpaqueSecret(refreshToken, 16, 8192) {
		clear(clientSecret)
		clear(refreshToken)
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, refreshErr)
	}
	result, exchangeErr := resolver.config.Okta.ExchangeDiscoveryRefreshToken(ctx, config.Issuer, resolver.config.OktaClientID, clientSecret, refreshToken)
	clear(clientSecret)
	clear(refreshToken)
	if exchangeErr != nil || ctx.Err() != nil {
		result.Destroy()
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, exchangeErr)
	}
	expiresAt := boundedDiscoveryCredentialExpiry(now, bound.Input.LeaseExpiresAt, result.ExpiresAt)
	wantScopes := []string{"okta.apps.read", "okta.groups.read", "okta.users.read"}
	if result.Tenant != bound.Input.SubjectID || !equalDiscoveryStrings(result.Scopes, wantScopes) || !validDiscoveryOpaqueSecret(result.Token, 16, 8192) || !expiresAt.After(now) {
		result.Destroy()
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureDenied)
	}
	token := bytes.Clone(result.Token)
	result.Destroy()
	return newDiscoveryCredentialEnvelope(bound, expiresAt, func(value *discoveryCredentialEnvelope) { value.Issuer, value.BearerToken = config.Issuer, token }), nil
}

type discoveryCredentialEnvelope struct {
	Version         string              `json:"version"`
	Provider        collection.Provider `json:"provider"`
	SubjectKind     string              `json:"subject_kind"`
	SubjectID       string              `json:"subject_id"`
	ExpiresAt       time.Time           `json:"expires_at"`
	Region          string              `json:"region,omitempty"`
	AccessKeyID     []byte              `json:"access_key_id,omitempty"`
	SecretAccessKey []byte              `json:"secret_access_key,omitempty"`
	SessionToken    []byte              `json:"session_token,omitempty"`
	Endpoint        string              `json:"endpoint,omitempty"`
	Context         string              `json:"context,omitempty"`
	CABundlePEM     []byte              `json:"ca_bundle_pem,omitempty"`
	Issuer          string              `json:"issuer,omitempty"`
	BearerToken     []byte              `json:"bearer_token,omitempty"`
}

func newDiscoveryCredentialEnvelope(bound discoveryCredentialMaterialRequest, expiresAt time.Time, populate func(*discoveryCredentialEnvelope)) discoveryCredentialEnvelope {
	value := discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: bound.Input.Provider, SubjectKind: bound.Input.SubjectKind, SubjectID: bound.Input.SubjectID, ExpiresAt: expiresAt.UTC()}
	populate(&value)
	return value
}

func encodeDiscoveryCredentialEnvelope(value discoveryCredentialEnvelope) ([]byte, error) {
	if !validDiscoveryCredentialEnvelope(value) {
		return nil, collection.ErrCredential
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) < 1 || len(encoded) > 65_536 {
		clear(encoded)
		return nil, collection.ErrCredential
	}
	return encoded, nil
}

func decodeDiscoveryCredentialEnvelope(raw []byte) (discoveryCredentialEnvelope, error) {
	var value discoveryCredentialEnvelope
	if !decodeCanonicalDiscoveryCredentialJSON(raw, &value, 65_536) || !validDiscoveryCredentialEnvelope(value) {
		value.Destroy()
		return discoveryCredentialEnvelope{}, collection.ErrCredential
	}
	return value, nil
}

func validDiscoveryCredentialEnvelope(value discoveryCredentialEnvelope) bool {
	if value.Version != discoveryCredentialEnvelopeVersion || value.ExpiresAt.IsZero() || value.ExpiresAt.Location() != time.UTC {
		return false
	}
	switch value.Provider {
	case collection.ProviderAWS:
		return value.SubjectKind == "aws_account" && discoveryRegionPattern.MatchString(value.Region) && validAWSDiscoveryMaterial(value.AccessKeyID, value.SecretAccessKey, value.SessionToken, value.ExpiresAt, time.Time{}) && value.Endpoint == "" && value.Context == "" && len(value.CABundlePEM) == 0 && value.Issuer == "" && len(value.BearerToken) == 0
	case collection.ProviderKubernetes:
		return value.SubjectKind == "kubernetes_cluster" && validKubernetesDiscoveryBinding(value.Endpoint, value.Context, value.SubjectID) && validDiscoveryCABundle(value.CABundlePEM) && validDiscoveryOpaqueSecret(value.BearerToken, 16, 16_384) && value.Region == "" && len(value.AccessKeyID) == 0 && len(value.SecretAccessKey) == 0 && len(value.SessionToken) == 0 && value.Issuer == ""
	case collection.ProviderGitHub:
		installationID, err := strconv.ParseInt(value.SubjectID, 10, 64)
		return value.SubjectKind == "github_installation" && err == nil && installationID > 0 && validDiscoveryOpaqueSecret(value.BearerToken, 16, 8192) && discoveryCredentialEnvelopeEmptyProviderFields(value)
	case collection.ProviderOkta:
		match := discoveryOktaIssuerPattern.FindStringSubmatch(value.Issuer)
		return value.SubjectKind == "okta_tenant" && len(match) == 2 && match[1] == value.SubjectID && validDiscoveryOpaqueSecret(value.BearerToken, 16, 8192) && discoveryCredentialEnvelopeEmptyProviderFields(value)
	default:
		return false
	}
}

func discoveryCredentialEnvelopeEmptyProviderFields(value discoveryCredentialEnvelope) bool {
	return value.Region == "" && len(value.AccessKeyID) == 0 && len(value.SecretAccessKey) == 0 && len(value.SessionToken) == 0 && value.Endpoint == "" && value.Context == "" && len(value.CABundlePEM) == 0
}

func (value *discoveryCredentialEnvelope) Destroy() {
	if value == nil {
		return
	}
	clear(value.AccessKeyID)
	clear(value.SecretAccessKey)
	clear(value.SessionToken)
	clear(value.CABundlePEM)
	clear(value.BearerToken)
	*value = discoveryCredentialEnvelope{}
}

func (value *discoveryGitHubInstallationToken) Destroy() {
	if value == nil {
		return
	}
	clear(value.Token)
	*value = discoveryGitHubInstallationToken{}
}

func cloneDiscoveryGitHubInstallationToken(value discoveryGitHubInstallationToken) discoveryGitHubInstallationToken {
	value.Token = bytes.Clone(value.Token)
	return value
}

func (value *discoveryOktaAccessToken) Destroy() {
	if value == nil {
		return
	}
	clear(value.Token)
	for index := range value.Scopes {
		value.Scopes[index] = ""
	}
	*value = discoveryOktaAccessToken{}
}

func cloneDiscoveryOktaAccessToken(value discoveryOktaAccessToken) discoveryOktaAccessToken {
	value.Token = bytes.Clone(value.Token)
	value.Scopes = append([]string(nil), value.Scopes...)
	return value
}

func validDiscoveryCredentialBinding(bound discoveryCredentialMaterialRequest) bool {
	if bound.Scope.Validate() != nil || !validDiscoveryExecutionInput(bound.Scope, bound.Input.JobID, bound.Input) || !workerIdentityPattern.MatchString(bound.WorkerID) || len(bound.LeaseToken) < 16 || len(bound.LeaseToken) > 128 {
		return false
	}
	request, ok := collectionRequest(bound.Scope, bound.Input)
	return ok && bound.Credential == credentialRequestForJob(request)
}

func validDiscoveryCredentialReference(value, prefix string) bool {
	return discoveryReferencePattern.MatchString(value) && strings.HasPrefix(value, prefix) && !strings.Contains(value, "..") && !strings.ContainsAny(value, "\\?#\x00\r\n\t ")
}

func decodeCanonicalDiscoveryCredentialJSON(raw []byte, destination any, limit int) bool {
	if len(raw) < 2 || len(raw) > limit || destination == nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(new(any)) != io.EOF {
		return false
	}
	canonical, err := json.Marshal(destination)
	return err == nil && bytes.Equal(raw, canonical)
}

func validDiscoveryOpaqueSecret(value []byte, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.Valid(value) || strings.TrimSpace(string(value)) != string(value) {
		return false
	}
	for _, character := range string(value) {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validDiscoveryCABundle(value []byte) bool {
	if len(value) < 64 || len(value) > 32<<10 {
		return false
	}
	rest := bytes.Clone(value)
	defer clear(rest)
	certificates := 0
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			clear(block.Bytes)
			return false
		}
		clear(block.Bytes)
		certificates++
		rest = remaining
	}
	return certificates >= 1 && certificates <= 32
}

func validKubernetesDiscoveryBinding(endpoint, contextName, subject string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.String() != endpoint || parsed.Scheme != "https" || parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() != "" && parsed.Port() != "443" || len(contextName) < 1 || len(contextName) > 128 || strings.ToLower(contextName) != contextName || strings.Contains(contextName, "..") {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return net.ParseIP(host) == nil && host != "localhost" && !strings.HasSuffix(host, ".localhost") && !strings.HasSuffix(host, ".local") && !strings.HasSuffix(host, ".internal") && subject == host+"/"+contextName
}

func validAWSDiscoveryMaterial(accessKey, secretKey, token []byte, expiresAt, now time.Time) bool {
	validExpiration := !expiresAt.IsZero() && expiresAt.Location() == time.UTC
	if !now.IsZero() {
		validExpiration = validExpiration && expiresAt.After(now)
	}
	return validExpiration && len(accessKey) >= 16 && len(accessKey) <= 128 && len(secretKey) >= 32 && len(secretKey) <= 128 && len(token) >= 16 && len(token) <= 4096 && validDiscoveryOpaqueSecret(accessKey, 16, 128) && validDiscoveryOpaqueSecret(secretKey, 32, 128) && validDiscoveryOpaqueSecret(token, 16, 4096)
}

func boundedDiscoveryCredentialExpiry(now, lease, provider time.Time) time.Time {
	expiresAt := lease.UTC()
	providerExpiry := provider.UTC().Add(-30 * time.Second)
	if providerExpiry.Before(expiresAt) {
		expiresAt = providerExpiry
	}
	if !expiresAt.After(now) {
		return time.Time{}
	}
	return expiresAt
}

func discoveryCredentialFailure(ctx context.Context, code collection.FailureCode) error {
	if ctx != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			code = collection.FailureCancelled
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			code = collection.FailureRetryable
		}
	}
	failure, err := collection.NewFailure(code, time.Time{})
	if err != nil {
		return collection.ErrCredential
	}
	return failure
}

func mapDiscoveryCredentialDependency(ctx context.Context, err error) error {
	var failure *collection.Failure
	if errors.As(err, &failure) && failure != nil {
		return failure
	}
	return discoveryCredentialFailure(ctx, collection.FailureRetryable)
}

func equalDiscoveryStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func nilDiscoveryCredentialDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

var _ discoveryCredentialMaterialResolver = (*productionDiscoveryCredentialResolver)(nil)
