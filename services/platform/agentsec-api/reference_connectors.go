package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
)

var (
	awsCustomerRolePrefixPattern = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,120}/$`)
	awsCustomerRoleARNPattern    = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,128}$`)
)

type referenceSecretResolver struct {
	driver *connectorSecretsDriver
	root   string
}

func (resolver *referenceSecretResolver) Resolve(ctx context.Context, reference string) ([]byte, error) {
	if resolver == nil || resolver.driver == nil || ctx == nil || ctx.Err() != nil || len(resolver.root) < 3 || len(resolver.root) > 128 || strings.Contains(resolver.root, "..") {
		return nil, errRuntimeUnavailable
	}
	prefixes := []string{"ref:aws/external-id/", "ref:kubernetes/connection/", "ref:kubernetes/ca/", "ref:kubernetes/credential/"}
	for _, prefix := range prefixes {
		if !strings.HasPrefix(reference, prefix) {
			continue
		}
		identifier := strings.TrimPrefix(reference, prefix)
		if len(identifier) < 8 || len(identifier) > 128 || strings.Contains(identifier, "..") || strings.ContainsAny(identifier, "/\\?#\x00\r\n\t ") {
			return nil, errRuntimeUnavailable
		}
		path := strings.TrimPrefix(strings.TrimSuffix(prefix, "/"), "ref:")
		value, err := resolver.driver.Read(ctx, resolver.root+"/"+path+"/"+identifier)
		if err != nil {
			return nil, errRuntimeUnavailable
		}
		return value, nil
	}
	return nil, errRuntimeUnavailable
}

type awsReferenceAPI interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

type awsCallerIdentityAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type awsReferenceIdentityClient struct {
	assume       awsReferenceAPI
	newCaller    func(string, aws.Credentials) awsCallerIdentityAPI
	rolePrefixes []string
	roleARNs     []string
}

func (client *awsReferenceIdentityClient) GetCallerIdentity(ctx context.Context, request awsdiscovery.AssumeRoleRequest) (awsdiscovery.Identity, error) {
	if client == nil || client.assume == nil || client.newCaller == nil || ctx == nil || ctx.Err() != nil || !validAWSCustomerRoleAuthority(client.rolePrefixes, client.roleARNs) || !containsString(client.roleARNs, request.RoleARN) || request.Duration != 15*time.Minute || len(request.ExternalID) < 16 || len(request.ExternalID) > 256 {
		return awsdiscovery.Identity{}, errRuntimeUnavailable
	}
	duration := int32(900)
	externalID := string(request.ExternalID)
	output, err := client.assume.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: aws.String(request.RoleARN), RoleSessionName: aws.String("zasp-reference-authorization"), ExternalId: &externalID, DurationSeconds: &duration})
	externalID = ""
	if err != nil || output == nil || output.Credentials == nil || output.Credentials.AccessKeyId == nil || output.Credentials.SecretAccessKey == nil || output.Credentials.SessionToken == nil || output.Credentials.Expiration == nil || !output.Credentials.Expiration.After(time.Now().Add(time.Minute)) {
		return awsdiscovery.Identity{}, errRuntimeUnavailable
	}
	credentials := aws.Credentials{AccessKeyID: *output.Credentials.AccessKeyId, SecretAccessKey: *output.Credentials.SecretAccessKey, SessionToken: *output.Credentials.SessionToken, CanExpire: true, Expires: output.Credentials.Expiration.UTC(), Source: "zasp-reference-assume-role"}
	identity, err := client.newCaller(request.Region, credentials).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken = "", "", ""
	if err != nil || identity == nil || identity.Account == nil || identity.Arn == nil {
		return awsdiscovery.Identity{}, errRuntimeUnavailable
	}
	return awsdiscovery.Identity{AccountID: *identity.Account, PrincipalARN: *identity.Arn}, nil
}

func parseAWSCustomerRolePrefixes(value string) []string {
	if value == "" {
		return nil
	}
	var values []string
	if json.Unmarshal([]byte(value), &values) != nil || !validAWSCustomerRolePrefixes(values) {
		return nil
	}
	canonical, err := json.Marshal(values)
	if err != nil || string(canonical) != value {
		return nil
	}
	return append([]string(nil), values...)
}

func parseAWSCustomerRoleARNs(value string) []string {
	if value == "" {
		return nil
	}
	var values []string
	if json.Unmarshal([]byte(value), &values) != nil || !validAWSCustomerRoleARNs(values) {
		return nil
	}
	canonical, err := json.Marshal(values)
	if err != nil || string(canonical) != value {
		return nil
	}
	return append([]string(nil), values...)
}

func validAWSCustomerRolePrefixes(values []string) bool {
	if len(values) < 1 || len(values) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !awsCustomerRolePrefixPattern.MatchString(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func matchesAWSCustomerRolePrefix(roleARN string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if roleARN != prefix && strings.HasPrefix(roleARN, prefix) {
			return true
		}
	}
	return false
}

func validAWSCustomerRoleARNs(values []string) bool {
	if len(values) < 1 || len(values) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !awsCustomerRoleARNPattern.MatchString(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validAWSCustomerRoleAuthority(prefixes, roleARNs []string) bool {
	if !validAWSCustomerRolePrefixes(prefixes) || !validAWSCustomerRoleARNs(roleARNs) {
		return false
	}
	for _, roleARN := range roleARNs {
		if !matchesAWSCustomerRolePrefix(roleARN, prefixes) {
			return false
		}
	}
	return true
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

type awsReferenceProbe struct{ adapter *awsdiscovery.Adapter }

func (probe *awsReferenceProbe) ProbeReferenceAuthorization(ctx context.Context, target apiserver.ReferenceAuthorizationTarget) error {
	var config struct {
		RoleARN             string `json:"role_arn"`
		ExternalIDReference string `json:"external_id_reference"`
		Region              string `json:"region"`
	}
	if probe == nil || probe.adapter == nil || !decodeStrictReferenceJSON(target.Configuration, &config, 4096) {
		return errRuntimeUnavailable
	}
	_, err := probe.adapter.TestConnection(ctx, awsdiscovery.Config{RoleARN: config.RoleARN, ExternalIDReference: config.ExternalIDReference, Region: config.Region})
	return err
}

type kubernetesReferenceProbe struct {
	adapter  *kubernetesdiscovery.Adapter
	resolver *referenceSecretResolver
}

func (probe *kubernetesReferenceProbe) ProbeReferenceAuthorization(ctx context.Context, target apiserver.ReferenceAuthorizationTarget) error {
	var configuration struct {
		ConnectionReference string `json:"connection_reference"`
	}
	if probe == nil || probe.adapter == nil || probe.resolver == nil || !decodeStrictReferenceJSON(target.Configuration, &configuration, 4096) || configuration.ConnectionReference != target.ConnectionReference {
		return errRuntimeUnavailable
	}
	descriptorBytes, err := probe.resolver.Resolve(ctx, configuration.ConnectionReference)
	if err != nil {
		return errRuntimeUnavailable
	}
	defer clear(descriptorBytes)
	var descriptor struct {
		Endpoint            string `json:"endpoint"`
		Context             string `json:"context"`
		CAReference         string `json:"ca_reference"`
		CredentialReference string `json:"credential_reference"`
	}
	if !decodeStrictReferenceJSON(descriptorBytes, &descriptor, 4096) {
		return errRuntimeUnavailable
	}
	_, err = probe.adapter.TestConnection(ctx, kubernetesdiscovery.Config{Endpoint: descriptor.Endpoint, Context: descriptor.Context, CAReference: descriptor.CAReference, CredentialReference: descriptor.CredentialReference})
	return err
}

func decodeStrictReferenceJSON(raw []byte, target any, limit int) bool {
	if len(raw) < 2 || len(raw) > limit || target == nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

type kubernetesProbeClient struct {
	resolver *referenceSecretResolver
	cidrs    []*net.IPNet
	lookup   func(context.Context, string) ([]net.IPAddr, error)
	timeout  time.Duration
}

func (client *kubernetesProbeClient) Probe(ctx context.Context, request kubernetesdiscovery.ProbeRequest) (kubernetesdiscovery.ProbeResult, error) {
	parsed, err := url.Parse(request.Endpoint)
	if client == nil || client.resolver == nil || len(client.cidrs) == 0 || client.lookup == nil || ctx == nil || ctx.Err() != nil || err != nil || parsed.Scheme != "https" || parsed.Port() != "" && parsed.Port() != "443" {
		return kubernetesdiscovery.ProbeResult{}, errRuntimeUnavailable
	}
	addresses, err := client.lookup(ctx, parsed.Hostname())
	if err != nil || len(addresses) < 1 || len(addresses) > 16 {
		return kubernetesdiscovery.ProbeResult{}, errRuntimeUnavailable
	}
	var pinned net.IP
	for _, address := range addresses {
		allowed := false
		for _, network := range client.cidrs {
			allowed = allowed || network.Contains(address.IP)
		}
		if !allowed {
			return kubernetesdiscovery.ProbeResult{}, errRuntimeUnavailable
		}
		if pinned == nil {
			pinned = append(net.IP(nil), address.IP...)
		}
	}
	ca, caErr := client.resolver.Resolve(ctx, request.CAReference)
	credential, credentialErr := client.resolver.Resolve(ctx, request.CredentialReference)
	defer clear(ca)
	defer clear(credential)
	pool := x509.NewCertPool()
	if caErr != nil || credentialErr != nil || len(credential) < 16 || len(credential) > 4096 || bytes.ContainsAny(credential, "\x00\r\n") || !pool.AppendCertsFromPEM(ca) {
		return kubernetesdiscovery.ProbeResult{}, errRuntimeUnavailable
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: parsed.Hostname()}, DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: client.timeout}).DialContext(dialCtx, network, net.JoinHostPort(pinned.String(), "443"))
	}, TLSHandshakeTimeout: client.timeout, ResponseHeaderTimeout: client.timeout, MaxResponseHeaderBytes: 64 << 10}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: client.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	requestJSON := []byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}`)
	versionBody, err := referenceKubernetesRequest(ctx, httpClient, request.Endpoint+"/version", http.MethodGet, nil, credential)
	if err != nil {
		return kubernetesdiscovery.ProbeResult{}, errRuntimeUnavailable
	}
	rulesBody, err := referenceKubernetesRequest(ctx, httpClient, request.Endpoint+"/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", http.MethodPost, requestJSON, credential)
	if err != nil {
		return kubernetesdiscovery.ProbeResult{}, errRuntimeUnavailable
	}
	var version struct {
		GitVersion string `json:"gitVersion"`
	}
	var rules struct {
		Status struct {
			ResourceRules []struct {
				Verbs []string `json:"verbs"`
			} `json:"resourceRules"`
		} `json:"status"`
	}
	if json.Unmarshal(versionBody, &version) != nil || json.Unmarshal(rulesBody, &rules) != nil {
		return kubernetesdiscovery.ProbeResult{}, errRuntimeUnavailable
	}
	verbs := map[string]struct{}{"api-discovery": {}}
	for _, rule := range rules.Status.ResourceRules {
		for _, verb := range rule.Verbs {
			if verb == "get" || verb == "list" || verb == "watch" {
				verbs[verb] = struct{}{}
			}
		}
	}
	allowed := make([]string, 0, len(verbs))
	for verb := range verbs {
		allowed = append(allowed, verb)
	}
	sort.Strings(allowed)
	return kubernetesdiscovery.ProbeResult{ClusterID: parsed.Hostname() + "/" + request.Context, ServerVersion: version.GitVersion, AllowedVerbs: allowed}, nil
}

func referenceKubernetesRequest(ctx context.Context, client *http.Client, endpoint, method string, body []byte, credential []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(credential))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != "application/json" {
		return nil, errors.New("kubernetes probe rejected")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(payload) < 2 || len(payload) > 64<<10 {
		return nil, errors.New("kubernetes probe rejected")
	}
	return payload, nil
}

func parseReferenceCIDRs(values []string) ([]*net.IPNet, error) {
	if len(values) < 1 || len(values) > 32 {
		return nil, errRuntimeUnavailable
	}
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil || network.String() != value {
			return nil, errRuntimeUnavailable
		}
		result = append(result, network)
	}
	return result, nil
}

func newReferenceAWSClient(config RuntimeConfig) (*awsReferenceIdentityClient, *http.Transport, error) {
	if !validAWSCustomerRoleAuthority(config.AWSCustomerRolePrefixes, config.AWSCustomerRoleARNs) {
		return nil, nil, errRuntimeUnavailable
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: config.ProviderTimeout, MaxResponseHeaderBytes: 1 << 20}
	httpClient := &http.Client{Transport: transport, Timeout: config.ProviderTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := aws.Config{Region: config.ConnectorAWSRegion, HTTPClient: httpClient, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	webSTS := sts.NewFromConfig(base)
	base.Credentials = aws.NewCredentialsCache(&connectorWebIdentityProvider{client: webSTS, roleARN: config.ConnectorRoleARN, tokenFile: config.ConnectorTokenFile, timeout: config.ProviderTimeout})
	assume := sts.NewFromConfig(base)
	return &awsReferenceIdentityClient{assume: assume, rolePrefixes: append([]string(nil), config.AWSCustomerRolePrefixes...), roleARNs: append([]string(nil), config.AWSCustomerRoleARNs...), newCaller: func(region string, credentials aws.Credentials) awsCallerIdentityAPI {
		candidate := base
		candidate.Region = region
		candidate.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return credentials, nil })
		return sts.NewFromConfig(candidate)
	}}, transport, nil
}

var _ apiserver.ReferenceAuthorizationProbe = (*awsReferenceProbe)(nil)
var _ apiserver.ReferenceAuthorizationProbe = (*kubernetesReferenceProbe)(nil)
var _ awsdiscovery.ReferenceResolver = (*referenceSecretResolver)(nil)
var _ awsdiscovery.IdentityClient = (*awsReferenceIdentityClient)(nil)
var _ kubernetesdiscovery.ProbeClient = (*kubernetesProbeClient)(nil)
