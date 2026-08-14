package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
)

const (
	fixedRegion = "us-east-1"
	maxBodySize = 1 << 20
)

type validatedEndpoint struct{ raw, host, port string }

type SDKBoundary struct {
	sourceIAM, targetIAM *iam.Client
	sourceSTS            *sts.Client
	transport            *http.Transport
	endpoint             validatedEndpoint
	httpClient           *http.Client
}

func ValidateLoopbackEndpoint(ctx context.Context, raw string) (string, error) {
	endpoint, _, err := validatedLoopbackTransport(ctx, raw)
	if err != nil {
		return "", errConfiguration
	}
	return endpoint.raw, nil
}

func NewSDKBoundary(ctx context.Context, rawEndpoint, sourceAccount, targetAccount string) (*SDKBoundary, error) {
	if sourceAccount != sourceNamespace || targetAccount != targetNamespace || sourceAccount == targetAccount {
		return nil, errConfiguration
	}
	endpoint, dialContext, err := validatedLoopbackTransport(ctx, rawEndpoint)
	if err != nil {
		return nil, errConfiguration
	}
	transport := &http.Transport{Proxy: nil, DialContext: dialContext, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	httpClient := &http.Client{Timeout: 25 * time.Second, Transport: bodyBoundTransport{base: transport}, CheckRedirect: rejectRedirect}
	sourceCredentials := aws.CredentialsProviderFunc(staticNamespaceCredentials(sourceAccount))
	targetCredentials := aws.CredentialsProviderFunc(staticNamespaceCredentials(targetAccount))
	readRetryer := retry.NewStandard(func(options *retry.StandardOptions) {
		options.MaxAttempts = 2
		options.MaxBackoff = 500 * time.Millisecond
		options.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 500 * time.Millisecond, nil })
	})
	return &SDKBoundary{
		sourceIAM: iam.New(iam.Options{Region: fixedRegion, BaseEndpoint: aws.String(endpoint.raw), HTTPClient: httpClient, Credentials: sourceCredentials, Retryer: readRetryer, RetryMaxAttempts: 2}),
		targetIAM: iam.New(iam.Options{Region: fixedRegion, BaseEndpoint: aws.String(endpoint.raw), HTTPClient: httpClient, Credentials: targetCredentials, Retryer: readRetryer, RetryMaxAttempts: 2}),
		sourceSTS: sts.New(sts.Options{Region: fixedRegion, BaseEndpoint: aws.String(endpoint.raw), HTTPClient: httpClient, Credentials: sourceCredentials, RetryMaxAttempts: 1}),
		transport: transport, endpoint: endpoint, httpClient: httpClient,
	}, nil
}

func staticNamespaceCredentials(account string) func(context.Context) (aws.Credentials, error) {
	return func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: account, SecretAccessKey: "test", Source: "localstack-namespace"}, nil
	}
}

func validatedLoopbackTransport(ctx context.Context, raw string) (validatedEndpoint, func(context.Context, string, string) (net.Conn, error), error) {
	if ctx == nil {
		return validatedEndpoint{}, nil, errConfiguration
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() == "" || u.Port() == "0" {
		return validatedEndpoint{}, nil, errConfiguration
	}
	host, port := u.Hostname(), u.Port()
	_, ok := resolveLoopback(ctx, host)
	if host == "" || !ok {
		return validatedEndpoint{}, nil, errConfiguration
	}
	endpoint := validatedEndpoint{raw: raw, host: host, port: port}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	dialContext := func(callCtx context.Context, network, address string) (net.Conn, error) {
		requestedHost, requestedPort, err := net.SplitHostPort(address)
		addresses, ok := resolveLoopback(callCtx, endpoint.host)
		if err != nil || requestedPort != endpoint.port || !sameHost(requestedHost, endpoint.host) || !ok {
			return nil, errConfiguration
		}
		return dialer.DialContext(callCtx, network, net.JoinHostPort(addresses[0].IP.String(), endpoint.port))
	}
	return endpoint, dialContext, nil
}

var lookupIPAddr = net.DefaultResolver.LookupIPAddr

func resolveLoopback(ctx context.Context, host string) ([]net.IPAddr, bool) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, ip.IsLoopback()
	}
	addresses, err := lookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, false
	}
	for _, address := range addresses {
		if !address.IP.IsLoopback() {
			return nil, false
		}
	}
	return addresses, true
}

func sameHost(left, right string) bool                    { return strings.Trim(left, "[]") == strings.Trim(right, "[]") }
func rejectRedirect(*http.Request, []*http.Request) error { return errConfiguration }

type bodyBoundTransport struct{ base http.RoundTripper }

func (t bodyBoundTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil {
		return response, err
	}
	if response.ContentLength > maxBodySize {
		response.Body = &limitedReadCloser{ReadCloser: response.Body, remaining: 0, status: response.StatusCode}
		return response, nil
	}
	response.Body = &limitedReadCloser{ReadCloser: response.Body, remaining: maxBodySize + 1, status: response.StatusCode}
	return response, nil
}

type limitedReadCloser struct {
	io.ReadCloser
	remaining int64
	status    int
}

func (r *limitedReadCloser) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, bodyStatusError{status: r.status}
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.ReadCloser.Read(p)
	r.remaining -= int64(n)
	if r.remaining == 0 && err == nil {
		return n, bodyStatusError{status: r.status}
	}
	return n, err
}

type bodyStatusError struct{ status int }

func (e bodyStatusError) Error() string       { return "response body too large" }
func (e bodyStatusError) HTTPStatusCode() int { return e.status }

func (b *SDKBoundary) SourceIdentity(ctx context.Context) (CallerIdentity, error) {
	out, err := b.sourceSTS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return CallerIdentity{}, errProvider
	}
	identity := CallerIdentity{AccountID: aws.ToString(out.Account), ARN: aws.ToString(out.Arn), UserID: aws.ToString(out.UserId)}
	if identity.AccountID != sourceNamespace || identity.ARN == "" || identity.UserID == "" {
		return CallerIdentity{}, errOwnership
	}
	return identity, nil
}

func (b *SDKBoundary) TargetIdentity(ctx context.Context) (CallerIdentity, error) {
	out, err := b.targetIAM.GetUser(ctx, &iam.GetUserInput{})
	if err != nil {
		return CallerIdentity{}, errProvider
	}
	if out.User == nil {
		return CallerIdentity{}, errOwnership
	}
	identity := CallerIdentity{AccountID: targetNamespace, ARN: aws.ToString(out.User.Arn), UserID: aws.ToString(out.User.UserId)}
	if identity.ARN == "" || identity.UserID == "" {
		return CallerIdentity{}, errOwnership
	}
	return identity, nil
}

func (b *SDKBoundary) ListPrincipals(ctx context.Context, prefix string) ([]PrincipalState, error) {
	var states []PrincipalState
	var marker *string
	for {
		out, err := b.sourceIAM.ListUsers(ctx, &iam.ListUsersInput{Marker: marker})
		if err != nil {
			return nil, errProvider
		}
		for _, user := range out.Users {
			state, ok := principalFromUser(user)
			if !ok {
				return nil, errOwnership
			}
			if strings.HasPrefix(state.Name, prefix) {
				states = append(states, state)
			}
		}
		if !out.IsTruncated || out.Marker == nil || aws.ToString(out.Marker) == "" {
			return states, nil
		}
		marker = out.Marker
	}
}
func (b *SDKBoundary) CreatePrincipal(ctx context.Context, spec PrincipalSpec) (PrincipalState, error) {
	out, err := b.sourceIAM.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String(spec.Name), Path: aws.String(spec.Path), Tags: iamTags(spec.Tags)}, oneAttemptIAM)
	if err != nil {
		return PrincipalState{}, classifyMutationError(err)
	}
	if out.User == nil {
		return PrincipalState{}, ambiguousMutationError{cause: errProvider}
	}
	state, ok := principalFromUser(*out.User)
	if !ok {
		return PrincipalState{}, ambiguousMutationError{cause: errProvider}
	}
	return state, nil
}
func (b *SDKBoundary) InspectPrincipal(ctx context.Context, name string) (PrincipalState, error) {
	out, err := b.sourceIAM.GetUser(ctx, &iam.GetUserInput{UserName: aws.String(name)})
	if err != nil {
		return PrincipalState{}, errProvider
	}
	if out.User == nil {
		return PrincipalState{}, errOwnership
	}
	state, ok := principalFromUser(*out.User)
	if !ok {
		return PrincipalState{}, errOwnership
	}
	return state, nil
}
func (b *SDKBoundary) CreateAccessKey(ctx context.Context, user string) (string, string, error) {
	out, err := b.sourceIAM.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String(user)}, oneAttemptIAM)
	if err != nil {
		return "", "", classifyMutationError(err)
	}
	if out.AccessKey == nil || aws.ToString(out.AccessKey.AccessKeyId) == "" || aws.ToString(out.AccessKey.SecretAccessKey) == "" || aws.ToString(out.AccessKey.UserName) != user || out.AccessKey.Status != iamtypes.StatusTypeActive {
		return "", "", ambiguousMutationError{cause: errProvider}
	}
	return aws.ToString(out.AccessKey.AccessKeyId), aws.ToString(out.AccessKey.SecretAccessKey), nil
}
func (b *SDKBoundary) ListAccessKeys(ctx context.Context, user string) ([]string, error) {
	out, err := b.sourceIAM.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(user)})
	if err != nil {
		return nil, errProvider
	}
	keys := make([]string, 0, len(out.AccessKeyMetadata))
	for _, key := range out.AccessKeyMetadata {
		id := aws.ToString(key.AccessKeyId)
		if id == "" || aws.ToString(key.UserName) != user {
			return nil, errOwnership
		}
		keys = append(keys, id)
	}
	return keys, nil
}
func (b *SDKBoundary) DeleteAccessKey(ctx context.Context, user, key string) error {
	_, err := b.sourceIAM.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: aws.String(user), AccessKeyId: aws.String(key)}, oneAttemptIAM)
	return classifyMutationError(err)
}
func (b *SDKBoundary) DeletePrincipal(ctx context.Context, user string) error {
	_, err := b.sourceIAM.DeleteUser(ctx, &iam.DeleteUserInput{UserName: aws.String(user)}, oneAttemptIAM)
	return classifyMutationError(err)
}

func (b *SDKBoundary) ListRoles(ctx context.Context, prefix string) ([]RoleState, error) {
	var states []RoleState
	var marker *string
	for {
		out, err := b.targetIAM.ListRoles(ctx, &iam.ListRolesInput{Marker: marker})
		if err != nil {
			return nil, errProvider
		}
		for _, role := range out.Roles {
			state, ok := roleFromSDK(role)
			if !ok {
				return nil, errOwnership
			}
			if strings.HasPrefix(state.Name, prefix) {
				states = append(states, state)
			}
		}
		if !out.IsTruncated || out.Marker == nil || aws.ToString(out.Marker) == "" {
			return states, nil
		}
		marker = out.Marker
	}
}
func (b *SDKBoundary) CreateRole(ctx context.Context, spec RoleSpec) (RoleState, error) {
	out, err := b.targetIAM.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String(spec.Name), Path: aws.String(spec.Path), Description: aws.String(spec.Description), AssumeRolePolicyDocument: aws.String(spec.TrustPolicy), Tags: iamTags(spec.Tags)}, oneAttemptIAM)
	if err != nil {
		return RoleState{}, classifyMutationError(err)
	}
	if out.Role == nil {
		return RoleState{}, ambiguousMutationError{cause: errProvider}
	}
	state, ok := roleFromSDK(*out.Role)
	if !ok {
		return RoleState{}, ambiguousMutationError{cause: errProvider}
	}
	if !sameRoleDefinition(spec, state) {
		return RoleState{}, ambiguousMutationError{cause: errProvider}
	}
	state.PolicyName, state.PermissionPolicy = spec.PolicyName, spec.PermissionPolicy
	return state, nil
}
func (b *SDKBoundary) InspectRole(ctx context.Context, name string) (RoleState, error) {
	out, err := b.targetIAM.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(name)})
	if err != nil {
		return RoleState{}, errProvider
	}
	if out.Role == nil {
		return RoleState{}, errOwnership
	}
	state, ok := roleFromSDK(*out.Role)
	if !ok {
		return RoleState{}, errOwnership
	}
	policyOutput, policyErr := b.targetIAM.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: aws.String(state.Name), PolicyName: aws.String(state.PolicyName)})
	if policyErr != nil {
		var apiErr smithy.APIError
		if !errors.As(policyErr, &apiErr) || !strings.EqualFold(apiErr.ErrorCode(), "NoSuchEntity") {
			return RoleState{}, errProvider
		}
		return state, nil
	}
	if aws.ToString(policyOutput.RoleName) != state.Name || aws.ToString(policyOutput.PolicyName) != state.PolicyName {
		return RoleState{}, errOwnership
	}
	policy, ok := decodeProviderPolicy(aws.ToString(policyOutput.PolicyDocument))
	if !ok {
		return RoleState{}, errOwnership
	}
	state.PermissionPolicy = policy
	return state, nil
}
func (b *SDKBoundary) PutRolePolicy(ctx context.Context, role, name, document string) error {
	_, err := b.targetIAM.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: aws.String(role), PolicyName: aws.String(name), PolicyDocument: aws.String(document)}, oneAttemptIAM)
	return classifyMutationError(err)
}
func (b *SDKBoundary) GetRolePolicy(ctx context.Context, role, name string) (string, error) {
	return b.rolePolicy(ctx, role, name)
}
func (b *SDKBoundary) rolePolicy(ctx context.Context, role, name string) (string, error) {
	out, err := b.targetIAM.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: aws.String(role), PolicyName: aws.String(name)})
	if err != nil {
		return "", errProvider
	}
	if aws.ToString(out.RoleName) != role || aws.ToString(out.PolicyName) != name {
		return "", errOwnership
	}
	document, ok := decodeProviderPolicy(aws.ToString(out.PolicyDocument))
	if !ok {
		return "", errOwnership
	}
	return document, nil
}
func (b *SDKBoundary) DeleteRolePolicy(ctx context.Context, role, name string) error {
	_, err := b.targetIAM.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{RoleName: aws.String(role), PolicyName: aws.String(name)}, oneAttemptIAM)
	return classifyMutationError(err)
}
func (b *SDKBoundary) DeleteRole(ctx context.Context, role string) error {
	_, err := b.targetIAM.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: aws.String(role)}, oneAttemptIAM)
	return classifyMutationError(err)
}

func (b *SDKBoundary) AssumeRole(ctx context.Context, request AssumeRequest, key, secret string) (AssumedSession, error) {
	client := sts.New(sts.Options{Region: fixedRegion, BaseEndpoint: aws.String(b.endpoint.raw), HTTPClient: b.httpClient, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: key, SecretAccessKey: secret, Source: "localstack-temporary"}, nil
	}), RetryMaxAttempts: 1})
	out, err := client.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: aws.String(request.RoleARN), RoleSessionName: aws.String(request.SessionName), ExternalId: aws.String(request.ExternalID), SourceIdentity: aws.String(request.SourceIdentity), Tags: stsTags(request.Tags)})
	if err != nil {
		return AssumedSession{}, classifyMutationError(err)
	}
	return sessionFromSDK(out)
}
func (b *SDKBoundary) AssumedIdentity(ctx context.Context, session AssumedSession) (CallerIdentity, error) {
	out, err := b.assumedSTS(session).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return CallerIdentity{}, errProvider
	}
	identity := CallerIdentity{AccountID: aws.ToString(out.Account), ARN: aws.ToString(out.Arn), UserID: aws.ToString(out.UserId)}
	if identity.AccountID != targetNamespace || identity.ARN == "" || identity.UserID == "" {
		return CallerIdentity{}, errOwnership
	}
	return identity, nil
}
func (b *SDKBoundary) AllowedGetRole(ctx context.Context, session AssumedSession, role string) (RoleState, error) {
	out, err := b.assumedIAM(session).GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(role)})
	if err != nil {
		return RoleState{}, errProvider
	}
	if out.Role == nil {
		return RoleState{}, errOwnership
	}
	state, ok := roleFromSDK(*out.Role)
	if !ok {
		return RoleState{}, errOwnership
	}
	return state, nil
}
func (b *SDKBoundary) DeniedListRoles(ctx context.Context, session AssumedSession) error {
	_, err := b.assumedIAM(session).ListRoles(ctx, &iam.ListRolesInput{})
	if err == nil {
		return errAuthorization
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && strings.EqualFold(apiErr.ErrorCode(), "ExplicitDeny") {
		return explicitDenyError{}
	}
	return errAuthorization
}
func (b *SDKBoundary) assumedIAM(session AssumedSession) *iam.Client {
	return iam.New(iam.Options{Region: fixedRegion, BaseEndpoint: aws.String(b.endpoint.raw), HTTPClient: b.httpClient, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: session.AccessKeyID, SecretAccessKey: session.SecretAccessKey, SessionToken: session.SessionToken, Source: "localstack-assumed"}, nil
	}), RetryMaxAttempts: 2})
}
func (b *SDKBoundary) assumedSTS(session AssumedSession) *sts.Client {
	return sts.New(sts.Options{Region: fixedRegion, BaseEndpoint: aws.String(b.endpoint.raw), HTTPClient: b.httpClient, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: session.AccessKeyID, SecretAccessKey: session.SecretAccessKey, SessionToken: session.SessionToken, Source: "localstack-assumed"}, nil
	}), RetryMaxAttempts: 2})
}

func principalFromUser(user iamtypes.User) (PrincipalState, bool) {
	state := PrincipalState{PrincipalSpec: PrincipalSpec{Name: aws.ToString(user.UserName), ARN: aws.ToString(user.Arn), Path: aws.ToString(user.Path), Tags: tagsFromIAM(user.Tags)}, UserID: aws.ToString(user.UserId)}
	state.Marker = state.Tags["proof"]
	return state, state.Name != "" && state.ARN != "" && state.Path != "" && state.UserID != "" && state.Marker != "" && len(state.Tags) == 1
}
func roleFromSDK(role iamtypes.Role) (RoleState, bool) {
	trust, ok := decodeProviderPolicy(aws.ToString(role.AssumeRolePolicyDocument))
	if !ok {
		return RoleState{}, false
	}
	state := RoleState{Name: aws.ToString(role.RoleName), ARN: aws.ToString(role.Arn), Path: aws.ToString(role.Path), RoleID: aws.ToString(role.RoleId), TrustPolicy: trust, Description: aws.ToString(role.Description), Tags: tagsFromIAM(role.Tags)}
	state.Marker = state.Tags["proof"]
	state.PolicyName = proofPrefix(state.Marker) + "-policy"
	return state, state.Name != "" && state.ARN != "" && state.Path != "" && state.RoleID != "" && state.Marker != "" && len(state.Tags) == 1
}
func sessionFromSDK(out *sts.AssumeRoleOutput) (AssumedSession, error) {
	if out == nil || out.Credentials == nil || out.AssumedRoleUser == nil {
		return AssumedSession{}, ambiguousMutationError{cause: errProvider}
	}
	session := AssumedSession{AccessKeyID: aws.ToString(out.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey), SessionToken: aws.ToString(out.Credentials.SessionToken), Expiration: aws.ToTime(out.Credentials.Expiration), AssumedRoleARN: aws.ToString(out.AssumedRoleUser.Arn), AssumedRoleID: aws.ToString(out.AssumedRoleUser.AssumedRoleId), SourceIdentity: aws.ToString(out.SourceIdentity)}
	if session.AccessKeyID == "" || session.SecretAccessKey == "" || session.SessionToken == "" || session.Expiration.IsZero() || session.AssumedRoleARN == "" || session.AssumedRoleID == "" {
		return AssumedSession{}, ambiguousMutationError{cause: errProvider}
	}
	return session, nil
}
func iamTags(tags map[string]string) []iamtypes.Tag {
	keys := sortedKeys(tags)
	result := make([]iamtypes.Tag, 0, len(keys))
	for _, key := range keys {
		result = append(result, iamtypes.Tag{Key: aws.String(key), Value: aws.String(tags[key])})
	}
	return result
}
func stsTags(tags map[string]string) []ststypes.Tag {
	keys := sortedKeys(tags)
	result := make([]ststypes.Tag, 0, len(keys))
	for _, key := range keys {
		result = append(result, ststypes.Tag{Key: aws.String(key), Value: aws.String(tags[key])})
	}
	return result
}
func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func tagsFromIAM(tags []iamtypes.Tag) map[string]string {
	values := make(map[string]string, len(tags))
	for _, tag := range tags {
		key, value := aws.ToString(tag.Key), aws.ToString(tag.Value)
		if key == "" || value == "" {
			return nil
		}
		if _, duplicate := values[key]; duplicate {
			return nil
		}
		values[key] = value
	}
	return values
}
func decodeProviderPolicy(raw string) (string, bool) {
	if len(raw) == 0 || len(raw) > maxBodySize {
		return "", false
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil || decoded == raw || len(decoded) > maxBodySize {
		return "", false
	}
	if !validIAMPolicyDocument(decoded) {
		return "", false
	}
	return decoded, true
}

func validIAMPolicyDocument(raw string) bool {
	value, ok := decodeStrictJSON(raw)
	if !ok {
		return false
	}
	document, ok := value.(map[string]any)
	if !ok || len(document) != 2 {
		return false
	}
	version, versionOK := document["Version"].(string)
	statements, statementsOK := document["Statement"].([]any)
	return versionOK && version == "2012-10-17" && statementsOK && len(statements) > 0
}

func classifyMutationError(err error) error {
	if err == nil {
		return nil
	}
	var responseErr interface{ HTTPStatusCode() int }
	if errors.As(err, &responseErr) {
		status := responseErr.HTTPStatusCode()
		if status >= 200 && status < 300 {
			return ambiguousMutationError{cause: err}
		}
		return errProvider
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return errProvider
	}
	return ambiguousMutationError{cause: err}
}

var _ IAMBoundary = (*SDKBoundary)(nil)

func oneAttemptIAM(options *iam.Options) { options.RetryMaxAttempts = 1 }
