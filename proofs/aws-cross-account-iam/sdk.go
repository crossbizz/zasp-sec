package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsretry "github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	awsCallTimeout       = 12 * time.Second
	awsResponseBodyLimit = 1 << 20
	assumeDuration       = int32(900)
)

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

type explicitCredentialSet struct {
	accessKeyID, secretAccessKey, sessionToken string
}

type sdkBoundaryConfig struct {
	region      string
	source      explicitCredentialSet
	targetAdmin explicitCredentialSet
}

type stsAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

type iamAPI interface {
	ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	CreateRole(context.Context, *iam.CreateRoleInput, ...func(*iam.Options)) (*iam.CreateRoleOutput, error)
	GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	PutRolePolicy(context.Context, *iam.PutRolePolicyInput, ...func(*iam.Options)) (*iam.PutRolePolicyOutput, error)
	GetRolePolicy(context.Context, *iam.GetRolePolicyInput, ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	ListRolePolicies(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	DeleteRolePolicy(context.Context, *iam.DeleteRolePolicyInput, ...func(*iam.Options)) (*iam.DeleteRolePolicyOutput, error)
	DeleteRole(context.Context, *iam.DeleteRoleInput, ...func(*iam.Options)) (*iam.DeleteRoleOutput, error)
}

type assumedClientFactory func(SessionCredentials) (stsAPI, iamAPI, error)

type sdkIAMBoundary struct {
	sourceSTS  stsAPI
	targetSTS  stsAPI
	targetIAM  iamAPI
	assumed    assumedClientFactory
	transports []*http.Transport
}

func newSDKIAMBoundary(config sdkBoundaryConfig) (*sdkIAMBoundary, error) {
	if !regionPattern.MatchString(config.region) || !validExplicitCredentials(config.source) || !validExplicitCredentials(config.targetAdmin) {
		return nil, errConfiguration
	}
	httpClient, transport := newAWSHTTPClient(config.region, net.DefaultResolver, nil)
	retryer := awsretry.NewStandard(func(options *awsretry.StandardOptions) {
		options.MaxAttempts = 2
		options.MaxBackoff = 250 * time.Millisecond
	})
	newSTS := func(credentials explicitCredentialSet) *sts.Client {
		return sts.New(sts.Options{
			Region: config.region, Credentials: staticCredentials(credentials), HTTPClient: httpClient,
			Retryer: retryer, RetryMaxAttempts: 2, DisableClockSkewCorrection: true,
		})
	}
	newIAM := func(credentials explicitCredentialSet) *iam.Client {
		return iam.New(iam.Options{
			Region: config.region, Credentials: staticCredentials(credentials), HTTPClient: httpClient,
			Retryer: retryer, RetryMaxAttempts: 2, DisableClockSkewCorrection: true,
		})
	}
	boundary := &sdkIAMBoundary{
		sourceSTS: newSTS(config.source), targetSTS: newSTS(config.targetAdmin), targetIAM: newIAM(config.targetAdmin),
		transports: []*http.Transport{transport},
	}
	boundary.assumed = func(credentials SessionCredentials) (stsAPI, iamAPI, error) {
		set := explicitCredentialSet{
			accessKeyID: credentials.AccessKeyID, secretAccessKey: credentials.SecretAccessKey, sessionToken: credentials.SessionToken,
		}
		if !validExplicitCredentials(set) {
			return nil, nil, errAuthentication
		}
		return newSTS(set), newIAM(set), nil
	}
	return boundary, nil
}

func newSDKIAMBoundaryWithClients(sourceSTS, targetSTS stsAPI, targetIAM iamAPI, factory assumedClientFactory) (*sdkIAMBoundary, error) {
	if sourceSTS == nil || targetSTS == nil || targetIAM == nil || factory == nil {
		return nil, errConfiguration
	}
	return &sdkIAMBoundary{sourceSTS: sourceSTS, targetSTS: targetSTS, targetIAM: targetIAM, assumed: factory}, nil
}

func (s *sdkIAMBoundary) Close() {
	for _, transport := range s.transports {
		transport.CloseIdleConnections()
	}
}

func validExplicitCredentials(credentials explicitCredentialSet) bool {
	return credentials.accessKeyID != "" && credentials.secretAccessKey != ""
}

func staticCredentials(credentials explicitCredentialSet) aws.CredentialsProvider {
	return aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyID: credentials.accessKeyID, SecretAccessKey: credentials.secretAccessKey,
			SessionToken: credentials.sessionToken, Source: "zasp-m0-09-explicit",
		}, nil
	})
}

func (s *sdkIAMBoundary) SourceIdentity(ctx context.Context) (CallerIdentity, error) {
	return getCallerIdentity(ctx, s.sourceSTS)
}

func (s *sdkIAMBoundary) TargetIdentity(ctx context.Context) (CallerIdentity, error) {
	return getCallerIdentity(ctx, s.targetSTS)
}

func getCallerIdentity(ctx context.Context, client stsAPI) (CallerIdentity, error) {
	callCtx, cancel := boundedCallContext(ctx)
	defer cancel()
	output, err := client.GetCallerIdentity(callCtx, &sts.GetCallerIdentityInput{}, readSTSOptions)
	if err != nil || output == nil || output.Account == nil || output.Arn == nil || output.UserId == nil ||
		*output.Account == "" || *output.Arn == "" || *output.UserId == "" {
		return CallerIdentity{}, errProvider
	}
	return CallerIdentity{AccountID: *output.Account, ARN: *output.Arn, UserID: *output.UserId}, nil
}

func (s *sdkIAMBoundary) ListRoles(ctx context.Context, path string) ([]RoleSummary, error) {
	callCtx, cancel := boundedCallContext(ctx)
	defer cancel()
	maximum := int32(2)
	output, err := s.targetIAM.ListRoles(callCtx, &iam.ListRolesInput{PathPrefix: aws.String(path), MaxItems: &maximum}, readIAMOptions)
	if err != nil || output == nil || output.IsTruncated || output.Marker != nil {
		return nil, errProvider
	}
	result := make([]RoleSummary, 0, len(output.Roles))
	for _, role := range output.Roles {
		summary, err := roleSummaryFromSDK(role)
		if err != nil {
			return nil, errOwnership
		}
		result = append(result, summary)
	}
	return result, nil
}

func (s *sdkIAMBoundary) CreateRole(ctx context.Context, spec RoleSpec) (RoleState, error) {
	callCtx, cancel := boundedCallContext(ctx)
	defer cancel()
	tags := make([]iamtypes.Tag, 0, len(spec.Tags))
	for _, key := range []string{proofTagKey, markerTagKey, purposeTagKey} {
		value, ok := spec.Tags[key]
		if !ok {
			return RoleState{}, errConfiguration
		}
		tags = append(tags, iamtypes.Tag{Key: aws.String(key), Value: aws.String(value)})
	}
	output, err := s.targetIAM.CreateRole(callCtx, &iam.CreateRoleInput{
		RoleName: aws.String(spec.Name), Path: aws.String(spec.Path), Description: aws.String(spec.Description),
		AssumeRolePolicyDocument: aws.String(spec.TrustPolicy), MaxSessionDuration: aws.Int32(spec.MaxSessionDuration), Tags: tags,
	}, mutationIAMOptions)
	if err != nil {
		return RoleState{}, classifyMutationError(err)
	}
	if output == nil || output.Role == nil {
		return RoleState{}, ambiguousMutation(errProvider)
	}
	state, convertErr := roleStateFromSDK(*output.Role)
	if convertErr != nil {
		return RoleState{}, ambiguousMutation(errProvider)
	}
	return state, nil
}

func (s *sdkIAMBoundary) InspectRole(ctx context.Context, name string) (RoleState, error) {
	callCtx, cancel := boundedCallContext(ctx)
	defer cancel()
	output, err := s.targetIAM.GetRole(callCtx, &iam.GetRoleInput{RoleName: aws.String(name)}, readIAMOptions)
	if err != nil {
		if isNoSuchEntity(err) {
			return RoleState{}, errNotFound
		}
		return RoleState{}, errProvider
	}
	if output == nil || output.Role == nil {
		return RoleState{}, errProvider
	}
	return roleStateFromSDK(*output.Role)
}

func (s *sdkIAMBoundary) PutRolePolicy(ctx context.Context, roleName, policyName, document string) error {
	callCtx, cancel := boundedCallContext(ctx)
	defer cancel()
	output, err := s.targetIAM.PutRolePolicy(callCtx, &iam.PutRolePolicyInput{
		RoleName: aws.String(roleName), PolicyName: aws.String(policyName), PolicyDocument: aws.String(document),
	}, mutationIAMOptions)
	if err != nil {
		return classifyMutationError(err)
	}
	if output == nil {
		return ambiguousMutation(errProvider)
	}
	return nil
}

func (s *sdkIAMBoundary) GetRolePolicy(ctx context.Context, roleName, policyName string) (string, error) {
	callCtx, cancel := boundedCallContext(ctx)
	defer cancel()
	output, err := s.targetIAM.GetRolePolicy(callCtx, &iam.GetRolePolicyInput{
		RoleName: aws.String(roleName), PolicyName: aws.String(policyName),
	}, readIAMOptions)
	if err != nil {
		if isNoSuchEntity(err) {
			return "", errNotFound
		}
		return "", errProvider
	}
	if output == nil || output.PolicyDocument == nil || output.PolicyName == nil || output.RoleName == nil ||
		*output.PolicyName != policyName || *output.RoleName != roleName {
		return "", errProvider
	}
	document, decodeErr := decodeIAMPolicyDocument(*output.PolicyDocument)
	if decodeErr != nil {
		return "", errProvider
	}
	return document, nil
}

func (s *sdkIAMBoundary) ListRolePolicies(ctx context.Context, roleName string) ([]string, error) {
	callCtx, cancel := boundedCallContext(ctx)
	defer cancel()
	maximum := int32(2)
	output, err := s.targetIAM.ListRolePolicies(callCtx, &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName), MaxItems: &maximum,
	}, readIAMOptions)
	if err != nil || output == nil || output.IsTruncated || output.Marker != nil {
		return nil, errProvider
	}
	result := append([]string(nil), output.PolicyNames...)
	seen := make(map[string]struct{}, len(result))
	for _, name := range result {
		if name == "" {
			return nil, errProvider
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, errProvider
		}
		seen[name] = struct{}{}
	}
	return result, nil
}

func (s *sdkIAMBoundary) AssumeRole(ctx context.Context, request AssumeRoleRequest) (AssumedSession, error) {
	callCtx, cancel := boundedCallContext(ctx)
	defer cancel()
	if len(request.Tags) != 1 || request.Tags[proofTagKey] != proofSessionTag {
		return AssumedSession{}, errConfiguration
	}
	output, err := s.sourceSTS.AssumeRole(callCtx, &sts.AssumeRoleInput{
		RoleArn: aws.String(request.RoleARN), ExternalId: aws.String(request.ExternalID), RoleSessionName: aws.String(request.SessionName),
		SourceIdentity: aws.String(request.SourceIdentity), DurationSeconds: aws.Int32(assumeDuration),
		Tags: []ststypes.Tag{{Key: aws.String(proofTagKey), Value: aws.String(proofSessionTag)}},
	}, mutationSTSOptions)
	if err != nil {
		return AssumedSession{}, errProvider
	}
	if output == nil || output.Credentials == nil || output.AssumedRoleUser == nil || output.SourceIdentity == nil ||
		output.Credentials.AccessKeyId == nil || output.Credentials.SecretAccessKey == nil || output.Credentials.SessionToken == nil ||
		output.Credentials.Expiration == nil || output.AssumedRoleUser.Arn == nil || output.AssumedRoleUser.AssumedRoleId == nil ||
		*output.AssumedRoleUser.AssumedRoleId == "" {
		return AssumedSession{}, errProvider
	}
	return AssumedSession{
		Credentials: SessionCredentials{
			AccessKeyID: *output.Credentials.AccessKeyId, SecretAccessKey: *output.Credentials.SecretAccessKey,
			SessionToken: *output.Credentials.SessionToken, Expiration: *output.Credentials.Expiration,
		},
		AssumedRoleARN: *output.AssumedRoleUser.Arn, AssumedRoleID: *output.AssumedRoleUser.AssumedRoleId,
		SourceIdentity: *output.SourceIdentity,
	}, nil
}

func (s *sdkIAMBoundary) AssumedIdentity(ctx context.Context, session AssumedSession) (CallerIdentity, error) {
	client, _, err := s.assumed(session.Credentials)
	if err != nil {
		return CallerIdentity{}, errAuthentication
	}
	return getCallerIdentity(ctx, client)
}

func (s *sdkIAMBoundary) AllowedGetRole(ctx context.Context, session AssumedSession, roleName string) (RoleState, error) {
	_, client, err := s.assumed(session.Credentials)
	if err != nil {
		return RoleState{}, errAuthentication
	}
	callCtx, cancel := boundedCallContext(ctx)
	defer cancel()
	output, err := client.GetRole(callCtx, &iam.GetRoleInput{RoleName: aws.String(roleName)}, readIAMOptions)
	if err != nil || output == nil || output.Role == nil {
		return RoleState{}, errAuthorization
	}
	return roleStateFromSDK(*output.Role)
}

func (s *sdkIAMBoundary) DeniedListRoles(ctx context.Context, session AssumedSession, path string) error {
	_, client, err := s.assumed(session.Credentials)
	if err != nil {
		return errAuthentication
	}
	callCtx, cancel := boundedCallContext(ctx)
	defer cancel()
	maximum := int32(1)
	_, err = client.ListRoles(callCtx, &iam.ListRolesInput{PathPrefix: aws.String(path), MaxItems: &maximum}, readIAMOptions)
	if err == nil {
		return nil
	}
	var apiError smithy.APIError
	var responseError *smithyhttp.ResponseError
	if errors.As(err, &apiError) && errors.As(err, &responseError) && responseError != nil && responseError.Response != nil &&
		responseError.Response.Response != nil && apiError.ErrorCode() == "AccessDenied" &&
		responseError.HTTPStatusCode() == 403 && explicitIdentityBasedListRolesDeny(apiError.ErrorMessage()) {
		return AuthorizationDeniedError{StatusCode: 403, Code: "AccessDenied"}
	}
	return errProvider
}

var explicitIdentityDenyPattern = regexp.MustCompile(`^User: \S+ is not authorized to perform: iam:ListRoles(?: on resource: \*)? with an explicit deny in an identity-based policy(?:: arn:aws:iam::[0-9]{12}:policy/[A-Za-z0-9_+=,.@/-]{1,512})?$`)

func explicitIdentityBasedListRolesDeny(message string) bool {
	return explicitIdentityDenyPattern.MatchString(message)
}

func (s *sdkIAMBoundary) DeleteRolePolicy(ctx context.Context, roleName, policyName string) error {
	callCtx, cancel := boundedCallContext(ctx)
	defer cancel()
	output, err := s.targetIAM.DeleteRolePolicy(callCtx, &iam.DeleteRolePolicyInput{
		RoleName: aws.String(roleName), PolicyName: aws.String(policyName),
	}, mutationIAMOptions)
	if err != nil {
		return classifyMutationError(err)
	}
	if output == nil {
		return ambiguousMutation(errProvider)
	}
	return nil
}

func (s *sdkIAMBoundary) DeleteRole(ctx context.Context, roleName string) error {
	callCtx, cancel := boundedCallContext(ctx)
	defer cancel()
	output, err := s.targetIAM.DeleteRole(callCtx, &iam.DeleteRoleInput{RoleName: aws.String(roleName)}, mutationIAMOptions)
	if err != nil {
		return classifyMutationError(err)
	}
	if output == nil {
		return ambiguousMutation(errProvider)
	}
	return nil
}

func roleSummaryFromSDK(role iamtypes.Role) (RoleSummary, error) {
	if role.RoleName == nil || role.Arn == nil || role.Path == nil || role.RoleId == nil || role.CreateDate == nil ||
		*role.RoleName == "" || *role.Arn == "" || *role.Path == "" || *role.RoleId == "" {
		return RoleSummary{}, errProvider
	}
	return RoleSummary{Name: *role.RoleName, ARN: *role.Arn, Path: *role.Path, RoleID: *role.RoleId}, nil
}

func roleStateFromSDK(role iamtypes.Role) (RoleState, error) {
	summary, err := roleSummaryFromSDK(role)
	if err != nil || role.AssumeRolePolicyDocument == nil || *role.AssumeRolePolicyDocument == "" || role.Description == nil ||
		role.MaxSessionDuration == nil || *role.Description == "" || *role.MaxSessionDuration <= 0 ||
		role.PermissionsBoundary != nil || role.SourceRoleTemplate != nil {
		return RoleState{}, errProvider
	}
	trustPolicy, err := decodeIAMPolicyDocument(*role.AssumeRolePolicyDocument)
	if err != nil {
		return RoleState{}, errProvider
	}
	tags := make(map[string]string, len(role.Tags))
	for _, tag := range role.Tags {
		if tag.Key == nil || tag.Value == nil || *tag.Key == "" {
			return RoleState{}, errProvider
		}
		if _, duplicate := tags[*tag.Key]; duplicate {
			return RoleState{}, errProvider
		}
		tags[*tag.Key] = *tag.Value
	}
	return RoleState{
		Name: summary.Name, ARN: summary.ARN, Path: summary.Path, RoleID: summary.RoleID,
		Description: *role.Description, MaxSessionDuration: *role.MaxSessionDuration,
		TrustPolicy: trustPolicy, Tags: tags,
	}, nil
}

func decodeIAMPolicyDocument(raw string) (string, error) {
	if _, err := decodeStrictJSON(raw); err == nil {
		return raw, nil
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return "", errProvider
	}
	if _, err := decodeStrictJSON(decoded); err != nil {
		return "", errProvider
	}
	return decoded, nil
}

func classifyMutationError(err error) error {
	if err == nil {
		return nil
	}
	var boundedBodyError *boundedHTTPBodyError
	if errors.As(err, &boundedBodyError) && boundedBodyError != nil {
		return classifyReceivedMutationStatus(boundedBodyError.statusCode)
	}
	var responseError *smithyhttp.ResponseError
	if errors.As(err, &responseError) && responseError != nil && responseError.Response != nil && responseError.Response.Response != nil {
		return classifyReceivedMutationStatus(responseError.HTTPStatusCode())
	}
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		return errProvider
	}
	return ambiguousMutation(errProvider)
}

func classifyReceivedMutationStatus(statusCode int) error {
	if statusCode >= 200 && statusCode < 300 {
		return ambiguousMutation(errProvider)
	}
	if statusCode >= 100 && statusCode <= 599 {
		return errProvider
	}
	return ambiguousMutation(errProvider)
}

func isNoSuchEntity(err error) bool {
	var apiError smithy.APIError
	return errors.As(err, &apiError) && apiError.ErrorCode() == "NoSuchEntity"
}

func readSTSOptions(options *sts.Options)     { options.RetryMaxAttempts = 2 }
func mutationSTSOptions(options *sts.Options) { options.RetryMaxAttempts = 1 }
func readIAMOptions(options *iam.Options)     { options.RetryMaxAttempts = 2 }
func mutationIAMOptions(options *iam.Options) { options.RetryMaxAttempts = 1 }

func boundedCallContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, awsCallTimeout)
}

type hostResolver interface {
	LookupHost(context.Context, string) ([]string, error)
}

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

func newAWSHTTPClient(region string, resolver hostResolver, dial dialContextFunc) (*http.Client, *http.Transport) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	baseDialer := &net.Dialer{Timeout: 4 * time.Second, KeepAlive: -1}
	if dial == nil {
		dial = baseDialer.DialContext
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: awsDialer(region, resolver, dial), DisableKeepAlives: true,
		ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 6 * time.Second,
	}
	bounded := &boundedResponseTransport{next: transport, maximum: awsResponseBodyLimit}
	return &http.Client{
		Transport: bounded, Timeout: awsCallTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, transport
}

func awsDialer(region string, resolver hostResolver, dial dialContextFunc) dialContextFunc {
	allowed := map[string]bool{"iam.amazonaws.com": true, "sts." + region + ".amazonaws.com": true}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
		if err != nil || port != "443" || !allowed[host] {
			return nil, errConfiguration
		}
		addresses, err := resolver.LookupHost(ctx, host)
		if err != nil || len(addresses) == 0 {
			return nil, errConfiguration
		}
		for _, candidate := range addresses {
			ip := net.ParseIP(candidate)
			if !isPublicIP(ip) {
				return nil, errConfiguration
			}
		}
		var lastErr error
		for _, candidate := range addresses {
			connection, dialErr := dial(ctx, network, net.JoinHostPort(candidate, port))
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
}

func isPublicIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

type boundedResponseTransport struct {
	next    http.RoundTripper
	maximum int64
}

type boundedHTTPBodyError struct{ statusCode int }

func (*boundedHTTPBodyError) Error() string { return "bounded HTTP response rejected" }
func (*boundedHTTPBodyError) Unwrap() error { return errProvider }

func (t *boundedResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.URL.Scheme != "https" || request.URL.User != nil ||
		request.URL.RawQuery != "" && request.Method != http.MethodPost {
		return nil, errConfiguration
	}
	response, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, errProvider
	}
	if response.ContentLength > t.maximum {
		_ = response.Body.Close()
		return nil, &boundedHTTPBodyError{statusCode: response.StatusCode}
	}
	response.Body = &boundedReadCloser{
		reader: io.LimitReader(response.Body, t.maximum+1), closer: response.Body,
		remaining: t.maximum, statusCode: response.StatusCode,
	}
	return response, nil
}

type boundedReadCloser struct {
	reader     io.Reader
	closer     io.Closer
	remaining  int64
	statusCode int
}

func (r *boundedReadCloser) Read(buffer []byte) (int, error) {
	if r.remaining < 0 {
		return 0, &boundedHTTPBodyError{statusCode: r.statusCode}
	}
	n, err := r.reader.Read(buffer)
	r.remaining -= int64(n)
	if r.remaining < 0 {
		_ = r.closer.Close()
		return n, &boundedHTTPBodyError{statusCode: r.statusCode}
	}
	return n, err
}

func (r *boundedReadCloser) Close() error { return r.closer.Close() }
