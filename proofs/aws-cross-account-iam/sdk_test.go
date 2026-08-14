package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type recordingSTS struct {
	identity                       *sts.GetCallerIdentityOutput
	identityErr                    error
	assumeOutput                   *sts.AssumeRoleOutput
	assumeErr                      error
	assumeInput                    *sts.AssumeRoleInput
	identityRetries, assumeRetries int
}

func (r *recordingSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, options ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	r.identityRetries = stsRetryAttempts(options)
	return r.identity, r.identityErr
}

func (r *recordingSTS) AssumeRole(_ context.Context, input *sts.AssumeRoleInput, options ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	r.assumeInput = input
	r.assumeRetries = stsRetryAttempts(options)
	return r.assumeOutput, r.assumeErr
}

type recordingIAM struct {
	role                               iamtypes.Role
	listOutput                         *iam.ListRolesOutput
	listErr                            error
	getRolePolicyOutput                *iam.GetRolePolicyOutput
	listRolePoliciesOutput             *iam.ListRolePoliciesOutput
	deniedErr                          error
	createInput                        *iam.CreateRoleInput
	putInput                           *iam.PutRolePolicyInput
	deletePolicyInput                  *iam.DeleteRolePolicyInput
	deleteRoleInput                    *iam.DeleteRoleInput
	listInput                          *iam.ListRolesInput
	getInput                           *iam.GetRoleInput
	createRetries, putRetries          int
	deletePolicyRetries, deleteRetries int
	listRetries, getRetries            int
}

func (r *recordingIAM) ListRoles(_ context.Context, input *iam.ListRolesInput, options ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	r.listInput = input
	r.listRetries = iamRetryAttempts(options)
	if r.deniedErr != nil {
		return nil, r.deniedErr
	}
	if r.listOutput != nil || r.listErr != nil {
		return r.listOutput, r.listErr
	}
	return &iam.ListRolesOutput{}, nil
}

func (r *recordingIAM) CreateRole(_ context.Context, input *iam.CreateRoleInput, options ...func(*iam.Options)) (*iam.CreateRoleOutput, error) {
	r.createInput = input
	r.createRetries = iamRetryAttempts(options)
	return &iam.CreateRoleOutput{Role: &r.role}, nil
}

func (r *recordingIAM) GetRole(_ context.Context, input *iam.GetRoleInput, options ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	r.getInput = input
	r.getRetries = iamRetryAttempts(options)
	return &iam.GetRoleOutput{Role: &r.role}, nil
}

func (r *recordingIAM) PutRolePolicy(_ context.Context, input *iam.PutRolePolicyInput, options ...func(*iam.Options)) (*iam.PutRolePolicyOutput, error) {
	r.putInput = input
	r.putRetries = iamRetryAttempts(options)
	return &iam.PutRolePolicyOutput{}, nil
}

func (r *recordingIAM) GetRolePolicy(_ context.Context, _ *iam.GetRolePolicyInput, options ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	r.getRetries = iamRetryAttempts(options)
	return r.getRolePolicyOutput, nil
}

func (r *recordingIAM) ListRolePolicies(_ context.Context, _ *iam.ListRolePoliciesInput, options ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	r.listRetries = iamRetryAttempts(options)
	return r.listRolePoliciesOutput, nil
}

func (r *recordingIAM) DeleteRolePolicy(_ context.Context, input *iam.DeleteRolePolicyInput, options ...func(*iam.Options)) (*iam.DeleteRolePolicyOutput, error) {
	r.deletePolicyInput = input
	r.deletePolicyRetries = iamRetryAttempts(options)
	return &iam.DeleteRolePolicyOutput{}, nil
}

func (r *recordingIAM) DeleteRole(_ context.Context, input *iam.DeleteRoleInput, options ...func(*iam.Options)) (*iam.DeleteRoleOutput, error) {
	r.deleteRoleInput = input
	r.deleteRetries = iamRetryAttempts(options)
	return &iam.DeleteRoleOutput{}, nil
}

func TestSDKBoundaryUsesExactExplicitRequestsAndRetryClasses(t *testing.T) {
	marker := "0123456789abcdef"
	options := validOptions(marker, newFakeIAMBoundary(marker))
	spec, err := expectedRoleSpec(options, "external", expectedRoleName(marker), expectedRoleName(marker))
	if err != nil {
		t.Fatal(err)
	}
	role := sdkRole(spec)
	sourceSTS := &recordingSTS{identity: identityOutput("111111111111", options.SourcePrincipalARN)}
	targetSTS := &recordingSTS{identity: identityOutput("222222222222", "arn:aws:iam::222222222222:role/zasp-proof-admin")}
	targetIAM := &recordingIAM{
		role: role,
		getRolePolicyOutput: &iam.GetRolePolicyOutput{
			PolicyDocument: aws.String(spec.PermissionPolicy), PolicyName: aws.String(spec.PolicyName), RoleName: aws.String(spec.Name),
		},
		listRolePoliciesOutput: &iam.ListRolePoliciesOutput{PolicyNames: []string{spec.PolicyName}},
	}
	assumedSTS := &recordingSTS{identity: identityOutput("222222222222", expectedAssumedARN("222222222222", marker))}
	assumedIAM := &recordingIAM{role: role, deniedErr: accessDeniedResponseError()}
	boundary, err := newSDKIAMBoundaryWithClients(sourceSTS, targetSTS, targetIAM, func(SessionCredentials) (stsAPI, iamAPI, error) {
		return assumedSTS, assumedIAM, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := boundary.SourceIdentity(context.Background()); err != nil || sourceSTS.identityRetries != 2 {
		t.Fatalf("source identity = (%v, retries=%d)", err, sourceSTS.identityRetries)
	}
	if _, err := boundary.TargetIdentity(context.Background()); err != nil || targetSTS.identityRetries != 2 {
		t.Fatalf("target identity = (%v, retries=%d)", err, targetSTS.identityRetries)
	}
	if _, err := boundary.ListRoles(context.Background(), spec.Path); err != nil || targetIAM.listRetries != 2 || aws.ToString(targetIAM.listInput.PathPrefix) != spec.Path || aws.ToInt32(targetIAM.listInput.MaxItems) != 2 {
		t.Fatalf("list roles request/retry mismatch")
	}
	created, err := boundary.CreateRole(context.Background(), spec)
	if err != nil || !validCreatedRoleState(created, spec) || targetIAM.createRetries != 1 {
		t.Fatalf("create = (%#v, %v, retries=%d)", created, err, targetIAM.createRetries)
	}
	spec.RoleID = created.RoleID
	if aws.ToString(targetIAM.createInput.RoleName) != spec.Name || aws.ToString(targetIAM.createInput.Path) != spec.Path ||
		aws.ToString(targetIAM.createInput.AssumeRolePolicyDocument) != spec.TrustPolicy || aws.ToInt32(targetIAM.createInput.MaxSessionDuration) != 3600 ||
		!reflect.DeepEqual(sdkTagsToMap(targetIAM.createInput.Tags), spec.Tags) {
		t.Fatal("create request did not carry exact role ownership")
	}
	if err := boundary.PutRolePolicy(context.Background(), spec.Name, spec.PolicyName, spec.PermissionPolicy); err != nil || targetIAM.putRetries != 1 {
		t.Fatalf("put policy = (%v, retries=%d)", err, targetIAM.putRetries)
	}
	if aws.ToString(targetIAM.putInput.RoleName) != spec.Name || aws.ToString(targetIAM.putInput.PolicyName) != spec.PolicyName || aws.ToString(targetIAM.putInput.PolicyDocument) != spec.PermissionPolicy {
		t.Fatal("put policy request mismatch")
	}

	request := AssumeRoleRequest{
		RoleARN: spec.ARN, ExternalID: "external", SessionName: expectedRoleName(marker), SourceIdentity: expectedRoleName(marker),
		Tags: map[string]string{proofTagKey: proofSessionTag},
	}
	sourceSTS.assumeOutput = assumedOutput(request, "222222222222")
	session, err := boundary.AssumeRole(context.Background(), request)
	if err != nil || sourceSTS.assumeRetries != 1 || aws.ToInt32(sourceSTS.assumeInput.DurationSeconds) != assumeDuration ||
		aws.ToString(sourceSTS.assumeInput.ExternalId) != request.ExternalID || aws.ToString(sourceSTS.assumeInput.SourceIdentity) != request.SourceIdentity ||
		len(sourceSTS.assumeInput.Tags) != 1 || aws.ToString(sourceSTS.assumeInput.Tags[0].Key) != proofTagKey || aws.ToString(sourceSTS.assumeInput.Tags[0].Value) != proofSessionTag {
		t.Fatalf("assume request/result mismatch: %v", err)
	}
	if identity, err := boundary.AssumedIdentity(context.Background(), session); err != nil || identity.AccountID != options.TargetAccountID || assumedSTS.identityRetries != 2 {
		t.Fatalf("assumed identity = (%#v, %v)", identity, err)
	}
	if state, err := boundary.AllowedGetRole(context.Background(), session, spec.Name); err != nil || !validRoleState(state, spec) || assumedIAM.getRetries != 2 {
		t.Fatalf("allowed read = (%#v, %v)", state, err)
	}
	denied := boundary.DeniedListRoles(context.Background(), session, spec.Path)
	var authorization AuthorizationDeniedError
	if !errors.As(denied, &authorization) || authorization.StatusCode != 403 || authorization.Code != "AccessDenied" || assumedIAM.listRetries != 2 {
		t.Fatalf("denied result = %v", denied)
	}
	if err := boundary.DeleteRolePolicy(context.Background(), spec.Name, spec.PolicyName); err != nil || targetIAM.deletePolicyRetries != 1 {
		t.Fatalf("delete policy = (%v, retries=%d)", err, targetIAM.deletePolicyRetries)
	}
	if err := boundary.DeleteRole(context.Background(), spec.Name); err != nil || targetIAM.deleteRetries != 1 {
		t.Fatalf("delete role = (%v, retries=%d)", err, targetIAM.deleteRetries)
	}
}

func TestSDKBoundaryRejectsMalformedIdentityRoleTagsAndDenial(t *testing.T) {
	marker := "0123456789abcdef"
	options := validOptions(marker, newFakeIAMBoundary(marker))
	spec, _ := expectedRoleSpec(options, "external", expectedRoleName(marker), expectedRoleName(marker))
	valid := sdkRole(spec)
	mutations := []struct {
		name string
		edit func(*iamtypes.Role)
	}{
		{name: "missing creation date", edit: func(role *iamtypes.Role) { role.CreateDate = nil }},
		{name: "missing trust", edit: func(role *iamtypes.Role) { role.AssumeRolePolicyDocument = nil }},
		{name: "missing description", edit: func(role *iamtypes.Role) { role.Description = nil }},
		{name: "duplicate tag", edit: func(role *iamtypes.Role) { role.Tags = append(role.Tags, role.Tags[0]) }},
		{name: "nil tag key", edit: func(role *iamtypes.Role) { role.Tags[0].Key = nil }},
		{name: "case variant tag", edit: func(role *iamtypes.Role) { role.Tags[0].Key = aws.String("Zasp-Proof") }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			role := valid
			role.Tags = append([]iamtypes.Tag(nil), valid.Tags...)
			mutation.edit(&role)
			state, err := roleStateFromSDK(role)
			if err == nil && validRoleState(state, spec) {
				t.Fatal("malformed provider role was accepted")
			}
		})
	}

	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "wrong status", err: responseAPIError(400, "AccessDenied")},
		{name: "wrong code", err: responseAPIError(403, "UnauthorizedOperation")},
		{name: "untyped transport", err: errors.New("transport")},
	} {
		t.Run(test.name, func(t *testing.T) {
			assumedIAM := &recordingIAM{deniedErr: test.err}
			boundary, _ := newSDKIAMBoundaryWithClients(&recordingSTS{}, &recordingSTS{}, &recordingIAM{}, func(SessionCredentials) (stsAPI, iamAPI, error) {
				return &recordingSTS{}, assumedIAM, nil
			})
			if errors.As(boundary.DeniedListRoles(context.Background(), AssumedSession{}, spec.Path), new(AuthorizationDeniedError)) {
				t.Fatal("wrong denial was normalized as exact authorization result")
			}
		})
	}
}

func TestDeniedListRolesRequiresExplicitIdentityBasedPolicyCategory(t *testing.T) {
	marker := "0123456789abcdef"
	spec, _ := expectedRoleSpec(validOptions(marker, newFakeIAMBoundary(marker)), "external", expectedRoleName(marker), expectedRoleName(marker))
	identityExplicit := "User: arn:aws:sts::222222222222:assumed-role/zasp-proof/session is not authorized to perform: iam:ListRoles on resource: * with an explicit deny in an identity-based policy"
	tests := []struct {
		name    string
		message string
		want    bool
	}{
		{name: "identity based explicit deny", message: identityExplicit, want: true},
		{name: "implicit no allow", message: "User: example is not authorized to perform: iam:ListRoles because no identity-based policy allows the iam:ListRoles action"},
		{name: "service control policy", message: "User: example is not authorized to perform: iam:ListRoles with an explicit deny in a service control policy"},
		{name: "permissions boundary", message: "User: example is not authorized to perform: iam:ListRoles with an explicit deny in a permissions boundary"},
		{name: "session policy", message: "User: example is not authorized to perform: iam:ListRoles with an explicit deny in a session policy"},
		{name: "resource policy", message: "User: example is not authorized to perform: iam:ListRoles with an explicit deny in a resource-based policy"},
		{name: "unknown access denied", message: "provider-sensitive-detail"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assumedIAM := &recordingIAM{deniedErr: responseAPIErrorMessage(403, "AccessDenied", test.message)}
			boundary, _ := newSDKIAMBoundaryWithClients(&recordingSTS{}, &recordingSTS{}, &recordingIAM{}, func(SessionCredentials) (stsAPI, iamAPI, error) {
				return &recordingSTS{}, assumedIAM, nil
			})
			err := boundary.DeniedListRoles(context.Background(), AssumedSession{}, spec.Path)
			var denied AuthorizationDeniedError
			if got := errors.As(err, &denied); got != test.want {
				t.Fatalf("typed explicit denial = %t, want %t", got, test.want)
			}
			if strings.Contains(err.Error(), test.message) {
				t.Fatal("provider denial detail escaped the fixed categorical boundary")
			}
		})
	}
}

func TestDeniedListRolesRejectsMalformedTypedHTTPEnvelopeWithoutPanic(t *testing.T) {
	marker := "0123456789abcdef"
	spec, _ := expectedRoleSpec(validOptions(marker, newFakeIAMBoundary(marker)), "external", expectedRoleName(marker), expectedRoleName(marker))
	assumedIAM := &recordingIAM{deniedErr: &smithyhttp.ResponseError{
		Err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "provider-sensitive-detail", Fault: smithy.FaultClient},
	}}
	boundary, _ := newSDKIAMBoundaryWithClients(&recordingSTS{}, &recordingSTS{}, &recordingIAM{}, func(SessionCredentials) (stsAPI, iamAPI, error) {
		return &recordingSTS{}, assumedIAM, nil
	})
	if err := boundary.DeniedListRoles(context.Background(), AssumedSession{}, spec.Path); !errors.Is(err, errProvider) {
		t.Fatal("malformed typed denial was not rejected safely")
	}
}

func TestMutationErrorsAreAmbiguousOnlyWithoutTypedAWSRejection(t *testing.T) {
	if isAmbiguousMutation(classifyMutationError(&smithy.GenericAPIError{Code: "Conflict", Message: "rejected"})) {
		t.Fatal("typed AWS rejection classified ambiguous")
	}
	if !isAmbiguousMutation(classifyMutationError(errors.New("transport"))) {
		t.Fatal("transport loss was not classified ambiguous")
	}
}

func TestMutationHTTPResponsesAreDefinitiveRegardlessOfBodyDecodeFailure(t *testing.T) {
	for _, status := range []int{403, 409, 500} {
		for _, cause := range []error{errors.New("malformed response"), errors.New("oversized response"), errors.New("deserialization response")} {
			if isAmbiguousMutation(classifyMutationError(responseHTTPError(status, cause))) {
				t.Fatalf("received non-2xx status %d classified ambiguous", status)
			}
		}
	}
	for _, status := range []int{200, 201, 204} {
		if !isAmbiguousMutation(classifyMutationError(responseHTTPError(status, errors.New("invalid successful response")))) {
			t.Fatalf("invalid successful status %d was not classified ambiguous", status)
		}
	}
}

func TestRunProofNeverAdoptsExactLookingRoleAfterDefinitiveHTTPRejection(t *testing.T) {
	for _, status := range []int{403, 409, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			marker := "0123456789abcdef"
			boundary := newFakeIAMBoundary(marker)
			boundary.createErr = classifyMutationError(responseHTTPError(status, errors.New("unparseable provider body")))
			boundary.createApplied = true
			_, err := RunProof(context.Background(), validOptions(marker, boundary))
			if !errors.Is(err, errProvider) || contains(boundary.events, "delete-role") || boundary.role.Name == "" {
				t.Fatalf("definitive collision was adopted: error=%v events=%#v", err, boundary.events)
			}
		})
	}
}

func TestIAMPolicyDocumentDecodingIsStrictAndExactlyOnce(t *testing.T) {
	document := `{"Version":"2012-10-17","Statement":[]}`
	encoded := url.QueryEscape(document)
	for _, input := range []string{document, encoded} {
		decoded, err := decodeIAMPolicyDocument(input)
		if err != nil || !equalPolicy(decoded, document) {
			t.Fatalf("valid policy decode = (%q, %v)", decoded, err)
		}
	}
	for _, input := range []string{
		url.QueryEscape(encoded),
		"%zz",
		url.QueryEscape(`{"Version":"2012-10-17","Version":"2012-10-17","Statement":[]}`),
	} {
		if _, err := decodeIAMPolicyDocument(input); err == nil {
			t.Fatalf("accepted malformed or multiply encoded policy: %q", input)
		}
	}
}

func TestAWSHTTPBoundaryRejectsAmbientAndUnsafeDestinations(t *testing.T) {
	resolver := staticResolver{addresses: map[string][]string{
		"iam.amazonaws.com": {"8.8.8.8"}, "sts.us-west-2.amazonaws.com": {"1.1.1.1"},
	}}
	var dialed string
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		return nil, errors.New("stopped")
	}
	client, transport := newAWSHTTPClient("us-west-2", resolver, dial)
	if transport.Proxy != nil || client.CheckRedirect == nil || transport.TLSClientConfig.MinVersion != 0x0303 {
		t.Fatal("HTTP client did not disable proxy/redirects or require TLS 1.2")
	}
	for _, address := range []string{"iam.amazonaws.com:443", "sts.us-west-2.amazonaws.com:443"} {
		dialed = ""
		_, _ = transport.DialContext(context.Background(), "tcp", address)
		if dialed == "" {
			t.Fatalf("allowed AWS host was not resolved/dialed: %s", address)
		}
	}
	for _, address := range []string{"iam.amazonaws.com:80", "example.com:443", "127.0.0.1:443"} {
		dialed = ""
		if _, err := transport.DialContext(context.Background(), "tcp", address); !errors.Is(err, errConfiguration) || dialed != "" {
			t.Fatalf("unsafe address accepted: %s", address)
		}
	}
	privateResolver := staticResolver{addresses: map[string][]string{"iam.amazonaws.com": {"10.0.0.1"}}}
	if _, err := awsDialer("us-west-2", privateResolver, dial)(context.Background(), "tcp", "iam.amazonaws.com:443"); !errors.Is(err, errConfiguration) {
		t.Fatal("private DNS resolution accepted")
	}
	mixedResolver := staticResolver{addresses: map[string][]string{"iam.amazonaws.com": {"8.8.8.8", "127.0.0.1"}}}
	if _, err := awsDialer("us-west-2", mixedResolver, dial)(context.Background(), "tcp", "iam.amazonaws.com:443"); !errors.Is(err, errConfiguration) {
		t.Fatal("mixed/rebinding DNS resolution accepted")
	}
	reservedResolver := staticResolver{addresses: map[string][]string{"iam.amazonaws.com": {"198.51.100.10"}}}
	if _, err := awsDialer("us-west-2", reservedResolver, dial)(context.Background(), "tcp", "iam.amazonaws.com:443"); !errors.Is(err, errConfiguration) {
		t.Fatal("reserved documentation address accepted as public")
	}
}

func TestBoundedResponseTransportRejectsOversizedAndInvalidResponses(t *testing.T) {
	closed := false
	transport := &boundedResponseTransport{maximum: 4, next: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: 5, Body: closeTracker{Reader: strings.NewReader("large"), closed: &closed}}, nil
	})}
	request := &http.Request{Method: http.MethodPost, URL: &url.URL{Scheme: "https", Host: "iam.amazonaws.com"}}
	if _, err := transport.RoundTrip(request); !errors.Is(err, errProvider) || !closed {
		t.Fatal("declared oversized response was not rejected and closed")
	}

	transport.next = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: -1, Body: io.NopCloser(strings.NewReader("large"))}, nil
	})
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(response.Body); !errors.Is(err, errProvider) {
		t.Fatal("streaming oversized response was not bounded")
	}
	bad := request.Clone(context.Background())
	bad.URL = &url.URL{Scheme: "http", Host: "iam.amazonaws.com"}
	if _, err := transport.RoundTrip(bad); !errors.Is(err, errConfiguration) {
		t.Fatal("non-TLS request accepted")
	}
	bad.URL = &url.URL{Scheme: "https", Host: "iam.amazonaws.com", User: url.User("ambient")}
	if _, err := transport.RoundTrip(bad); !errors.Is(err, errConfiguration) {
		t.Fatal("userinfo request accepted")
	}
}

func TestSDKConstructorRequiresExplicitCredentialsAndCommercialRegion(t *testing.T) {
	valid := sdkBoundaryConfig{
		region: "us-west-2", source: explicitCredentialSet{accessKeyID: "source", secretAccessKey: "secret"},
		targetAdmin: explicitCredentialSet{accessKeyID: "target", secretAccessKey: "secret"},
	}
	for _, edit := range []func(*sdkBoundaryConfig){
		func(config *sdkBoundaryConfig) { config.region = "" },
		func(config *sdkBoundaryConfig) { config.region = "us-gov-west-1" },
		func(config *sdkBoundaryConfig) { config.source.accessKeyID = "" },
		func(config *sdkBoundaryConfig) { config.targetAdmin.secretAccessKey = "" },
	} {
		config := valid
		edit(&config)
		if boundary, err := newSDKIAMBoundary(config); err == nil || boundary != nil {
			t.Fatal("incomplete explicit configuration accepted")
		}
	}
}

func TestProofOptionsAcceptOnlyCommercialAWSPartitionRegions(t *testing.T) {
	for _, region := range []string{"us-east-1", "us-west-2", "af-south-1", "ap-east-2", "ap-southeast-7", "ca-west-1", "eu-central-2", "il-central-1", "me-central-1", "mx-central-1", "sa-east-1"} {
		options := validOptions("0123456789abcdef", newFakeIAMBoundary("0123456789abcdef"))
		options.Region = region
		if err := validateProofOptions(context.Background(), &options); err != nil {
			t.Fatalf("commercial region rejected")
		}
	}
	for _, region := range []string{"cn-north-1", "us-gov-west-1", "us-iso-east-1", "us-isob-east-1", "eu-isoe-west-1", "eusc-de-east-1", "xx-west-1", "US-WEST-2", "us-west", "us-west-0", "us-east-9"} {
		options := validOptions("0123456789abcdef", newFakeIAMBoundary("0123456789abcdef"))
		options.Region = region
		if err := validateProofOptions(context.Background(), &options); !errors.Is(err, errConfiguration) {
			t.Fatalf("non-commercial or malformed region accepted")
		}
	}
}

func TestPinnedSDKResolvesOnlyExpectedRealAWSHostsWithoutAmbientEndpoint(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:1")
	credentials := staticCredentials(explicitCredentialSet{accessKeyID: "explicit", secretAccessKey: "explicit"})
	iamCapture := &captureRoundTripper{}
	iamClient := iam.New(iam.Options{
		Region: "us-west-2", Credentials: credentials,
		HTTPClient: &http.Client{Transport: iamCapture}, RetryMaxAttempts: 1,
	})
	_, _ = iamClient.ListRoles(context.Background(), &iam.ListRolesInput{}, mutationIAMOptions)
	if iamCapture.host != "iam.amazonaws.com" || iamCapture.scheme != "https" {
		t.Fatalf("IAM resolved unexpected endpoint category")
	}
	stsCapture := &captureRoundTripper{}
	stsClient := sts.New(sts.Options{
		Region: "us-west-2", Credentials: credentials,
		HTTPClient: &http.Client{Transport: stsCapture}, RetryMaxAttempts: 1,
	})
	_, _ = stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{}, mutationSTSOptions)
	if stsCapture.host != "sts.us-west-2.amazonaws.com" || stsCapture.scheme != "https" {
		t.Fatalf("STS resolved unexpected endpoint category")
	}
}

func sdkRole(spec RoleSpec) iamtypes.Role {
	now := time.Now()
	tags := make([]iamtypes.Tag, 0, len(spec.Tags))
	for _, key := range []string{proofTagKey, markerTagKey, purposeTagKey} {
		tags = append(tags, iamtypes.Tag{Key: aws.String(key), Value: aws.String(spec.Tags[key])})
	}
	return iamtypes.Role{
		RoleName: aws.String(spec.Name), Arn: aws.String(spec.ARN), Path: aws.String(spec.Path), RoleId: aws.String("role-id"),
		CreateDate: &now, Description: aws.String(spec.Description), MaxSessionDuration: aws.Int32(spec.MaxSessionDuration),
		AssumeRolePolicyDocument: aws.String(spec.TrustPolicy), Tags: tags,
	}
}

func identityOutput(account, arn string) *sts.GetCallerIdentityOutput {
	return &sts.GetCallerIdentityOutput{Account: aws.String(account), Arn: aws.String(arn), UserId: aws.String("identity-id")}
}

func assumedOutput(request AssumeRoleRequest, account string) *sts.AssumeRoleOutput {
	expiration := time.Now().Add(time.Hour)
	return &sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId: aws.String("temporary-access"), SecretAccessKey: aws.String("temporary-secret"),
			SessionToken: aws.String("temporary-token"), Expiration: &expiration,
		},
		AssumedRoleUser: &ststypes.AssumedRoleUser{
			Arn:           aws.String("arn:aws:sts::" + account + ":assumed-role/" + expectedRoleName(strings.TrimPrefix(request.SessionName, "zasp-m0-09-")) + "/" + request.SessionName),
			AssumedRoleId: aws.String("assumed-id:" + request.SessionName),
		},
		SourceIdentity: aws.String(request.SourceIdentity),
	}
}

func sdkTagsToMap(tags []iamtypes.Tag) map[string]string {
	result := map[string]string{}
	for _, tag := range tags {
		result[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return result
}

func stsRetryAttempts(options []func(*sts.Options)) int {
	value := sts.Options{}
	for _, option := range options {
		option(&value)
	}
	return value.RetryMaxAttempts
}

func iamRetryAttempts(options []func(*iam.Options)) int {
	value := iam.Options{}
	for _, option := range options {
		option(&value)
	}
	return value.RetryMaxAttempts
}

func accessDeniedResponseError() error {
	return responseAPIErrorMessage(403, "AccessDenied", "User: arn:aws:sts::222222222222:assumed-role/zasp-proof/session is not authorized to perform: iam:ListRoles on resource: * with an explicit deny in an identity-based policy")
}

func responseAPIError(status int, code string) error {
	return responseAPIErrorMessage(status, code, "redacted")
}

func responseAPIErrorMessage(status int, code, message string) error {
	return &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
		Err:      &smithy.GenericAPIError{Code: code, Message: message, Fault: smithy.FaultClient},
	}
}

func responseHTTPError(status int, cause error) error {
	return &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
		Err:      cause,
	}
}

type staticResolver struct{ addresses map[string][]string }

func (r staticResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	addresses := r.addresses[host]
	if len(addresses) == 0 {
		return nil, errors.New("not found")
	}
	return append([]string(nil), addresses...), nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

type captureRoundTripper struct{ scheme, host string }

func (c *captureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	c.scheme, c.host = request.URL.Scheme, request.URL.Host
	return nil, errors.New("captured")
}

type closeTracker struct {
	io.Reader
	closed *bool
}

func (c closeTracker) Close() error {
	*c.closed = true
	return nil
}
