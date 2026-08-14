package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const (
	proofName       = "m0-09"
	rolePurpose     = "read-only"
	proofPathRoot   = "/zasp-proof/m0-09/"
	proofTagKey     = "zasp-proof"
	markerTagKey    = "zasp-marker"
	purposeTagKey   = "zasp-role"
	proofSessionTag = "m0-09"
)

var (
	errConfiguration  = errors.New("configuration rejected")
	errCapability     = errors.New("isolated AWS capability rejected")
	errAuthentication = errors.New("AWS authentication rejected")
	errAuthorization  = errors.New("AWS authorization result rejected")
	errOwnership      = errors.New("AWS proof ownership rejected")
	errProvider       = errors.New("AWS proof operation failed")
	errCleanup        = errors.New("AWS proof cleanup failed")
	errNotFound       = errors.New("AWS proof resource absent")

	markerPattern    = regexp.MustCompile(`^[a-f0-9]{16}$`)
	accountPattern   = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern    = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[1-9][0-9]?$`)
	principalPattern = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):(role|user)/([A-Za-z0-9_+=,.@/-]{1,512})$`)
	callerARNPattern = regexp.MustCompile(`^arn:aws:(?:iam::[0-9]{12}:(?:root|(?:role|user)/[A-Za-z0-9_+=,.@/-]{1,512})|sts::[0-9]{12}:assumed-role/[A-Za-z0-9_+=,.@/-]{1,512}/[A-Za-z0-9_+=,.@-]{1,64})$`)
)

type CallerIdentity struct {
	AccountID string
	ARN       string
}

type RoleSummary struct {
	Name, ARN, Path, RoleID string
}

type RoleSpec struct {
	Name, ARN, Path, RoleID       string
	Description                   string
	MaxSessionDuration            int32
	TrustPolicy, PermissionPolicy string
	PolicyName                    string
	Tags                          map[string]string
}

type RoleState = RoleSpec

type AssumeRoleRequest struct {
	RoleARN, ExternalID, SessionName, SourceIdentity string
	Tags                                             map[string]string
}

type SessionCredentials struct {
	AccessKeyID, SecretAccessKey, SessionToken string
	Expiration                                 time.Time
}

type AssumedSession struct {
	Credentials                    SessionCredentials
	AssumedRoleARN, SourceIdentity string
}

type AuthorizationDeniedError struct {
	StatusCode int
	Code       string
}

func (AuthorizationDeniedError) Error() string { return "authorization denied" }

type ambiguousMutationError struct{ cause error }

func (e ambiguousMutationError) Error() string { return "mutation outcome ambiguous" }
func (e ambiguousMutationError) Unwrap() error { return e.cause }

func ambiguousMutation(cause error) error {
	if cause == nil {
		cause = errProvider
	}
	return ambiguousMutationError{cause: cause}
}

func isAmbiguousMutation(err error) bool {
	var target ambiguousMutationError
	return errors.As(err, &target)
}

type IAMProofBoundary interface {
	SourceIdentity(context.Context) (CallerIdentity, error)
	TargetIdentity(context.Context) (CallerIdentity, error)
	ListRoles(context.Context, string) ([]RoleSummary, error)
	CreateRole(context.Context, RoleSpec) (RoleState, error)
	InspectRole(context.Context, string) (RoleState, error)
	PutRolePolicy(context.Context, string, string, string) error
	GetRolePolicy(context.Context, string, string) (string, error)
	ListRolePolicies(context.Context, string) ([]string, error)
	AssumeRole(context.Context, AssumeRoleRequest) (AssumedSession, error)
	AssumedIdentity(context.Context, AssumedSession) (CallerIdentity, error)
	AllowedGetRole(context.Context, AssumedSession, string) (RoleState, error)
	DeniedListRoles(context.Context, AssumedSession, string) error
	DeleteRolePolicy(context.Context, string, string) error
	DeleteRole(context.Context, string) error
}

type ProofOptions struct {
	Marker, Region                   string
	SourceAccountID, TargetAccountID string
	SourcePrincipalARN               string
	Boundary                         IAMProofBoundary
	CleanupTimeout, PollInterval     time.Duration
	Now                              func() time.Time
}

type ProofResult struct {
	CrossAccount, Assumed, AllowedRead, DeniedCall, Cleanup, Audit bool
}

type cleanupTarget struct {
	spec           RoleSpec
	policyAttached bool
}

func RunProof(ctx context.Context, options ProofOptions) (result ProofResult, resultErr error) {
	if err := validateProofOptions(ctx, &options); err != nil {
		return result, err
	}
	externalID := "zasp-external-" + options.Marker
	sessionName := "zasp-m0-09-" + options.Marker
	sourceIdentity := "zasp-m0-09-" + options.Marker
	spec, err := expectedRoleSpec(options, externalID, sessionName, sourceIdentity)
	if err != nil {
		return result, errConfiguration
	}

	var target *cleanupTarget
	defer func() {
		panicked := recover() != nil
		if target != nil {
			if safeCleanupAndAudit(options, target) != nil {
				resultErr = errCleanup
				return
			}
			result.Cleanup, result.Audit = true, true
		}
		if panicked {
			resultErr = errProvider
		}
	}()

	source, err := options.Boundary.SourceIdentity(ctx)
	if err != nil || !validCallerIdentity(source, options.SourceAccountID) || !callerMatchesPrincipal(source.ARN, options.SourcePrincipalARN) {
		return result, errAuthentication
	}
	targetIdentity, err := options.Boundary.TargetIdentity(ctx)
	if err != nil || !validCallerIdentity(targetIdentity, options.TargetAccountID) {
		return result, errAuthentication
	}
	if source.AccountID == targetIdentity.AccountID {
		return result, errCapability
	}
	result.CrossAccount = true

	roles, err := options.Boundary.ListRoles(ctx, spec.Path)
	if err != nil {
		return result, errProvider
	}
	if len(roles) != 0 {
		return result, errOwnership
	}

	created, createErr := options.Boundary.CreateRole(ctx, spec)
	if createErr == nil {
		target = &cleanupTarget{spec: copyRoleSpec(spec)}
		if !validRoleState(created, spec) {
			if !reconcileCreatedRole(ctx, options.Boundary, spec) {
				return result, errOwnership
			}
		}
	} else if isAmbiguousMutation(createErr) {
		if !reconcileCreatedRole(ctx, options.Boundary, spec) {
			return result, errProvider
		}
		target = &cleanupTarget{spec: copyRoleSpec(spec)}
	} else {
		return result, errProvider
	}
	current, err := options.Boundary.InspectRole(ctx, spec.Name)
	if err != nil || !validRoleState(current, spec) {
		return result, errOwnership
	}

	policyErr := options.Boundary.PutRolePolicy(ctx, spec.Name, spec.PolicyName, spec.PermissionPolicy)
	if policyErr == nil {
		target.policyAttached = true
	} else if !isAmbiguousMutation(policyErr) {
		return result, errProvider
	}
	policy, inspectPolicyErr := options.Boundary.GetRolePolicy(ctx, spec.Name, spec.PolicyName)
	if inspectPolicyErr != nil || !equalPolicy(policy, spec.PermissionPolicy) {
		if policyErr != nil || inspectPolicyErr != nil {
			return result, errProvider
		}
		return result, errOwnership
	}
	target.policyAttached = true

	request := AssumeRoleRequest{
		RoleARN: spec.ARN, ExternalID: externalID, SessionName: sessionName,
		SourceIdentity: sourceIdentity, Tags: map[string]string{proofTagKey: proofSessionTag},
	}
	session, err := options.Boundary.AssumeRole(ctx, request)
	if err != nil || !validAssumedSession(session, request, options.TargetAccountID, options.Now()) {
		return result, errAuthentication
	}
	assumedIdentity, err := options.Boundary.AssumedIdentity(ctx, session)
	if err != nil || !validCallerIdentity(assumedIdentity, options.TargetAccountID) || assumedIdentity.ARN != session.AssumedRoleARN {
		return result, errAuthentication
	}
	result.Assumed = true

	allowed, err := options.Boundary.AllowedGetRole(ctx, session, spec.Name)
	if err != nil {
		return result, errAuthorization
	}
	if !validRoleState(allowed, spec) {
		return result, errOwnership
	}
	result.AllowedRead = true

	deniedErr := options.Boundary.DeniedListRoles(ctx, session, spec.Path)
	var denied AuthorizationDeniedError
	if !errors.As(deniedErr, &denied) || denied.StatusCode != 403 || denied.Code != "AccessDenied" {
		return result, errAuthorization
	}
	result.DeniedCall = true
	return result, nil
}

func validateProofOptions(ctx context.Context, options *ProofOptions) error {
	if ctx == nil || options == nil || options.Boundary == nil || !markerPattern.MatchString(options.Marker) ||
		!regionPattern.MatchString(options.Region) || !accountPattern.MatchString(options.SourceAccountID) ||
		!accountPattern.MatchString(options.TargetAccountID) || options.SourceAccountID == options.TargetAccountID {
		return errConfiguration
	}
	principal := principalPattern.FindStringSubmatch(options.SourcePrincipalARN)
	if len(principal) != 4 || principal[1] != options.SourceAccountID || (principal[2] == "role" && strings.Contains(principal[3], "/")) {
		return errConfiguration
	}
	if options.CleanupTimeout <= 0 {
		options.CleanupTimeout = 30 * time.Second
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 250 * time.Millisecond
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return nil
}

func expectedRoleSpec(options ProofOptions, externalID, sessionName, sourceIdentity string) (RoleSpec, error) {
	name := expectedRoleName(options.Marker)
	path := expectedRolePath(options.Marker)
	arn := fmt.Sprintf("arn:aws:iam::%s:role%s%s", options.TargetAccountID, path, name)
	trust, err := json.Marshal(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{map[string]any{
			"Sid": "ZaspM009Trust", "Effect": "Allow",
			"Principal": map[string]any{"AWS": options.SourcePrincipalARN},
			"Action":    []any{"sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"},
			"Condition": map[string]any{
				"StringEquals": map[string]any{
					"sts:ExternalId": externalID, "sts:RoleSessionName": sessionName,
					"sts:SourceIdentity": sourceIdentity, "aws:RequestTag/" + proofTagKey: proofSessionTag,
				},
				"ForAllValues:StringEquals": map[string]any{"aws:TagKeys": []any{proofTagKey}},
			},
		}},
	})
	if err != nil {
		return RoleSpec{}, err
	}
	permission, err := json.Marshal(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{
				"Sid": "AllowExactRoleRead", "Effect": "Allow", "Action": []any{"iam:GetRole"},
				"Resource":  arn,
				"Condition": map[string]any{"StringEquals": map[string]any{"aws:PrincipalTag/" + proofTagKey: proofSessionTag}},
			},
			map[string]any{"Sid": "DenyRoleListing", "Effect": "Deny", "Action": []any{"iam:ListRoles"}, "Resource": "*"},
		},
	})
	if err != nil {
		return RoleSpec{}, err
	}
	return RoleSpec{
		Name: name, ARN: arn, Path: path, Description: "Zasp isolated M0-09 proof role", MaxSessionDuration: 3600,
		TrustPolicy: string(trust), PermissionPolicy: string(permission),
		PolicyName: expectedPolicyName(options.Marker),
		Tags:       map[string]string{proofTagKey: proofName, markerTagKey: options.Marker, purposeTagKey: rolePurpose},
	}, nil
}

func expectedRoleName(marker string) string   { return "zasp-m0-09-" + marker }
func expectedRolePath(marker string) string   { return proofPathRoot + marker + "/" }
func expectedPolicyName(marker string) string { return "zasp-m0-09-policy-" + marker }

func expectedAssumedARN(accountID, marker string) string {
	return fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/%s", accountID, expectedRoleName(marker), expectedRoleName(marker))
}

func roleStateFromSpec(spec RoleSpec, roleID string) RoleState {
	state := copyRoleSpec(spec)
	state.RoleID = roleID
	return state
}

func assumedSessionForRequest(request AssumeRoleRequest) AssumedSession {
	account := accountFromARN(request.RoleARN)
	marker := strings.TrimPrefix(request.SessionName, "zasp-m0-09-")
	return AssumedSession{
		Credentials: SessionCredentials{
			AccessKeyID: "temporary-access", SecretAccessKey: "temporary-secret",
			SessionToken: "temporary-token", Expiration: time.Now().Add(time.Hour),
		},
		AssumedRoleARN: expectedAssumedARN(account, marker), SourceIdentity: request.SourceIdentity,
	}
}

func validCallerIdentity(identity CallerIdentity, accountID string) bool {
	return identity.AccountID == accountID && callerARNPattern.MatchString(identity.ARN) && accountFromARN(identity.ARN) == accountID
}

func callerMatchesPrincipal(callerARN, principalARN string) bool {
	if callerARN == principalARN {
		return true
	}
	principal := principalPattern.FindStringSubmatch(principalARN)
	if len(principal) != 4 || principal[2] != "role" || strings.Contains(principal[3], "/") {
		return false
	}
	expectedPrefix := fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/", principal[1], principal[3])
	return strings.HasPrefix(callerARN, expectedPrefix) && len(callerARN) > len(expectedPrefix)
}

func accountFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != "aws" || !accountPattern.MatchString(parts[4]) {
		return ""
	}
	return parts[4]
}

func validAssumedSession(session AssumedSession, request AssumeRoleRequest, accountID string, now time.Time) bool {
	credentials := session.Credentials
	return credentials.AccessKeyID != "" && credentials.SecretAccessKey != "" && credentials.SessionToken != "" &&
		credentials.Expiration.After(now.Add(time.Minute)) && session.SourceIdentity == request.SourceIdentity &&
		session.AssumedRoleARN == expectedAssumedARN(accountID, strings.TrimPrefix(request.SessionName, "zasp-m0-09-"))
}

func validRoleState(state RoleState, expected RoleSpec) bool {
	return state.Name == expected.Name && state.ARN == expected.ARN && state.Path == expected.Path && state.RoleID != "" &&
		state.Description == expected.Description && state.MaxSessionDuration == expected.MaxSessionDuration &&
		equalStringMap(state.Tags, expected.Tags) && equalPolicy(state.TrustPolicy, expected.TrustPolicy)
}

func validRoleSummary(summary RoleSummary, expected RoleSpec) bool {
	return summary.Name == expected.Name && summary.ARN == expected.ARN && summary.Path == expected.Path && summary.RoleID != ""
}

func reconcileCreatedRole(ctx context.Context, boundary IAMProofBoundary, spec RoleSpec) bool {
	roles, err := boundary.ListRoles(ctx, spec.Path)
	if err != nil || len(roles) != 1 || !validRoleSummary(roles[0], spec) {
		return false
	}
	state, err := boundary.InspectRole(ctx, spec.Name)
	return err == nil && validRoleState(state, spec)
}

func safeCleanupAndAudit(options ProofOptions, target *cleanupTarget) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errCleanup
		}
	}()
	return cleanupAndAudit(options, target)
}

func cleanupAndAudit(options ProofOptions, target *cleanupTarget) error {
	ctx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
	defer cancel()
	failed := false
	identity, err := options.Boundary.TargetIdentity(ctx)
	if err != nil || !validCallerIdentity(identity, options.TargetAccountID) {
		return errCleanup
	}
	roles, err := options.Boundary.ListRoles(ctx, target.spec.Path)
	if err != nil || len(roles) != 1 || !validRoleSummary(roles[0], target.spec) {
		return errCleanup
	}
	current, err := options.Boundary.InspectRole(ctx, target.spec.Name)
	if err != nil || !validRoleState(current, target.spec) {
		return errCleanup
	}
	policies, err := options.Boundary.ListRolePolicies(ctx, target.spec.Name)
	if err != nil || len(policies) > 1 || (len(policies) == 1 && policies[0] != target.spec.PolicyName) {
		return errCleanup
	}
	if len(policies) == 1 {
		policy, inspectErr := options.Boundary.GetRolePolicy(ctx, target.spec.Name, target.spec.PolicyName)
		if inspectErr != nil || !equalPolicy(policy, target.spec.PermissionPolicy) {
			return errCleanup
		}
		deletePolicyErr := options.Boundary.DeleteRolePolicy(ctx, target.spec.Name, target.spec.PolicyName)
		if deletePolicyErr != nil && !isAmbiguousMutation(deletePolicyErr) {
			failed = true
		} else {
			if err := pollUntil(ctx, options.PollInterval, func() (bool, error) {
				currentPolicies, listErr := options.Boundary.ListRolePolicies(ctx, target.spec.Name)
				if listErr != nil {
					return false, errCleanup
				}
				return len(currentPolicies) == 0, nil
			}); err != nil {
				failed = true
			}
		}
	}
	current, err = options.Boundary.InspectRole(ctx, target.spec.Name)
	if err != nil || !validRoleState(current, target.spec) {
		return errCleanup
	}
	if err := options.Boundary.DeleteRole(ctx, target.spec.Name); err != nil && !isAmbiguousMutation(err) {
		failed = true
	}
	if err := pollUntil(ctx, options.PollInterval, func() (bool, error) {
		remaining, listErr := options.Boundary.ListRoles(ctx, target.spec.Path)
		if listErr != nil {
			return false, errCleanup
		}
		return len(remaining) == 0, nil
	}); err != nil {
		failed = true
	}
	remaining, err := options.Boundary.ListRoles(ctx, target.spec.Path)
	if err != nil || len(remaining) != 0 {
		failed = true
	}
	if failed {
		return errCleanup
	}
	return nil
}

func pollUntil(ctx context.Context, interval time.Duration, check func() (bool, error)) error {
	for {
		ok, err := check()
		if err != nil || ok {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return errCleanup
		case <-timer.C:
		}
	}
}

func copyRoleSpec(input RoleSpec) RoleSpec {
	result := input
	result.Tags = cloneStringMap(input.Tags)
	return result
}

func cloneStringMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func equalStringMap(left, right map[string]string) bool {
	return reflect.DeepEqual(left, right)
}

func equalPolicy(left, right string) bool {
	leftValue, leftErr := decodeStrictJSON(left)
	rightValue, rightErr := decodeStrictJSON(right)
	return leftErr == nil && rightErr == nil && reflect.DeepEqual(leftValue, rightValue)
}

func decodeStrictJSON(raw string) (any, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errConfiguration
	}
	return value, nil
}

func decodeJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errConfiguration
			}
			if _, duplicate := object[key]; duplicate {
				return nil, errConfiguration
			}
			value, err := decodeJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return nil, errConfiguration
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := decodeJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return nil, errConfiguration
		}
		return array, nil
	default:
		return nil, errConfiguration
	}
}
