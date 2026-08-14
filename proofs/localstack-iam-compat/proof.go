package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"
)

var (
	errConfiguration = errors.New("configuration rejected")
	errCapability    = errors.New("capability rejected")
	errProvider      = errors.New("provider operation failed")
	errAuthorization = errors.New("authorization rejected")
	errOwnership     = errors.New("ownership rejected")
	errCleanup       = errors.New("cleanup failed")

	markerPattern = regexp.MustCompile(`^[a-f0-9]{16}$`)
)

const (
	sourceNamespace = "000000000041"
	targetNamespace = "000000000042"
)

type CallerIdentity struct{ AccountID, ARN, UserID string }

type PrincipalSpec struct {
	Name, ARN, Path, Marker string
	Tags                    map[string]string
}

type PrincipalState struct {
	PrincipalSpec
	UserID string
}

type RoleSpec struct {
	Name, ARN, Path, Marker, Description, PolicyName string
	RoleID, TrustPolicy, PermissionPolicy            string
	Tags                                             map[string]string
}

type RoleState = RoleSpec

type AssumeRequest struct {
	RoleARN, ExternalID, SessionName, SourceIdentity string
	Tags                                             map[string]string
}

type AssumedSession struct {
	AccessKeyID, SecretAccessKey, SessionToken    string
	AssumedRoleARN, AssumedRoleID, SourceIdentity string
	Expiration                                    time.Time
}

type IAMBoundary interface {
	SourceIdentity(context.Context) (CallerIdentity, error)
	TargetIdentity(context.Context) (CallerIdentity, error)
	ListPrincipals(context.Context, string) ([]PrincipalState, error)
	CreatePrincipal(context.Context, PrincipalSpec) (PrincipalState, error)
	InspectPrincipal(context.Context, string) (PrincipalState, error)
	CreateAccessKey(context.Context, string) (string, string, error)
	ListAccessKeys(context.Context, string) ([]string, error)
	DeleteAccessKey(context.Context, string, string) error
	DeletePrincipal(context.Context, string) error
	ListRoles(context.Context, string) ([]RoleState, error)
	CreateRole(context.Context, RoleSpec) (RoleState, error)
	InspectRole(context.Context, string) (RoleState, error)
	PutRolePolicy(context.Context, string, string, string) error
	GetRolePolicy(context.Context, string, string) (string, error)
	AssumeRole(context.Context, AssumeRequest, string, string) (AssumedSession, error)
	AssumedIdentity(context.Context, AssumedSession) (CallerIdentity, error)
	AllowedGetRole(context.Context, AssumedSession, string) (RoleState, error)
	DeniedListRoles(context.Context, AssumedSession) error
	DeleteRolePolicy(context.Context, string, string) error
	DeleteRole(context.Context, string) error
}

type ProofOptions struct {
	Marker, Endpoint, SourceAccountID, TargetAccountID string
	Boundary                                           IAMBoundary
	CleanupTimeout, PollInterval                       time.Duration
	Now                                                func() time.Time
}

type ProofResult struct {
	Namespaces, Assumed, AllowedRead, ExplicitDeny, Cleanup, Audit bool
}

type ambiguousMutationError struct{ cause error }

func (e ambiguousMutationError) Error() string { return "mutation outcome ambiguous" }
func (e ambiguousMutationError) Unwrap() error { return e.cause }

type explicitDenyError struct{}

func (explicitDenyError) Error() string { return "explicit denial" }

type principalTarget struct {
	spec         PrincipalSpec
	state        *PrincipalState
	keyID        string
	keySecret    string
	attempted    bool
	uncertain    bool
	keyAttempted bool
}

type roleTarget struct {
	spec        RoleSpec
	state       *RoleState
	policyArmed bool
	attempted   bool
	uncertain   bool
}

func RunProof(ctx context.Context, options ProofOptions) (result ProofResult, resultErr error) {
	if err := validateOptions(ctx, options); err != nil {
		return result, errConfiguration
	}
	principalSpec, roleSpec := expectedSpecs(options)
	principal := &principalTarget{spec: principalSpec}
	role := &roleTarget{spec: roleSpec}
	defer func() {
		panicked := recover() != nil
		if panicked || principal.uncertain || role.uncertain {
			reconcileCtx, reconcileCancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
			safeArmUncertainTargets(reconcileCtx, options, principal, role, panicked)
			reconcileCancel()
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
		defer cancel()
		attempted := principal.attempted || role.attempted
		cleanup, audit := safeCleanupAndAudit(cleanupCtx, options, principal, role)
		if attempted && cleanup {
			result.Cleanup = true
		}
		if attempted && audit {
			result.Audit = true
		}
		if !cleanup || !audit {
			resultErr = errCleanup
		} else if panicked {
			resultErr = errProvider
		}
	}()
	if err := preflightEmpty(ctx, options, principalSpec, roleSpec); err != nil {
		return result, err
	}
	result.Namespaces = true
	if ctx.Err() != nil {
		return result, errProvider
	}
	if resultErr = createAndProvePrincipal(ctx, options, principal); resultErr != nil {
		return result, resultErr
	}
	if resultErr = createAndProveRole(ctx, options, role); resultErr != nil {
		return result, resultErr
	}
	return proveAssumeAllowDeny(ctx, options, principal, role, result)
}

func validateOptions(ctx context.Context, options ProofOptions) error {
	if ctx == nil || options.Boundary == nil || !markerPattern.MatchString(options.Marker) || options.Endpoint == "" || options.Now == nil || options.CleanupTimeout <= 0 || options.PollInterval <= 0 {
		return errConfiguration
	}
	if options.SourceAccountID != sourceNamespace || options.TargetAccountID != targetNamespace || options.SourceAccountID == options.TargetAccountID {
		return errConfiguration
	}
	return nil
}

func expectedSpecs(options ProofOptions) (PrincipalSpec, RoleSpec) {
	prefix := "zasp-prov-01-" + options.Marker
	path := "/" + options.Marker + "/"
	principal := PrincipalSpec{
		Name: prefix + "-principal", ARN: iamUserARN(sourceNamespace, path, prefix+"-principal"),
		Path: path, Marker: options.Marker, Tags: map[string]string{"proof": options.Marker},
	}
	externalID := prefix + "-external"
	sessionName := prefix + "-session"
	sourceIdentity := prefix + "-source"
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + principal.ARN + `"},"Action":["sts:AssumeRole","sts:SetSourceIdentity","sts:TagSession"],"Condition":{"StringEquals":{"sts:ExternalId":"` + externalID + `","sts:RoleSessionName":"` + sessionName + `","sts:SourceIdentity":"` + sourceIdentity + `","aws:RequestTag/proof":"` + options.Marker + `"}}}]}`
	roleARN := iamRoleARN(targetNamespace, path, prefix+"-role")
	permission := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"` + roleARN + `"},{"Effect":"Allow","Action":"iam:ListRoles","Resource":"*"},{"Effect":"Deny","Action":"iam:ListRoles","Resource":"*"}]}`
	role := RoleSpec{
		Name: prefix + "-role", ARN: roleARN,
		Path: path, Marker: options.Marker, Description: "provisional LocalStack compatibility proof", PolicyName: prefix + "-policy",
		TrustPolicy: trust, PermissionPolicy: permission, Tags: map[string]string{"proof": options.Marker},
	}
	return principal, role
}

func preflightEmpty(ctx context.Context, options ProofOptions, principal PrincipalSpec, role RoleSpec) error {
	source, err := options.Boundary.SourceIdentity(ctx)
	if err != nil {
		return errProvider
	}
	if source.AccountID != sourceNamespace || source.UserID == "" || !validCallerARN(source.ARN, sourceNamespace) {
		return errOwnership
	}
	target, err := options.Boundary.TargetIdentity(ctx)
	if err != nil {
		return errProvider
	}
	if target.AccountID != targetNamespace || target.UserID == "" || !validCallerARN(target.ARN, targetNamespace) {
		return errOwnership
	}
	prefix := proofPrefix(options.Marker)
	principals, err := options.Boundary.ListPrincipals(ctx, prefix)
	if err != nil {
		return errProvider
	}
	if len(principals) != 0 {
		return errOwnership
	}
	roles, err := options.Boundary.ListRoles(ctx, prefix)
	if err != nil {
		return errProvider
	}
	if len(roles) != 0 {
		return errOwnership
	}
	return nil
}

func createAndProvePrincipal(ctx context.Context, options ProofOptions, target *principalTarget) error {
	target.attempted = true
	created, err := options.Boundary.CreatePrincipal(ctx, target.spec)
	if err != nil {
		var ambiguous ambiguousMutationError
		if !errors.As(err, &ambiguous) {
			return errProvider
		}
		target.uncertain = true
		reconcileCtx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
		defer cancel()
		state, outcome := reconcilePrincipal(reconcileCtx, options.Boundary, target.spec, options.PollInterval)
		if outcome != reconciliationOwned {
			return errOwnership
		}
		created = *state
	}
	if !exactPrincipal(target.spec, created) {
		target.uncertain = true
		reconcileCtx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
		defer cancel()
		state, outcome := reconcilePrincipal(reconcileCtx, options.Boundary, target.spec, options.PollInterval)
		if outcome != reconciliationOwned {
			return errOwnership
		}
		created = *state
	}
	target.state = &created
	target.uncertain = false
	observed, err := options.Boundary.InspectPrincipal(ctx, target.spec.Name)
	if err != nil || !exactPrincipal(created.PrincipalSpec, observed) || observed.UserID != created.UserID {
		return errOwnership
	}
	target.keyAttempted = true
	keyID, keySecret, err := options.Boundary.CreateAccessKey(ctx, target.spec.Name)
	if err != nil {
		var ambiguous ambiguousMutationError
		if !errors.As(err, &ambiguous) {
			return errProvider
		}
	} else if keyID != "" && keySecret != "" {
		target.keyID = keyID
		target.keySecret = keySecret
		return nil
	}
	if keyID != "" {
		target.keyID = keyID
	} else {
		reconcileCtx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
		defer cancel()
		if reconciled, ok := reconcileAccessKey(reconcileCtx, options.Boundary, target.state.Name, options.PollInterval); ok {
			target.keyID = reconciled
		}
	}
	return errProvider
}

func createAndProveRole(ctx context.Context, options ProofOptions, target *roleTarget) error {
	target.attempted = true
	created, err := options.Boundary.CreateRole(ctx, target.spec)
	if err != nil {
		var ambiguous ambiguousMutationError
		if !errors.As(err, &ambiguous) {
			return errProvider
		}
		target.uncertain = true
		reconcileCtx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
		defer cancel()
		state, outcome := reconcileRole(reconcileCtx, options.Boundary, target.spec, options.PollInterval)
		if outcome != reconciliationOwned {
			return errOwnership
		}
		created = *state
	}
	if !exactRole(target.spec, created) {
		target.uncertain = true
		reconcileCtx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
		defer cancel()
		state, outcome := reconcileRole(reconcileCtx, options.Boundary, target.spec, options.PollInterval)
		if outcome != reconciliationOwned {
			return errOwnership
		}
		created = *state
	}
	target.state = &created
	target.uncertain = false
	target.policyArmed = true
	if err := options.Boundary.PutRolePolicy(ctx, target.spec.Name, target.spec.PolicyName, target.spec.PermissionPolicy); err != nil {
		return errProvider
	}
	observed, err := options.Boundary.InspectRole(ctx, target.spec.Name)
	if err != nil || !exactRole(created, observed) {
		return errOwnership
	}
	policy, err := options.Boundary.GetRolePolicy(ctx, target.spec.Name, target.spec.PolicyName)
	if err != nil || !sameJSON(policy, target.spec.PermissionPolicy) {
		return errOwnership
	}
	return nil
}

func proveAssumeAllowDeny(ctx context.Context, options ProofOptions, principal *principalTarget, role *roleTarget, result ProofResult) (ProofResult, error) {
	if principal.state == nil || role.state == nil {
		return result, errOwnership
	}
	prefix := "zasp-prov-01-" + options.Marker
	session, err := options.Boundary.AssumeRole(ctx, AssumeRequest{
		RoleARN: role.state.ARN, ExternalID: prefix + "-external", SessionName: prefix + "-session", SourceIdentity: prefix + "-source",
		Tags: map[string]string{"proof": options.Marker},
	}, principal.keyID, principal.keySecret)
	expectedSessionARN := assumedRoleARN(*role.state, prefix+"-session")
	expectedSessionID := role.state.RoleID + ":" + prefix + "-session"
	if err != nil || session.AccessKeyID == "" || session.SecretAccessKey == "" || session.SessionToken == "" || session.AssumedRoleARN != expectedSessionARN || session.SourceIdentity != prefix+"-source" || !session.Expiration.After(options.Now()) {
		return result, errAuthorization
	}
	if session.AssumedRoleID != expectedSessionID {
		return result, errOwnership
	}
	identity, err := options.Boundary.AssumedIdentity(ctx, session)
	if err != nil || identity.AccountID != targetNamespace || identity.ARN != expectedSessionARN || identity.UserID != expectedSessionID {
		return result, errOwnership
	}
	result.Assumed = true
	read, err := options.Boundary.AllowedGetRole(ctx, session, role.state.Name)
	if err != nil || !sameRoleDefinition(*role.state, read) {
		return result, errOwnership
	}
	result.AllowedRead = true
	policy, err := options.Boundary.GetRolePolicy(ctx, role.state.Name, role.state.PolicyName)
	if err != nil || !sameJSON(policy, role.state.PermissionPolicy) {
		return result, errOwnership
	}
	err = options.Boundary.DeniedListRoles(ctx, session)
	var explicit explicitDenyError
	if !errors.As(err, &explicit) {
		return result, errAuthorization
	}
	result.ExplicitDeny = true
	return result, nil
}

type reconciliationOutcome uint8

const (
	reconciliationAbsent reconciliationOutcome = iota
	reconciliationOwned
	reconciliationMismatch
	reconciliationUnresolved
)

func reconcilePrincipal(ctx context.Context, boundary IAMBoundary, expected PrincipalSpec, interval time.Duration) (*PrincipalState, reconciliationOutcome) {
	observed := false
	lastObservationWasCleanAbsence := false
	for ctx.Err() == nil {
		principals, err := boundary.ListPrincipals(ctx, expected.Name)
		if err == nil && len(principals) == 1 {
			lastObservationWasCleanAbsence = false
			observed = true
			state, inspectErr := boundary.InspectPrincipal(ctx, expected.Name)
			if inspectErr == nil && exactPrincipal(expected, state) {
				return &state, reconciliationOwned
			}
			if inspectErr == nil {
				return nil, reconciliationMismatch
			}
		} else if err == nil && len(principals) == 0 {
			lastObservationWasCleanAbsence = true
		} else {
			lastObservationWasCleanAbsence = false
			observed = observed || err == nil && len(principals) > 0
		}
		waitForPoll(ctx, interval)
	}
	if lastObservationWasCleanAbsence && !observed {
		return nil, reconciliationAbsent
	}
	return nil, reconciliationUnresolved
}

func reconcileRole(ctx context.Context, boundary IAMBoundary, expected RoleSpec, interval time.Duration) (*RoleState, reconciliationOutcome) {
	observed := false
	lastObservationWasCleanAbsence := false
	for ctx.Err() == nil {
		roles, err := boundary.ListRoles(ctx, expected.Name)
		if err == nil && len(roles) == 1 {
			lastObservationWasCleanAbsence = false
			observed = true
			state, inspectErr := boundary.InspectRole(ctx, expected.Name)
			if inspectErr == nil && sameRoleDefinition(expected, state) {
				state.PolicyName, state.PermissionPolicy = expected.PolicyName, expected.PermissionPolicy
				return &state, reconciliationOwned
			}
			if inspectErr == nil {
				return nil, reconciliationMismatch
			}
		} else if err == nil && len(roles) == 0 {
			lastObservationWasCleanAbsence = true
		} else {
			lastObservationWasCleanAbsence = false
			observed = observed || err == nil && len(roles) > 0
		}
		waitForPoll(ctx, interval)
	}
	if lastObservationWasCleanAbsence && !observed {
		return nil, reconciliationAbsent
	}
	return nil, reconciliationUnresolved
}

func waitForPoll(ctx context.Context, interval time.Duration) {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func cleanupAndAudit(ctx context.Context, options ProofOptions, principal *principalTarget, role *roleTarget) (bool, bool) {
	if !principal.attempted && !role.attempted {
		return true, true
	}
	cleanupOK := true
	if role.state != nil && role.policyArmed {
		policy, err := safeCleanupValue(func() (string, error) {
			return options.Boundary.GetRolePolicy(ctx, role.state.Name, role.state.PolicyName)
		})
		policyOwned := err == nil && sameJSON(policy, role.state.PermissionPolicy)
		if !policyOwned {
			cleanupOK = false
		}
		observed, err := safeCleanupValue(func() (RoleState, error) { return options.Boundary.InspectRole(ctx, role.state.Name) })
		if err != nil || !exactRole(*role.state, observed) {
			cleanupOK = false
		} else if policyOwned && safeCleanupCall(func() error { return options.Boundary.DeleteRolePolicy(ctx, role.state.Name, role.state.PolicyName) }) != nil {
			cleanupOK = false
		}
	}
	if principal.state != nil {
		observed, err := safeCleanupValue(func() (PrincipalState, error) { return options.Boundary.InspectPrincipal(ctx, principal.state.Name) })
		if err != nil || !exactPrincipal(principal.state.PrincipalSpec, observed) || observed.UserID != principal.state.UserID {
			cleanupOK = false
		} else {
			if principal.keyID != "" && safeCleanupCall(func() error { return options.Boundary.DeleteAccessKey(ctx, principal.state.Name, principal.keyID) }) != nil {
				cleanupOK = false
			}
			if safeCleanupCall(func() error { return options.Boundary.DeletePrincipal(ctx, principal.state.Name) }) != nil {
				cleanupOK = false
			}
		}
	}
	if role.state != nil {
		observed, err := safeCleanupValue(func() (RoleState, error) { return options.Boundary.InspectRole(ctx, role.state.Name) })
		if err != nil || !sameRoleDefinition(*role.state, observed) {
			cleanupOK = false
		} else if err := safeCleanupCall(func() error { return options.Boundary.DeleteRole(ctx, role.state.Name) }); err != nil {
			cleanupOK = false
		}
	}
	prefix := proofPrefix(options.Marker)
	principals, principalErr := safeCleanupValue(func() ([]PrincipalState, error) { return options.Boundary.ListPrincipals(ctx, prefix) })
	roles, roleErr := safeCleanupValue(func() ([]RoleState, error) { return options.Boundary.ListRoles(ctx, prefix) })
	auditOK := principalErr == nil && roleErr == nil && len(principals) == 0 && len(roles) == 0
	return cleanupOK, auditOK
}

func armUncertainTargets(ctx context.Context, options ProofOptions, principal *principalTarget, role *roleTarget, includeAttempted bool) {
	if (principal.uncertain || includeAttempted && principal.attempted) && principal.state == nil {
		if state, outcome := reconcilePrincipal(ctx, options.Boundary, principal.spec, options.PollInterval); outcome == reconciliationOwned {
			principal.state = state
			principal.uncertain = false
		}
	}
	if principal.state != nil && principal.keyAttempted && principal.keyID == "" {
		if keyID, ok := reconcileAccessKey(ctx, options.Boundary, principal.state.Name, options.PollInterval); ok {
			principal.keyID = keyID
		}
	}
	if (role.uncertain || includeAttempted && role.attempted) && role.state == nil {
		if state, outcome := reconcileRole(ctx, options.Boundary, role.spec, options.PollInterval); outcome == reconciliationOwned {
			role.state = state
			role.uncertain = false
		}
	}
}

func safeArmUncertainTargets(ctx context.Context, options ProofOptions, principal *principalTarget, role *roleTarget, includeAttempted bool) {
	defer func() { _ = recover() }()
	armUncertainTargets(ctx, options, principal, role, includeAttempted)
}

func safeCleanupAndAudit(ctx context.Context, options ProofOptions, principal *principalTarget, role *roleTarget) (cleanup, audit bool) {
	defer func() {
		if recover() != nil {
			cleanup, audit = false, false
		}
	}()
	return cleanupAndAudit(ctx, options, principal, role)
}

func safeCleanupCall(call func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = errCleanup
		}
	}()
	return call()
}

func safeCleanupValue[T any](call func() (T, error)) (value T, err error) {
	defer func() {
		if recover() != nil {
			err = errCleanup
		}
	}()
	return call()
}

func proofPrefix(marker string) string { return "zasp-prov-01-" + marker }

func iamUserARN(account, path, name string) string {
	return "arn:aws:iam::" + account + ":user/" + strings.TrimPrefix(path, "/") + name
}

func iamRoleARN(account, path, name string) string {
	return "arn:aws:iam::" + account + ":role/" + strings.TrimPrefix(path, "/") + name
}

func assumedRoleARN(role RoleState, sessionName string) string {
	return "arn:aws:sts::" + targetNamespace + ":assumed-role/" + role.Name + "/" + sessionName
}

func reconcileAccessKey(ctx context.Context, boundary IAMBoundary, principalName string, interval time.Duration) (string, bool) {
	for ctx.Err() == nil {
		keys, err := boundary.ListAccessKeys(ctx, principalName)
		if err == nil && len(keys) == 1 && keys[0] != "" {
			return keys[0], true
		}
		waitForPoll(ctx, interval)
	}
	return "", false
}

var callerARNPattern = regexp.MustCompile(`^arn:aws:(iam|sts)::([0-9]{12}):(root|(?:user|role|assumed-role)/[A-Za-z0-9+=,.@_/-]+)$`)

func validCallerARN(arn, account string) bool {
	matches := callerARNPattern.FindStringSubmatch(arn)
	if len(matches) != 4 || matches[2] != account {
		return false
	}
	resource := matches[3]
	if resource == "root" {
		return matches[1] == "iam"
	}
	if matches[1] == "iam" {
		return strings.HasPrefix(resource, "user/") || strings.HasPrefix(resource, "role/")
	}
	return matches[1] == "sts" && strings.HasPrefix(resource, "assumed-role/")
}

func exactPrincipal(expected PrincipalSpec, observed PrincipalState) bool {
	return expected.Name == observed.Name && expected.ARN == observed.ARN && expected.Path == observed.Path && expected.Marker == observed.Marker && exactTags(expected.Tags, observed.Tags) && observed.UserID != ""
}

func exactRole(expected RoleSpec, observed RoleState) bool {
	if expected.Name != observed.Name || expected.ARN != observed.ARN || expected.Path != observed.Path || expected.Marker != observed.Marker || expected.Description != observed.Description || expected.PolicyName != observed.PolicyName || !exactTags(expected.Tags, observed.Tags) || observed.RoleID == "" {
		return false
	}
	if expected.RoleID != "" && expected.RoleID != observed.RoleID {
		return false
	}
	return sameJSON(expected.TrustPolicy, observed.TrustPolicy) && sameJSON(expected.PermissionPolicy, observed.PermissionPolicy)
}

func sameRoleDefinition(expected RoleSpec, observed RoleState) bool {
	return expected.Name == observed.Name && expected.ARN == observed.ARN && expected.Path == observed.Path && expected.Marker == observed.Marker && expected.Description == observed.Description && exactTags(expected.Tags, observed.Tags) && observed.RoleID != "" && (expected.RoleID == "" || expected.RoleID == observed.RoleID) && sameJSON(expected.TrustPolicy, observed.TrustPolicy)
}

func exactTags(left, right map[string]string) bool {
	return reflect.DeepEqual(left, right)
}

func sameJSON(left, right string) bool {
	leftValue, leftOK := decodeStrictJSON(left)
	rightValue, rightOK := decodeStrictJSON(right)
	return leftOK && rightOK && reflect.DeepEqual(leftValue, rightValue)
}

func decodeStrictJSON(raw string) (any, bool) {
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.UseNumber()
	value, ok := decodeJSONValue(decoder)
	if !ok {
		return nil, false
	}
	var extra any
	return value, decoder.Decode(&extra) == io.EOF
}

func decodeJSONValue(decoder *json.Decoder) (any, bool) {
	token, err := decoder.Token()
	if err != nil {
		return nil, false
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return nil, false
				}
				name, ok := key.(string)
				if !ok || strings.TrimSpace(name) == "" {
					return nil, false
				}
				if _, duplicate := object[name]; duplicate {
					return nil, false
				}
				value, ok := decodeJSONValue(decoder)
				if !ok {
					return nil, false
				}
				object[name] = value
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, false
			}
			return object, true
		case '[':
			array := []any{}
			for decoder.More() {
				value, ok := decodeJSONValue(decoder)
				if !ok {
					return nil, false
				}
				array = append(array, value)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, false
			}
			return array, true
		}
	}
	return token, true
}
