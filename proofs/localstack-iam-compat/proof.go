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
	spec  PrincipalSpec
	state *PrincipalState
	keyID string
}

type roleTarget struct {
	spec  RoleSpec
	state *RoleState
}

func RunProof(ctx context.Context, options ProofOptions) (result ProofResult, resultErr error) {
	if err := validateOptions(ctx, options); err != nil {
		return result, errConfiguration
	}
	principalSpec, roleSpec := expectedSpecs(options)
	principal := &principalTarget{spec: principalSpec}
	role := &roleTarget{spec: roleSpec}
	defer func() {
		if recover() != nil {
			resultErr = errProvider
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
		defer cancel()
		cleanup, audit := cleanupAndAudit(cleanupCtx, options, principal, role)
		if cleanup {
			result.Cleanup = true
		}
		if audit {
			result.Audit = true
		}
		if !cleanup || !audit {
			resultErr = errCleanup
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
		Name: prefix + "-principal", ARN: "arn:aws:iam::" + sourceNamespace + ":user/" + prefix + "-principal",
		Path: path, Marker: options.Marker, Tags: map[string]string{"proof": options.Marker},
	}
	externalID := prefix + "-external"
	sessionName := prefix + "-session"
	sourceIdentity := prefix + "-source"
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + principal.ARN + `"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"` + externalID + `","sts:RoleSessionName":"` + sessionName + `","sts:SourceIdentity":"` + sourceIdentity + `","aws:RequestTag/proof":"` + options.Marker + `"}}}]}`
	permission := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"arn:aws:iam::` + targetNamespace + `:role/` + prefix + `-role"},{"Effect":"Deny","Action":"iam:ListRoles","Resource":"*"}]}`
	role := RoleSpec{
		Name: prefix + "-role", ARN: "arn:aws:iam::" + targetNamespace + ":role/" + prefix + "-role",
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
	if source.AccountID != sourceNamespace || source.ARN == "" || source.UserID == "" {
		return errOwnership
	}
	target, err := options.Boundary.TargetIdentity(ctx)
	if err != nil {
		return errProvider
	}
	if target.AccountID != targetNamespace || target.ARN == "" || target.UserID == "" {
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
	created, err := options.Boundary.CreatePrincipal(ctx, target.spec)
	if err != nil {
		var ambiguous ambiguousMutationError
		if !errors.As(err, &ambiguous) {
			return errProvider
		}
		reconcileCtx, cancel := context.WithTimeout(ctx, options.CleanupTimeout)
		defer cancel()
		state, outcome := reconcilePrincipal(reconcileCtx, options.Boundary, target.spec, options.PollInterval)
		if outcome != reconciliationOwned {
			return errOwnership
		}
		created = *state
	}
	if !exactPrincipal(target.spec, created) {
		return errOwnership
	}
	target.state = &created
	observed, err := options.Boundary.InspectPrincipal(ctx, target.spec.Name)
	if err != nil || !exactPrincipal(created.PrincipalSpec, observed) || observed.UserID != created.UserID {
		return errOwnership
	}
	keyID, _, err := options.Boundary.CreateAccessKey(ctx, target.spec.Name)
	if err != nil || keyID == "" {
		return errProvider
	}
	target.keyID = keyID
	return nil
}

func createAndProveRole(ctx context.Context, options ProofOptions, target *roleTarget) error {
	created, err := options.Boundary.CreateRole(ctx, target.spec)
	if err != nil {
		var ambiguous ambiguousMutationError
		if !errors.As(err, &ambiguous) {
			return errProvider
		}
		reconcileCtx, cancel := context.WithTimeout(ctx, options.CleanupTimeout)
		defer cancel()
		state, outcome := reconcileRole(reconcileCtx, options.Boundary, target.spec, options.PollInterval)
		if outcome != reconciliationOwned {
			return errOwnership
		}
		created = *state
	}
	if !exactRole(target.spec, created) {
		return errOwnership
	}
	target.state = &created
	observed, err := options.Boundary.InspectRole(ctx, target.spec.Name)
	if err != nil || !exactRole(created, observed) {
		return errOwnership
	}
	if err := options.Boundary.PutRolePolicy(ctx, target.spec.Name, target.spec.PolicyName, target.spec.PermissionPolicy); err != nil {
		return errProvider
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
	}, principal.keyID, "")
	if err != nil || session.AccessKeyID == "" || session.SecretAccessKey == "" || session.SessionToken == "" || session.AssumedRoleARN != role.state.ARN || session.SourceIdentity != prefix+"-source" || !session.Expiration.After(options.Now()) {
		return result, errAuthorization
	}
	if session.AssumedRoleID != role.state.RoleID {
		return result, errOwnership
	}
	identity, err := options.Boundary.AssumedIdentity(ctx, session)
	if err != nil || identity.AccountID != targetNamespace || identity.ARN != role.state.ARN || identity.UserID != role.state.RoleID {
		return result, errOwnership
	}
	result.Assumed = true
	read, err := options.Boundary.AllowedGetRole(ctx, session, role.state.Name)
	if err != nil || !exactRole(*role.state, read) {
		return result, errOwnership
	}
	result.AllowedRead = true
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
	for ctx.Err() == nil {
		principals, err := boundary.ListPrincipals(ctx, expected.Name)
		if err == nil && len(principals) == 1 {
			observed = true
			state, inspectErr := boundary.InspectPrincipal(ctx, expected.Name)
			if inspectErr == nil && exactPrincipal(expected, state) {
				return &state, reconciliationOwned
			}
			if inspectErr == nil {
				return nil, reconciliationMismatch
			}
		} else if err == nil && len(principals) == 0 && !observed {
			return nil, reconciliationAbsent
		}
		waitForPoll(ctx, interval)
	}
	return nil, reconciliationUnresolved
}

func reconcileRole(ctx context.Context, boundary IAMBoundary, expected RoleSpec, interval time.Duration) (*RoleState, reconciliationOutcome) {
	observed := false
	for ctx.Err() == nil {
		roles, err := boundary.ListRoles(ctx, expected.Name)
		if err == nil && len(roles) == 1 {
			observed = true
			state, inspectErr := boundary.InspectRole(ctx, expected.Name)
			if inspectErr == nil && exactRole(expected, state) {
				return &state, reconciliationOwned
			}
			if inspectErr == nil {
				return nil, reconciliationMismatch
			}
		} else if err == nil && len(roles) == 0 && !observed {
			return nil, reconciliationAbsent
		}
		waitForPoll(ctx, interval)
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
	cleanupOK := true
	if role.state != nil {
		policy, err := options.Boundary.GetRolePolicy(ctx, role.state.Name, role.state.PolicyName)
		if err != nil || !sameJSON(policy, role.state.PermissionPolicy) {
			cleanupOK = false
		}
		observed, err := options.Boundary.InspectRole(ctx, role.state.Name)
		if err != nil || !exactRole(*role.state, observed) {
			cleanupOK = false
		} else if err := options.Boundary.DeleteRolePolicy(ctx, role.state.Name, role.state.PolicyName); err != nil {
			cleanupOK = false
		}
	}
	if principal.state != nil {
		observed, err := options.Boundary.InspectPrincipal(ctx, principal.state.Name)
		if err != nil || !exactPrincipal(principal.state.PrincipalSpec, observed) || observed.UserID != principal.state.UserID {
			cleanupOK = false
		} else {
			if principal.keyID != "" && options.Boundary.DeleteAccessKey(ctx, principal.state.Name, principal.keyID) != nil {
				cleanupOK = false
			}
			if options.Boundary.DeletePrincipal(ctx, principal.state.Name) != nil {
				cleanupOK = false
			}
		}
	}
	if role.state != nil {
		observed, err := options.Boundary.InspectRole(ctx, role.state.Name)
		if err != nil || !exactRole(*role.state, observed) {
			cleanupOK = false
		} else if err := options.Boundary.DeleteRole(ctx, role.state.Name); err != nil {
			cleanupOK = false
		}
	}
	prefix := proofPrefix(options.Marker)
	principals, principalErr := options.Boundary.ListPrincipals(ctx, prefix)
	roles, roleErr := options.Boundary.ListRoles(ctx, prefix)
	auditOK := principalErr == nil && roleErr == nil && len(principals) == 0 && len(roles) == 0
	return cleanupOK, auditOK
}

func proofPrefix(marker string) string { return "zasp-prov-01-" + marker }

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
