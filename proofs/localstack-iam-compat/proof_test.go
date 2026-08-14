package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const marker = "0123456789abcdef"

func TestRunProof(t *testing.T) {
	fake := newFakeBoundary()
	result, err := RunProof(context.Background(), testOptions(fake))
	if err != nil {
		t.Fatalf("RunProof() error = %v", err)
	}
	if result != (ProofResult{Namespaces: true, Assumed: true, AllowedRead: true, ExplicitDeny: true, Cleanup: true, Audit: true}) {
		t.Fatalf("RunProof() result = %#v", result)
	}
	want := []string{
		"source-identity", "target-identity", "list-principals", "list-roles",
		"create-principal", "inspect-principal", "create-access-key",
		"create-role", "inspect-role", "put-role-policy", "get-role-policy",
		"assume-role", "assumed-identity", "allowed-get-role", "denied-list-roles",
		"cleanup-get-role-policy", "cleanup-inspect-role", "delete-role-policy",
		"cleanup-inspect-principal", "delete-access-key", "delete-principal",
		"cleanup-inspect-role", "delete-role", "audit-principals", "audit-roles",
	}
	if got := fake.eventsSnapshot(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("event order = %#v, want %#v", got, want)
	}
}

func TestRunProof_Rejects(t *testing.T) {
	tests := []struct {
		name string
		set  func(*fakeBoundary)
		want error
	}{
		{"same namespace", func(f *fakeBoundary) { f.options.SourceAccountID = f.options.TargetAccountID }, errConfiguration},
		{"unexpected source identity", func(f *fakeBoundary) { f.source.AccountID = "000000000099" }, errOwnership},
		{"unexpected target identity", func(f *fakeBoundary) { f.target.AccountID = "000000000099" }, errOwnership},
		{"prefix principal collision", func(f *fakeBoundary) { f.principalCollision = true }, errOwnership},
		{"prefix role collision", func(f *fakeBoundary) { f.roleCollision = true }, errOwnership},
		{"replacement principal id", func(f *fakeBoundary) { f.replacePrincipal = true }, errCleanup},
		{"replacement role id", func(f *fakeBoundary) { f.replaceRole = true }, errCleanup},
		{"wrong trust", func(f *fakeBoundary) { f.wrongTrust = true }, errCleanup},
		{"wrong permission", func(f *fakeBoundary) { f.wrongPermission = true }, errCleanup},
		{"wrong marker tags", func(f *fakeBoundary) { f.wrongTags = true }, errCleanup},
		{"missing external id", func(f *fakeBoundary) { f.missingExternalID = true }, errAuthorization},
		{"wrong session name", func(f *fakeBoundary) { f.wrongSessionName = true }, errAuthorization},
		{"wrong source identity", func(f *fakeBoundary) { f.wrongSourceIdentity = true }, errAuthorization},
		{"wrong session tag", func(f *fakeBoundary) { f.wrongSessionTag = true }, errAuthorization},
		{"wrong assumed role id", func(f *fakeBoundary) { f.wrongAssumedRoleID = true }, errOwnership},
		{"wrong assumed caller user id", func(f *fakeBoundary) { f.wrongAssumedCaller = true }, errOwnership},
		{"allowed read returns foreign role", func(f *fakeBoundary) { f.foreignRead = true }, errOwnership},
		{"implicit denial", func(f *fakeBoundary) { f.implicitDeny = true }, errAuthorization},
		{"enforcement disabled", func(f *fakeBoundary) { f.enforcementDisabled = true }, errAuthorization},
		{"canceled main context", func(f *fakeBoundary) { f.cancelMain = true }, errProvider},
		{"cleanup mismatch", func(f *fakeBoundary) { f.cleanupMismatch = true }, errCleanup},
		{"cleanup failure precedence", func(f *fakeBoundary) { f.cleanupFails = true }, errCleanup},
		{"audit prefix remains", func(f *fakeBoundary) { f.auditRemains = true }, errCleanup},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeBoundary()
			test.set(fake)
			ctx := context.Background()
			if fake.cancelMain {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			_, err := RunProof(ctx, fake.options)
			if !errors.Is(err, test.want) {
				t.Fatalf("RunProof() error = %v, want %v", err, test.want)
			}
			if fake.deletedReplacement {
				t.Fatal("proof deleted an unproven replacement")
			}
		})
	}
}

func TestRunProof_Reconciles(t *testing.T) {
	tests := []struct {
		name string
		set  func(*fakeBoundary)
		want error
	}{
		{"create ambiguity exact", func(f *fakeBoundary) { f.ambiguousPrincipal = true; f.ambiguousRole = true }, nil},
		{"create ambiguity mismatch", func(f *fakeBoundary) { f.ambiguousRole = true; f.replaceRole = true }, errCleanup},
		{"delayed visibility", func(f *fakeBoundary) { f.ambiguousRole = true; f.delayedRole = 2 }, nil},
		{"panic after apply", func(f *fakeBoundary) { f.panicAfterRole = true }, errProvider},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeBoundary()
			test.set(fake)
			_, err := RunProof(context.Background(), fake.options)
			if !errors.Is(err, test.want) {
				t.Fatalf("RunProof() error = %v, want %v", err, test.want)
			}
			if fake.deletedReplacement {
				t.Fatal("proof deleted an unproven replacement")
			}
		})
	}
}

func TestRunProof_Cleans(t *testing.T) {
	fake := newFakeBoundary()
	fake.cleanupFails = true
	fake.cleanupContinuation = true
	_, err := RunProof(context.Background(), fake.options)
	if !errors.Is(err, errCleanup) {
		t.Fatalf("RunProof() error = %v, want cleanup error", err)
	}
	if !fake.continuedCleanup {
		t.Fatal("cleanup stopped after an independent failure")
	}
}

func TestRunProof_ReviewFixes(t *testing.T) {
	t.Run("passes temporary access secret to assume role", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.requireAccessSecret = true
		if _, err := RunProof(context.Background(), fake.options); err != nil {
			t.Fatalf("RunProof() error = %v", err)
		}
	})
	t.Run("uses configured paths in identity and permission ARNs", func(t *testing.T) {
		fake := newFakeBoundary()
		if _, err := RunProof(context.Background(), fake.options); err != nil {
			t.Fatalf("RunProof() error = %v", err)
		}
		if !strings.Contains(fake.createdPrincipal.ARN, fake.createdPrincipal.Path) || !strings.Contains(fake.createdRole.ARN, fake.createdRole.Path) || !strings.Contains(fake.createdRole.PermissionPolicy, fake.createdRole.ARN) {
			t.Fatal("configured IAM path is absent from a generated ARN or permission resource")
		}
	})
	t.Run("trust delegates every requested STS action", func(t *testing.T) {
		_, role := expectedSpecs(testOptions(newFakeBoundary()))
		for _, action := range []string{"sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"} {
			if !strings.Contains(role.TrustPolicy, action) {
				t.Fatalf("trust policy does not delegate %q", action)
			}
		}
	})
	t.Run("accepts only canonical STS assumed identity", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.returnSTSIdentity = true
		if _, err := RunProof(context.Background(), fake.options); err != nil {
			t.Fatalf("RunProof() error = %v", err)
		}
	})
	t.Run("rejects malformed caller identity ARN", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.source.ARN = "not-an-arn"
		if _, err := RunProof(context.Background(), fake.options); !errors.Is(err, errOwnership) {
			t.Fatalf("RunProof() error = %v, want ownership error", err)
		}
	})
	t.Run("reconciles invalid successful create responses and cleans", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.invalidPrincipalSuccess = true
		fake.invalidRoleSuccess = true
		if _, err := RunProof(context.Background(), fake.options); err != nil {
			t.Fatalf("RunProof() error = %v", err)
		}
		if fake.principal != nil || fake.role != nil {
			t.Fatal("resource remains after an invalid successful create response")
		}
	})
	t.Run("reconciles panic after apply and proves absence", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.panicAfterRole = true
		if _, err := RunProof(context.Background(), fake.options); !errors.Is(err, errProvider) {
			t.Fatalf("RunProof() error = %v, want provider error", err)
		}
		if fake.principal != nil || fake.role != nil {
			t.Fatal("resource remains after create panic")
		}
	})
	t.Run("continues cleanup after cleanup panic", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.panicCleanup = true
		fake.cleanupContinuation = true
		if _, err := RunProof(context.Background(), fake.options); !errors.Is(err, errCleanup) {
			t.Fatalf("RunProof() error = %v, want cleanup error", err)
		}
		if !fake.continuedCleanup || fake.principal != nil || fake.role != nil {
			t.Fatal("cleanup panic prevented independent cleanup continuation")
		}
	})
}

func TestRunProof_ReviewRound2Fixes(t *testing.T) {
	t.Run("uses STS assumed-role ARN without IAM path", func(t *testing.T) {
		fake := newFakeBoundary()
		if _, err := RunProof(context.Background(), fake.options); err != nil {
			t.Fatalf("RunProof() error = %v", err)
		}
	})
	t.Run("accepts root caller ARNs in the expected namespaces", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.source.ARN = "arn:aws:iam::000000000041:root"
		fake.target.ARN = "arn:aws:iam::000000000042:root"
		if _, err := RunProof(context.Background(), fake.options); err != nil {
			t.Fatalf("RunProof() error = %v", err)
		}
	})
	t.Run("rejects invalid caller ARN partition service and resource combinations", func(t *testing.T) {
		for _, arn := range []string{
			"arn:aws-cn:iam::000000000041:root",
			"arn:aws:s3::000000000041:root",
			"arn:aws:sts::000000000041:root",
			"arn:aws:iam::000000000041:assumed-role/name/session",
			"arn:aws:sts::000000000041:user/name",
		} {
			if validCallerARN(arn, "000000000041") {
				t.Fatalf("validCallerARN(%q) accepted an invalid caller identity", arn)
			}
		}
	})
	t.Run("does not adopt resources when preflight panics", func(t *testing.T) {
		fake := newFakeBoundary()
		principal, role := expectedSpecs(fake.options)
		fake.principal = &PrincipalState{PrincipalSpec: principal, UserID: "existing-principal"}
		role.RoleID = "existing-role"
		fake.role = &role
		fake.preexistingPrincipal = true
		fake.preexistingRole = true
		fake.panicSource = true
		if _, err := RunProof(context.Background(), fake.options); !errors.Is(err, errProvider) {
			t.Fatalf("RunProof() error = %v, want provider error", err)
		}
		if fake.principal == nil || fake.role == nil {
			t.Fatal("preflight panic allowed cleanup to delete an unattempted resource")
		}
	})
	t.Run("cleans invalid and panic-applied access keys", func(t *testing.T) {
		for _, test := range []struct {
			name string
			set  func(*fakeBoundary)
		}{
			{"invalid success", func(f *fakeBoundary) { f.invalidAccessKeySuccess = true }},
			{"panic after apply", func(f *fakeBoundary) { f.panicAfterAccessKey = true }},
		} {
			t.Run(test.name, func(t *testing.T) {
				fake := newFakeBoundary()
				test.set(fake)
				if _, err := RunProof(context.Background(), fake.options); !errors.Is(err, errProvider) {
					t.Fatalf("RunProof() error = %v, want provider error", err)
				}
				if fake.accessKeyPresent {
					t.Fatal("access key remains after uncertain creation")
				}
			})
		}
	})
	t.Run("does not delete an unproven role policy", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.cleanupPolicyMismatch = true
		if _, err := RunProof(context.Background(), fake.options); !errors.Is(err, errCleanup) {
			t.Fatalf("RunProof() error = %v, want cleanup error", err)
		}
		if fake.deletedRolePolicy {
			t.Fatal("cleanup deleted a policy after ownership proof failed")
		}
	})
}

func testOptions(boundary *fakeBoundary) ProofOptions {
	return ProofOptions{
		Marker: marker, Endpoint: "http://127.0.0.1:4566",
		SourceAccountID: "000000000041", TargetAccountID: "000000000042",
		Boundary: boundary, CleanupTimeout: time.Second, PollInterval: time.Millisecond,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
}

type fakeBoundary struct {
	mu                                                                                                sync.Mutex
	events                                                                                            []string
	options                                                                                           ProofOptions
	source, target                                                                                    CallerIdentity
	principal                                                                                         *PrincipalState
	role                                                                                              *RoleState
	createdPrincipal                                                                                  PrincipalSpec
	createdRole                                                                                       RoleSpec
	policy                                                                                            string
	accessKeyID                                                                                       string
	accessKeyPresent                                                                                  bool
	principalCollision, roleCollision, replacePrincipal, replaceRole                                  bool
	wrongTrust, wrongPermission, wrongTags                                                            bool
	missingExternalID, wrongSessionName, wrongSourceIdentity, wrongSessionTag                         bool
	wrongAssumedRoleID, wrongAssumedCaller, foreignRead, implicitDeny, enforcementDisabled            bool
	ambiguousPrincipal, ambiguousRole                                                                 bool
	delayedRole                                                                                       int
	panicAfterRole, cancelMain, cleanupMismatch, cleanupFails, cleanupContinuation, auditRemains      bool
	requireAccessSecret, returnSTSIdentity, invalidPrincipalSuccess, invalidRoleSuccess, panicCleanup bool
	panicSource, preexistingPrincipal, preexistingRole                                                bool
	invalidAccessKeySuccess, panicAfterAccessKey, cleanupPolicyMismatch, deletedRolePolicy            bool
	deletedReplacement, continuedCleanup                                                              bool
	principalLists, roleLists, roleInspects, policyGets                                               int
}

func newFakeBoundary() *fakeBoundary {
	f := &fakeBoundary{
		source:            CallerIdentity{AccountID: "000000000041", ARN: "arn:aws:iam::000000000041:user/source", UserID: "source-id"},
		target:            CallerIdentity{AccountID: "000000000042", ARN: "arn:aws:iam::000000000042:user/target", UserID: "target-id"},
		returnSTSIdentity: true,
	}
	f.options = testOptions(f)
	return f
}

func (f *fakeBoundary) event(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, name)
}
func (f *fakeBoundary) eventsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}
func (f *fakeBoundary) SourceIdentity(context.Context) (CallerIdentity, error) {
	f.event("source-identity")
	if f.panicSource {
		panic("preflight")
	}
	return f.source, nil
}
func (f *fakeBoundary) TargetIdentity(context.Context) (CallerIdentity, error) {
	f.event("target-identity")
	return f.target, nil
}
func (f *fakeBoundary) ListPrincipals(_ context.Context, _ string) ([]PrincipalState, error) {
	f.principalLists++
	if f.principalLists == 1 {
		f.event("list-principals")
		if f.preexistingPrincipal && f.principal != nil {
			return []PrincipalState{*f.principal}, nil
		}
		if f.principalCollision {
			return []PrincipalState{{}}, nil
		}
		return nil, nil
	}
	f.event("audit-principals")
	if f.principal != nil {
		return []PrincipalState{*f.principal}, nil
	}
	if f.auditRemains {
		return []PrincipalState{{}}, nil
	}
	return nil, nil
}
func (f *fakeBoundary) CreatePrincipal(_ context.Context, spec PrincipalSpec) (PrincipalState, error) {
	f.event("create-principal")
	f.createdPrincipal = spec
	state := PrincipalState{PrincipalSpec: spec, UserID: "principal-id"}
	f.principal = &state
	if f.invalidPrincipalSuccess {
		return PrincipalState{}, nil
	}
	if f.ambiguousPrincipal {
		return PrincipalState{}, ambiguousMutationError{cause: errors.New("uncertain")}
	}
	return state, nil
}
func (f *fakeBoundary) InspectPrincipal(_ context.Context, _ string) (PrincipalState, error) {
	if f.principal == nil {
		return PrincipalState{}, errors.New("absent")
	}
	if f.policyGets <= 1 {
		f.event("inspect-principal")
	} else {
		f.event("cleanup-inspect-principal")
	}
	state := *f.principal
	if f.replacePrincipal {
		state.UserID = "replacement-id"
	}
	if f.wrongTags {
		state.Tags = map[string]string{"proof": "wrong"}
	}
	if f.cleanupMismatch && f.principalLists > 1 {
		state.UserID = "replacement-id"
	}
	return state, nil
}
func (f *fakeBoundary) CreateAccessKey(context.Context, string) (string, string, error) {
	f.event("create-access-key")
	f.accessKeyID = "key"
	f.accessKeyPresent = true
	if f.panicAfterAccessKey {
		panic("access-key")
	}
	if f.invalidAccessKeySuccess {
		return f.accessKeyID, "", nil
	}
	return "key", "secret", nil
}
func (f *fakeBoundary) ListAccessKeys(context.Context, string) ([]string, error) {
	if !f.accessKeyPresent {
		return nil, nil
	}
	return []string{f.accessKeyID}, nil
}
func (f *fakeBoundary) DeleteAccessKey(context.Context, string, string) error {
	f.event("delete-access-key")
	f.continuedCleanup = f.cleanupContinuation
	if f.panicCleanup {
		panic("cleanup")
	}
	if f.cleanupFails {
		return errors.New("cleanup")
	}
	f.accessKeyPresent = false
	return nil
}
func (f *fakeBoundary) DeletePrincipal(context.Context, string) error {
	f.event("delete-principal")
	f.continuedCleanup = f.cleanupContinuation
	f.principal = nil
	return nil
}
func (f *fakeBoundary) ListRoles(_ context.Context, _ string) ([]RoleState, error) {
	f.roleLists++
	if f.roleLists == 1 {
		f.event("list-roles")
		if f.preexistingRole && f.role != nil {
			return []RoleState{*f.role}, nil
		}
		if f.roleCollision {
			return []RoleState{{}}, nil
		}
		return nil, nil
	}
	if f.role == nil {
		f.event("audit-roles")
		if f.auditRemains {
			return []RoleState{{}}, nil
		}
		return nil, nil
	}
	if f.delayedRole > 0 {
		f.delayedRole--
		return nil, errors.New("not ready")
	}
	return []RoleState{*f.role}, nil
}
func (f *fakeBoundary) CreateRole(_ context.Context, spec RoleSpec) (RoleState, error) {
	f.event("create-role")
	f.createdRole = spec
	state := RoleState(spec)
	state.RoleID = "role-id"
	f.role = &state
	if f.panicAfterRole {
		panic("after apply")
	}
	if f.invalidRoleSuccess {
		return RoleState{}, nil
	}
	if f.ambiguousRole {
		return RoleState{}, ambiguousMutationError{cause: errors.New("uncertain")}
	}
	return state, nil
}
func (f *fakeBoundary) InspectRole(_ context.Context, _ string) (RoleState, error) {
	if f.role == nil {
		return RoleState{}, errors.New("absent")
	}
	f.roleInspects++
	if f.roleInspects == 1 {
		f.event("inspect-role")
	} else {
		f.event("cleanup-inspect-role")
	}
	state := *f.role
	if f.replaceRole {
		state.RoleID = "replacement-role-id"
	}
	if f.replaceRole && f.ambiguousRole {
		state.Tags = map[string]string{"proof": "replacement"}
	}
	if f.wrongTrust {
		state.TrustPolicy = "{}"
	}
	if f.wrongPermission {
		state.PermissionPolicy = "{}"
	}
	if f.wrongTags {
		state.Tags = map[string]string{"proof": "wrong"}
	}
	if f.cleanupMismatch && f.roleInspects > 1 {
		state.RoleID = "replacement-role-id"
	}
	return state, nil
}
func (f *fakeBoundary) PutRolePolicy(_ context.Context, _ string, _ string, policy string) error {
	f.event("put-role-policy")
	f.policy = policy
	return nil
}
func (f *fakeBoundary) GetRolePolicy(context.Context, string, string) (string, error) {
	f.policyGets++
	if f.policyGets == 1 {
		f.event("get-role-policy")
	} else {
		f.event("cleanup-get-role-policy")
	}
	if f.wrongPermission {
		return "{}", nil
	}
	if f.cleanupPolicyMismatch && f.policyGets > 1 {
		return "{}", nil
	}
	return f.policy, nil
}
func (f *fakeBoundary) AssumeRole(_ context.Context, request AssumeRequest, keyID, secret string) (AssumedSession, error) {
	f.event("assume-role")
	if f.requireAccessSecret && (keyID != "key" || secret != "secret") {
		return AssumedSession{}, errors.New("temporary access key not supplied")
	}
	if f.missingExternalID && request.ExternalID != "" {
		return AssumedSession{}, errors.New("missing external id")
	}
	if f.wrongSessionName && request.SessionName != "wrong" {
		return AssumedSession{}, errors.New("wrong session")
	}
	if f.wrongSourceIdentity && request.SourceIdentity != "wrong" {
		return AssumedSession{}, errors.New("wrong source")
	}
	if f.wrongSessionTag && request.Tags["proof"] != "wrong" {
		return AssumedSession{}, errors.New("wrong tag")
	}
	if f.role == nil {
		return AssumedSession{}, errors.New("absent")
	}
	roleID := f.role.RoleID
	if f.wrongAssumedRoleID {
		roleID = "wrong-role-id"
	}
	roleARN := f.role.ARN
	if f.returnSTSIdentity {
		roleID += ":" + request.SessionName
		roleARN = "arn:aws:sts::000000000042:assumed-role/" + f.role.Name + "/" + request.SessionName
	}
	return AssumedSession{AccessKeyID: "key", SecretAccessKey: "secret", SessionToken: "token", AssumedRoleARN: roleARN, AssumedRoleID: roleID, SourceIdentity: request.SourceIdentity, Expiration: time.Now().Add(time.Hour)}, nil
}
func (f *fakeBoundary) AssumedIdentity(_ context.Context, session AssumedSession) (CallerIdentity, error) {
	f.event("assumed-identity")
	id := session.AssumedRoleID
	if f.wrongAssumedCaller {
		id = "wrong-user-id"
	}
	return CallerIdentity{AccountID: "000000000042", ARN: session.AssumedRoleARN, UserID: id}, nil
}
func (f *fakeBoundary) AllowedGetRole(context.Context, AssumedSession, string) (RoleState, error) {
	f.event("allowed-get-role")
	if f.foreignRead {
		return RoleState{RoleID: "foreign"}, nil
	}
	if f.role == nil {
		return RoleState{}, errors.New("absent")
	}
	return *f.role, nil
}
func (f *fakeBoundary) DeniedListRoles(context.Context, AssumedSession) error {
	f.event("denied-list-roles")
	if f.enforcementDisabled {
		return nil
	}
	if f.implicitDeny {
		return errors.New("implicit")
	}
	return explicitDenyError{}
}
func (f *fakeBoundary) DeleteRolePolicy(context.Context, string, string) error {
	f.event("delete-role-policy")
	f.deletedRolePolicy = true
	return nil
}
func (f *fakeBoundary) DeleteRole(context.Context, string) error {
	f.event("delete-role")
	if f.replaceRole || f.cleanupMismatch {
		f.deletedReplacement = true
		return nil
	}
	f.role = nil
	return nil
}

func (f *fakeBoundary) String() string { return fmt.Sprintf("events=%d", len(f.events)) }

func sortedTags(tags map[string]string) []string {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
