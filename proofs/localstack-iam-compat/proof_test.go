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
		{"panic after apply", func(f *fakeBoundary) { f.panicAfterRole = true }, errCleanup},
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

func testOptions(boundary *fakeBoundary) ProofOptions {
	return ProofOptions{
		Marker: marker, Endpoint: "http://127.0.0.1:4566",
		SourceAccountID: "000000000041", TargetAccountID: "000000000042",
		Boundary: boundary, CleanupTimeout: time.Second, PollInterval: time.Millisecond,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
}

type fakeBoundary struct {
	mu                                                                                           sync.Mutex
	events                                                                                       []string
	options                                                                                      ProofOptions
	source, target                                                                               CallerIdentity
	principal                                                                                    *PrincipalState
	role                                                                                         *RoleState
	policy                                                                                       string
	principalCollision, roleCollision, replacePrincipal, replaceRole                             bool
	wrongTrust, wrongPermission, wrongTags                                                       bool
	missingExternalID, wrongSessionName, wrongSourceIdentity, wrongSessionTag                    bool
	wrongAssumedRoleID, wrongAssumedCaller, foreignRead, implicitDeny, enforcementDisabled       bool
	ambiguousPrincipal, ambiguousRole                                                            bool
	delayedRole                                                                                  int
	panicAfterRole, cancelMain, cleanupMismatch, cleanupFails, cleanupContinuation, auditRemains bool
	deletedReplacement, continuedCleanup                                                         bool
	principalLists, roleLists, roleInspects, policyGets                                          int
}

func newFakeBoundary() *fakeBoundary {
	f := &fakeBoundary{
		source: CallerIdentity{AccountID: "000000000041", ARN: "source", UserID: "source-id"},
		target: CallerIdentity{AccountID: "000000000042", ARN: "target", UserID: "target-id"},
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
	state := PrincipalState{PrincipalSpec: spec, UserID: "principal-id"}
	f.principal = &state
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
	return "key", "secret", nil
}
func (f *fakeBoundary) DeleteAccessKey(context.Context, string, string) error {
	f.event("delete-access-key")
	f.continuedCleanup = f.cleanupContinuation
	if f.cleanupFails {
		return errors.New("cleanup")
	}
	return nil
}
func (f *fakeBoundary) DeletePrincipal(context.Context, string) error {
	f.event("delete-principal")
	f.principal = nil
	return nil
}
func (f *fakeBoundary) ListRoles(_ context.Context, _ string) ([]RoleState, error) {
	f.roleLists++
	if f.roleLists == 1 {
		f.event("list-roles")
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
	state := RoleState(spec)
	state.RoleID = "role-id"
	f.role = &state
	if f.panicAfterRole {
		panic("after apply")
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
	return f.policy, nil
}
func (f *fakeBoundary) AssumeRole(_ context.Context, request AssumeRequest, _, _ string) (AssumedSession, error) {
	f.event("assume-role")
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
	return AssumedSession{AccessKeyID: "key", SecretAccessKey: "secret", SessionToken: "token", AssumedRoleARN: f.role.ARN, AssumedRoleID: roleID, SourceIdentity: request.SourceIdentity, Expiration: time.Now().Add(time.Hour)}, nil
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
