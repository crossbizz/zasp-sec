package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRunProofDesiredCrossAccountLifecycle(t *testing.T) {
	marker := "0123456789abcdef"
	boundary := newFakeIAMBoundary(marker)
	result, err := RunProof(context.Background(), ProofOptions{
		Marker: marker, Region: "us-west-2",
		SourceAccountID: "111111111111", TargetAccountID: "222222222222",
		SourcePrincipalARN: "arn:aws:iam::111111111111:role/zasp-proof-source",
		Boundary:           boundary, CleanupTimeout: time.Second, PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("RunProof returned error: %v", err)
	}
	want := ProofResult{CrossAccount: true, Assumed: true, AllowedRead: true, DeniedCall: true, Cleanup: true, Audit: true}
	if result != want {
		t.Fatalf("result = %#v, want %#v", result, want)
	}
	wantEvents := []string{
		"source-identity", "target-identity", "preflight-list", "create-role",
		"inspect-role", "put-policy", "get-policy", "assume-role",
		"assumed-identity", "allowed-get-role", "denied-list-roles",
		"cleanup-target-identity", "cleanup-prefix-list", "cleanup-inspect-role",
		"cleanup-list-policies", "cleanup-get-policy", "delete-policy",
		"policy-absence-list", "cleanup-predelete-inspect", "delete-role",
		"absence-list", "audit-list",
	}
	if !reflect.DeepEqual(boundary.events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", boundary.events, wantEvents)
	}
}

type fakeIAMBoundary struct {
	marker                                             string
	events                                             []string
	role                                               RoleState
	policy                                             string
	listCalls, inspectCalls, policyListCalls           int
	sourceIdentity, targetIdentity, assumedIdentity    CallerIdentity
	sourceErr, targetErr, createErr, putErr, assumeErr error
	assumedIdentityErr, allowedErr                     error
	deletePolicyErr, deleteRoleErr                     error
	createApplied, putApplied, preflightCollision      bool
	deniedSet                                          bool
	deniedErr                                          error
	panicAt                                            string
	panicAfterCreateApply                              bool
	cancelAfterCreate                                  context.CancelFunc
	honorCanceledContext                               bool
	roleVisibleAfterListCall                           int
	createMutation, allowedMutation                    func(RoleState) RoleState
	listMutation                                       map[int]func([]RoleSummary) []RoleSummary
	listWindowMutation                                 func(int, int, []RoleSummary) []RoleSummary
	inspectMutation                                    map[int]func(RoleState) RoleState
	inspectErrors, policyErrors, policyListErrors      map[int]error
	sessionMutation                                    func(AssumedSession) AssumedSession
	lastListContext                                    context.Context
	listWindow, listWindowCall                         int
}

func newFakeIAMBoundary(marker string) *fakeIAMBoundary {
	boundary := &fakeIAMBoundary{
		marker:          marker,
		sourceIdentity:  CallerIdentity{AccountID: "111111111111", ARN: "arn:aws:iam::111111111111:role/zasp-proof-source"},
		targetIdentity:  CallerIdentity{AccountID: "222222222222", ARN: "arn:aws:iam::222222222222:role/zasp-proof-admin"},
		assumedIdentity: CallerIdentity{AccountID: "222222222222", ARN: expectedAssumedARN("222222222222", marker)},
		inspectMutation: map[int]func(RoleState) RoleState{}, inspectErrors: map[int]error{},
		policyErrors: map[int]error{}, policyListErrors: map[int]error{}, listMutation: map[int]func([]RoleSummary) []RoleSummary{},
	}
	setOptionalStringField(&boundary.sourceIdentity, "UserID", "source-user-id")
	setOptionalStringField(&boundary.targetIdentity, "UserID", "target-user-id")
	setOptionalStringField(&boundary.assumedIdentity, "UserID", "role-id:"+expectedRoleName(marker))
	return boundary
}

func (f *fakeIAMBoundary) SourceIdentity(context.Context) (CallerIdentity, error) {
	f.maybePanic("source-identity")
	f.events = append(f.events, "source-identity")
	return f.sourceIdentity, f.sourceErr
}

func (f *fakeIAMBoundary) TargetIdentity(context.Context) (CallerIdentity, error) {
	f.maybePanic("target-identity")
	name := "target-identity"
	if f.role.Name != "" {
		name = "cleanup-target-identity"
	}
	f.events = append(f.events, name)
	return f.targetIdentity, f.targetErr
}

func (f *fakeIAMBoundary) ListRoles(ctx context.Context, prefix string) ([]RoleSummary, error) {
	f.maybePanic("list-roles")
	if f.lastListContext != ctx {
		f.lastListContext = ctx
		f.listWindow++
		f.listWindowCall = 0
	}
	f.listWindowCall++
	f.listCalls++
	name := map[int]string{1: "preflight-list", 2: "cleanup-prefix-list", 3: "absence-list", 4: "audit-list"}[f.listCalls]
	f.events = append(f.events, name)
	if f.listCalls == 1 && f.preflightCollision {
		return []RoleSummary{{Name: "foreign", ARN: "foreign", Path: prefix, RoleID: "foreign"}}, nil
	}
	var roles []RoleSummary
	if f.role.Name != "" && (f.roleVisibleAfterListCall == 0 || f.listCalls >= f.roleVisibleAfterListCall) {
		roles = []RoleSummary{{Name: f.role.Name, ARN: f.role.ARN, Path: f.role.Path, RoleID: f.role.RoleID}}
	}
	if mutate := f.listMutation[f.listCalls]; mutate != nil {
		roles = mutate(roles)
	}
	if f.listWindowMutation != nil {
		roles = f.listWindowMutation(f.listWindow, f.listWindowCall, roles)
	}
	if f.honorCanceledContext && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return roles, nil
}

func (f *fakeIAMBoundary) CreateRole(_ context.Context, spec RoleSpec) (RoleState, error) {
	f.maybePanic("create-role")
	f.events = append(f.events, "create-role")
	state := roleStateFromSpec(spec, "role-id")
	if f.createMutation != nil {
		state = f.createMutation(state)
	}
	if f.createErr == nil || f.createApplied {
		f.role = roleStateFromSpec(spec, "role-id")
	}
	if f.cancelAfterCreate != nil {
		f.cancelAfterCreate()
	}
	if f.panicAfterCreateApply {
		panic("provider panic")
	}
	return state, f.createErr
}

func (f *fakeIAMBoundary) InspectRole(_ context.Context, name string) (RoleState, error) {
	f.maybePanic("inspect-role")
	f.inspectCalls++
	event := map[int]string{1: "inspect-role", 2: "cleanup-inspect-role", 3: "cleanup-predelete-inspect"}[f.inspectCalls]
	f.events = append(f.events, event)
	state := f.role
	if mutate := f.inspectMutation[f.inspectCalls]; mutate != nil {
		state = mutate(state)
	}
	return state, f.inspectErrors[f.inspectCalls]
}

func (f *fakeIAMBoundary) PutRolePolicy(_ context.Context, roleName, policyName, document string) error {
	f.maybePanic("put-policy")
	f.events = append(f.events, "put-policy")
	if f.putErr == nil || f.putApplied {
		f.policy = document
	}
	return f.putErr
}

func (f *fakeIAMBoundary) GetRolePolicy(_ context.Context, roleName, policyName string) (string, error) {
	f.maybePanic("get-policy")
	event := "get-policy"
	if len(f.events) > 0 && f.events[len(f.events)-1] == "cleanup-list-policies" {
		event = "cleanup-get-policy"
	}
	f.events = append(f.events, event)
	return f.policy, f.policyErrors[len(filterEvents(f.events, "get-policy", "cleanup-get-policy"))]
}

func (f *fakeIAMBoundary) ListRolePolicies(context.Context, string) ([]string, error) {
	f.maybePanic("list-role-policies")
	f.policyListCalls++
	event := map[int]string{1: "cleanup-list-policies", 2: "policy-absence-list"}[f.policyListCalls]
	f.events = append(f.events, event)
	if err := f.policyListErrors[f.policyListCalls]; err != nil {
		return nil, err
	}
	if f.policy == "" {
		return nil, nil
	}
	return []string{expectedPolicyName(f.marker)}, nil
}

func (f *fakeIAMBoundary) AssumeRole(_ context.Context, request AssumeRoleRequest) (AssumedSession, error) {
	f.maybePanic("assume-role")
	f.events = append(f.events, "assume-role")
	session := assumedSessionForRequest(request)
	setOptionalStringField(&session, "AssumedRoleID", f.role.RoleID+":"+request.SessionName)
	if f.sessionMutation != nil {
		session = f.sessionMutation(session)
	}
	return session, f.assumeErr
}

func (f *fakeIAMBoundary) AssumedIdentity(context.Context, AssumedSession) (CallerIdentity, error) {
	f.maybePanic("assumed-identity")
	f.events = append(f.events, "assumed-identity")
	return f.assumedIdentity, f.assumedIdentityErr
}

func (f *fakeIAMBoundary) AllowedGetRole(context.Context, AssumedSession, string) (RoleState, error) {
	f.maybePanic("allowed-get-role")
	f.events = append(f.events, "allowed-get-role")
	state := copyRoleSpec(f.role)
	if f.allowedMutation != nil {
		state = f.allowedMutation(state)
	}
	return state, f.allowedErr
}

func (f *fakeIAMBoundary) DeniedListRoles(context.Context, AssumedSession, string) error {
	f.maybePanic("denied-list-roles")
	f.events = append(f.events, "denied-list-roles")
	if f.deniedSet {
		return f.deniedErr
	}
	return AuthorizationDeniedError{StatusCode: 403, Code: "AccessDenied"}
}

func (f *fakeIAMBoundary) DeleteRolePolicy(context.Context, string, string) error {
	f.maybePanic("delete-policy")
	f.events = append(f.events, "delete-policy")
	if f.deletePolicyErr == nil || isAmbiguousMutation(f.deletePolicyErr) {
		f.policy = ""
	}
	return f.deletePolicyErr
}

func (f *fakeIAMBoundary) DeleteRole(context.Context, string) error {
	f.maybePanic("delete-role")
	f.events = append(f.events, "delete-role")
	if f.deleteRoleErr == nil || isAmbiguousMutation(f.deleteRoleErr) {
		f.role = RoleState{}
	}
	return f.deleteRoleErr
}

func (f *fakeIAMBoundary) maybePanic(operation string) {
	if f.panicAt == operation {
		panic("provider panic")
	}
}

func filterEvents(events []string, wanted ...string) []string {
	allowed := map[string]bool{}
	for _, value := range wanted {
		allowed[value] = true
	}
	var result []string
	for _, event := range events {
		if allowed[event] {
			result = append(result, event)
		}
	}
	return result
}

func setOptionalStringField(target any, name, value string) {
	field := reflect.ValueOf(target).Elem().FieldByName(name)
	if field.IsValid() && field.CanSet() && field.Kind() == reflect.String {
		field.SetString(value)
	}
}

func optionalStringField(value any, name string) string {
	field := reflect.ValueOf(value).FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.String {
		return ""
	}
	return field.String()
}

func validOptions(marker string, boundary IAMProofBoundary) ProofOptions {
	return ProofOptions{
		Marker: marker, Region: "us-west-2", SourceAccountID: "111111111111", TargetAccountID: "222222222222",
		SourcePrincipalARN: "arn:aws:iam::111111111111:role/zasp-proof-source", Boundary: boundary,
		CleanupTimeout: 20 * time.Millisecond, PollInterval: time.Millisecond,
	}
}

func TestRunProofRejectsCapabilityAndOwnershipFailuresBeforeMutation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*fakeIAMBoundary, *ProofOptions)
		want error
	}{
		{name: "same configured account", edit: func(_ *fakeIAMBoundary, o *ProofOptions) { o.TargetAccountID = o.SourceAccountID }, want: errConfiguration},
		{name: "source principal account mismatch", edit: func(_ *fakeIAMBoundary, o *ProofOptions) {
			o.SourcePrincipalARN = "arn:aws:iam::333333333333:role/zasp-proof-source"
		}, want: errConfiguration},
		{name: "source role path unsupported", edit: func(_ *fakeIAMBoundary, o *ProofOptions) {
			o.SourcePrincipalARN = "arn:aws:iam::111111111111:role/path/zasp-proof-source"
		}, want: errConfiguration},
		{name: "source authentication", edit: func(f *fakeIAMBoundary, _ *ProofOptions) { f.sourceErr = errors.New("rejected") }, want: errAuthentication},
		{name: "target authentication", edit: func(f *fakeIAMBoundary, _ *ProofOptions) { f.targetIdentity.AccountID = "333333333333" }, want: errAuthentication},
		{name: "actual accounts equal", edit: func(f *fakeIAMBoundary, _ *ProofOptions) {
			f.targetIdentity = CallerIdentity{AccountID: "111111111111", ARN: "arn:aws:iam::111111111111:role/admin"}
		}, want: errAuthentication},
		{name: "generated path collision", edit: func(f *fakeIAMBoundary, _ *ProofOptions) { f.preflightCollision = true }, want: errOwnership},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			marker := "0123456789abcdef"
			boundary := newFakeIAMBoundary(marker)
			options := validOptions(marker, boundary)
			test.edit(boundary, &options)
			_, err := RunProof(context.Background(), options)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			for _, event := range boundary.events {
				if event == "create-role" {
					t.Fatal("resource mutation occurred before capability/ownership gate")
				}
			}
		})
	}
}

func TestRunProofReconcilesOnlyExactAmbiguousRoleAndPolicyMutations(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*fakeIAMBoundary)
		want error
	}{
		{name: "ambiguous role applied exact", edit: func(f *fakeIAMBoundary) { f.createErr = ambiguousMutation(errProvider); f.createApplied = true }},
		{name: "invalid role response applied exact", edit: func(f *fakeIAMBoundary) { f.createMutation = func(s RoleState) RoleState { s.RoleID = ""; return s } }},
		{name: "ambiguous policy applied exact", edit: func(f *fakeIAMBoundary) { f.putErr = ambiguousMutation(errProvider); f.putApplied = true }},
		{name: "definitive role rejection", edit: func(f *fakeIAMBoundary) { f.createErr = errors.New("rejected") }, want: errProvider},
		{name: "ambiguous role unapplied", edit: func(f *fakeIAMBoundary) { f.createErr = ambiguousMutation(errProvider) }, want: errProvider},
		{name: "definitive policy rejection", edit: func(f *fakeIAMBoundary) { f.putErr = errors.New("rejected") }, want: errProvider},
		{name: "ambiguous policy unapplied", edit: func(f *fakeIAMBoundary) { f.putErr = ambiguousMutation(errProvider) }, want: errProvider},
	} {
		t.Run(test.name, func(t *testing.T) {
			marker := "0123456789abcdef"
			boundary := newFakeIAMBoundary(marker)
			test.edit(boundary)
			result, err := RunProof(context.Background(), validOptions(marker, boundary))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if test.want == nil && (!result.Cleanup || !result.Audit) {
				t.Fatalf("successful reconciliation did not clean and audit: %#v", result)
			}
			if boundary.role.Name != "" || boundary.policy != "" {
				t.Fatal("owned resource remained after reconciliation case")
			}
		})
	}
}

func TestRunProofBindsEveryRoleProofAndCleanupStepToImmutableRoleID(t *testing.T) {
	marker := "0123456789abcdef"
	replace := func(state RoleState) RoleState { state.RoleID = "replacement-role-id"; return state }
	replaceSummary := func(roles []RoleSummary) []RoleSummary {
		if len(roles) == 1 {
			roles[0].RoleID = "replacement-role-id"
		}
		return roles
	}
	tests := []struct {
		name       string
		edit       func(*fakeIAMBoundary)
		want       error
		wantDelete bool
	}{
		{name: "replacement before initial inspection", edit: func(f *fakeIAMBoundary) { f.inspectMutation[1] = replace }, want: errOwnership, wantDelete: true},
		{name: "replacement returned by allowed read", edit: func(f *fakeIAMBoundary) { f.allowedMutation = replace }, want: errOwnership, wantDelete: true},
		{name: "same name role deleted and recreated before allowed read", edit: func(f *fakeIAMBoundary) {
			f.allowedMutation = func(RoleState) RoleState {
				f.role.RoleID = "replacement-role-id"
				return f.role
			}
		}, want: errCleanup},
		{name: "replacement in cleanup prefix list", edit: func(f *fakeIAMBoundary) { f.listMutation[2] = replaceSummary }, want: errCleanup},
		{name: "replacement in cleanup inspection", edit: func(f *fakeIAMBoundary) { f.inspectMutation[2] = replace }, want: errCleanup},
		{name: "replacement immediately before delete", edit: func(f *fakeIAMBoundary) { f.inspectMutation[3] = replace }, want: errCleanup},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			boundary := newFakeIAMBoundary(marker)
			test.edit(boundary)
			_, err := RunProof(context.Background(), validOptions(marker, boundary))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if got := contains(boundary.events, "delete-role"); got != test.wantDelete {
				t.Fatalf("delete-role = %t, want %t; events=%#v", got, test.wantDelete, boundary.events)
			}
		})
	}
}

func TestRunProofRecoversAmbiguousRoleCreationUnderIndependentCleanupContext(t *testing.T) {
	marker := "0123456789abcdef"
	t.Run("delayed provider visibility is polled before authority is armed", func(t *testing.T) {
		boundary := newFakeIAMBoundary(marker)
		boundary.createErr, boundary.createApplied = ambiguousMutation(errProvider), true
		boundary.roleVisibleAfterListCall = 4
		result, err := RunProof(context.Background(), validOptions(marker, boundary))
		if err != nil || !result.Cleanup || !result.Audit || boundary.role.Name != "" || boundary.listCalls < 4 {
			t.Fatalf("delayed reconciliation = (%#v, %v, list-calls=%d)", result, err, boundary.listCalls)
		}
	})
	t.Run("canceled request context cannot cancel ownership reconciliation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		boundary := newFakeIAMBoundary(marker)
		boundary.createErr, boundary.createApplied = ambiguousMutation(errProvider), true
		boundary.cancelAfterCreate, boundary.honorCanceledContext = cancel, true
		result, err := RunProof(ctx, validOptions(marker, boundary))
		if err != nil || !result.Cleanup || !result.Audit || boundary.role.Name != "" {
			t.Fatalf("canceled-context reconciliation = (%#v, %v)", result, err)
		}
	})
	t.Run("panic after applied create is reconciled and cleaned", func(t *testing.T) {
		boundary := newFakeIAMBoundary(marker)
		boundary.panicAfterCreateApply = true
		result, err := RunProof(context.Background(), validOptions(marker, boundary))
		if !errors.Is(err, errProvider) || !result.Cleanup || !result.Audit || boundary.role.Name != "" || !contains(boundary.events, "delete-role") {
			t.Fatalf("panic recovery = (%#v, %v, %#v)", result, err, boundary.events)
		}
	})
	t.Run("panic before create is applied confirms absence without deletion", func(t *testing.T) {
		boundary := newFakeIAMBoundary(marker)
		boundary.panicAt = "create-role"
		_, err := RunProof(context.Background(), validOptions(marker, boundary))
		if !errors.Is(err, errProvider) || boundary.listCalls < 3 || contains(boundary.events, "delete-role") || boundary.role.Name != "" {
			t.Fatalf("pre-apply panic = (%v, list-calls=%d, %#v)", err, boundary.listCalls, boundary.events)
		}
	})
	t.Run("ambiguous absence is confirmed by repeated reads without deletion", func(t *testing.T) {
		boundary := newFakeIAMBoundary(marker)
		boundary.createErr = ambiguousMutation(errProvider)
		_, err := RunProof(context.Background(), validOptions(marker, boundary))
		if !errors.Is(err, errProvider) || boundary.listCalls < 3 || contains(boundary.events, "delete-role") || boundary.role.Name != "" {
			t.Fatalf("absence reconciliation = (%v, list-calls=%d, %#v)", err, boundary.listCalls, boundary.events)
		}
	})
	t.Run("mismatched provider state is never adopted or deleted", func(t *testing.T) {
		boundary := newFakeIAMBoundary(marker)
		boundary.createErr, boundary.createApplied = ambiguousMutation(errProvider), true
		boundary.inspectMutation[1] = func(state RoleState) RoleState { state.Tags[markerTagKey] = "foreign"; return state }
		_, err := RunProof(context.Background(), validOptions(marker, boundary))
		if !errors.Is(err, errProvider) || contains(boundary.events, "delete-role") || boundary.role.Name == "" {
			t.Fatalf("mismatch reconciliation = (%v, %#v)", err, boundary.events)
		}
	})
	t.Run("visible but uninspectable role cannot inherit an earlier absence", func(t *testing.T) {
		boundary := newFakeIAMBoundary(marker)
		boundary.createErr, boundary.createApplied = ambiguousMutation(errProvider), true
		boundary.roleVisibleAfterListCall = 3
		for call := 1; call <= 100; call++ {
			boundary.inspectErrors[call] = errors.New("unavailable")
		}
		_, err := RunProof(context.Background(), validOptions(marker, boundary))
		if !errors.Is(err, errCleanup) || contains(boundary.events, "delete-role") || boundary.role.Name == "" {
			t.Fatalf("unresolved visible role = (%v, %#v)", err, boundary.events)
		}
	})
	t.Run("cleanup failure overrides panic after applied create", func(t *testing.T) {
		boundary := newFakeIAMBoundary(marker)
		boundary.panicAfterCreateApply = true
		boundary.deleteRoleErr = errors.New("rejected")
		_, err := RunProof(context.Background(), validOptions(marker, boundary))
		if !errors.Is(err, errCleanup) || !contains(boundary.events, "delete-role") || !contains(boundary.events, "audit-list") {
			t.Fatalf("cleanup precedence = (%v, %#v)", err, boundary.events)
		}
	})
}

func TestRunProofRejectsInvalidSessionAllowedReadAndDeniedCategoryWithCleanup(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*fakeIAMBoundary)
		want error
	}{
		{name: "assume rejected", edit: func(f *fakeIAMBoundary) { f.assumeErr = errors.New("rejected") }, want: errAuthentication},
		{name: "session credentials incomplete", edit: func(f *fakeIAMBoundary) {
			f.sessionMutation = func(s AssumedSession) AssumedSession { s.Credentials.SessionToken = ""; return s }
		}, want: errAuthentication},
		{name: "session source identity mismatch", edit: func(f *fakeIAMBoundary) {
			f.sessionMutation = func(s AssumedSession) AssumedSession { s.SourceIdentity = "wrong"; return s }
		}, want: errAuthentication},
		{name: "assumed target identity mismatch", edit: func(f *fakeIAMBoundary) { f.assumedIdentity.AccountID = "333333333333" }, want: errAuthentication},
		{name: "allowed read rejected", edit: func(f *fakeIAMBoundary) { f.allowedErr = errors.New("denied") }, want: errAuthorization},
		{name: "allowed read foreign", edit: func(f *fakeIAMBoundary) {
			f.allowedMutation = func(s RoleState) RoleState { s.Tags[markerTagKey] = "foreign"; return s }
		}, want: errOwnership},
		{name: "denied call succeeded", edit: func(f *fakeIAMBoundary) { f.deniedSet = true }, want: errAuthorization},
		{name: "wrong denial status", edit: func(f *fakeIAMBoundary) {
			f.deniedSet = true
			f.deniedErr = AuthorizationDeniedError{StatusCode: 400, Code: "AccessDenied"}
		}, want: errAuthorization},
		{name: "implicit or other denial code", edit: func(f *fakeIAMBoundary) {
			f.deniedSet = true
			f.deniedErr = AuthorizationDeniedError{StatusCode: 403, Code: "UnauthorizedOperation"}
		}, want: errAuthorization},
	} {
		t.Run(test.name, func(t *testing.T) {
			marker := "0123456789abcdef"
			boundary := newFakeIAMBoundary(marker)
			test.edit(boundary)
			result, err := RunProof(context.Background(), validOptions(marker, boundary))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if !result.Cleanup || !result.Audit || boundary.role.Name != "" {
				t.Fatalf("post-create failure did not clean exact fixture: %#v", result)
			}
		})
	}
}

func TestRunProofRequiresCapturedImmutableRoleIDAtAssumeAndIdentityBoundaries(t *testing.T) {
	marker := "0123456789abcdef"
	sessionName := expectedRoleName(marker)
	tests := []struct {
		name string
		edit func(*fakeIAMBoundary)
	}{
		{name: "assume response missing role id", edit: func(f *fakeIAMBoundary) {
			f.sessionMutation = func(session AssumedSession) AssumedSession {
				setOptionalStringField(&session, "AssumedRoleID", "")
				return session
			}
		}},
		{name: "assume response same-name replacement role id", edit: func(f *fakeIAMBoundary) {
			f.sessionMutation = func(session AssumedSession) AssumedSession {
				setOptionalStringField(&session, "AssumedRoleID", "replacement-role-id:"+sessionName)
				return session
			}
		}},
		{name: "assume response wrong session suffix", edit: func(f *fakeIAMBoundary) {
			f.sessionMutation = func(session AssumedSession) AssumedSession {
				setOptionalStringField(&session, "AssumedRoleID", "role-id:wrong-session")
				return session
			}
		}},
		{name: "assume response malformed id", edit: func(f *fakeIAMBoundary) {
			f.sessionMutation = func(session AssumedSession) AssumedSession {
				setOptionalStringField(&session, "AssumedRoleID", "malformed")
				return session
			}
		}},
		{name: "assumed identity missing role id", edit: func(f *fakeIAMBoundary) { setOptionalStringField(&f.assumedIdentity, "UserID", "") }},
		{name: "assumed identity same-name replacement role id", edit: func(f *fakeIAMBoundary) {
			setOptionalStringField(&f.assumedIdentity, "UserID", "replacement-role-id:"+sessionName)
		}},
		{name: "assumed identity wrong session suffix", edit: func(f *fakeIAMBoundary) {
			setOptionalStringField(&f.assumedIdentity, "UserID", "role-id:wrong-session")
		}},
		{name: "assumed identity malformed id", edit: func(f *fakeIAMBoundary) { setOptionalStringField(&f.assumedIdentity, "UserID", "malformed") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			boundary := newFakeIAMBoundary(marker)
			test.edit(boundary)
			result, err := RunProof(context.Background(), validOptions(marker, boundary))
			if !errors.Is(err, errAuthentication) || !result.Cleanup || !result.Audit || boundary.role.Name != "" {
				t.Fatalf("immutable assumed identity = (%#v, %v)", result, err)
			}
		})
	}
}

func TestRunProofNeverDowngradesObservedCandidateToAbsence(t *testing.T) {
	marker := "0123456789abcdef"
	configure := func(boundary *fakeIAMBoundary) {
		boundary.createErr, boundary.createApplied = ambiguousMutation(errProvider), true
		boundary.inspectErrors[1] = errors.New("temporarily unavailable")
		boundary.listWindowMutation = func(window, call int, roles []RoleSummary) []RoleSummary {
			if window == 2 && call > 1 {
				return nil
			}
			return roles
		}
	}
	t.Run("later empty reads remain unresolved and deferred cleanup proves ownership", func(t *testing.T) {
		boundary := newFakeIAMBoundary(marker)
		configure(boundary)
		result, err := RunProof(context.Background(), validOptions(marker, boundary))
		if !errors.Is(err, errProvider) || !result.Cleanup || !result.Audit || boundary.role.Name != "" || !contains(boundary.events, "delete-role") {
			t.Fatalf("monotonic reconciliation = (%#v, %v, %#v)", result, err, boundary.events)
		}
	})
	t.Run("canceled original context cannot downgrade observed ownership", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		boundary := newFakeIAMBoundary(marker)
		configure(boundary)
		boundary.cancelAfterCreate, boundary.honorCanceledContext = cancel, true
		result, err := RunProof(ctx, validOptions(marker, boundary))
		if !errors.Is(err, errProvider) || !result.Cleanup || !result.Audit || boundary.role.Name != "" {
			t.Fatalf("canceled monotonic reconciliation = (%#v, %v)", result, err)
		}
	})
	t.Run("deferred cleanup failure overrides ambiguous operation failure", func(t *testing.T) {
		boundary := newFakeIAMBoundary(marker)
		configure(boundary)
		boundary.deleteRoleErr = errors.New("rejected")
		_, err := RunProof(context.Background(), validOptions(marker, boundary))
		if !errors.Is(err, errCleanup) || !contains(boundary.events, "delete-role") || !contains(boundary.events, "audit-list") {
			t.Fatalf("monotonic cleanup precedence = (%v, %#v)", err, boundary.events)
		}
	})
}

func TestRunProofCleanupReprovesOwnershipAndTakesPrecedence(t *testing.T) {
	marker := "0123456789abcdef"
	t.Run("ownership mutation refuses delete", func(t *testing.T) {
		boundary := newFakeIAMBoundary(marker)
		boundary.inspectMutation[2] = func(s RoleState) RoleState { s.Tags[markerTagKey] = "foreign"; return s }
		result, err := RunProof(context.Background(), validOptions(marker, boundary))
		if !errors.Is(err, errCleanup) || result.Cleanup || contains(boundary.events, "delete-role") {
			t.Fatalf("cleanup authorization = (%#v, %v, %#v)", result, err, boundary.events)
		}
	})
	t.Run("policy delete failure still attempts role and overrides proof", func(t *testing.T) {
		boundary := newFakeIAMBoundary(marker)
		boundary.deniedSet = true
		boundary.deletePolicyErr = errors.New("rejected")
		_, err := RunProof(context.Background(), validOptions(marker, boundary))
		if !errors.Is(err, errCleanup) || !contains(boundary.events, "delete-role") {
			t.Fatalf("cleanup precedence/continuation = (%v, %#v)", err, boundary.events)
		}
	})
	t.Run("provider panic is contained and exact cleanup runs", func(t *testing.T) {
		boundary := newFakeIAMBoundary(marker)
		boundary.panicAt = "allowed-get-role"
		result, err := RunProof(context.Background(), validOptions(marker, boundary))
		if !errors.Is(err, errProvider) || !result.Cleanup || !result.Audit {
			t.Fatalf("panic result = (%#v, %v)", result, err)
		}
	})
}

func TestPolicyComparisonRejectsDuplicateAndCaseVariantKeys(t *testing.T) {
	left := `{"Version":"2012-10-17","Statement":[]}`
	for _, mutated := range []string{
		`{"Version":"2012-10-17","Version":"2012-10-17","Statement":[]}`,
		`{"version":"2012-10-17","Statement":[]}`,
		`{"Version":"2012-10-17","Statement":[]} trailing`,
	} {
		if equalPolicy(left, mutated) {
			t.Fatalf("accepted mutated policy: %q", mutated)
		}
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
