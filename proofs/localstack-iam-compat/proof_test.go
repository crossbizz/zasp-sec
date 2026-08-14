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
		"create-role", "put-role-policy", "inspect-role", "get-role-policy",
		"assume-role", "assumed-identity", "allowed-get-role", "cleanup-get-role-policy", "denied-list-roles",
		"cleanup-get-role-policy", "cleanup-inspect-role", "delete-role-policy",
		"cleanup-inspect-principal", "delete-access-key", "delete-principal",
		"cleanup-inspect-role", "delete-role", "audit-principals", "audit-roles",
	}
	if got := fake.eventsSnapshot(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("event order = %#v, want %#v", got, want)
	}
}

func TestExpectedPolicyMakesExplicitDenyNecessary(t *testing.T) {
	_, role := expectedSpecs(testOptions(newFakeBoundary()))
	value, ok := decodeStrictJSON(role.PermissionPolicy)
	if !ok {
		t.Fatal("permission policy is not strict JSON")
	}
	policy := fmt.Sprint(value)
	if !strings.Contains(policy, "iam:GetRole") || strings.Count(policy, "iam:ListRoles") != 2 || !strings.Contains(policy, "Allow") || !strings.Contains(policy, "Deny") {
		t.Fatalf("permission policy does not make ListRoles deny precedence necessary: %s", policy)
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

func TestRunProof_ReviewRound3Fixes(t *testing.T) {
	t.Run("reconciles ambiguous and empty access-key outcomes", func(t *testing.T) {
		for _, test := range []struct {
			name string
			set  func(*fakeBoundary)
		}{
			{"ambiguous error", func(f *fakeBoundary) { f.ambiguousAccessKey = true; f.delayedAccessKey = 2 }},
			{"empty success", func(f *fakeBoundary) { f.emptyAccessKeySuccess = true; f.delayedAccessKey = 2 }},
		} {
			t.Run(test.name, func(t *testing.T) {
				fake := newFakeBoundary()
				test.set(fake)
				if _, err := RunProof(context.Background(), fake.options); !errors.Is(err, errProvider) {
					t.Fatalf("RunProof() error = %v, want provider error", err)
				}
				if fake.accessKeyPresent {
					t.Fatal("access key remains after an ambiguous outcome")
				}
			})
		}
	})
	t.Run("does not claim audit when preflight never audited", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.principalCollision = true
		result, err := RunProof(context.Background(), fake.options)
		if !errors.Is(err, errOwnership) {
			t.Fatalf("RunProof() error = %v, want ownership error", err)
		}
		if result.Audit {
			t.Fatal("result claimed audit without running prefix audits")
		}
	})
}

func TestRunProof_ReviewRound4Fixes(t *testing.T) {
	t.Run("does not reconcile or delete after a definitive access-key rejection", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.definitiveAccessKeyError = true
		if _, err := RunProof(context.Background(), fake.options); !errors.Is(err, errProvider) {
			t.Fatalf("RunProof() error = %v, want provider error", err)
		}
		if fake.accessKeyLists != 0 {
			t.Fatalf("ListAccessKeys() calls = %d, want 0 after definitive rejection", fake.accessKeyLists)
		}
		if fake.accessKeyDeletes != 0 {
			t.Fatalf("DeleteAccessKey() calls = %d, want 0 for an unowned key", fake.accessKeyDeletes)
		}
		if !fake.accessKeyPresent {
			t.Fatal("proof deleted an unowned key exposed after definitive rejection")
		}
	})

	for _, test := range []struct {
		name string
		run  func(*testing.T, *fakeBoundary) error
	}{
		{
			name: "canceled ambiguous access-key creation",
			run: func(_ *testing.T, fake *fakeBoundary) error {
				ctx, cancel := context.WithCancel(context.Background())
				fake.cancelAccessKeyContext = cancel
				return runProofError(ctx, fake)
			},
		},
		{
			name: "timed-out ambiguous access-key creation",
			run: func(t *testing.T, fake *fakeBoundary) error {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				fake.waitForAccessKeyContext = true
				err := runProofError(ctx, fake)
				if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
					t.Fatalf("main context error = %v, want deadline exceeded", ctx.Err())
				}
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeBoundary()
			if err := test.run(t, fake); !errors.Is(err, errProvider) {
				t.Fatalf("RunProof() error = %v, want provider error", err)
			}
			if fake.accessKeyPresent {
				t.Fatal("access key remains after an ambiguous canceled mutation")
			}
			if fake.accessKeyLists == 0 {
				t.Fatal("ambiguous access-key mutation was not reconciled")
			}
			if fake.accessKeyListSawCanceledContext {
				t.Fatal("access-key reconciliation reused the canceled main context")
			}
		})
	}

	t.Run("cleanup failure wins after independent access-key reconciliation", func(t *testing.T) {
		fake := newFakeBoundary()
		ctx, cancel := context.WithCancel(context.Background())
		fake.cancelAccessKeyContext = cancel
		fake.cleanupFails = true
		if _, err := RunProof(ctx, fake.options); !errors.Is(err, errCleanup) {
			t.Fatalf("RunProof() error = %v, want cleanup error", err)
		}
		if fake.accessKeyLists == 0 || fake.accessKeyDeletes == 0 {
			t.Fatalf("access-key reconciliation/deletion calls = %d/%d, want both non-zero", fake.accessKeyLists, fake.accessKeyDeletes)
		}
		if fake.accessKeyListSawCanceledContext {
			t.Fatal("cleanup reconciliation reused the canceled main context")
		}
	})
}

func TestRunProof_FinalReviewRound1Fixes(t *testing.T) {
	t.Run("earlier absence cannot mask a later principal list error", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.principalListErrorsAfterFirst = true
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		principal, _ := expectedSpecs(fake.options)
		_, outcome := reconcilePrincipal(ctx, fake, principal, time.Millisecond)
		if outcome != reconciliationUnresolved {
			t.Fatalf("reconciliation outcome = %v, want unresolved", outcome)
		}
	})

	t.Run("earlier absence cannot mask a later role list error", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.roleListErrorsAfterFirst = true
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		_, role := expectedSpecs(fake.options)
		_, outcome := reconcileRole(ctx, fake, role, time.Millisecond)
		if outcome != reconciliationUnresolved {
			t.Fatalf("reconciliation outcome = %v, want unresolved", outcome)
		}
	})

	for _, test := range []struct {
		name string
		set  func(*fakeBoundary)
	}{
		{
			name: "principal ambiguity tolerates delayed visibility",
			set: func(fake *fakeBoundary) {
				fake.ambiguousPrincipal = true
				fake.emptyPrincipalReconciles = 2
			},
		},
		{
			name: "role ambiguity tolerates delayed visibility",
			set: func(fake *fakeBoundary) {
				fake.ambiguousRole = true
				fake.emptyRoleReconciles = 2
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeBoundary()
			test.set(fake)
			result, err := RunProof(context.Background(), fake.options)
			if err != nil {
				t.Fatalf("RunProof() error = %v, want delayed candidate reconciliation", err)
			}
			if fake.principal != nil || fake.role != nil || fake.accessKeyPresent {
				t.Fatal("delayed candidate remains after cleanup")
			}
			if !result.Cleanup || !result.Audit {
				t.Fatalf("RunProof() result = %#v, want cleanup and audit", result)
			}
		})
	}

	for _, test := range []struct {
		name string
		set  func(context.CancelFunc, *fakeBoundary)
	}{
		{
			name: "principal typed ambiguity after cancellation",
			set:  func(cancel context.CancelFunc, fake *fakeBoundary) { fake.cancelPrincipalContext = cancel },
		},
		{
			name: "principal invalid success after timeout",
			set: func(_ context.CancelFunc, fake *fakeBoundary) {
				fake.waitForPrincipalContext = true
				fake.invalidPrincipalSuccess = true
			},
		},
		{
			name: "role typed ambiguity after cancellation",
			set:  func(cancel context.CancelFunc, fake *fakeBoundary) { fake.cancelRoleContext = cancel },
		},
		{
			name: "role invalid success after timeout",
			set: func(_ context.CancelFunc, fake *fakeBoundary) {
				fake.waitForRoleContext = true
				fake.invalidRoleSuccess = true
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeBoundary()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			test.set(cancel, fake)
			result, err := RunProof(ctx, fake.options)
			if !errors.Is(err, errOwnership) {
				t.Fatalf("RunProof() error = %v, want ownership error after canceled main work", err)
			}
			if fake.principal != nil || fake.role != nil || fake.accessKeyPresent {
				t.Fatal("uncertain resource remains after independent reconciliation and cleanup")
			}
			if !result.Cleanup || !result.Audit {
				t.Fatalf("RunProof() result = %#v, want cleanup and audit", result)
			}
			if strings.Contains(test.name, "principal") && fake.principalInspects == 0 {
				t.Fatal("principal ambiguity was not independently reconciled")
			}
			if strings.Contains(test.name, "role") && fake.roleInspects == 0 {
				t.Fatal("role ambiguity was not independently reconciled")
			}
			if fake.principalListSawCanceledContext || fake.roleListSawCanceledContext {
				t.Fatal("resource reconciliation reused the canceled main context")
			}
		})
	}

	t.Run("deferred cleanup re-arms a delayed ambiguous role", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.ambiguousRole = true
		fake.blockFirstRoleReconcile = true
		fake.options.CleanupTimeout = 50 * time.Millisecond
		result, err := RunProof(context.Background(), fake.options)
		if !errors.Is(err, errOwnership) {
			t.Fatalf("RunProof() error = %v, want ownership error from the first bounded reconcile", err)
		}
		if fake.role != nil || fake.principal != nil || fake.accessKeyPresent {
			t.Fatal("deferred cleanup did not re-arm and remove exact delayed resources")
		}
		if !result.Cleanup || !result.Audit || fake.roleDeletes == 0 {
			t.Fatalf("RunProof() result/deletes = %#v/%d, want cleanup, audit, and role deletion", result, fake.roleDeletes)
		}
	})

	t.Run("cleanup failure wins after deferred role re-arm", func(t *testing.T) {
		fake := newFakeBoundary()
		fake.ambiguousRole = true
		fake.blockFirstRoleReconcile = true
		fake.cleanupFails = true
		fake.options.CleanupTimeout = 50 * time.Millisecond
		if _, err := RunProof(context.Background(), fake.options); !errors.Is(err, errCleanup) {
			t.Fatalf("RunProof() error = %v, want cleanup precedence", err)
		}
		if fake.role != nil || fake.roleDeletes == 0 {
			t.Fatal("cleanup failure prevented independent delayed-role cleanup")
		}
	})

	for _, test := range []struct {
		name string
		set  func(*fakeBoundary)
		left func(*fakeBoundary) bool
	}{
		{"definitive principal rejection", func(fake *fakeBoundary) { fake.definitivePrincipalError = true }, func(fake *fakeBoundary) bool { return fake.principal != nil && fake.principalDeletes == 0 }},
		{"definitive role rejection", func(fake *fakeBoundary) { fake.definitiveRoleError = true }, func(fake *fakeBoundary) bool { return fake.role != nil && fake.roleDeletes == 0 }},
	} {
		t.Run(test.name+" is never adopted", func(t *testing.T) {
			fake := newFakeBoundary()
			test.set(fake)
			if _, err := RunProof(context.Background(), fake.options); !errors.Is(err, errCleanup) {
				t.Fatalf("RunProof() error = %v, want cleanup audit failure", err)
			}
			if !test.left(fake) {
				t.Fatal("definitively rejected resource was adopted or deleted")
			}
		})
	}
}

func runProofError(ctx context.Context, fake *fakeBoundary) error {
	_, err := RunProof(ctx, fake.options)
	return err
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
	definitivePrincipalError, definitiveRoleError                                                     bool
	delayedRole                                                                                       int
	panicAfterRole, cancelMain, cleanupMismatch, cleanupFails, cleanupContinuation, auditRemains      bool
	requireAccessSecret, returnSTSIdentity, invalidPrincipalSuccess, invalidRoleSuccess, panicCleanup bool
	panicSource, preexistingPrincipal, preexistingRole                                                bool
	invalidAccessKeySuccess, panicAfterAccessKey, cleanupPolicyMismatch, deletedRolePolicy            bool
	ambiguousAccessKey, emptyAccessKeySuccess, definitiveAccessKeyError                               bool
	waitForAccessKeyContext, accessKeyListSawCanceledContext                                          bool
	cancelAccessKeyContext                                                                            context.CancelFunc
	waitForPrincipalContext, waitForRoleContext                                                       bool
	principalListSawCanceledContext, roleListSawCanceledContext                                       bool
	principalListErrorsAfterFirst, roleListErrorsAfterFirst                                           bool
	cancelPrincipalContext, cancelRoleContext                                                         context.CancelFunc
	blockFirstRoleReconcile                                                                           bool
	blockedRoleReconcileContext                                                                       context.Context
	emptyPrincipalReconciles, emptyRoleReconciles                                                     int
	delayedAccessKey                                                                                  int
	accessKeyLists, accessKeyDeletes                                                                  int
	principalInspects, principalDeletes, roleDeletes                                                  int
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
func (f *fakeBoundary) ListPrincipals(ctx context.Context, _ string) ([]PrincipalState, error) {
	f.principalLists++
	if ctx.Err() != nil {
		f.principalListSawCanceledContext = true
		return nil, ctx.Err()
	}
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
	if f.principalListErrorsAfterFirst {
		return nil, errors.New("unavailable")
	}
	if f.principal != nil {
		if f.emptyPrincipalReconciles > 0 {
			f.emptyPrincipalReconciles--
			return nil, nil
		}
		return []PrincipalState{*f.principal}, nil
	}
	if f.auditRemains {
		return []PrincipalState{{}}, nil
	}
	return nil, nil
}
func (f *fakeBoundary) CreatePrincipal(ctx context.Context, spec PrincipalSpec) (PrincipalState, error) {
	f.event("create-principal")
	f.createdPrincipal = spec
	state := PrincipalState{PrincipalSpec: spec, UserID: "principal-id"}
	f.principal = &state
	if f.definitivePrincipalError {
		return PrincipalState{}, errors.New("rejected")
	}
	if f.cancelPrincipalContext != nil {
		f.cancelPrincipalContext()
		if f.invalidPrincipalSuccess {
			return PrincipalState{}, nil
		}
		return PrincipalState{}, ambiguousMutationError{cause: context.Canceled}
	}
	if f.waitForPrincipalContext {
		<-ctx.Done()
		if f.invalidPrincipalSuccess {
			return PrincipalState{}, nil
		}
		return PrincipalState{}, ambiguousMutationError{cause: ctx.Err()}
	}
	if f.invalidPrincipalSuccess {
		return PrincipalState{}, nil
	}
	if f.ambiguousPrincipal {
		return PrincipalState{}, ambiguousMutationError{cause: errors.New("uncertain")}
	}
	return state, nil
}
func (f *fakeBoundary) InspectPrincipal(ctx context.Context, _ string) (PrincipalState, error) {
	if ctx.Err() != nil {
		return PrincipalState{}, ctx.Err()
	}
	f.principalInspects++
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
func (f *fakeBoundary) CreateAccessKey(ctx context.Context, _ string) (string, string, error) {
	f.event("create-access-key")
	if f.definitiveAccessKeyError {
		f.accessKeyID = "foreign-key"
		f.accessKeyPresent = true
		return "", "", errors.New("rejected")
	}
	f.accessKeyID = "key"
	f.accessKeyPresent = true
	if f.panicAfterAccessKey {
		panic("access-key")
	}
	if f.ambiguousAccessKey {
		return "", "", ambiguousMutationError{cause: errors.New("uncertain")}
	}
	if f.cancelAccessKeyContext != nil {
		f.cancelAccessKeyContext()
		return "", "", ambiguousMutationError{cause: context.Canceled}
	}
	if f.waitForAccessKeyContext {
		<-ctx.Done()
		return "", "", ambiguousMutationError{cause: ctx.Err()}
	}
	if f.emptyAccessKeySuccess {
		return "", "", nil
	}
	if f.invalidAccessKeySuccess {
		return f.accessKeyID, "", nil
	}
	return "key", "secret", nil
}
func (f *fakeBoundary) ListAccessKeys(ctx context.Context, _ string) ([]string, error) {
	f.accessKeyLists++
	if ctx.Err() != nil {
		f.accessKeyListSawCanceledContext = true
	}
	if !f.accessKeyPresent {
		return nil, nil
	}
	if f.delayedAccessKey > 0 {
		f.delayedAccessKey--
		return nil, errors.New("not ready")
	}
	return []string{f.accessKeyID}, nil
}
func (f *fakeBoundary) DeleteAccessKey(context.Context, string, string) error {
	f.event("delete-access-key")
	f.accessKeyDeletes++
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
	f.principalDeletes++
	f.continuedCleanup = f.cleanupContinuation
	f.principal = nil
	return nil
}
func (f *fakeBoundary) ListRoles(ctx context.Context, _ string) ([]RoleState, error) {
	f.roleLists++
	if ctx.Err() != nil {
		f.roleListSawCanceledContext = true
		return nil, ctx.Err()
	}
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
	if f.roleListErrorsAfterFirst {
		return nil, errors.New("unavailable")
	}
	if f.role == nil {
		f.event("audit-roles")
		if f.auditRemains {
			return []RoleState{{}}, nil
		}
		return nil, nil
	}
	if f.emptyRoleReconciles > 0 {
		f.emptyRoleReconciles--
		return nil, nil
	}
	if f.blockFirstRoleReconcile {
		if f.blockedRoleReconcileContext == nil {
			f.blockedRoleReconcileContext = ctx
		}
		if f.blockedRoleReconcileContext == ctx {
			return nil, errors.New("not ready")
		}
	}
	if f.delayedRole > 0 {
		f.delayedRole--
		return nil, errors.New("not ready")
	}
	return []RoleState{*f.role}, nil
}
func (f *fakeBoundary) CreateRole(ctx context.Context, spec RoleSpec) (RoleState, error) {
	f.event("create-role")
	f.createdRole = spec
	state := RoleState(spec)
	state.RoleID = "role-id"
	f.role = &state
	if f.definitiveRoleError {
		return RoleState{}, errors.New("rejected")
	}
	if f.cancelRoleContext != nil {
		f.cancelRoleContext()
		if f.invalidRoleSuccess {
			return RoleState{}, nil
		}
		return RoleState{}, ambiguousMutationError{cause: context.Canceled}
	}
	if f.waitForRoleContext {
		<-ctx.Done()
		if f.invalidRoleSuccess {
			return RoleState{}, nil
		}
		return RoleState{}, ambiguousMutationError{cause: ctx.Err()}
	}
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
func (f *fakeBoundary) InspectRole(ctx context.Context, _ string) (RoleState, error) {
	if ctx.Err() != nil {
		return RoleState{}, ctx.Err()
	}
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
	f.roleDeletes++
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
