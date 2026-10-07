package apiserver

import (
	"bytes"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/approvalmaintenance"
)

// Uses the unchanged original payload fixture. These are application admission
// controls, not evidence that a native origin or active delegation exists.
func TestMaintenanceDeliveryPreservesOriginalPayloadAndAttemptBoundary(t *testing.T) {
	lease := approvalNotificationFixture(t)
	p := approvalmaintenance.DeliveryPayload{
		Organization: lease.Scope.OrganizationID().String(), Workspace: lease.Scope.WorkspaceID().String(), Environment: lease.Scope.EnvironmentID().String(),
		DeliveryID: lease.DeliveryID, ApprovalID: lease.ApprovalID, RunID: lease.RunID,
		Payload: lease.Payload, PayloadDigest: lease.PayloadDigest, DestinationURL: lease.DestinationURL, SecretReference: lease.SecretReference,
		LeaseToken: lease.LeaseToken, LeaseExpiresAt: lease.LeaseExpiresAt, Attempt: 0,
	}
	for _, attempt := range []int{0, 9} {
		valid := p
		valid.Attempt = attempt
		if !validMaintenanceDeliveryPayload(valid) || valid.Attempt != attempt {
			t.Fatal("valid reservation rejected or validation consumed an attempt")
		}
	}
	for name, change := range map[string]func(*approvalmaintenance.DeliveryPayload){
		"attempt below zero":   func(v *approvalmaintenance.DeliveryPayload) { v.Attempt = -1 },
		"attempt exhausted":    func(v *approvalmaintenance.DeliveryPayload) { v.Attempt = 10 },
		"expired lease":        func(v *approvalmaintenance.DeliveryPayload) { v.LeaseExpiresAt = time.Now().Add(-time.Second) },
		"no settlement margin": func(v *approvalmaintenance.DeliveryPayload) { v.LeaseExpiresAt = time.Now().Add(time.Second) },
		"changed payload":      func(v *approvalmaintenance.DeliveryPayload) { v.Payload += " " },
		"foreign organization": func(v *approvalmaintenance.DeliveryPayload) {
			v.Organization = "pid_10000000-0000-4000-8000-000000000002"
		},
		"changed delivery id": func(v *approvalmaintenance.DeliveryPayload) {
			v.DeliveryID = "pid_10000000-0000-4000-8000-000000000002"
		},
		"insecure destination": func(v *approvalmaintenance.DeliveryPayload) { v.DestinationURL = "http://hooks.example.test/zasp" },
		"invalid lease token":  func(v *approvalmaintenance.DeliveryPayload) { v.LeaseToken = "malformed" },
		"missing secret":       func(v *approvalmaintenance.DeliveryPayload) { v.SecretReference = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			change(&bad)
			if validMaintenanceDeliveryPayload(bad) {
				t.Fatal("unsafe delivery admitted")
			}
		})
	}
}

// BeforeConnect is a public pool boundary and refuses before ANY socket/SQL.
// Its counter distinguishes invalid configuration refusal from a valid-shaped
// constructor reaching native readiness; no successful readiness is fabricated.
func maintenanceBoundaryUnavailableNative(t *testing.T) (*approvalmaintenance.Executor, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	cfg, err := pgxpool.ParseConfig("postgres://fixture_user@127.0.0.1:1/fixture?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	cfg.BeforeConnect = func(context.Context, *pgx.ConnConfig) error {
		calls.Add(1)
		return errors.New("owned unavailable database boundary")
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	checker := authorizationDecisionFunc(func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
		t.Error("constructor invoked authorization check")
		return authorization.Decision{}, authorization.ErrDenied
	})
	native, err := approvalmaintenance.NewExecutor(pool, checker, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAW", strings.Repeat("a", 64), bytes.Repeat([]byte{0xa5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(native.Close)
	return native, calls
}
func TestAuthorizedApprovalConstructorRejectsMissingAuthorityAndInvalidLeaseConfig(t *testing.T) {
	secrets := &findingTicketSecretResolverStub{}
	webhook := &approvalNotificationWebhookStub{}
	valid := AuthorizedApprovalNotificationConfig{Secrets: secrets, Webhook: webhook, Owner: "owned_maintenance", LeaseSeconds: 30, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 64), nil }}
	// Genuine positive-shaped control proves readiness is reached, while the
	// intentionally unavailable database still prevents creating a reconciler.
	native, calls := maintenanceBoundaryUnavailableNative(t)
	control := valid
	control.Native = native
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if r, err := NewAuthorizedApprovalNotificationReconciler(ctx, control); r != nil || !errors.Is(err, ErrRepositoryConfiguration) || calls.Load() == 0 {
		t.Fatal("valid shape failed to reach native admission")
	}
	for name, change := range map[string]func(*AuthorizedApprovalNotificationConfig){
		"nil native":  func(c *AuthorizedApprovalNotificationConfig) { c.Native = nil },
		"nil secrets": func(c *AuthorizedApprovalNotificationConfig) { c.Secrets = nil },
		"typed nil secrets": func(c *AuthorizedApprovalNotificationConfig) {
			var value *findingTicketSecretResolverStub
			c.Secrets = value
		},
		"nil webhook": func(c *AuthorizedApprovalNotificationConfig) { c.Webhook = nil },
		"typed nil webhook": func(c *AuthorizedApprovalNotificationConfig) {
			var value *approvalNotificationWebhookStub
			c.Webhook = value
		},
		"owner control character":         func(c *AuthorizedApprovalNotificationConfig) { c.Owner = "owned\nmaintenance" },
		"lease below minimum":             func(c *AuthorizedApprovalNotificationConfig) { c.LeaseSeconds = 14 },
		"lease above maximum":             func(c *AuthorizedApprovalNotificationConfig) { c.LeaseSeconds = 61 },
		"nil token producer":              func(c *AuthorizedApprovalNotificationConfig) { c.NewLeaseToken = nil },
		"interval below minimum":          func(c *AuthorizedApprovalNotificationConfig) { c.Interval = time.Millisecond },
		"interval above maximum":          func(c *AuthorizedApprovalNotificationConfig) { c.Interval = 2 * time.Minute },
		"executor without registered key": func(c *AuthorizedApprovalNotificationConfig) { c.Native = &approvalmaintenance.Executor{} },
	} {
		t.Run(name, func(t *testing.T) {
			native, calls := maintenanceBoundaryUnavailableNative(t)
			c := valid
			c.Native = native
			change(&c)
			r, err := NewAuthorizedApprovalNotificationReconciler(context.Background(), c)
			if r != nil || !errors.Is(err, ErrRepositoryConfiguration) || calls.Load() != 0 {
				t.Fatal("invalid configuration reached native connection or was admitted", calls.Load())
			}
		})
	}
	native, calls = maintenanceBoundaryUnavailableNative(t)
	valid.Native = native
	if r, err := NewAuthorizedApprovalNotificationReconciler(nil, valid); r != nil || !errors.Is(err, ErrRepositoryConfiguration) || calls.Load() != 0 {
		t.Fatal("nil context reached native admission")
	}
	if secrets.calls != 0 || webhook.calls != 0 {
		t.Fatal("constructor invoked effects")
	}
}

// The checker refuses and must NOT be invoked. This test establishes native
// inactive admission only, not a synthetic successful authorization decision.
func TestAuthorizedApprovalConstructorRefusesActualInactiveNativeModule(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, _, _, _, _, _ string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()
		installAutomaticSourceFixture(t, ctx, owner)
		runner, err := migrations.NewRunner(&runtimeObservedMigrationDatabase{workerObservedMigrationDatabase{integrationMigrationDatabase{connection: owner}, t}})
		if err != nil {
			t.Fatal("owned runner", err)
		}
		for _, up := range []func(context.Context) error{runner.UpProductionTemporalFindingResponse, runner.UpProductionAuthorizationTemporalProfile, runner.UpProductionAuthorizationWorkerProfile, runner.UpProductionApprovalMaintenanceProfile} {
			if err := up(ctx); err != nil {
				t.Fatal("owned native installation", err)
			}
		}
		key := bytes.Repeat([]byte{0xa5}, 32)
		if _, err := owner.Exec(ctx, `CREATE ROLE maintenance_boundary_login LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;GRANT zasp_approval_maintenance_worker TO maintenance_boundary_login;SELECT zasp_approval_maintenance.register_principal('maintenance_boundary_login')`); err != nil {
			t.Fatal("owned restricted login", err)
		}
		if _, err := owner.Exec(ctx, `SELECT zasp_approval_maintenance.register_verifier('approval-forward',encode(digest($1::bytea,'sha256'),'hex'),$1::bytea)`, key); err != nil {
			t.Fatal("owned verifier", err)
		}
		var active, catalog bool
		if err := owner.QueryRow(ctx, `SELECT active,zasp_approval_maintenance.catalog_ready() FROM zasp_approval_maintenance.registration WHERE singleton`).Scan(&active, &catalog); err != nil || active || !catalog {
			t.Fatal("inactive baseline", active, catalog, err)
		}
		cfg, err := pgxpool.ParseConfig(owner.Config().ConnString())
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.User = "maintenance_boundary_login"
		cfg.MaxConns = 1
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		checks := 0
		checker := authorizationDecisionFunc(func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
			checks++
			return authorization.Decision{}, authorization.ErrDenied
		})
		native, err := approvalmaintenance.NewExecutor(pool, checker, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAW", migrations.ApprovalMaintenanceProfileChecksum(), key)
		clear(key)
		if err != nil {
			t.Fatal("owned executor", err)
		}
		defer native.Close()
		secrets := &findingTicketSecretResolverStub{}
		webhook := &approvalNotificationWebhookStub{}
		reconciler, err := NewAuthorizedApprovalNotificationReconciler(ctx, AuthorizedApprovalNotificationConfig{Native: native, Secrets: secrets, Webhook: webhook, Owner: "owned_maintenance", LeaseSeconds: 30, NewLeaseToken: func() (string, error) { return strings.Repeat("b", 64), nil }})
		if reconciler != nil || !errors.Is(err, ErrRepositoryConfiguration) || checks != 0 || secrets.calls != 0 || webhook.calls != 0 {
			t.Fatal("inactive native constructor admitted or invoked effects", checks, secrets.calls, webhook.calls)
		}
	})
}
