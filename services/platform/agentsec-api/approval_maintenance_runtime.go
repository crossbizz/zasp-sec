package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/approvalmaintenance"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimepostgres"
)

// This profile is explicit and closed. Its dedicated SQL login must be
// registered by the native installer; the checksum is not an activation grant.
func validApprovalMaintenanceRuntimeConfig(c RuntimeConfig) bool {
	pin := c.RuntimeServices.ApprovalMaintenanceProfileChecksum
	if pin == "" {
		return c.ApprovalMaintenancePostgresDSN == "" && c.ApprovalMaintenanceKeyFile == ""
	}
	if !c.RuntimeServices.Enabled || c.RuntimeServices.Validate() != nil || !filepath.IsAbs(c.ApprovalMaintenanceKeyFile) || filepath.Clean(c.ApprovalMaintenanceKeyFile) != c.ApprovalMaintenanceKeyFile {
		return false
	}
	original, ok := parseRuntimePostgresDSN(c.SecurityAgentPostgresDSN)
	maintenance, valid := parseRuntimePostgresDSN(c.ApprovalMaintenancePostgresDSN)
	if !ok || !valid || maintenance.User.Username() == original.User.Username() {
		return false
	}
	core, coreOK := parseRuntimePostgresDSN(c.PostgresDSN)
	return coreOK && maintenance.User.Username() != core.User.Username() && maintenance.Scheme == original.Scheme && maintenance.Host == original.Host && maintenance.Path == original.Path && maintenance.RawQuery == original.RawQuery
}

// A replacement symlink/FIFO cannot block startup or supply the verifier seed.
// The native caller_ready check below separately proves role and key registration.
func loadApprovalMaintenanceKey(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errRuntimeUnavailable
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0400 || before.Size() != 32 {
		return nil, errRuntimeUnavailable
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return nil, errRuntimeUnavailable
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || opened.Mode() != before.Mode() || opened.Size() != 32 || !opened.ModTime().Equal(before.ModTime()) {
		return nil, errRuntimeUnavailable
	}
	seed, err := io.ReadAll(io.LimitReader(f, 33))
	afterFD, fdErr := f.Stat()
	closeErr := f.Close()
	after, pathErr := os.Lstat(path)
	if err != nil || fdErr != nil || closeErr != nil || pathErr != nil || len(seed) != 32 || !os.SameFile(opened, afterFD) || !os.SameFile(opened, after) || afterFD.Mode() != opened.Mode() || after.Mode() != opened.Mode() || afterFD.Size() != 32 || after.Size() != 32 || !afterFD.ModTime().Equal(opened.ModTime()) || !after.ModTime().Equal(opened.ModTime()) || !approvalKeyOwner(afterFD) || !approvalKeyOwner(after) {
		clear(seed)
		return nil, errRuntimeUnavailable
	}
	return seed, nil
}

func approvalKeyOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1 && stat.Uid == uint32(os.Geteuid())
}

type approvalMaintenanceRuntimeCloser struct {
	executor *approvalmaintenance.Executor
	pool     *pgxpool.Pool
}

func (c *approvalMaintenanceRuntimeCloser) Close() error {
	if c != nil {
		if c.executor != nil {
			c.executor.Close()
		}
		if c.pool != nil {
			c.pool.Close()
		}
	}
	return nil
}

func newRuntimeApprovalMaintenance(ctx context.Context, c RuntimeConfig, a apiserver.RequestAuthorizer, secrets apiserver.FindingTicketSecretResolver, webhook apiserver.ApprovalNotificationWebhook, owner string) (*apiserver.AuthorizedApprovalNotificationReconciler, io.Closer, error) {
	if ctx == nil || ctx.Err() != nil || !validApprovalMaintenanceRuntimeConfig(c) || c.ApprovalMaintenancePostgresDSN == "" {
		return nil, nil, errRuntimeUnavailable
	}
	authorizer, ok := a.(*apiserver.OpenFGAAuthorizer)
	if !ok || authorizer == nil || authorizer.Checker == nil || authorizer.StoreID != c.RuntimeServices.StoreID || authorizer.ModelID != c.RuntimeServices.ModelID {
		return nil, nil, errRuntimeUnavailable
	}
	seed, err := loadApprovalMaintenanceKey(c.ApprovalMaintenanceKeyFile)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	defer clear(seed)
	bounded, cancel := context.WithTimeout(ctx, c.ProviderTimeout)
	defer cancel()
	cfg, err := runtimepostgres.ParsePoolConfig(c.ApprovalMaintenancePostgresDSN)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	cfg.MaxConns = 2
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(bounded, cfg)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	closer := &approvalMaintenanceRuntimeCloser{pool: pool}
	executor, err := approvalmaintenance.NewExecutor(pool, authorizer.Checker, authorizer.StoreID, authorizer.ModelID, c.RuntimeServices.ApprovalMaintenanceProfileChecksum, seed)
	if err != nil {
		_ = closer.Close()
		return nil, nil, errRuntimeUnavailable
	}
	closer.executor = executor
	reconciler, err := apiserver.NewAuthorizedApprovalNotificationReconciler(bounded, apiserver.AuthorizedApprovalNotificationConfig{Native: executor, Secrets: secrets, Webhook: webhook, Owner: owner, LeaseSeconds: 30, Interval: time.Second, NewLeaseToken: newFindingTicketLeaseToken})
	if err != nil {
		_ = closer.Close()
		return nil, nil, errRuntimeUnavailable
	}
	return reconciler, closer, nil
}

// Both runtime branches retain original fixed release/principal metadata.
// Selection never treats a native registration pin as live authority.
type approvalNotificationLifecycle interface {
	Run(context.Context) error
	Ready() bool
}
type approvalNotificationFactory func() (approvalNotificationLifecycle, io.Closer, error)

func selectApprovalNotificationLifecycle(c RuntimeConfig, native, legacy approvalNotificationFactory) (approvalNotificationLifecycle, io.Closer, error) {
	if !validApprovalMaintenanceRuntimeConfig(c) {
		return nil, nil, errRuntimeUnavailable
	}
	chosen := legacy
	if c.ApprovalMaintenancePostgresDSN != "" {
		chosen = native
	}
	if chosen == nil {
		return nil, nil, errRuntimeUnavailable
	}
	r, closer, err := chosen()
	if err != nil || invalidRuntimeValue(r) {
		if closer != nil {
			_ = closer.Close()
		}
		return nil, nil, errRuntimeUnavailable
	}
	return r, closer, nil
}
func approvalNotificationLifecycleReady(ctx context.Context, metadata func(context.Context) error, r approvalNotificationLifecycle) error {
	if ctx == nil || ctx.Err() != nil || metadata == nil || r == nil {
		return errRuntimeUnavailable
	}
	if metadata(ctx) != nil || !r.Ready() || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	return nil
}
