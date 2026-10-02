package main

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"github.com/zasp-ai/zasp-sec/services/platform/bucketlayout"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type complianceExportProcessor struct {
	authority          *postgresComplianceExportAuthority
	store              *artifactstore.Store
	verifier           *s3driver.ExportVerifier
	cleanup            *s3driver.ExportCleanup
	worker             string
	cleanupMode        bool
	batch              int
	timeout, heartbeat time.Duration
}

func (p *complianceExportProcessor) RunOnce(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	lanes := []string{"execute"}
	if p.cleanupMode {
		bounded, cancel := context.WithTimeout(ctx, p.timeout)
		err := p.authority.Maintenance(bounded)
		cancel()
		if err != nil {
			return err
		}
		lanes = []string{"reconcile", "cleanup"}
	}
	var failed bool
	for _, lane := range lanes {
		bounded, cancel := context.WithTimeout(ctx, p.timeout)
		items, err := p.authority.Candidates(bounded, lane, p.batch)
		cancel()
		if err != nil {
			return err
		}
		for _, item := range items {
			token, err := newAuditExportProductionToken()
			if err != nil {
				return err
			}
			bounded, cancel := context.WithTimeout(ctx, p.timeout)
			lease, err := p.authority.Claim(bounded, item.Scope, item.ExportID, p.worker, token, lane)
			cancel()
			if err != nil {
				failed = true
				continue
			}
			if lease == nil {
				continue
			}
			if err = p.process(ctx, lease); err != nil {
				failed = true
			}
			if ctx.Err() != nil {
				return errWorkerExecution
			}
		}
	}
	if failed {
		return errWorkerExecution
	}
	return nil
}

func (p *complianceExportProcessor) process(parent context.Context, l *complianceExportLease) (resultErr error) {
	// Rendering/SQL and provider work share a finite attempt deadline. Heartbeats
	// have their own shorter deadline; losing renewal cancels all in-flight work.
	ctx, cancel := context.WithTimeout(parent, 55*time.Second)
	h := &complianceLeaseHandle{lease: cloneComplianceExportLease(*l)}
	stop := make(chan struct{})
	joined := make(chan struct{})
	lost := make(chan struct{}, 1)
	go func() {
		defer close(joined)
		ticker := time.NewTicker(p.heartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				bounded, end := context.WithTimeout(ctx, minDuration(p.timeout, 5*time.Second))
				err := h.heartbeat(bounded, p.authority)
				end()
				if err != nil {
					if ctx.Err() == nil {
						lost <- struct{}{}
						cancel()
					}
					return
				}
			}
		}
	}()
	outcome := complianceBeforePut
	// Always stop and join the sole child before releasing this attempt. Retry
	// records uncertainty even on caller cancellation; it has a bounded context
	// and the same registered authority/current lease, never a quota-release path.
	defer func() {
		if recover() != nil {
			resultErr = errWorkerExecution
			if l.Prepared || l.Lane != "execute" {
				outcome = complianceWriteUnknown
			}
		}
		close(stop)
		cancel()
		<-joined
		if resultErr != nil {
			select {
			case <-lost:
				return
			default:
			}
			retryOutcome := "source_failed"
			if outcome == complianceWriteUnknown || l.Lane != "execute" {
				retryOutcome = "unknown"
			}
			retryCtx, end := context.WithTimeout(context.Background(), minDuration(p.timeout, 5*time.Second))
			defer end()
			_ = p.authority.Retry(retryCtx, h.current(), retryOutcome)
		}
	}()
	switch l.Lane {
	case "execute":
		outcome, resultErr = executeComplianceExportPackage(ctx, p.authority, p.store, h, renderExportPackageByOrigin)
		return resultErr
	case "reconcile":
		outcome = complianceWriteUnknown
		prepared, err := p.authority.LoadPrepared(ctx, h.current())
		if err != nil {
			return err
		}
		ref, err := domain.ParseEvidenceRef(prepared.Reference)
		if err != nil {
			return errWorkerExecution
		}
		key, err := bucketlayout.ExportKey(l.Scope, ref.ArtifactID())
		if err != nil {
			return errWorkerExecution
		}
		bounded, end := context.WithTimeout(ctx, p.timeout)
		receipt, err := p.verifier.Verify(bounded, artifactstore.DriverObject{DriverLocator: artifactstore.DriverLocator{Scope: l.Scope, Reference: ref, Key: key}, Body: prepared.Bytes, Size: prepared.Size, SHA256: sha256.Sum256(prepared.Bytes), MediaType: "application/json"})
		end()
		if err != nil {
			return err
		}
		return p.authority.Finish(ctx, h.current(), prepared, receipt.VersionID)
	case "cleanup":
		outcome = complianceWriteUnknown
		if l.Prepared {
			ref, err := domain.ParseEvidenceRef(l.Reference)
			if err != nil {
				return errWorkerExecution
			}
			key, err := bucketlayout.ExportKey(l.Scope, ref.ArtifactID())
			if err != nil {
				return errWorkerExecution
			}
			bounded, end := context.WithTimeout(ctx, p.timeout)
			err = p.cleanup.DeleteExact(bounded, artifactstore.DriverLocator{Scope: l.Scope, Reference: ref, Key: key, VersionID: l.VersionID})
			end()
			if err != nil {
				return err
			}
		} else if l.Reference != "" || l.VersionID != "" {
			return errWorkerExecution
		}
		return p.authority.ConfirmDeleted(ctx, h.current(), l.Reference, l.VersionID)
	default:
		return errWorkerExecution
	}
}

type complianceExportRuntime struct {
	mu             sync.Mutex
	closed         bool
	next           uint64
	borrowers      map[uint64]context.CancelFunc
	active         sync.WaitGroup
	closeMu        sync.Mutex
	closeDone      chan struct{}
	processor      *complianceExportProcessor
	ready          func(context.Context) error
	closeTransport func()
	shutdown       time.Duration
}

func (r *complianceExportRuntime) begin(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, errRuntimeUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, nil, errRuntimeUnavailable
	}
	child, cancel := context.WithCancel(ctx)
	r.next++
	id := r.next
	r.borrowers[id] = cancel
	r.active.Add(1)
	return child, func() { cancel(); r.mu.Lock(); delete(r.borrowers, id); r.mu.Unlock(); r.active.Done() }, nil
}
func (r *complianceExportRuntime) Ready(ctx context.Context) error {
	ctx, end, err := r.begin(ctx)
	if err != nil {
		return err
	}
	defer end()
	return r.ready(ctx)
}
func (r *complianceExportRuntime) RunOnce(ctx context.Context) error {
	ctx, end, err := r.begin(ctx)
	if err != nil {
		return err
	}
	defer end()
	if r.ready(ctx) != nil {
		return errRuntimeUnavailable
	}
	return r.processor.RunOnce(ctx)
}
func (r *complianceExportRuntime) Close() error {
	r.closeMu.Lock()
	defer r.closeMu.Unlock()
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		for _, cancel := range r.borrowers {
			cancel()
		}
		r.closeDone = make(chan struct{})
		go func() { r.active.Wait(); close(r.closeDone) }()
	}
	r.mu.Unlock()
	timer := time.NewTimer(r.shutdown)
	defer timer.Stop()
	select {
	case <-r.closeDone:
		r.closeTransport()
		return nil
	case <-timer.C:
		return errRuntimeUnavailable
	}
}
