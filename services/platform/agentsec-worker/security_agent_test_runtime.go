package main

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type existingTestRuntimeDependencies struct {
	Artifacts existingTestArtifactReader
	Ready     func(context.Context) error
	Close     func() error
}

func composeExistingTestRuntime(c workerRuntimeConfig, db existingTestQuery, deps existingTestRuntimeDependencies) (workerRuntimeDependencies, error) {
	if c.Mode != workerModeTestReconciler || !validWorkerRuntimeConfig(c) || nilWorkerDependency(db) || nilWorkerDependency(deps.Artifacts) || deps.Ready == nil || deps.Close == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	client, err := newExistingTestClient(db, c.WorkerID, func() time.Time { return time.Now().UTC() })
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	scheduler, err := newExistingTestScheduler(client, deps.Artifacts)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	ready, err := newBoundedCachedWorkerReadiness(func(ctx context.Context) error {
		if deps.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		_, _, err := client.NextScope(ctx, domain.Scope{})
		return err
	}, 5*time.Second, workerReadinessCacheTTL(c.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	root, cancel := context.WithCancel(context.Background())
	r := &existingTestProductionRuntime{scheduler: scheduler, ready: ready, closeDependencies: deps.Close, root: root, cancel: cancel, idle: make(chan struct{}), timeout: c.ShutdownTimeout}
	return workerRuntimeDependencies{Processor: r, Ready: r.Ready, Close: r.Close}, nil
}

type existingTestProductionRuntime struct {
	scheduler interface {
		RunOnce(context.Context) error
		Close(context.Context) error
	}
	ready             func(context.Context) error
	closeDependencies func() error
	root              context.Context
	cancel            context.CancelFunc
	timeout           time.Duration
	mu                sync.Mutex
	closed            bool
	active            int
	idle              chan struct{}
	cleanup           sync.Mutex
	cleaned           bool
}

func (r *existingTestProductionRuntime) borrow(ctx context.Context, timeout time.Duration) (context.Context, func(), error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, errRuntimeUnavailable
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, nil, errRuntimeUnavailable
	}
	r.active++
	r.mu.Unlock()
	work, cancel := context.WithTimeout(ctx, timeout)
	stop := context.AfterFunc(r.root, cancel)
	return work, func() {
		stop()
		cancel()
		r.mu.Lock()
		r.active--
		if r.closed && r.active == 0 {
			close(r.idle)
		}
		r.mu.Unlock()
	}, nil
}

func (r *existingTestProductionRuntime) Ready(ctx context.Context) error {
	work, release, err := r.borrow(ctx, 5*time.Second)
	if err != nil {
		return err
	}
	defer release()
	if r.ready(work) != nil || work.Err() != nil {
		return errRuntimeUnavailable
	}
	return nil
}

func (r *existingTestProductionRuntime) RunOnce(ctx context.Context) error {
	work, release, err := r.borrow(ctx, 30*time.Second)
	if err != nil {
		return err
	}
	defer release()
	if r.ready(work) != nil || r.scheduler.RunOnce(work) != nil || work.Err() != nil {
		return errRuntimeUnavailable
	}
	return nil
}

func (r *existingTestProductionRuntime) Close() error {
	r.cleanup.Lock()
	defer r.cleanup.Unlock()
	if r.cleaned {
		return nil
	}
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		r.cancel()
		if r.active == 0 {
			close(r.idle)
		}
	}
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	select {
	case <-r.idle:
	case <-ctx.Done():
		return errRuntimeUnavailable
	}
	if r.scheduler.Close(ctx) != nil || r.closeDependencies() != nil {
		return errRuntimeUnavailable
	}
	r.cleaned = true
	return nil
}

func validExistingTestRuntimeAuthority(c workerRuntimeConfig) bool {
	role := discoveryAWSRolePattern.FindStringSubmatch(c.TestReconcilerRoleARN)
	if len(role) != 2 || role[1] != c.EvidenceOwner || !workerRegionPattern.MatchString(c.AWSRegion) || !workerAccountPattern.MatchString(c.EvidenceOwner) || !workerBucketPattern.MatchString(c.EvidenceBucket) || !workerKMSPattern.MatchString(c.EvidenceKMSKeyARN) || !strings.HasPrefix(c.EvidenceKMSKeyARN, "arn:aws:kms:"+c.AWSRegion+":"+c.EvidenceOwner+":key/") || c.TestReconcilerTokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || c.LeaseDuration != time.Minute || c.BatchSize != 1 {
		return false
	}
	// This mode has a closed configuration surface. New shared config fields
	// must not silently introduce credentials or execution authority here.
	allowed := workerRuntimeConfig{
		Mode: c.Mode, PostgresDSN: c.PostgresDSN, DatabaseAuthority: c.DatabaseAuthority, WorkerID: c.WorkerID,
		PollInterval: c.PollInterval, LeaseDuration: c.LeaseDuration, BatchSize: c.BatchSize, ShutdownTimeout: c.ShutdownTimeout,
		AWSRegion: c.AWSRegion, EvidenceBucket: c.EvidenceBucket, EvidenceOwner: c.EvidenceOwner, EvidenceKMSKeyARN: c.EvidenceKMSKeyARN,
		TestReconcilerRoleARN: c.TestReconcilerRoleARN, TestReconcilerTokenFile: c.TestReconcilerTokenFile,
	}
	return reflect.DeepEqual(c, allowed)
}
