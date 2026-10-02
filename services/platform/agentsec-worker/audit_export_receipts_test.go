package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

// This driver models receipt authority, not wall-clock expiry. SQL in the
// execution fixture is synthetic; decoding, dispatcher and executor are real.
type auditReceiptDriver struct {
	*runtimeCoordinatorQueueDriver
	mu             sync.Mutex
	renewed        map[string]bool
	steps          []string
	requireRenewal bool
	messages       []jobqueue.DriverMessage
	deliveries     int
	failACK        int
	ackHandles     []string
}

func (d *auditReceiptDriver) PublishBatch(_ context.Context, messages []jobqueue.DriverMessage) ([]jobqueue.DriverPublished, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.messages = append([]jobqueue.DriverMessage(nil), messages...)
	result := make([]jobqueue.DriverPublished, len(messages))
	for i, m := range messages {
		result[i] = jobqueue.DriverPublished{EntryID: m.EntryID, JobID: m.JobID, MessageID: fmt.Sprintf("message-%d", i)}
	}
	return result, nil
}
func (d *auditReceiptDriver) ConsumeBatch(context.Context, int) ([]jobqueue.DriverDelivery, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deliveries++
	result := make([]jobqueue.DriverDelivery, len(d.messages))
	for i, m := range d.messages {
		result[i] = jobqueue.DriverDelivery{Message: m, MessageID: fmt.Sprintf("message-%d", i), ReceiptHandle: fmt.Sprintf("private-%d-%d", i, d.deliveries), ReceiveCount: d.deliveries}
	}
	return result, nil
}

type auditReceiptBoundary struct {
	*auditExportDispatchQueueFixture
	renew func(context.Context, []jobqueue.Receipt, time.Duration) error
	ack   func(context.Context, []jobqueue.Receipt) error
}

func (q *auditReceiptBoundary) AcknowledgeBatch(ctx context.Context, receipts []jobqueue.Receipt) error {
	if q.ack != nil {
		return q.ack(ctx, receipts)
	}
	return q.auditExportDispatchQueueFixture.AcknowledgeBatch(ctx, receipts)
}
func (q *auditReceiptBoundary) ExtendVisibility(ctx context.Context, receipts []jobqueue.Receipt, duration time.Duration) error {
	return q.renew(ctx, receipts, duration)
}

// Pulses model scheduling only. The watchdog catches a missing call/hung join;
// neither a pulse nor the SQL fixture establishes elapsed receipt expiration.
func TestAuditExportDispatcherPeriodicRenewalWhileExecutionBlocked(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "renew", true: "failure cancels execution"}[failure], func(t *testing.T) {
			f := newAuditExportExecutionFixture(t, true)
			entered, release := make(chan struct{}), make(chan struct{})
			f.db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerCaptureSQL {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return f.query(ctx, sql, args...)
			}
			e, err := newAuditExportExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			job := auditExportDispatchJobFixture(t, f)
			jobs := []jobqueue.Job{job}
			if failure {
				second := job
				second.JobID = workerID(t, "pid_52000048-0000-4000-8000-000000000048")
				second.Payload = []byte(strings.Replace(string(job.Payload), job.JobID.String(), second.JobID.String(), 1))
				second.AuthorityDigest = sha256.Sum256(second.Payload)
				jobs = append(jobs, second)
			}
			q, err := jobqueue.New(&auditReceiptDriver{renewed: map[string]bool{}}, jobqueue.Config{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := q.PublishBatch(context.Background(), jobs); err != nil {
				t.Fatal(err)
			}
			deliveries, err := q.ConsumeBatch(context.Background(), len(jobs))
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			renewed := make(chan struct{}, 10)
			boundary := &auditReceiptBoundary{auditExportDispatchQueueFixture: &auditExportDispatchQueueFixture{queue: q, deliveries: deliveries}}
			boundary.renew = func(ctx context.Context, receipts []jobqueue.Receipt, duration time.Duration) error {
				if len(receipts) != len(jobs) {
					t.Error("later queued receipt omitted from renewal")
				}
				calls++
				if calls == 2 {
					renewed <- struct{}{}
					if failure {
						return errors.New("private queue failure")
					}
				}
				return q.ExtendVisibility(ctx, receipts, duration)
			}
			d, err := newAuditExportDispatcher(boundary, map[string]*auditExportExecutor{f.lease.Policy.PolicyID: e}, len(jobs), 180*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			pulses := make(chan time.Time, 1)
			d.newTicker = func(time.Duration) (<-chan time.Time, func()) { return pulses, func() {} }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- d.RunOnce(ctx) }()
			select {
			case <-entered:
			case err := <-done:
				t.Fatalf("execution not reached: %v", err)
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("execution not reached")
			}
			pulses <- time.Now()
			select {
			case <-renewed:
			case <-time.After(time.Second):
				cancel()
				close(release)
				<-done
				t.Fatal("periodic renewal missing while executor blocked")
			}
			if !failure {
				close(release)
			}
			err = <-done
			if (err != nil) != failure || failure && boundary.acks != 0 {
				t.Fatalf("periodic result=%v ACKs=%d", err, boundary.acks)
			}
			if failure {
				claims := 0
				for _, step := range f.trace {
					if step == "claim" {
						claims++
					}
				}
				if claims != 1 {
					t.Fatal("later execution started after receipt failure")
				}
			}
		})
	}
}

func (d *auditReceiptDriver) ExtendVisibility(ctx context.Context, receipts []jobqueue.DriverReceipt, duration int32) ([]domain.ProductID, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.steps = append(d.steps, "renew")
	for _, r := range receipts {
		d.renewed[r.ReceiptHandle] = true
	}
	ids := make([]domain.ProductID, len(receipts))
	for i, r := range receipts {
		ids[i] = r.JobID
	}
	return ids, nil
}

func (d *auditReceiptDriver) AcknowledgeBatch(ctx context.Context, receipts []jobqueue.DriverReceipt) ([]domain.ProductID, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.steps = append(d.steps, "ack")
	for _, r := range receipts {
		d.ackHandles = append(d.ackHandles, r.ReceiptHandle)
	}
	for _, r := range receipts {
		if d.requireRenewal && !d.renewed[r.ReceiptHandle] {
			return nil, errors.New("receipt renewal required")
		}
	}
	if d.failACK > 0 {
		d.failACK--
		return nil, errors.New("lost ACK")
	}
	ids := make([]domain.ProductID, len(receipts))
	for i, r := range receipts {
		ids[i] = r.JobID
	}
	return ids, nil
}

func auditReceiptDispatchFixture(t *testing.T) (*auditExportExecutionFixture, *auditExportDispatcher, *auditReceiptBoundary) {
	t.Helper()
	f := newAuditExportExecutionFixture(t, true)
	e, err := newAuditExportExecutor(f.config)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := runtimeCoordinatorQueueForJob(t, &runtimeCoordinatorSteps{}, auditExportDispatchJobFixture(t, f))
	deliveries, err := q.ConsumeBatch(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	b := &auditReceiptBoundary{auditExportDispatchQueueFixture: &auditExportDispatchQueueFixture{queue: q, deliveries: deliveries}, renew: q.ExtendVisibility}
	d, err := newAuditExportDispatcher(b, map[string]*auditExportExecutor{f.lease.Policy.PolicyID: e}, 1, 180*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return f, d, b
}

func TestAuditExportReceiptOwnerProtectsPendingSetAndRemovesACKedReceipt(t *testing.T) {
	f := newAuditExportExecutionFixture(t, true)
	job := auditExportDispatchJobFixture(t, f)
	second := job
	second.JobID = workerID(t, "pid_52000048-0000-4000-8000-000000000048")
	second.Payload = []byte(strings.Replace(string(job.Payload), job.JobID.String(), second.JobID.String(), 1))
	second.AuthorityDigest = sha256.Sum256(second.Payload)
	driver := &auditReceiptDriver{renewed: map[string]bool{}}
	q, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.PublishBatch(context.Background(), []jobqueue.Job{job, second}); err != nil {
		t.Fatal(err)
	}
	deliveries, err := q.ConsumeBatch(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	b := &auditReceiptBoundary{auditExportDispatchQueueFixture: &auditExportDispatchQueueFixture{queue: q, deliveries: deliveries}}
	sets := make(chan []string, 10)
	b.renew = func(ctx context.Context, receipts []jobqueue.Receipt, v time.Duration) error {
		ids := []string{}
		for _, r := range receipts {
			ids = append(ids, r.JobID().String())
		}
		sets <- ids
		if v != 180*time.Second {
			return errors.New("incorrect visibility")
		}
		return q.ExtendVisibility(ctx, receipts, v)
	}
	pulses := make(chan time.Time, 1)
	d := &auditExportDispatcher{queue: b, visibility: 180 * time.Second, newTicker: func(c time.Duration) (<-chan time.Time, func()) {
		if c != 60*time.Second {
			t.Error("wrong cadence")
		}
		return pulses, func() {}
	}}
	ready := make(chan struct{})
	acks := make(chan auditExportReceiptACK)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- d.ownReceipts(ctx, deliveries, ready, acks) }()
	<-ready
	want := []string{job.JobID.String(), second.JobID.String()}
	if got := <-sets; !reflect.DeepEqual(got, want) {
		t.Fatal("initial pending receipts", got)
	}
	pulses <- time.Now()
	if got := <-sets; !reflect.DeepEqual(got, want) {
		t.Fatal("later queued receipt was not renewed", got)
	}
	first := auditExportReceiptACK{index: 0, done: make(chan struct{})}
	acks <- first
	<-first.done
	if got := <-sets; !reflect.DeepEqual(got, want) {
		t.Fatal("pre ACK set", got)
	}
	pulses <- time.Now()
	if got := <-sets; !reflect.DeepEqual(got, []string{second.JobID.String()}) {
		t.Fatal("ACKed receipt renewed", got)
	}
	last := auditExportReceiptACK{index: 1, done: make(chan struct{})}
	acks <- last
	<-last.done
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := <-sets; !reflect.DeepEqual(got, []string{second.JobID.String()}) {
		t.Fatal("last pre ACK set", got)
	}
}

func TestAuditExportDispatcherJoinsPendingRenewalAndLatchesFailure(t *testing.T) {
	for _, mode := range []string{"terminal then renewal failure", "parent cancellation", "executor panic", "renewal panic"} {
		t.Run(mode, func(t *testing.T) {
			f, d, b := auditReceiptDispatchFixture(t)
			executing, finish, renewing, release, observedCancel := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			terminalReturned := make(chan struct{})
			f.db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerFinishSQL {
					close(executing)
					select {
					case <-finish:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					if mode == "executor panic" {
						panic("private executor panic")
					}
				}
				result, err := f.query(ctx, sql, args...)
				if sql == auditExportWorkerFinishSQL {
					close(terminalReturned)
				}
				return result, err
			}
			calls := 0
			b.renew = func(ctx context.Context, receipts []jobqueue.Receipt, v time.Duration) error {
				calls++
				if calls == 2 {
					close(renewing)
					if mode == "parent cancellation" || mode == "executor panic" {
						<-ctx.Done()
						close(observedCancel)
					}
					<-release
					if mode == "renewal panic" {
						panic("private renewal panic")
					}
					return errors.New("private renewal failure")
				}
				return b.queue.ExtendVisibility(ctx, receipts, v)
			}
			pulses := make(chan time.Time, 1)
			stopped := make(chan struct{})
			d.newTicker = func(time.Duration) (<-chan time.Time, func()) { return pulses, func() { close(stopped) } }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- d.RunOnce(ctx) }()
			<-executing
			pulses <- time.Now()
			<-renewing
			if mode == "parent cancellation" {
				cancel()
			} else {
				close(finish)
			}
			if mode == "parent cancellation" || mode == "executor panic" {
				<-observedCancel
			} else {
				<-terminalReturned
			}
			select {
			case <-done:
				t.Fatal("dispatcher released ownership before renewal joined")
			default:
			}
			close(release)
			select {
			case err := <-done:
				if err != errWorkerExecution {
					t.Fatal("failure not redacted", err)
				}
			case <-time.After(time.Second):
				t.Fatal("receipt owner did not join")
			}
			<-stopped
			if b.acks != 0 {
				t.Fatal("failed renewal permitted ACK")
			}
			if mode == "terminal then renewal failure" && !f.finished {
				t.Fatal("fixture did not reach durable terminal before renewal failure")
			}
		})
	}
}

func TestAuditExportDispatcherRejectsUnownedAndEmptyBatchWithoutEffects(t *testing.T) {
	for _, mode := range []string{"empty", "foreign receipt"} {
		t.Run(mode, func(t *testing.T) {
			f, d, b := auditReceiptDispatchFixture(t)
			if mode == "empty" {
				b.deliveries = nil
			} else {
				foreign, _ := runtimeCoordinatorQueueForJob(t, &runtimeCoordinatorSteps{}, auditExportDispatchJobFixture(t, f))
				b.deliveries, _ = foreign.ConsumeBatch(context.Background(), 1)
			}
			f.db.queries = nil
			err := d.RunOnce(context.Background())
			if (err != nil) != (mode == "foreign receipt") || len(f.db.queries) != 0 || b.acks != 0 {
				t.Fatal("invalid batch effects", err)
			}
		})
	}
}

func TestAuditExportDispatcherVisibilityRange(t *testing.T) {
	_, d, _ := auditReceiptDispatchFixture(t)
	for _, v := range []time.Duration{0, 59 * time.Second, 60 * time.Second, 180 * time.Second, 300 * time.Second, 301 * time.Second, 180*time.Second + time.Nanosecond} {
		_, err := newAuditExportDispatcher(d.queue, d.executors, 1, v)
		valid := v == 60*time.Second || v == 180*time.Second || v == 300*time.Second
		if (err == nil) != valid {
			t.Fatalf("visibility acceptance %v: %v", v, err)
		}
	}
}

func TestAuditExportDispatcherFreshReceiptReplaysTerminalOnlyAfterLostACK(t *testing.T) {
	f := newAuditExportExecutionFixture(t, true)
	e, err := newAuditExportExecutor(f.config)
	if err != nil {
		t.Fatal(err)
	}
	driver := &auditReceiptDriver{renewed: map[string]bool{}, requireRenewal: true, failACK: 1}
	q, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.PublishBatch(context.Background(), []jobqueue.Job{auditExportDispatchJobFixture(t, f)}); err != nil {
		t.Fatal(err)
	}
	d, err := newAuditExportDispatcher(q, map[string]*auditExportExecutor{f.lease.Policy.PolicyID: e}, 1, 180*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if d.RunOnce(context.Background()) == nil || !f.finished {
		t.Fatal("lost ACK did not preserve durable finish")
	}
	f.trace = nil
	if d.RunOnce(context.Background()) != nil || !reflect.DeepEqual(f.trace, []string{"claim", "terminal"}) {
		t.Fatal("fresh delivery rewrote artifacts", f.trace)
	}
	if len(driver.ackHandles) != 2 || driver.ackHandles[0] == driver.ackHandles[1] {
		t.Fatal("replay reused old receipt")
	}
}

func TestAuditExportDispatcherCancellationDuringACKJoinsOwner(t *testing.T) {
	_, d, b := auditReceiptDispatchFixture(t)
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	b.ack = func(ctx context.Context, _ []jobqueue.Receipt) error {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.RunOnce(ctx) }()
	<-entered
	cancel()
	<-canceled
	select {
	case <-done:
		t.Fatal("ACK owner not joined")
	default:
	}
	close(release)
	if err := <-done; err != errWorkerExecution {
		t.Fatal("canceled ACK reported success", err)
	}
}

func TestAuditExportDispatcherInitialRenewalFailurePreventsExecution(t *testing.T) {
	for _, mode := range []string{"error", "panic", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f, d, b := auditReceiptDispatchFixture(t)
			f.db.queries = nil
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b.renew = func(context.Context, []jobqueue.Receipt, time.Duration) error {
				switch mode {
				case "panic":
					panic("private")
				case "cancel":
					cancel()
					return nil
				}
				return errors.New("private")
			}
			if d.RunOnce(ctx) != errWorkerExecution || len(f.db.queries) != 0 || b.acks != 0 {
				t.Fatal("unconfirmed initial receipt authority reached execution")
			}
		})
	}
}

func TestAuditExportReceiptOwnerDerivesBoundedCadence(t *testing.T) {
	for _, tc := range []struct{ visibility, cadence, bound time.Duration }{{60 * time.Second, 20 * time.Second, 10 * time.Second}, {180 * time.Second, 60 * time.Second, 30 * time.Second}, {300 * time.Second, 100 * time.Second, 30 * time.Second}} {
		t.Run(tc.visibility.String(), func(t *testing.T) {
			_, d, b := auditReceiptDispatchFixture(t)
			d.visibility = tc.visibility
			bounds := make(chan time.Duration, 2)
			b.renew = func(ctx context.Context, _ []jobqueue.Receipt, v time.Duration) error {
				deadline, ok := ctx.Deadline()
				if !ok || v != tc.visibility {
					return errors.New("unbounded or wrong visibility")
				}
				bounds <- time.Until(deadline)
				return nil
			}
			var cadence time.Duration
			stopped := false
			d.newTicker = func(c time.Duration) (<-chan time.Time, func()) {
				cadence = c
				return make(chan time.Time), func() { stopped = true }
			}
			if err := d.RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if cadence != tc.cadence || !stopped {
				t.Fatal("wrong cadence or unjoined ticker")
			}
			for i := 0; i < 2; i++ {
				bound := <-bounds
				if bound <= tc.bound-time.Second || bound > tc.bound {
					t.Fatal("wrong renewal bound", bound)
				}
			}
		})
	}
}

func TestAuditExportDispatcherRenewsBeforeAcknowledgingRealExecutor(t *testing.T) {
	for _, mode := range []string{"ordinary ACK control", "direct extension control", "dispatcher renewal"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuditExportExecutionFixture(t, true)
			e, err := newAuditExportExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			driver := &auditReceiptDriver{runtimeCoordinatorQueueDriver: &runtimeCoordinatorQueueDriver{steps: &runtimeCoordinatorSteps{}, messageID: "audit-receipt"}, renewed: map[string]bool{}, requireRenewal: mode != "ordinary ACK control"}
			q, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := q.PublishBatch(context.Background(), []jobqueue.Job{auditExportDispatchJobFixture(t, f)}); err != nil {
				t.Fatal(err)
			}
			if mode == "direct extension control" {
				deliveries, err := q.ConsumeBatch(context.Background(), 1)
				if err != nil {
					t.Fatal(err)
				}
				if err := q.ExtendVisibility(context.Background(), []jobqueue.Receipt{deliveries[0].Receipt}, 180*time.Second); err != nil {
					t.Fatal(err)
				}
				if err := q.AcknowledgeBatch(context.Background(), []jobqueue.Receipt{deliveries[0].Receipt}); err != nil {
					t.Fatal(err)
				}
				return
			}
			d, err := newAuditExportDispatcher(q, map[string]*auditExportExecutor{f.lease.Policy.PolicyID: e}, 1, 180*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			err = d.RunOnce(context.Background())
			if err != nil || !f.finished {
				t.Fatalf("renewal-before-ACK missing: err=%v finished=%v queue_steps=%v", err, f.finished, driver.steps)
			}
		})
	}
}
