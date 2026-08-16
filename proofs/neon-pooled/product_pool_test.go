package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	platformdatabase "github.com/zasp-ai/zasp-sec/services/platform/database"
)

const productDriverSecret = "product-driver-secret-must-not-escape"

func TestPrepareProductPGXPoolConfigRetainsValidatedDestinationAndBoundsPool(t *testing.T) {
	t.Parallel()

	target, err := validatedPGXConnection(validDirectNeonURL())
	if err != nil {
		t.Fatalf("validatedPGXConnection() error = %v", err)
	}
	config, err := prepareProductPGXPoolConfig(target)
	if err != nil {
		t.Fatalf("prepareProductPGXPoolConfig() error = %v", err)
	}
	if config.MaxConns != 2 || config.MinConns != 0 || config.MinIdleConns != 0 {
		t.Fatalf("product pool bounds = max %d min %d idle %d", config.MaxConns, config.MinConns, config.MinIdleConns)
	}
	if err := validateEffectivePGXConfig(config.ConnConfig, target.expected); err != nil {
		t.Fatalf("product pool changed the validated destination: %v", err)
	}
	if config.BeforeConnect == nil {
		t.Fatal("product pool omitted per-connection destination revalidation")
	}
}

func TestExecuteProductPoolProofReportsWaitInUseAndCleanClose(t *testing.T) {
	t.Parallel()

	driver := newContendedDriver(2, 20*time.Millisecond)
	opener := func(context.Context, validatedConnection) (*platformdatabase.Pool, error) {
		return platformdatabase.New(driver, platformdatabase.Config{
			QueryTimeout: time.Second, HealthTimeout: time.Second,
		})
	}

	summary, err := executeProductPoolProof(context.Background(), validDirectNeonURL(), opener, time.Millisecond)
	if err != nil {
		t.Fatalf("executeProductPoolProof() error = %v", err)
	}
	if summary != productPoolSuccessSummary {
		t.Fatalf("summary = %q, want fixed success", summary)
	}
	if driver.queryCalls.Load() != concurrentReadCount {
		t.Fatalf("query calls = %d, want %d", driver.queryCalls.Load(), concurrentReadCount)
	}
	if !driver.closed.Load() || driver.closeCalls.Load() != 1 {
		t.Fatalf("closed = %t, close calls = %d", driver.closed.Load(), driver.closeCalls.Load())
	}
	if driver.maximumActive.Load() != 2 || driver.waitCount.Load() == 0 {
		t.Fatalf("maximum active = %d, waits = %d", driver.maximumActive.Load(), driver.waitCount.Load())
	}
}

func TestExecuteProductPoolProofClosesOnEveryFailureWithCleanupPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		driver    *contendedDriver
		openError error
		want      error
	}{
		{name: "open", openError: errors.New(productDriverSecret), want: errPoolSetup},
		{name: "query", driver: func() *contendedDriver {
			driver := newContendedDriver(2, time.Millisecond)
			driver.queryError = true
			return driver
		}(), want: errConcurrentReads},
		{name: "no wait", driver: newContendedDriver(concurrentReadCount, time.Millisecond), want: errPoolStats},
		{name: "cleanup precedence", driver: func() *contendedDriver {
			driver := newContendedDriver(2, time.Millisecond)
			driver.queryError = true
			driver.retainAfterClose = true
			driver.created.Store(1)
			return driver
		}(), want: errPoolClose},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			opener := func(context.Context, validatedConnection) (*platformdatabase.Pool, error) {
				if test.openError != nil {
					return nil, test.openError
				}
				return platformdatabase.New(test.driver, platformdatabase.Config{
					QueryTimeout: 100 * time.Millisecond, HealthTimeout: 100 * time.Millisecond,
				})
			}
			_, err := executeProductPoolProof(ctx, validDirectNeonURL(), opener, time.Millisecond)
			if !errors.Is(err, test.want) {
				t.Fatalf("executeProductPoolProof() error = %v, want %v", err, test.want)
			}
			if test.driver != nil && (!test.driver.closed.Load() || test.driver.closeCalls.Load() != 1) {
				t.Fatalf("failure did not close exactly once: closed %t calls %d", test.driver.closed.Load(), test.driver.closeCalls.Load())
			}
		})
	}
}

func TestExecuteProductPoolProofRequiresWaitsCausedByItsReads(t *testing.T) {
	t.Parallel()

	driver := newContendedDriver(concurrentReadCount, 20*time.Millisecond)
	driver.waitCount.Store(1)
	opener := func(context.Context, validatedConnection) (*platformdatabase.Pool, error) {
		return platformdatabase.New(driver, platformdatabase.Config{
			QueryTimeout: time.Second, HealthTimeout: time.Second,
		})
	}

	if _, err := executeProductPoolProof(context.Background(), validDirectNeonURL(), opener, time.Millisecond); !errors.Is(err, errPoolStats) {
		t.Fatalf("executeProductPoolProof() error = %v, want pool statistics", err)
	}
}

func TestExecuteProductPoolProofClosesMalformedOpenResult(t *testing.T) {
	t.Parallel()

	driver := newContendedDriver(2, time.Millisecond)
	opener := func(context.Context, validatedConnection) (*platformdatabase.Pool, error) {
		pool, err := platformdatabase.New(driver, platformdatabase.Config{
			QueryTimeout: time.Second, HealthTimeout: time.Second,
		})
		if err != nil {
			t.Fatalf("database.New() error = %v", err)
		}
		return pool, errors.New(productDriverSecret)
	}

	if _, err := executeProductPoolProof(context.Background(), validDirectNeonURL(), opener, time.Millisecond); !errors.Is(err, errPoolSetup) {
		t.Fatalf("executeProductPoolProof() error = %v, want pool setup", err)
	}
	if !driver.closed.Load() || driver.closeCalls.Load() != 1 {
		t.Fatalf("malformed open cleanup = closed %t calls %d, want true/1", driver.closed.Load(), driver.closeCalls.Load())
	}

	failingDriver := newContendedDriver(2, time.Millisecond)
	failingDriver.retainAfterClose = true
	failingDriver.created.Store(1)
	failingOpener := func(context.Context, validatedConnection) (*platformdatabase.Pool, error) {
		pool, err := platformdatabase.New(failingDriver, platformdatabase.Config{
			QueryTimeout: time.Second, HealthTimeout: time.Second,
		})
		if err != nil {
			t.Fatalf("database.New() error = %v", err)
		}
		return pool, errors.New(productDriverSecret)
	}
	if _, err := executeProductPoolProof(context.Background(), validDirectNeonURL(), failingOpener, time.Millisecond); !errors.Is(err, errPoolClose) {
		t.Fatalf("malformed open cleanup-precedence error = %v, want pool close", err)
	}
}

func TestExecuteProductPoolProofRejectsInvalidInputWithoutOpening(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	opener := func(context.Context, validatedConnection) (*platformdatabase.Pool, error) {
		calls.Add(1)
		return nil, errors.New(productDriverSecret)
	}
	if _, err := executeProductPoolProof(context.Background(), "", opener, time.Millisecond); !errors.Is(err, errConfiguration) {
		t.Fatalf("invalid URL error = %v, want configuration", err)
	}
	if _, err := executeProductPoolProof(nil, validDirectNeonURL(), opener, time.Millisecond); !errors.Is(err, errConfiguration) {
		t.Fatalf("nil context error = %v, want configuration", err)
	}
	if _, err := executeProductPoolProof(context.Background(), validDirectNeonURL(), nil, time.Millisecond); !errors.Is(err, errConfiguration) {
		t.Fatalf("nil opener error = %v, want configuration", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("opener calls = %d, want 0", calls.Load())
	}
}

type contendedDriver struct {
	semaphore        chan struct{}
	delay            time.Duration
	active           atomic.Int32
	created          atomic.Int32
	maximumActive    atomic.Int32
	waitCount        atomic.Int64
	waitNanos        atomic.Int64
	queryCalls       atomic.Int32
	closeCalls       atomic.Int32
	closed           atomic.Bool
	queryError       bool
	retainAfterClose bool
}

func newContendedDriver(maximum int, delay time.Duration) *contendedDriver {
	return &contendedDriver{semaphore: make(chan struct{}, maximum), delay: delay}
}

func (driver *contendedDriver) QueryRow(ctx context.Context, statement string, arguments ...any) platformdatabase.Row {
	driver.queryCalls.Add(1)
	return contendedRow{driver: driver, ctx: ctx, statement: statement, arguments: arguments}
}

func (driver *contendedDriver) Ping(context.Context) error {
	return nil
}

func (driver *contendedDriver) Stats() platformdatabase.DriverStats {
	maximum := int32(cap(driver.semaphore))
	if driver.closed.Load() && !driver.retainAfterClose {
		return platformdatabase.DriverStats{
			Maximum: maximum, WaitCount: driver.waitCount.Load(),
			WaitDuration: time.Duration(driver.waitNanos.Load()),
		}
	}
	total := driver.created.Load()
	active := driver.active.Load()
	return platformdatabase.DriverStats{
		InUse: active, Idle: total - active, Total: total, Maximum: maximum,
		WaitCount: driver.waitCount.Load(), WaitDuration: time.Duration(driver.waitNanos.Load()),
	}
}

func (driver *contendedDriver) Close() {
	driver.closeCalls.Add(1)
	driver.closed.Store(true)
}

type contendedRow struct {
	driver    *contendedDriver
	ctx       context.Context
	statement string
	arguments []any
}

func (row contendedRow) Scan(destinations ...any) error {
	if row.driver.queryError {
		return errors.New(productDriverSecret)
	}
	if row.statement != readQuery || len(row.arguments) != 0 || len(destinations) != 1 {
		return errors.New(productDriverSecret)
	}
	waited := false
	waitStarted := time.Now()
	select {
	case row.driver.semaphore <- struct{}{}:
	default:
		waited = true
		row.driver.waitCount.Add(1)
		select {
		case row.driver.semaphore <- struct{}{}:
		case <-row.ctx.Done():
			row.driver.waitNanos.Add(int64(time.Since(waitStarted)))
			return row.ctx.Err()
		}
	}
	if waited {
		row.driver.waitNanos.Add(int64(time.Since(waitStarted)))
	}
	active := row.driver.active.Add(1)
	updateAtomicMaximum(&row.driver.maximumActive, active)
	updateAtomicMaximum(&row.driver.created, active)
	defer func() {
		row.driver.active.Add(-1)
		<-row.driver.semaphore
	}()
	select {
	case <-time.After(row.driver.delay):
	case <-row.ctx.Done():
		return row.ctx.Err()
	}
	value, ok := destinations[0].(*int)
	if !ok {
		return errors.New(productDriverSecret)
	}
	*value = 1
	return nil
}

var _ platformdatabase.Driver = (*contendedDriver)(nil)

var _ platformdatabase.Row = contendedRow{}
