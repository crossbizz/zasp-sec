package database

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const driverSecret = "driver-secret-must-not-escape"

func TestPoolQueryHealthStatsAndClose(t *testing.T) {
	t.Parallel()

	var closed atomic.Bool
	var closeCalls atomic.Int32
	var pingCalls atomic.Int32
	driver := &recordingDriver{}
	driver.query = func(ctx context.Context, statement string, arguments ...any) Row {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("query context has no deadline")
		}
		if statement != "SELECT $1::int" || len(arguments) != 1 || arguments[0] != 7 {
			t.Error("query was not forwarded exactly")
		}
		return recordingRow{scan: func(destinations ...any) error {
			if len(destinations) != 1 {
				t.Fatal("scan destinations were not forwarded exactly")
			}
			value, ok := destinations[0].(*int)
			if !ok {
				t.Fatal("scan destination type changed")
			}
			*value = 7
			return nil
		}}
	}
	driver.ping = func(ctx context.Context) error {
		pingCalls.Add(1)
		if _, ok := ctx.Deadline(); !ok {
			t.Error("health context has no deadline")
		}
		return nil
	}
	driver.snapshot = func() DriverStats {
		if closed.Load() {
			return DriverStats{Maximum: 4, WaitCount: 3, WaitDuration: 4 * time.Millisecond}
		}
		return DriverStats{
			InUse: 1, Idle: 1, Total: 2, Maximum: 4,
			WaitCount: 3, CanceledWaitCount: 2, WaitDuration: 4 * time.Millisecond,
		}
	}
	driver.close = func() {
		closeCalls.Add(1)
		closed.Store(true)
	}

	pool, err := New(driver, validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	var value int
	if err := pool.QueryRow(context.Background(), "SELECT $1::int", []any{7}, &value); err != nil {
		t.Fatalf("QueryRow() error = %v", err)
	}
	if value != 7 {
		t.Fatalf("query result = %d, want 7", value)
	}

	want := Stats{
		InUse: 1, Idle: 1, Total: 2, Maximum: 4,
		WaitCount: 3, CanceledWaitCount: 2, WaitDuration: 4 * time.Millisecond,
	}
	stats, err := pool.Stats()
	if err != nil || stats != want {
		t.Fatalf("Stats() = %#v, %v, want %#v, nil", stats, err, want)
	}
	health, err := pool.Health(context.Background())
	if err != nil || health != want || pingCalls.Load() != 1 {
		t.Fatalf("Health() = %#v, %v, ping calls %d", health, err, pingCalls.Load())
	}

	if err := pool.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if closeCalls.Load() != 1 {
		t.Fatalf("driver close calls = %d, want 1", closeCalls.Load())
	}
	closedStats, err := pool.Stats()
	if err != nil || !closedStats.Closed || closedStats.Total != 0 || closedStats.InUse != 0 {
		t.Fatalf("closed Stats() = %#v, %v", closedStats, err)
	}
	if err := pool.QueryRow(context.Background(), "SELECT 1", nil, &value); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-close QueryRow() error = %v, want closed", err)
	}
	if _, err := pool.Health(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-close Health() error = %v, want closed", err)
	}
}

func TestNewRejectsInvalidConfigurationAndDrivers(t *testing.T) {
	t.Parallel()

	validDriver := &recordingDriver{}
	invalidConfigs := []Config{
		{},
		{QueryTimeout: time.Second, HealthTimeout: 0},
		{QueryTimeout: 0, HealthTimeout: time.Second},
		{QueryTimeout: -time.Second, HealthTimeout: time.Second},
		{QueryTimeout: time.Second, HealthTimeout: -time.Second},
		{QueryTimeout: 30*time.Second + time.Nanosecond, HealthTimeout: time.Second},
		{QueryTimeout: time.Second, HealthTimeout: 30*time.Second + time.Nanosecond},
	}
	for index, config := range invalidConfigs {
		if _, err := New(validDriver, config); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("invalid config %d error = %v, want configuration", index, err)
		}
	}
	if _, err := New(nil, validConfig()); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("nil driver error = %v, want configuration", err)
	}
	var typedNil *recordingDriver
	if _, err := New(typedNil, validConfig()); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("typed-nil driver error = %v, want configuration", err)
	}
}

func TestQueryRowRejectsInvalidRequestsBeforeDriver(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	driver := &recordingDriver{query: func(context.Context, string, ...any) Row {
		calls.Add(1)
		return recordingRow{}
	}}
	pool := mustPool(t, driver)
	t.Cleanup(func() { _ = pool.Close() })
	invalidUTF8 := string([]byte{0xff})
	long := strings.Repeat("x", 64*1024+1)
	tests := []struct {
		name         string
		ctx          context.Context
		statement    string
		destinations []any
	}{
		{name: "nil context", statement: "SELECT 1", destinations: []any{new(int)}},
		{name: "empty", ctx: context.Background(), statement: "", destinations: []any{new(int)}},
		{name: "space", ctx: context.Background(), statement: " ", destinations: []any{new(int)}},
		{name: "outer whitespace", ctx: context.Background(), statement: " SELECT 1", destinations: []any{new(int)}},
		{name: "nul", ctx: context.Background(), statement: "SELECT\x00 1", destinations: []any{new(int)}},
		{name: "invalid utf8", ctx: context.Background(), statement: invalidUTF8, destinations: []any{new(int)}},
		{name: "oversized", ctx: context.Background(), statement: long, destinations: []any{new(int)}},
		{name: "no destination", ctx: context.Background(), statement: "SELECT 1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := pool.QueryRow(test.ctx, test.statement, nil, test.destinations...); !errors.Is(err, ErrQuery) {
				t.Fatalf("QueryRow() error = %v, want query", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("driver query calls = %d, want 0", calls.Load())
	}
}

func TestQueryRowBoundsDriverAndScanFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		query func(context.Context, string, ...any) Row
	}{
		{name: "nil row", query: func(context.Context, string, ...any) Row { return nil }},
		{name: "driver panic", query: func(context.Context, string, ...any) Row { panic(driverSecret) }},
		{name: "scan error", query: func(context.Context, string, ...any) Row {
			return recordingRow{scan: func(...any) error { return errors.New(driverSecret) }}
		}},
		{name: "scan panic", query: func(context.Context, string, ...any) Row {
			return recordingRow{scan: func(...any) error { panic(driverSecret) }}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := mustPool(t, &recordingDriver{query: test.query})
			defer func() { _ = pool.Close() }()
			var value int
			err := pool.QueryRow(context.Background(), "SELECT 1", nil, &value)
			if !errors.Is(err, ErrQuery) || strings.Contains(err.Error(), driverSecret) {
				t.Fatalf("QueryRow() error = %q, want fixed query error", err)
			}
		})
	}
}

func TestQueryRowUsesEarlierCallerOrConfiguredDeadline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		config     Config
		context    func() (context.Context, context.CancelFunc)
		maximumRun time.Duration
	}{
		{
			name: "configured", config: Config{QueryTimeout: 20 * time.Millisecond, HealthTimeout: time.Second},
			context:    func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			maximumRun: 250 * time.Millisecond,
		},
		{
			name: "caller", config: validConfig(),
			context: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 20*time.Millisecond)
			},
			maximumRun: 250 * time.Millisecond,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			driver := &recordingDriver{query: func(ctx context.Context, _ string, _ ...any) Row {
				return recordingRow{scan: func(...any) error {
					<-ctx.Done()
					return ctx.Err()
				}}
			}}
			pool, err := New(driver, test.config)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() { _ = pool.Close() }()
			ctx, cancel := test.context()
			defer cancel()
			started := time.Now()
			var value int
			err = pool.QueryRow(ctx, "SELECT 1", nil, &value)
			if !errors.Is(err, ErrQuery) || time.Since(started) > test.maximumRun {
				t.Fatalf("QueryRow() error = %v, duration = %s", err, time.Since(started))
			}
		})
	}
}

func TestStatsRejectsMalformedDriverSnapshots(t *testing.T) {
	t.Parallel()

	closed := DriverStats{Maximum: 2}
	tests := []DriverStats{
		{InUse: -1, Maximum: 1},
		{Idle: -1, Maximum: 1},
		{Constructing: -1, Maximum: 1},
		{Total: -1, Maximum: 1},
		{Maximum: -1},
		{InUse: 1, Total: 2, Maximum: 2},
		{Total: 2, Maximum: 1},
		{WaitCount: -1, Maximum: 1},
		{CanceledWaitCount: -1, Maximum: 1},
		{WaitDuration: -time.Nanosecond, Maximum: 1},
	}
	for index, snapshot := range tests {
		driver := &recordingDriver{snapshot: func() DriverStats { return snapshot }}
		pool := mustPool(t, driver)
		if _, err := pool.Stats(); !errors.Is(err, ErrStats) {
			t.Fatalf("malformed stats %d error = %v, want stats", index, err)
		}
		driver.snapshot = func() DriverStats { return closed }
		if err := pool.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}

	pool := mustPool(t, &recordingDriver{snapshot: func() DriverStats { panic(driverSecret) }})
	if _, err := pool.Stats(); !errors.Is(err, ErrStats) || strings.Contains(err.Error(), driverSecret) {
		t.Fatalf("Stats() panic error = %q, want fixed stats", err)
	}
}

func TestHealthBoundsPingAndSnapshotFailures(t *testing.T) {
	t.Parallel()

	driver := &recordingDriver{ping: func(ctx context.Context) error {
		<-ctx.Done()
		return errors.New(driverSecret)
	}}
	pool, err := New(driver, Config{QueryTimeout: time.Second, HealthTimeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	started := time.Now()
	if _, err := pool.Health(context.Background()); !errors.Is(err, ErrHealth) || strings.Contains(err.Error(), driverSecret) || time.Since(started) > 250*time.Millisecond {
		t.Fatalf("Health() error = %q, duration = %s", err, time.Since(started))
	}
	driver.ping = func(context.Context) error { panic(driverSecret) }
	if _, err := pool.Health(context.Background()); !errors.Is(err, ErrHealth) || strings.Contains(err.Error(), driverSecret) {
		t.Fatalf("Health() panic error = %q", err)
	}
	driver.ping = nil
	driver.snapshot = func() DriverStats { return DriverStats{InUse: 1, Maximum: 1} }
	if _, err := pool.Health(context.Background()); !errors.Is(err, ErrStats) {
		t.Fatalf("Health() malformed stats error = %v, want stats", err)
	}
	driver.snapshot = nil
	if err := pool.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestCloseWaitsForAdmittedQueryAndRejectsNewWork(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})
	closed := make(chan struct{})
	var closeCalls atomic.Int32
	driver := &recordingDriver{query: func(context.Context, string, ...any) Row {
		return recordingRow{scan: func(...any) error {
			close(entered)
			<-release
			return nil
		}}
	}}
	driver.close = func() {
		closeCalls.Add(1)
		close(closed)
	}
	pool := mustPool(t, driver)
	queryDone := make(chan error, 1)
	go func() {
		var value int
		queryDone <- pool.QueryRow(context.Background(), "SELECT 1", nil, &value)
	}()
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- pool.Close() }()
	select {
	case <-closed:
		t.Fatal("driver closed before admitted query completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-queryDone; err != nil {
		t.Fatalf("QueryRow() error = %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closeCalls.Load() != 1 {
		t.Fatalf("close calls = %d, want 1", closeCalls.Load())
	}
}

func TestCloseIsConcurrentIdempotentAndRetainsFixedFailure(t *testing.T) {
	t.Parallel()

	t.Run("concurrent", func(t *testing.T) {
		var calls atomic.Int32
		driver := &recordingDriver{close: func() { calls.Add(1) }}
		pool := mustPool(t, driver)
		results := make(chan error, 10)
		for range 10 {
			go func() { results <- pool.Close() }()
		}
		for range 10 {
			if err := <-results; err != nil {
				t.Fatalf("Close() error = %v", err)
			}
		}
		if calls.Load() != 1 {
			t.Fatalf("close calls = %d, want 1", calls.Load())
		}
	})

	tests := []struct {
		name   string
		driver *recordingDriver
	}{
		{name: "panic", driver: &recordingDriver{close: func() { panic(driverSecret) }}},
		{name: "retained connections", driver: &recordingDriver{
			close: func() {}, snapshot: func() DriverStats { return DriverStats{Idle: 1, Total: 1, Maximum: 1} },
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := mustPool(t, test.driver)
			first := pool.Close()
			second := pool.Close()
			if !errors.Is(first, ErrClose) || !errors.Is(second, ErrClose) || strings.Contains(first.Error(), driverSecret) {
				t.Fatalf("Close() errors = %q, %q, want fixed stable close", first, second)
			}
		})
	}
}

func TestZeroPoolFailsClosedWithoutPanic(t *testing.T) {
	t.Parallel()

	var pool Pool
	var value int
	if err := pool.QueryRow(context.Background(), "SELECT 1", nil, &value); !errors.Is(err, ErrClosed) {
		t.Fatalf("zero QueryRow() error = %v, want closed", err)
	}
	if _, err := pool.Health(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("zero Health() error = %v, want closed", err)
	}
	if _, err := pool.Stats(); !errors.Is(err, ErrClosed) {
		t.Fatalf("zero Stats() error = %v, want closed", err)
	}
	if err := pool.Close(); !errors.Is(err, ErrClose) {
		t.Fatalf("zero Close() error = %v, want close", err)
	}
}

func TestClosedStatePrecedesRequestValidation(t *testing.T) {
	t.Parallel()

	pool := mustPool(t, &recordingDriver{})
	if err := pool.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := pool.QueryRow(nil, "", nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("invalid post-close QueryRow() error = %v, want closed", err)
	}
	if _, err := pool.Health(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("invalid post-close Health() error = %v, want closed", err)
	}
}

func validConfig() Config {
	return Config{QueryTimeout: time.Second, HealthTimeout: time.Second}
}

func mustPool(t *testing.T, driver Driver) *Pool {
	t.Helper()
	pool, err := New(driver, validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return pool
}

type recordingRow struct {
	scan func(...any) error
}

func (row recordingRow) Scan(destinations ...any) error {
	if row.scan != nil {
		return row.scan(destinations...)
	}
	return nil
}

type recordingDriver struct {
	mu       sync.Mutex
	query    func(context.Context, string, ...any) Row
	ping     func(context.Context) error
	snapshot func() DriverStats
	close    func()
}

func (driver *recordingDriver) QueryRow(ctx context.Context, statement string, arguments ...any) Row {
	driver.mu.Lock()
	query := driver.query
	driver.mu.Unlock()
	if query != nil {
		return query(ctx, statement, arguments...)
	}
	return recordingRow{}
}

func (driver *recordingDriver) Ping(ctx context.Context) error {
	driver.mu.Lock()
	ping := driver.ping
	driver.mu.Unlock()
	if ping != nil {
		return ping(ctx)
	}
	return nil
}

func (driver *recordingDriver) Stats() DriverStats {
	driver.mu.Lock()
	snapshot := driver.snapshot
	driver.mu.Unlock()
	if snapshot != nil {
		return snapshot()
	}
	return DriverStats{}
}

func (driver *recordingDriver) Close() {
	driver.mu.Lock()
	closeDriver := driver.close
	driver.mu.Unlock()
	if closeDriver != nil {
		closeDriver()
	}
}
