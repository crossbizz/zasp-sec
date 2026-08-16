package database

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maximumOperationTimeout = 30 * time.Second
	maximumStatementBytes   = 64 * 1024
)

var (
	ErrConfiguration = errors.New("database pool configuration rejected")
	ErrQuery         = errors.New("database query failed")
	ErrHealth        = errors.New("database health check failed")
	ErrStats         = errors.New("database pool statistics rejected")
	ErrClosed        = errors.New("database pool is closed")
	ErrClose         = errors.New("database pool close failed")
)

type Config struct {
	QueryTimeout  time.Duration
	HealthTimeout time.Duration
}

type Row interface {
	Scan(...any) error
}

type Driver interface {
	QueryRow(context.Context, string, ...any) Row
	Ping(context.Context) error
	Stats() DriverStats
	Close()
}

type DriverStats struct {
	InUse             int32
	Idle              int32
	Constructing      int32
	Total             int32
	Maximum           int32
	WaitCount         int64
	CanceledWaitCount int64
	WaitDuration      time.Duration
}

type Stats struct {
	InUse             int32
	Idle              int32
	Constructing      int32
	Total             int32
	Maximum           int32
	WaitCount         int64
	CanceledWaitCount int64
	WaitDuration      time.Duration
	Closed            bool
}

type Pool struct {
	mu             sync.RWMutex
	driver         Driver
	config         Config
	closeAttempted bool
	closed         bool
	closeErr       error
	finalStats     Stats
}

func New(driver Driver, config Config) (*Pool, error) {
	if nilInterface(driver) || !validTimeout(config.QueryTimeout) || !validTimeout(config.HealthTimeout) {
		return nil, ErrConfiguration
	}
	return &Pool{driver: driver, config: config}, nil
}

func (pool *Pool) QueryRow(ctx context.Context, statement string, arguments []any, destinations ...any) (resultErr error) {
	if pool == nil {
		return ErrClosed
	}

	pool.mu.RLock()
	defer pool.mu.RUnlock()
	if pool.closed || nilInterface(pool.driver) {
		return ErrClosed
	}
	if ctx == nil || !validStatement(statement) || len(destinations) == 0 {
		return ErrQuery
	}
	defer func() {
		if recover() != nil {
			resultErr = ErrQuery
		}
	}()

	queryCtx, cancel := context.WithTimeout(ctx, pool.config.QueryTimeout)
	defer cancel()
	if queryCtx.Err() != nil {
		return ErrQuery
	}
	row := pool.driver.QueryRow(queryCtx, statement, arguments...)
	if nilInterface(row) {
		return ErrQuery
	}
	if err := row.Scan(destinations...); err != nil || queryCtx.Err() != nil {
		return ErrQuery
	}
	return nil
}

func (pool *Pool) Health(ctx context.Context) (Stats, error) {
	if pool == nil {
		return Stats{}, ErrClosed
	}

	pool.mu.RLock()
	defer pool.mu.RUnlock()
	if pool.closed || nilInterface(pool.driver) {
		return Stats{}, ErrClosed
	}
	if ctx == nil {
		return Stats{}, ErrHealth
	}
	healthCtx, cancel := context.WithTimeout(ctx, pool.config.HealthTimeout)
	defer cancel()
	if healthCtx.Err() != nil {
		return Stats{}, ErrHealth
	}
	if err := pingDriver(pool.driver, healthCtx); err != nil || healthCtx.Err() != nil {
		return Stats{}, ErrHealth
	}
	return readStats(pool.driver, false)
}

func (pool *Pool) Stats() (Stats, error) {
	if pool == nil {
		return Stats{}, ErrClosed
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	if pool.closed {
		return pool.finalStats, pool.closeErr
	}
	if nilInterface(pool.driver) {
		return Stats{}, ErrClosed
	}
	return readStats(pool.driver, false)
}

func (pool *Pool) Close() error {
	if pool == nil {
		return ErrClose
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.closeAttempted {
		return pool.closeErr
	}
	pool.closeAttempted = true
	pool.closed = true
	pool.finalStats = Stats{Closed: true}
	if nilInterface(pool.driver) {
		pool.closeErr = ErrClose
		return pool.closeErr
	}
	if err := closeDriver(pool.driver); err != nil {
		pool.closeErr = ErrClose
		return pool.closeErr
	}
	stats, err := readStats(pool.driver, true)
	pool.finalStats = stats
	if err != nil || stats.InUse != 0 || stats.Idle != 0 || stats.Constructing != 0 || stats.Total != 0 {
		pool.closeErr = ErrClose
	}
	return pool.closeErr
}

func validTimeout(value time.Duration) bool {
	return value > 0 && value <= maximumOperationTimeout
}

func validStatement(statement string) bool {
	return len(statement) > 0 && len(statement) <= maximumStatementBytes &&
		utf8.ValidString(statement) && strings.TrimSpace(statement) == statement &&
		!strings.ContainsRune(statement, '\x00')
}

func readStats(driver Driver, closed bool) (Stats, error) {
	raw, err := driverStats(driver)
	if err != nil {
		return Stats{Closed: closed}, ErrStats
	}
	stats := Stats{
		InUse: raw.InUse, Idle: raw.Idle, Constructing: raw.Constructing,
		Total: raw.Total, Maximum: raw.Maximum, WaitCount: raw.WaitCount,
		CanceledWaitCount: raw.CanceledWaitCount, WaitDuration: raw.WaitDuration,
		Closed: closed,
	}
	if !validStats(stats) {
		return Stats{Closed: closed}, ErrStats
	}
	return stats, nil
}

func validStats(stats Stats) bool {
	if stats.InUse < 0 || stats.Idle < 0 || stats.Constructing < 0 || stats.Total < 0 || stats.Maximum < 0 ||
		stats.WaitCount < 0 || stats.CanceledWaitCount < 0 || stats.WaitDuration < 0 ||
		stats.CanceledWaitCount > stats.WaitCount {
		return false
	}
	totalParts := int64(stats.InUse) + int64(stats.Idle) + int64(stats.Constructing)
	return totalParts == int64(stats.Total) && stats.Total <= stats.Maximum &&
		(stats.WaitCount != 0 || stats.WaitDuration == 0)
}

func pingDriver(driver Driver, ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrHealth
		}
	}()
	if err := driver.Ping(ctx); err != nil {
		return ErrHealth
	}
	return nil
}

func driverStats(driver Driver) (stats DriverStats, resultErr error) {
	defer func() {
		if recover() != nil {
			stats = DriverStats{}
			resultErr = ErrStats
		}
	}()
	return driver.Stats(), nil
}

func closeDriver(driver Driver) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrClose
		}
	}()
	driver.Close()
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
