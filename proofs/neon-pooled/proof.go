package main

import (
	"context"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	concurrentReadCount = 10
	readQuery           = "SELECT 1 FROM pg_sleep(0.2)"
	successSummary      = "Neon pooled proof passed: reads=10 acquired=0 closed=true."
)

var (
	dnsLabelPattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	endpointLabelPattern  = regexp.MustCompile(`^ep-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	errConfiguration      = errors.New("database configuration rejected")
	errPoolSetup          = errors.New("pool setup failed")
	errConcurrentReads    = errors.New("concurrent reads failed")
	errReadCount          = errors.New("concurrent read count was not satisfied")
	errMissingOverlap     = errors.New("concurrent read overlap was not observed")
	errAcquiredConnection = errors.New("pool retained an acquired connection")
)

type proofPool interface {
	Read(context.Context) error
	MaximumOverlap() int32
	AcquiredConns() int32
	Close()
}

type poolOpener func(context.Context, string) (proofPool, error)

type readRunResult struct {
	completed int32
	failures  []error
}

type workerResult struct {
	err error
}

func pooledNeonURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.Fragment != "" {
		return "", errConfiguration
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return "", errConfiguration
	}

	hostname := strings.ToLower(parsed.Hostname())
	labels := strings.Split(hostname, ".")
	if len(labels) < 3 || labels[len(labels)-2] != "neon" || labels[len(labels)-1] != "tech" {
		return "", errConfiguration
	}
	for _, label := range labels {
		if !dnsLabelPattern.MatchString(label) {
			return "", errConfiguration
		}
	}

	endpoint := labels[0]
	alreadyPooled := strings.HasSuffix(endpoint, "-pooler")
	baseEndpoint := strings.TrimSuffix(endpoint, "-pooler")
	if !endpointLabelPattern.MatchString(baseEndpoint) || strings.HasSuffix(baseEndpoint, "-pooler") {
		return "", errConfiguration
	}

	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query["sslmode"]) != 1 {
		return "", errConfiguration
	}
	switch query["sslmode"][0] {
	case "require", "verify-ca", "verify-full":
	default:
		return "", errConfiguration
	}

	if !alreadyPooled {
		labels[0] = endpoint + "-pooler"
	}
	pooledHostname := strings.Join(labels, ".")
	if port := parsed.Port(); port != "" {
		parsed.Host = net.JoinHostPort(pooledHostname, port)
	} else {
		parsed.Host = pooledHostname
	}

	return parsed.String(), nil
}

func runConcurrentReads(ctx context.Context, read func(context.Context) error) readRunResult {
	start := make(chan struct{})
	results := make(chan workerResult, concurrentReadCount)
	var ready sync.WaitGroup
	ready.Add(int(concurrentReadCount))

	for range concurrentReadCount {
		go func() {
			ready.Done()
			<-start
			results <- workerResult{err: read(ctx)}
		}()
	}

	ready.Wait()
	close(start)

	result := readRunResult{failures: make([]error, 0, concurrentReadCount)}
	for range concurrentReadCount {
		worker := <-results
		if worker.err != nil {
			result.failures = append(result.failures, worker.err)
			continue
		}
		result.completed++
	}

	return result
}

func executeProof(ctx context.Context, rawURL string, open poolOpener) (string, error) {
	connectionURL, err := pooledNeonURL(rawURL)
	if err != nil {
		return "", errConfiguration
	}

	pool, err := open(ctx, connectionURL)
	if err != nil {
		return "", errPoolSetup
	}
	closed := false
	closePool := func() {
		if !closed {
			pool.Close()
			closed = true
		}
	}
	defer closePool()

	result := runConcurrentReads(ctx, pool.Read)
	acquired := pool.AcquiredConns()

	if len(result.failures) != 0 {
		return "", errConcurrentReads
	}
	if result.completed != concurrentReadCount {
		return "", errReadCount
	}
	if pool.MaximumOverlap() < 2 {
		return "", errMissingOverlap
	}
	if acquired != 0 {
		return "", errAcquiredConnection
	}

	closePool()
	return successSummary, nil
}

type pgxProofPool struct {
	active         atomic.Int32
	maximumOverlap atomic.Int32
	pool           *pgxpool.Pool
}

func openPGXPool(ctx context.Context, connectionURL string) (proofPool, error) {
	config, err := pgxpool.ParseConfig(connectionURL)
	if err != nil {
		return nil, err
	}
	config.MaxConns = concurrentReadCount
	config.MinConns = 0
	config.MinIdleConns = 0
	config.MaxConnIdleTime = 30 * time.Second
	config.MaxConnLifetime = 5 * time.Minute
	config.HealthCheckPeriod = 15 * time.Second
	config.ConnConfig.ConnectTimeout = 10 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	return &pgxProofPool{pool: pool}, nil
}

func (pool *pgxProofPool) Read(ctx context.Context) error {
	connection, err := pool.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	current := pool.active.Add(1)
	updateAtomicMaximum(&pool.maximumOverlap, current)
	defer func() {
		pool.active.Add(-1)
		connection.Release()
	}()

	var value int
	if err := connection.QueryRow(ctx, readQuery).Scan(&value); err != nil {
		return err
	}
	if value != 1 {
		return errors.New("unexpected read result")
	}
	return nil
}

func (pool *pgxProofPool) MaximumOverlap() int32 {
	return pool.maximumOverlap.Load()
}

func (pool *pgxProofPool) AcquiredConns() int32 {
	return pool.pool.Stat().AcquiredConns()
}

func (pool *pgxProofPool) Close() {
	pool.pool.Close()
}

func updateAtomicMaximum(maximum *atomic.Int32, candidate int32) {
	for {
		current := maximum.Load()
		if candidate <= current || maximum.CompareAndSwap(current, candidate) {
			return
		}
	}
}
