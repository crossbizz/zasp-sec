package main

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	concurrentReadCount = 10
	readQuery           = "SELECT 1 FROM pg_sleep(0.2)"
	successSummary      = "Neon pooled proof passed: reads=10 acquired=0 closed=true."
)

var (
	dnsLabelPattern        = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	endpointLabelPattern   = regexp.MustCompile(`^ep-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	errConfiguration       = errors.New("database configuration rejected")
	errPoolSetup           = errors.New("pool setup failed")
	errConcurrentReads     = errors.New("concurrent reads failed")
	errReadCount           = errors.New("concurrent read count was not satisfied")
	errMissingOverlap      = errors.New("concurrent read overlap was not observed")
	errAcquiredConnection  = errors.New("pool retained an acquired connection")
	errWorkerPanic         = errors.New("worker failed internally")
	pgEnvironmentVariables = []string{
		"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
		"PGAPPNAME", "PGCONNECT_TIMEOUT", "PGSSLMODE", "PGSSLKEY", "PGSSLCERT",
		"PGSSLSNI", "PGSSLROOTCERT", "PGSSLPASSWORD", "PGSSLNEGOTIATION",
		"PGTARGETSESSIONATTRS", "PGSERVICE", "PGSERVICEFILE", "PGTZ", "PGOPTIONS",
		"PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION", "PGCHANNELBINDING", "PGREQUIREAUTH",
	}
)

type proofPool interface {
	Read(context.Context) error
	MaximumOverlap() int32
	AcquiredConns() int32
	Close()
}

type poolOpener func(context.Context, validatedConnection) (proofPool, error)

type expectedPGXDestination struct {
	channelBinding string
	database       string
	host           string
	password       string
	port           uint16
	user           string
}

type validatedConnection struct {
	config   *pgx.ConnConfig
	expected expectedPGXDestination
}

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
	if parsed.User == nil || parsed.User.Username() == "" || strings.TrimLeft(parsed.Path, "/") == "" {
		return "", errConfiguration
	}
	password, passwordPresent := parsed.User.Password()
	if !passwordPresent || password == "" || strings.Contains(parsed.Host, ",") {
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
	for key, values := range query {
		switch key {
		case "sslmode":
		case "channel_binding":
			if len(values) != 1 || values[0] != "require" {
				return "", errConfiguration
			}
		default:
			return "", errConfiguration
		}
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
			result := workerResult{}
			func() {
				defer func() {
					if recover() != nil {
						result.err = errWorkerPanic
					}
				}()
				result.err = read(ctx)
			}()
			results <- result
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
	target, err := validatedPGXConnection(rawURL)
	if err != nil {
		return "", errConfiguration
	}

	pool, err := open(ctx, target)
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

func pgEnvironmentConfigured() bool {
	for _, variable := range pgEnvironmentVariables {
		if os.Getenv(variable) != "" {
			return true
		}
	}
	return false
}

func validatedPGXConnection(raw string) (validatedConnection, error) {
	if pgEnvironmentConfigured() {
		return validatedConnection{}, errConfiguration
	}
	pooledURL, err := pooledNeonURL(raw)
	if err != nil {
		return validatedConnection{}, errConfiguration
	}

	parsed, err := url.Parse(pooledURL)
	if err != nil {
		return validatedConnection{}, errConfiguration
	}
	password, passwordPresent := parsed.User.Password()
	if !passwordPresent {
		return validatedConnection{}, errConfiguration
	}
	port := uint64(5432)
	if explicitPort := parsed.Port(); explicitPort != "" {
		port, err = strconv.ParseUint(explicitPort, 10, 16)
		if err != nil || port == 0 {
			return validatedConnection{}, errConfiguration
		}
	}
	channelBinding := "prefer"
	if parsed.Query().Get("channel_binding") == "require" {
		channelBinding = "require"
	}
	expected := expectedPGXDestination{
		channelBinding: channelBinding,
		database:       strings.TrimLeft(parsed.Path, "/"),
		host:           parsed.Hostname(),
		password:       password,
		port:           uint16(port),
		user:           parsed.User.Username(),
	}

	query := url.Values{
		"passfile":    {""},
		"sslcert":     {""},
		"sslkey":      {""},
		"sslmode":     {"verify-full"},
		"sslrootcert": {""},
	}
	if channelBinding == "require" {
		query.Set("channel_binding", "require")
	}
	parsed.RawQuery = query.Encode()

	config, err := pgx.ParseConfigWithOptions(parsed.String(), pgx.ParseConfigOptions{
		ParseConfigOptions: pgconn.ParseConfigOptions{
			ConnStringAllowedKeys: []string{
				"host", "port", "user", "password", "database", "sslmode",
				"channel_binding", "passfile", "sslcert", "sslkey", "sslrootcert",
			},
		},
	})
	if err != nil || validateEffectivePGXConfig(config, expected) != nil {
		return validatedConnection{}, errConfiguration
	}
	return validatedConnection{config: config, expected: expected}, nil
}

func validateEffectivePGXConfig(config *pgx.ConnConfig, expected expectedPGXDestination) error {
	if config == nil ||
		config.Host != expected.host ||
		config.Port != expected.port ||
		config.User != expected.user ||
		config.Password != expected.password ||
		config.Database != expected.database ||
		config.ChannelBinding != expected.channelBinding ||
		config.TLSConfig == nil ||
		config.TLSConfig.ServerName != expected.host ||
		config.TLSConfig.InsecureSkipVerify ||
		config.TLSConfig.VerifyPeerCertificate != nil ||
		config.TLSConfig.VerifyConnection != nil ||
		len(config.TLSConfig.Certificates) != 0 ||
		config.TLSConfig.GetClientCertificate != nil ||
		config.TLSConfig.RootCAs != nil ||
		config.TLSConfig.ClientCAs != nil ||
		len(config.Fallbacks) != 0 ||
		len(config.RuntimeParams) != 0 ||
		config.SSLNegotiation != "" ||
		config.ValidateConnect != nil ||
		config.AfterConnect != nil ||
		config.AfterNetConnect != nil ||
		config.OAuthTokenProvider != nil ||
		config.KerberosSrvName != "" ||
		config.KerberosSpn != "" ||
		config.RequireAuth != "" {
		return errConfiguration
	}
	return nil
}

type pgxProofPool struct {
	active         atomic.Int32
	maximumOverlap atomic.Int32
	pool           *pgxpool.Pool
}

func preparePGXPoolConfig(target validatedConnection) (*pgxpool.Config, error) {
	if pgEnvironmentConfigured() || validateEffectivePGXConfig(target.config, target.expected) != nil {
		return nil, errConfiguration
	}
	config, err := pgxpool.ParseConfig(target.config.ConnString())
	if err != nil {
		return nil, errConfiguration
	}
	if pgEnvironmentConfigured() {
		return nil, errConfiguration
	}
	config.ConnConfig = target.config.Copy()
	config.MaxConns = concurrentReadCount
	config.MinConns = 0
	config.MinIdleConns = 0
	config.MaxConnIdleTime = 30 * time.Second
	config.MaxConnLifetime = 5 * time.Minute
	config.HealthCheckPeriod = 15 * time.Second
	config.ConnConfig.ConnectTimeout = 10 * time.Second
	config.BeforeConnect = func(_ context.Context, connectionConfig *pgx.ConnConfig) error {
		return validateEffectivePGXConfig(connectionConfig, target.expected)
	}
	if err := validateEffectivePGXConfig(config.ConnConfig, target.expected); err != nil {
		return nil, errConfiguration
	}
	return config, nil
}

func openPGXPool(ctx context.Context, target validatedConnection) (proofPool, error) {
	config, err := preparePGXPoolConfig(target)
	if err != nil {
		return nil, err
	}
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
