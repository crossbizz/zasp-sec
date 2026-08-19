package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func buildRuntimeDependencies(ctx context.Context, config RuntimeConfig) (RuntimeDependencies, error) {
	connectCtx, cancel := context.WithTimeout(ctx, config.ProviderTimeout)
	defer cancel()
	poolConfig, err := pgxpool.ParseConfig(config.PostgresDSN)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	poolConfig.MaxConns = 20
	poolConfig.MinConns = 2
	poolConfig.HealthCheckPeriod = config.ProviderTimeout
	pool, err := pgxpool.NewWithConfig(connectCtx, poolConfig)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	if err := pool.Ping(connectCtx); err != nil {
		pool.Close()
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	database, err := apiserver.NewPostgresJSONDatabase(&pgxProductionDriver{pool: pool})
	if err != nil {
		pool.Close()
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	authenticator, err := apiserver.NewStytchOAuthAuthenticator(config.StytchBaseURL, config.StytchProjectID, config.StytchSecret, config.ProviderTimeout, func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) })
	if err != nil {
		_ = database.Close()
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := apiserver.NewPostgresRepository(database)
	if err != nil {
		_ = database.Close()
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	provider, err := apiserver.NewRepositoryIdentityProviderWithStart(authenticator, repository, repository, config.StytchAuthorizeURL, config.StytchPublicToken, config.StytchOrganizationID, config.PublicOrigin+"/auth/callback")
	if err != nil {
		_ = database.Close()
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	dependencies, err := composeRuntimeDependencies(config, database, provider)
	if err != nil {
		_ = database.Close()
		return RuntimeDependencies{}, err
	}
	dependencies.Closers = []io.Closer{database}
	return dependencies, nil
}

func composeRuntimeDependencies(config RuntimeConfig, database apiserver.JSONDatabase, provider apiserver.CallbackProvider) (RuntimeDependencies, error) {
	repository, err := apiserver.NewPostgresRepository(database)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	handlers, authenticate, err := apiserver.NewProductionHandlers(repository, provider, apiserver.CookiePolicy{Secure: config.CookieSecure})
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	composition, err := apiserver.NewComposition(handlers)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	product, err := apiserver.NewProductMiddleware(apiserver.ProductSecurity{
		PublicOrigin: config.PublicOrigin, MaximumBodyBytes: 16 * 1024, Authenticate: authenticate, GenerateCorrelationID: generateCorrelationID,
	}, composition)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	return RuntimeDependencies{ProductHandler: product, ReadinessCheck: func(ctx context.Context) error {
		if err := repository.Ready(ctx); err != nil {
			return errRuntimeUnavailable
		}
		if err := provider.Ready(ctx); err != nil {
			return errRuntimeUnavailable
		}
		return nil
	}, Stores: []StoreDependency{{Name: "postgres-core", Durable: true}}}, nil
}

func generateCorrelationID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return ""
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value)
	return "pid_" + encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

type pgxProductionDriver struct{ pool *pgxpool.Pool }

func (driver *pgxProductionDriver) QueryRow(ctx context.Context, statement string, arguments ...any) apiserver.PostgresRow {
	if driver == nil || driver.pool == nil {
		return unavailablePostgresRow{}
	}
	return driver.pool.QueryRow(ctx, statement, arguments...)
}
func (driver *pgxProductionDriver) Exec(ctx context.Context, statement string, arguments ...any) error {
	if driver == nil || driver.pool == nil {
		return errors.New("database unavailable")
	}
	_, err := driver.pool.Exec(ctx, statement, arguments...)
	return err
}
func (driver *pgxProductionDriver) Close() error {
	if driver != nil && driver.pool != nil {
		driver.pool.Close()
	}
	return nil
}

type unavailablePostgresRow struct{}

func (unavailablePostgresRow) Scan(...any) error { return errors.New("database unavailable") }
