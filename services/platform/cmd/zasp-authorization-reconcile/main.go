// zasp-authorization-reconcile performs one bounded, restartable queue pass.
// It neither installs a model nor changes active product configuration.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimepostgres"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	mode := flag.String("mode", "reconcile", "configure or reconcile")
	org := flag.String("organization", "", "canonical product organization ID; required for configure")
	repair := flag.Bool("repair", false, "mark configured organization pending for a full replay")
	limit := flag.Int("limit", 20, "maximum pending organizations in this pass (1..100)")
	timeout := flag.Duration("timeout", 2*time.Minute, "total pass deadline (1s..10m)")
	flag.Parse()
	if flag.NArg() != 0 || (*mode != "configure" && *mode != "reconcile") || *limit < 1 || *limit > 100 || *timeout < time.Second || *timeout > 10*time.Minute || (*repair && *mode != "configure") {
		return authorization.ErrInvalid
	}
	if *org != "" {
		if _, err := domain.ParseProductID(*org); err != nil {
			return authorization.ErrInvalid
		}
	}
	if *mode == "configure" && *org == "" {
		return authorization.ErrInvalid
	}
	config, err := runtimeservices.Load(os.Getenv)
	if err != nil || !config.Enabled {
		return runtimeservices.ErrConfiguration
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, *timeout)
	defer cancel()
	dsn := os.Getenv("ZASP_POSTGRES_DSN")
	if dsn == "" {
		return authorization.ErrInvalid
	}
	poolConfig, err := runtimepostgres.ParsePoolConfig(dsn)
	if err != nil {
		return authorization.ErrInvalid
	}
	poolConfig.MaxConns = 3
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return authorization.ErrUnavailable
	}
	defer pool.Close()
	if *mode == "configure" {
		var data json.RawMessage
		if err := pool.QueryRow(ctx, `SELECT zasp_authorization79.configure($1,$2,$3,$4)`, *org, config.StoreID, config.ModelID, *repair).Scan(&data); err != nil {
			return authorization.ErrUnavailable
		}
		return json.NewEncoder(os.Stdout).Encode(data)
	}
	clients, err := runtimeservices.Connect(ctx, config)
	if err != nil {
		return err
	}
	defer clients.Close()
	repository, err := authorization.NewPostgresProjectionRepository(pool)
	if err != nil {
		return err
	}
	writer, err := authorization.NewOpenFGATupleWriter(clients.FGA, config)
	if err != nil {
		return err
	}
	pending, err := repository.Pending(ctx, *limit)
	if err != nil {
		return err
	}
	if *org != "" {
		selected := authorization.PendingProjection{Revision: authorization.Revision{OrganizationID: *org}}
		for _, item := range pending {
			if item.OrganizationID == *org {
				selected = item
				break
			}
		}
		pending = []authorization.PendingProjection{selected}
	}
	failed := false
	for _, item := range pending {
		receipt, err := authorization.Reconcile(ctx, repository, writer, item.OrganizationID, config.StoreID, config.ModelID)
		state := "applied"
		if err != nil {
			failed = true
			switch {
			case errors.Is(err, authorization.ErrBusy):
				state = "busy"
			case errors.Is(err, authorization.ErrPending):
				state = "pending_configuration"
			case errors.Is(err, authorization.ErrConflict):
				state = "retry_from_current_state"
			case errors.Is(err, authorization.ErrInvalid):
				state = "invalid_source"
			default:
				state = "delivery_failed"
			}
		}
		// A targeted organization may be outside the bounded pending queue.
		// Unknown age is omitted, never reported as the year-one zero time.
		var pendingSince *time.Time
		if !item.PendingSince.IsZero() {
			pendingSince = &item.PendingSince
		}
		if outputErr := json.NewEncoder(os.Stdout).Encode(struct {
			OrganizationID string                          `json:"organization_id"`
			Status         string                          `json:"status"`
			Receipt        authorization.ProjectionReceipt `json:"receipt"`
			PendingSince   *time.Time                      `json:"pending_since,omitempty"`
		}{item.OrganizationID, state, receipt, pendingSince}); outputErr != nil {
			return authorization.ErrUnavailable
		}
		if ctx.Err() != nil {
			return authorization.ErrUnavailable
		}
	}
	if failed {
		return authorization.ErrPending
	}
	return nil
}
