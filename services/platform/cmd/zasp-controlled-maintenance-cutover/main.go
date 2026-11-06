// zasp-controlled-maintenance-cutover observes one owned local writer only.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/connectormaintenancecutover"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimepostgres"
)

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "controlled maintenance cutover refused")
		os.Exit(1)
	}
}
func pins() (map[string]string, error) {
	connector, e := migrations.ConnectorMaintenanceProfileChecksum()
	if e != nil {
		return nil, e
	}
	activation, e := migrations.ApprovalActivationProfileChecksum()
	if e != nil {
		return nil, e
	}
	return map[string]string{"connector_profile_checksum": connector, "approval_profile_checksum": migrations.ApprovalMaintenanceProfileChecksum(), "activation_profile_checksum": activation}, nil
}
func run() error {
	mode := flag.String("mode", "activate", "pins or activate")
	organization := flag.String("organization", "", "canonical product organization")
	pid := flag.Int("old-writer-pid", 0, "exact owned original writer PID")
	flag.Parse()
	if flag.NArg() != 0 || (*mode != "pins" && *mode != "activate") {
		return connectormaintenancecutover.ErrRefused
	}
	p, e := pins()
	if e != nil {
		return connectormaintenancecutover.ErrRefused
	}
	if *mode == "pins" {
		if *organization != "" || *pid != 0 {
			return connectormaintenancecutover.ErrRefused
		}
		return json.NewEncoder(os.Stdout).Encode(p)
	}
	if _, e = domain.ParseProductID(*organization); e != nil || *pid <= 1 {
		return connectormaintenancecutover.ErrRefused
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, 30*time.Second)
	defer cancel()
	pc, e := runtimepostgres.ParsePoolConfig(os.Getenv("ZASP_POSTGRES_DSN"))
	if e != nil || !net.ParseIP(pc.ConnConfig.Host).IsLoopback() {
		return connectormaintenancecutover.ErrRefused
	}
	pc.MaxConns = 1
	pool, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		return connectormaintenancecutover.ErrRefused
	}
	defer pool.Close()
	coordinator, close, e := connectormaintenancecutover.NewCombinedControlled(connectormaintenancecutover.Config{Endpoint: os.Getenv("ZASP_OPENFGA_URL"), StoreID: os.Getenv("ZASP_OPENFGA_STORE_ID"), ModelID: os.Getenv("ZASP_OPENFGA_MODEL_ID"), OldTokenFile: os.Getenv("ZASP_CONTROLLED_OLD_TOKEN_FILE"), NewTokenFile: os.Getenv("ZASP_CONTROLLED_NEW_TOKEN_FILE"), ProfileChecksum: p["connector_profile_checksum"], ApprovalProfileChecksum: p["approval_profile_checksum"], OperatorPool: pool}, p["activation_profile_checksum"])
	if e != nil {
		return e
	}
	defer close()
	permit, e := coordinator.Prepare(ctx, *organization, *pid)
	if e != nil {
		return e
	}
	if e = json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "withdrawal-required"}); e != nil {
		return e
	}
	if e = awaitContinue(ctx, os.Stdin); e != nil {
		return e
	}
	if e = coordinator.Activate(ctx, permit); e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "activated"})
}
func awaitContinue(ctx context.Context, r io.Reader) error {
	result := make(chan bool, 1)
	go func() { b, e := io.ReadAll(io.LimitReader(r, 11)); result <- e == nil && string(b) == "continue\n" }()
	if ctx.Err() != nil {
		return connectormaintenancecutover.ErrRefused
	}
	select {
	case ok := <-result:
		if ok && ctx.Err() == nil {
			return nil
		}
	case <-ctx.Done():
	}
	return connectormaintenancecutover.ErrRefused
}
