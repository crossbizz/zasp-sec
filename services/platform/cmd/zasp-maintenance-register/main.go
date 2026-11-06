// zasp-maintenance-register installs verifier material through the original
// operator-only registration functions. It cannot activate a maintenance lane.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimepostgres"
)

var errRefused = errors.New("maintenance registration refused")
var principalName = regexp.MustCompile(`^[a-z][a-z0-9_]{2,62}$`)

type registrationConfig struct {
	dsn, connector, approval, connectorFile, approvalFile string
	connectorPin, approvalPin, activationPin              string
}

func main() {
	if len(os.Args) != 1 || run() != nil {
		fmt.Fprintln(os.Stderr, errRefused)
		os.Exit(1)
	}
}

func loadConfig(getenv func(string) string) (registrationConfig, error) {
	c := registrationConfig{dsn: getenv("ZASP_POSTGRES_DSN"), connector: getenv("ZASP_CONNECTOR_MAINTENANCE_DB_PRINCIPAL"), approval: getenv("ZASP_APPROVAL_MAINTENANCE_DB_PRINCIPAL"), connectorFile: getenv("ZASP_CONNECTOR_MAINTENANCE_KEY_FILE"), approvalFile: getenv("ZASP_APPROVAL_MAINTENANCE_KEY_FILE"), connectorPin: getenv("ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM"), approvalPin: getenv("ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM"), activationPin: getenv("ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM")}
	connector, err := migrations.ConnectorMaintenanceProfileChecksum()
	if err != nil {
		return registrationConfig{}, errRefused
	}
	activation, err := migrations.ApprovalActivationProfileChecksum()
	if err != nil || c.dsn == "" || !principalName.MatchString(c.connector) || !principalName.MatchString(c.approval) || c.connector == c.approval || c.connectorFile == c.approvalFile || c.connectorPin != connector || c.approvalPin != migrations.ApprovalMaintenanceProfileChecksum() || c.activationPin != activation {
		return registrationConfig{}, errRefused
	}
	for _, path := range []string{c.connectorFile, c.approvalFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return registrationConfig{}, errRefused
		}
	}
	if _, err := runtimepostgres.ParsePoolConfig(c.dsn); err != nil {
		return registrationConfig{}, errRefused
	}
	return c, nil
}

func run() error {
	c, err := loadConfig(os.Getenv)
	if err != nil {
		return errRefused
	}
	var keys [4][32]byte
	defer func() {
		for i := range keys {
			clear(keys[i][:])
		}
	}()
	for i, path := range []string{c.connectorFile, c.approvalFile} {
		seed, e := readSeed(path)
		if e != nil {
			return errRefused
		}
		copy(keys[i*2][:], seed)
		clear(seed)
		if _, e = rand.Read(keys[i*2+1][:]); e != nil {
			return errRefused
		}
	}
	for i := range keys {
		for j := 0; j < i; j++ {
			if keys[i] == keys[j] {
				return errRefused
			}
		}
	}
	config, err := runtimepostgres.ParsePoolConfig(c.dsn)
	if err != nil {
		return errRefused
	}
	config.MaxConns = 1
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return errRefused
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return errRefused
	}
	if registerKeys(ctx, c, tx, keys) != nil {
		return errRefused
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "registered"})
}

type registrationTransaction interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Commit(context.Context) error
	Rollback(context.Context) error
}

const catalogSQL = `SELECT zasp_connector_maintenance.catalog_ready($1) AND zasp_approval_maintenance.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_approval_maintenance.registration WHERE singleton AND checksum=$2) AND zasp_approval_activation_v1.catalog_ready($3)`

func registerKeys(ctx context.Context, c registrationConfig, tx registrationTransaction, keys [4][32]byte) error {
	defer func() {
		for i := range keys {
			clear(keys[i][:])
		}
	}()
	defer func() {
		rollback, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(rollback)
	}()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE zasp_discovery_authority"); err != nil {
		return errRefused
	}
	check := func() bool {
		var ok bool
		return tx.QueryRow(ctx, catalogSQL, c.connectorPin, c.approvalPin, c.activationPin).Scan(&ok) == nil && ok
	}
	if !check() {
		return errRefused
	}
	version := func(key [32]byte) string { sum := sha256.Sum256(key[:]); return hex.EncodeToString(sum[:]) }
	if _, err := tx.Exec(ctx, `SELECT zasp_connector_maintenance.register_principal($1::name,$2,$3,$4,$5)`, c.connector, version(keys[0]), version(keys[1]), keys[0][:], keys[1][:]); err != nil {
		return errRefused
	}
	var ok bool
	if tx.QueryRow(ctx, `SELECT zasp_approval_maintenance.register_principal($1::name)`, c.approval).Scan(&ok) != nil || !ok {
		return errRefused
	}
	for i, purpose := range []string{"approval-forward", "approval-captured"} {
		if tx.QueryRow(ctx, `SELECT zasp_approval_maintenance.register_verifier($1,$2,$3)`, purpose, version(keys[i+2]), keys[i+2][:]).Scan(&ok) != nil || !ok {
			return errRefused
		}
	}
	if !check() || ctx.Err() != nil || tx.Commit(ctx) != nil {
		return errRefused
	}
	return nil
}

func readSeed(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errRefused
	}
	valid := func(info os.FileInfo) bool {
		if info == nil {
			return false
		}
		s, ok := info.Sys().(*syscall.Stat_t)
		return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0400 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && info.Size() == 32 && s.Nlink == 1 && s.Uid == uint32(os.Geteuid())
	}
	before, err := os.Lstat(path)
	if err != nil || !valid(before) {
		return nil, errRefused
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errRefused
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !valid(opened) || !os.SameFile(before, opened) || before.Mode() != opened.Mode() || !before.ModTime().Equal(opened.ModTime()) {
		return nil, errRefused
	}
	seed, err := io.ReadAll(io.LimitReader(f, 33))
	fd, fdErr := f.Stat()
	closeErr := f.Close()
	after, pathErr := os.Lstat(path)
	if err != nil || fdErr != nil || closeErr != nil || pathErr != nil || len(seed) != 32 || !valid(fd) || !valid(after) || !os.SameFile(opened, fd) || !os.SameFile(opened, after) || fd.Mode() != opened.Mode() || after.Mode() != opened.Mode() || !fd.ModTime().Equal(opened.ModTime()) || !after.ModTime().Equal(opened.ModTime()) {
		clear(seed)
		return nil, errRefused
	}
	return seed, nil
}
