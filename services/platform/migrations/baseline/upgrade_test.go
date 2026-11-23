package baseline

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

//go:embed testdata/v2_predecessor_seed.sql
var predecessorSeed string

//go:embed testdata/v2_predecessor_snapshot.sql
var predecessorSnapshot string

// The test script compiles the same API contract against both source trees.
// Keep each process (and its service connections) alive across the transition.
type releaseProbe struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Reader
}

func startReleaseProbe(t *testing.T, ctx context.Context, executable string) *releaseProbe {
	t.Helper()
	p := &releaseProbe{cmd: exec.CommandContext(ctx, executable, "-test.run=^TestPinnedReleaseDatabaseContract$")}
	input, err := p.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := p.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p.cmd.Stderr = os.Stderr
	p.input, p.output = input, bufio.NewReader(output)
	if err = p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if p.input != nil {
			_ = p.stop()
		}
	})
	return p
}

func (p *releaseProbe) read() error {
	if _, err := io.WriteString(p.input, "read\n"); err != nil {
		return err
	}
	response, err := p.output.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read probe result: %w", err)
	}
	if response != "SCOPED_READS_OK\n" {
		detail, _ := io.ReadAll(io.LimitReader(p.output, 4096))
		return fmt.Errorf("API contract failed: %s%s", strings.TrimSpace(response), detail)
	}
	return nil
}

func (p *releaseProbe) stop() error {
	err := p.input.Close()
	p.input = nil
	if waitErr := p.cmd.Wait(); waitErr != nil {
		return waitErr
	}
	return err
}

// Supply a disposable database freshly installed from the exact previous release.
func TestV2UpgradePopulatedBaseline(t *testing.T) {
	dsn := os.Getenv("ZASP_V2_UPGRADE_TEST_DSN")
	if dsn == "" {
		t.Skip("run scripts/test-feature-v2-upgrade.sh against its disposable cluster")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	t.Cleanup(cancel)
	connect := func(dsn string) *pgx.Conn {
		t.Helper()
		c, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	conn, admin := connect(dsn), connect(os.Getenv("ZASP_V2_UPGRADE_ADMIN_TEST_DSN"))
	state, err := Verify(ctx, conn)
	if err != nil || state.Artifact != precedingV2Artifact || !state.Intact {
		t.Fatal("fixture must be the intact predecessor", err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, predecessorSeed, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal("restoring predecessor data:", err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	key, err := authorization.NewAttestationKey(bytes.Repeat([]byte{0x47}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, "SELECT zasp_authorization80.register_verifier($1,$2)", key.Version(), key.Verifier()); err != nil {
		t.Fatal(err)
	}
	// Register the ephemeral identity issuers as a configured predecessor
	// deployment would. Every subsequent token admission uses its service role.
	identitySeed := bytes.Repeat([]byte{0x63}, 32)
	session, err := authorization.NewIdentitySessionKey(identitySeed)
	if err != nil {
		t.Fatal(err)
	}
	webhook, err := authorization.NewIdentityWebhookKey(identitySeed)
	if err != nil {
		t.Fatal(err)
	}
	audience := sha256.Sum256([]byte("https://upgrade-rehearsal.invalid"))
	for statement, issuer := range map[string][2]any{
		"SELECT zasp_authorization80_identity.register_session($1,$2,$3,$4,$5,$6)": {session.Version(), session.Verifier()},
		"SELECT zasp_authorization80_identity.register_webhook($1,$2,$3,$4,$5,$6)": {webhook.Version(), webhook.Verifier()},
	} {
		if _, err := conn.Exec(ctx, statement, issuer[0], issuer[1], hex.EncodeToString(audience[:]), "project-upgrade-rehearsal", "zasp_svc_api", ""); err != nil {
			t.Fatal("registering fixture issuer:", err)
		}
	}
	snapshot := func() []string {
		t.Helper()
		rows, err := admin.Query(ctx, predecessorSnapshot)
		if err != nil {
			t.Fatal(err)
		}
		all, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil || len(all) != 2 {
			t.Fatalf("expected complete historical records for two tenants: %d, %v", len(all), err)
		}
		return all
	}
	before := snapshot()
	unchanged := func() {
		t.Helper()
		if !slices.Equal(before, snapshot()) {
			t.Fatal("historical identity, credential, policy, decision or export changed")
		}
	}
	oldPath := os.Getenv("ZASP_V2_UPGRADE_PREDECESSOR_API")
	old := startReleaseProbe(t, ctx, oldPath)
	if err := old.read(); err != nil {
		t.Fatalf("before upgrade: %v", err)
	}
	const injected = "injected readiness failure"
	var failure *StageError
	err = UpgradeToV2(ctx, conn, Check{Name: injected, SQL: "SELECT false"})
	if !errors.As(err, &failure) || failure.Stage != StageVerification || failure.Reason != injected || failure.Err != nil {
		t.Fatalf("expected injected failure at final verification: %v", err)
	}
	var rolledBack bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('public.zasp_addon_versions') IS NULL").Scan(&rolledBack); err != nil || !rolledBack {
		t.Fatal("V2 DDL survived the failed transaction", err)
	}
	state, err = Verify(ctx, conn)
	if err != nil || !state.Intact || state.Artifact != precedingV2Artifact {
		t.Fatal("prior catalog not restored", err)
	}
	unchanged()
	if err := old.read(); err != nil {
		t.Fatalf("after failed upgrade: %v", err)
	}
	var current *releaseProbe
	for pass := 1; pass <= 2; pass++ {
		if err = UpgradeToV2(ctx, conn, Check{Name: "V2 registry", SQL: "SELECT to_regclass('public.zasp_addon_versions') IS NOT NULL"}); err != nil {
			t.Fatalf("upgrade %d: %v, %v", pass, err, unwrapUpgrade(err))
		}
		state, err = Verify(ctx, conn)
		if err != nil || !state.Current || !state.Intact {
			t.Fatalf("verification %v, %v", state, err)
		}
		if current == nil {
			current = startReleaseProbe(t, ctx, os.Getenv("ZASP_V2_UPGRADE_CANDIDATE_API"))
		}
		priorResult := make(chan error, 1)
		go func() { priorResult <- old.read() }()
		currentErr := current.read()
		if err := <-priorResult; err != nil || currentErr != nil {
			t.Fatalf("coexisting APIs on pass %d: prior=%v current=%v", pass, err, currentErr)
		}
		unchanged()
	}
	if err := current.stop(); err != nil {
		t.Fatal(err)
	}
	if err := old.stop(); err != nil {
		t.Fatal(err)
	}
	restarted := startReleaseProbe(t, ctx, oldPath)
	if err := restarted.read(); err != nil {
		t.Fatalf("restart predecessor against upgraded data: %v", err)
	}
	if err := restarted.stop(); err != nil {
		t.Fatal(err)
	}
	unchanged()
}

func unwrapUpgrade(err error) error {
	if stage, ok := err.(*StageError); ok {
		return stage.Err
	}
	return err
}
