package baseline

import (
	"context"
	"github.com/jackc/pgx/v5"
	"os"
	"testing"
	"time"
)

// Supply a disposable database freshly cloned from the previous sealed release.
// The intentionally failed first upgrade must preserve both the seal and row.
func TestV2UpgradePopulatedBaseline(t *testing.T) {
	dsn := os.Getenv("ZASP_V2_UPGRADE_TEST_DSN")
	if dsn == "" {
		t.Skip("needs a disposable clone of the previous release")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	state, err := Verify(ctx, conn)
	if err != nil || state.Artifact != precedingV2Artifact || !state.Intact {
		t.Fatal("fixture must be the intact predecessor", err)
	}
	const org = "pid_deafbeef-0000-4000-8000-000000000009"
	_, err = conn.Exec(ctx, `INSERT INTO public.zasp_organizations(id,name,domain) VALUES ($1,'Upgrade fixture','fixture.invalid')`, org)
	if err != nil {
		t.Fatal(err)
	}
	if UpgradeToV2(ctx, conn, Check{Name: "injected readiness failure", SQL: "SELECT false"}) == nil {
		t.Fatal("failed check committed")
	}
	state, err = Verify(ctx, conn)
	if err != nil || !state.Intact || state.Artifact != precedingV2Artifact {
		t.Fatal("prior catalog not restored", err)
	}
	for i := 0; i < 2; i++ {
		if err = UpgradeToV2(ctx, conn, Check{Name: "V2 registry", SQL: "SELECT to_regclass('public.zasp_addon_versions') IS NOT NULL"}); err != nil {
			t.Fatalf("upgrade %d: %v, %v", i, err, unwrapUpgrade(err))
		}
		state, err = Verify(ctx, conn)
		if err != nil || !state.Current || !state.Intact {
			t.Fatalf("verification %v, %v", state, err)
		}
		var name string
		if err = conn.QueryRow(ctx, `SELECT name FROM public.zasp_organizations WHERE id=$1`, org).Scan(&name); err != nil || name != "Upgrade fixture" {
			t.Fatal("prior organization lost", err)
		}
	}
}
func unwrapUpgrade(err error) error {
	if stage, ok := err.(*StageError); ok {
		return stage.Err
	}
	return err
}
