package baseline

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestArtifactMatchesRecordedChecksum(t *testing.T) {
	artifact, err := loadArtifact()
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	for _, required := range []string{"CREATE SCHEMA zasp_baseline;", "CREATE FUNCTION zasp_baseline.intact()", "zasp_schema_versions"} {
		if !strings.Contains(artifact, required) {
			t.Fatalf("artifact lacks %q", required)
		}
	}
	// pg_dump psql directives and COPY blocks cannot be sent over the wire.
	for _, line := range strings.Split(artifact, "\n") {
		if strings.HasPrefix(line, `\`) || strings.HasPrefix(line, "COPY ") {
			t.Fatalf("artifact has a line the installer cannot execute: %q", line)
		}
	}
}

func TestPlanTransfersOwnershipThroughTemporaryGrants(t *testing.T) {
	artifact, err := loadArtifact()
	if err != nil {
		t.Fatal(err)
	}
	steps, err := buildPlan(artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(steps.objects, "\n") {
		if ownerStatement.MatchString(line) {
			t.Fatalf("object pass still transfers ownership: %s", line)
		}
	}
	if len(steps.owners) == 0 || len(steps.roles) < 2 {
		t.Fatalf("owners=%d roles=%v", len(steps.owners), steps.roles)
	}
	for _, role := range steps.roles {
		if !regexp.MustCompile(`^zasp_[a-z0-9_]+$`).MatchString(role) || role == Operator {
			t.Fatalf("unexpected owner role %q", role)
		}
	}
	// The scripts revoke exactly what they grant, and never the operator's
	// permanent authority membership.
	if !strings.Contains(grantScript, "zasp_baseline_temporary_grants") || !strings.Contains(revokeScript, "zasp_baseline_temporary_grants") ||
		strings.Count(grantScript, "<> 'zasp_discovery_authority'") != 1 || strings.Count(revokeScript, "<> 'zasp_discovery_authority'") != 1 {
		t.Fatal("temporary grant scripts do not mirror each other")
	}
	for _, statement := range steps.owners {
		if strings.HasSuffix(statement, " OWNER TO "+Operator+";") {
			t.Fatalf("ownership pass assigns the operator: %s", statement)
		}
	}
}

func TestRoleScriptIsLeastPrivilege(t *testing.T) {
	sawAuthority := false
	for _, line := range strings.Split(roleScript, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !roleStatement.MatchString(line) {
			t.Fatalf("unexpected role statement: %s", line)
		}
		upper := " " + strings.ToUpper(line) + " "
		for _, forbidden := range []string{" SUPERUSER", " REPLICATION", " BYPASSRLS", " PASSWORD", " CREATEROLE", " CREATEDB"} {
			if strings.Contains(upper, forbidden) {
				t.Fatalf("role statement grants %s: %s", strings.TrimSpace(forbidden), line)
			}
		}
		if strings.Contains(line, "ROLE "+Operator+" ") || strings.Contains(line, "ROLE "+Operator+";") {
			t.Fatalf("role script alters the operator: %s", line)
		}
		if line == "GRANT "+Authority+" TO "+Operator+" WITH INHERIT TRUE, SET TRUE;" {
			sawAuthority = true
		}
	}
	if !sawAuthority {
		t.Fatal("role script does not give the operator its authority membership")
	}
}

// TestInstallOnNonSuperuserDatabase needs ZASP_BASELINE_TEST_DSN: a connection
// as the zasp_operator role (CREATEROLE, BYPASSRLS, not superuser) to an empty
// database it owns, with C collation.
func TestInstallOnNonSuperuserDatabase(t *testing.T) {
	dsn := os.Getenv("ZASP_BASELINE_TEST_DSN")
	if dsn == "" {
		t.Skip("ZASP_BASELINE_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var super bool
	if err := conn.QueryRow(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname=current_user`).Scan(&super); err != nil || super {
		t.Fatalf("the test needs a non-superuser operator: super=%v err=%v", super, err)
	}
	if err := Install(ctx, conn); err != nil {
		t.Fatalf("install: %v (%v)", err, errors.Unwrap(err))
	}
	state, err := Verify(ctx, conn)
	if err != nil || !state.Sealed || !state.Intact || !state.Current {
		t.Fatalf("verify: %+v %v", state, err)
	}
	// No temporary privilege survives the installation.
	var leftovers int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM zasp_baseline.role_memberships m WHERE m.member=$1::regrole AND m.roleid<>$2::regrole`, Operator, Authority).Scan(&leftovers); err != nil || leftovers != 0 {
		t.Fatalf("operator keeps %d temporary memberships (%v)", leftovers, err)
	}
	// Every schema owner can still create in its own schema, and no role
	// kept a CREATE privilege it was lent for the ownership pass.
	var ownersWithoutCreate, lentCreate int
	if err := conn.QueryRow(ctx, `SELECT count(*) FILTER (WHERE NOT has_schema_privilege(n.nspowner, n.oid, 'CREATE')),
		(SELECT count(*) FROM pg_namespace s CROSS JOIN LATERAL aclexplode(s.nspacl) a JOIN pg_roles g ON g.oid=a.grantee
		 WHERE s.nspname LIKE 'zasp\_%' AND a.privilege_type='CREATE' AND a.grantee<>s.nspowner AND g.rolname LIKE 'zasp\_%authority')
		FROM pg_namespace n WHERE n.nspname LIKE 'zasp\_%'`).Scan(&ownersWithoutCreate, &lentCreate); err != nil || ownersWithoutCreate != 0 {
		t.Fatalf("schema owners without CREATE=%d err=%v", ownersWithoutCreate, err)
	}
	t.Logf("non-owner authority CREATE grants carried from the reference: %d", lentCreate)
	var open bool
	if err := conn.QueryRow(ctx, `SELECT zasp_authorization80_worker.runtime_ready()`).Scan(&open); err != nil || !open {
		t.Fatalf("worker gate: open=%v err=%v", open, err)
	}
	// A second installation is refused before anything is written.
	var staged *StageError
	if err := Install(ctx, conn); !errors.As(err, &staged) || staged.Stage != StagePreconditions {
		t.Fatalf("second install: %v", err)
	}
	// Any change to a product function breaks the seal, closes the gate and
	// cannot be re-sealed.
	if _, err := conn.Exec(ctx, `SET ROLE `+Authority); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `CREATE OR REPLACE FUNCTION zasp_baseline.state() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$ SELECT '{"sealed":true,"intact":true}'::jsonb $$`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := conn.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	var intact bool
	if err := conn.QueryRow(ctx, `SELECT zasp_baseline.intact()`).Scan(&intact); err != nil || intact {
		t.Fatalf("tampered catalog reported intact=%v err=%v", intact, err)
	}
	if err := conn.QueryRow(ctx, `SELECT zasp_authorization80_worker.runtime_ready()`).Scan(&open); err != nil || open {
		t.Fatalf("worker gate stayed open on a tampered catalog: open=%v err=%v", open, err)
	}
	if _, err := conn.Exec(ctx, `SELECT zasp_baseline.seal($1)`, Checksum()); err == nil {
		t.Fatal("a tampered catalog was re-sealed")
	}
}
