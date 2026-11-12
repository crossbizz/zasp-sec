// Package baseline installs the product schema on a database whose owner is
// not a PostgreSQL superuser.
//
// The artifact is generated from the historical migration chain by
// generate.sh. Install replays it in one transaction: it creates the product
// roles, creates every object as the operator, hands each object to its owner
// role through memberships it holds only for the duration of the transaction,
// and seals the resulting catalog. See prelude.sql for the integrity model.
package baseline

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Operator is the role that installs and owns the baseline. The artifact
// records it as grantor and as the owner of the objects no product role owns,
// so the name is fixed.
const Operator = "zasp_operator"

// Authority is the role that owns the integrity schema and the registration
// functions. The operator keeps an INHERIT, SET membership in it.
const Authority = "zasp_discovery_authority"

//go:embed baseline.sql.gz
var compressedArtifact []byte

//go:embed roles.sql
var roleScript string

//go:embed baseline.sha256
var recordedChecksum string

//go:embed grant.sql
var grantScript string

//go:embed revoke.sql
var revokeScript string

// Stages name where an installation refused. They are a closed list and carry
// no configuration value.
const (
	StageArtifact      = "artifact"
	StagePreconditions = "preconditions"
	StageRoles         = "roles"
	StageObjects       = "objects"
	StageOwnership     = "ownership"
	StageSeal          = "seal"
	StageVerification  = "verification"
	StageCommit        = "commit"
)

// StageError reports the stage that refused and the underlying cause.
type StageError struct {
	Stage  string
	Reason string
	Err    error
}

func (e *StageError) Error() string {
	if e.Reason != "" {
		return "baseline " + e.Stage + ": " + e.Reason
	}
	return "baseline " + e.Stage + " refused"
}
func (e *StageError) Unwrap() error { return e.Err }

func refuse(stage, reason string, err error) error {
	return &StageError{Stage: stage, Reason: reason, Err: err}
}

// Check is a statement that must return a single true value before the
// installation commits.
type Check struct {
	Name string
	SQL  string
	Args []any
}

// Checksum is the SHA-256 of the uncompressed artifact. It is recorded in the
// seal, so a database states which artifact it was installed from.
func Checksum() string { return strings.TrimSpace(recordedChecksum) }

var (
	ownerStatement  = regexp.MustCompile(`^ALTER .* OWNER TO ([a-z_0-9]+);$`)
	createRole      = regexp.MustCompile(`^CREATE ROLE ([a-z_0-9]+);$`)
	roleStatement   = regexp.MustCompile(`^(CREATE ROLE|ALTER ROLE|GRANT) [a-zA-Z_0-9 ,]+;$`)
	checksumPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type plan struct {
	objects string
	owners  []string
	// roles are the roles the artifact assigns ownership to.
	roles []string
}

func loadArtifact() (string, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressedArtifact))
	if err != nil {
		return "", err
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	if !checksumPattern.MatchString(Checksum()) || hex.EncodeToString(sum[:]) != Checksum() {
		return "", errors.New("artifact checksum mismatch")
	}
	return string(raw), nil
}

// buildPlan splits the artifact into object creation and ownership. The
// ownership pass needs temporary privileges (grant.sql) that revoke.sql
// removes before the transaction ends.
func buildPlan(artifact string) (plan, error) {
	var result plan
	var objects strings.Builder
	ownerRoles := map[string]bool{}
	for _, line := range strings.Split(artifact, "\n") {
		if match := ownerStatement.FindStringSubmatch(line); match != nil {
			if match[1] != Operator {
				ownerRoles[match[1]] = true
				result.owners = append(result.owners, line)
			}
			continue
		}
		objects.WriteString(line)
		objects.WriteByte('\n')
	}
	if len(result.owners) == 0 || !ownerRoles[Authority] {
		return plan{}, errors.New("artifact has no ownership section")
	}
	for role := range ownerRoles {
		result.roles = append(result.roles, role)
	}
	sort.Strings(result.roles)
	result.objects = objects.String()
	return result, nil
}

func execScript(ctx context.Context, conn *pgx.Conn, script string) error {
	_, err := conn.PgConn().Exec(ctx, script).ReadAll()
	return err
}

func queryBool(ctx context.Context, conn *pgx.Conn, statement string, arguments ...any) (bool, error) {
	var value bool
	err := conn.QueryRow(ctx, statement, arguments...).Scan(&value)
	return value, err
}

// Install installs the baseline into an empty database and commits only if
// the catalog seals, is intact and every check passes.
func Install(ctx context.Context, conn *pgx.Conn, checks ...Check) (err error) {
	if ctx == nil || conn == nil {
		return refuse(StagePreconditions, "no connection", nil)
	}
	artifact, loadErr := loadArtifact()
	if loadErr != nil {
		return refuse(StageArtifact, "embedded artifact is unreadable", loadErr)
	}
	steps, planErr := buildPlan(artifact)
	if planErr != nil {
		return refuse(StageArtifact, "embedded artifact is malformed", planErr)
	}
	if reason, checkErr := preconditions(ctx, conn); checkErr != nil || reason != "" {
		return refuse(StagePreconditions, reason, checkErr)
	}
	if execErr := execScript(ctx, conn, "BEGIN"); execErr != nil {
		return refuse(StagePreconditions, "transaction did not start", execErr)
	}
	committed := false
	defer func() {
		if !committed {
			_ = execScript(context.WithoutCancel(ctx), conn, "ROLLBACK")
			_ = execScript(context.WithoutCancel(ctx), conn, "RESET ALL")
		}
	}()
	if roleErr := installRoles(ctx, conn); roleErr != nil {
		return refuse(StageRoles, "", roleErr)
	}
	if execErr := execScript(ctx, conn, steps.objects); execErr != nil {
		return refuse(StageObjects, "", execErr)
	}
	// The dump sets an empty search_path for its own statements; the scripts
	// below name every object in full.
	ownership := "SELECT pg_catalog.set_config('zasp_baseline.owners', '" + strings.Join(steps.roles, ",") + "', true);\n" +
		grantScript + "\n" + strings.Join(steps.owners, "\n") + "\n" + revokeScript
	if execErr := execScript(ctx, conn, ownership); execErr != nil {
		return refuse(StageOwnership, "", execErr)
	}
	if execErr := execScript(ctx, conn, "RESET search_path; RESET row_security; RESET check_function_bodies"); execErr != nil {
		return refuse(StageOwnership, "", execErr)
	}
	if sealed, sealErr := queryBool(ctx, conn, `SELECT zasp_baseline.seal($1)`, Checksum()); sealErr != nil || !sealed {
		return refuse(StageSeal, "", sealErr)
	}
	if intact, intactErr := queryBool(ctx, conn, `SELECT zasp_baseline.intact()`); intactErr != nil || !intact {
		return refuse(StageVerification, "sealed catalog is not intact", intactErr)
	}
	for _, check := range checks {
		if passed, checkErr := queryBool(ctx, conn, check.SQL, check.Args...); checkErr != nil || !passed {
			return refuse(StageVerification, check.Name, checkErr)
		}
	}
	if execErr := execScript(ctx, conn, "COMMIT"); execErr != nil {
		return refuse(StageCommit, "", execErr)
	}
	committed = true
	return nil
}

// preconditions returns a reason when the database cannot take the baseline.
func preconditions(ctx context.Context, conn *pgx.Conn) (string, error) {
	var version int
	var collation, owner, user, session string
	var super, createRole, bypass, empty bool
	err := conn.QueryRow(ctx, `SELECT current_setting('server_version_num')::int, d.datcollate, pg_catalog.pg_get_userbyid(d.datdba),
		current_user::text, session_user::text, r.rolsuper, r.rolcreaterole, r.rolbypassrls,
		NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname LIKE 'zasp\_%') AND pg_catalog.to_regclass('public.zasp_schema_versions') IS NULL
		FROM pg_catalog.pg_database d, pg_catalog.pg_roles r WHERE d.datname = current_database() AND r.rolname = current_user`).
		Scan(&version, &collation, &owner, &user, &session, &super, &createRole, &bypass, &empty)
	switch {
	case err != nil:
		return "", err
	case version < 160000:
		return "PostgreSQL 16 or later is required", nil
	case collation != "C" && collation != "C.UTF-8" && collation != "POSIX":
		return "the database collation must be C or C.UTF-8", nil
	case user != Operator || session != Operator:
		return "connect as the " + Operator + " role", nil
	case owner != Operator:
		return "the " + Operator + " role must own the database", nil
	case !super && !createRole:
		return "the " + Operator + " role needs CREATEROLE", nil
	case !super && !bypass:
		return "the " + Operator + " role needs BYPASSRLS", nil
	case !empty:
		return "the database already contains a product schema", nil
	}
	return "", nil
}

// installRoles creates the product roles that do not exist and applies the
// role attributes and memberships. Roles are cluster-wide, so a second
// database in the same cluster finds them already present.
func installRoles(ctx context.Context, conn *pgx.Conn) error {
	existing := map[string]bool{}
	rows, err := conn.Query(ctx, `SELECT rolname::text FROM pg_catalog.pg_roles WHERE rolname LIKE 'zasp\_%'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var script strings.Builder
	for _, line := range strings.Split(roleScript, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !roleStatement.MatchString(line) {
			return errors.New("role script is malformed")
		}
		if match := createRole.FindStringSubmatch(line); match != nil && existing[match[1]] {
			continue
		}
		script.WriteString(line)
		script.WriteByte('\n')
	}
	return execScript(ctx, conn, script.String())
}

// State is what a database reports about its baseline.
type State struct {
	Sealed   bool   `json:"sealed"`
	Intact   bool   `json:"intact"`
	Artifact string `json:"artifact,omitempty"`
	Current  bool   `json:"current"`
}

// Verify reports whether the database holds this artifact's catalog,
// unchanged. When only catalog row versions moved (after VACUUM FULL or a
// restore) it refreshes the fast-path marker.
func Verify(ctx context.Context, conn *pgx.Conn) (State, error) {
	if ctx == nil || conn == nil {
		return State{}, refuse(StagePreconditions, "no connection", nil)
	}
	var state State
	var installed bool
	if err := conn.QueryRow(ctx, `SELECT pg_catalog.to_regprocedure('zasp_baseline.state()') IS NOT NULL`).Scan(&installed); err != nil {
		return State{}, refuse(StageVerification, "", err)
	}
	if !installed {
		return state, nil
	}
	var artifact *string
	if err := conn.QueryRow(ctx, `SELECT (s->>'sealed')::boolean, (s->>'intact')::boolean, s->>'artifact' FROM zasp_baseline.state() s`).Scan(&state.Sealed, &state.Intact, &artifact); err != nil {
		return State{}, refuse(StageVerification, "", err)
	}
	if artifact != nil {
		state.Artifact = *artifact
	}
	state.Current = state.Sealed && state.Artifact == Checksum()
	if state.Current && state.Intact {
		if _, err := queryBool(ctx, conn, `SELECT zasp_baseline.seal($1)`, Checksum()); err != nil {
			return state, refuse(StageSeal, "", err)
		}
	}
	return state, nil
}
