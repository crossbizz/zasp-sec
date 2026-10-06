package roleassertion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

// Fixed server assertion. Success emits no tuples; false or NULL raises 22012.
// Role/session parameters originate from the owned session and declared role,
// never from a role string presented as an observed SELECT value.
const AssertionSQL = `WITH assertion AS (SELECT ((current_user::pg_catalog.text OPERATOR(pg_catalog.=) $1::pg_catalog.text) AND (session_user::pg_catalog.text OPERATOR(pg_catalog.=) $2::pg_catalog.text) AND (pg_catalog.pg_backend_pid() OPERATOR(pg_catalog.=) $3::pg_catalog.int4)) AS ok) SELECT 1 OPERATOR(pg_catalog./) CASE WHEN ok IS TRUE THEN 1 ELSE 0 END AS role_assertion FROM assertion WHERE ok IS NOT TRUE`

var ErrAssertion = errors.New("role/session assertion refused")

type Expectation struct {
	Role        string
	SessionUser string
	BackendPID  int32
}
type Receipt struct {
	Kind             string `json:"kind"`
	SQLSHA256        string `json:"sql_sha256"`
	ParameterSHA256  string `json:"parameter_sha256"`
	AssertedRole     string `json:"asserted_role"`
	BoundSessionUser string `json:"bound_session_user"`
	BoundBackendPID  int32  `json:"bound_backend_pid"`
	Placement        string `json:"placement"`
	SQLState         string `json:"sqlstate"`
	RowCount         int    `json:"row_count"`
	CommandTag       string `json:"command_tag"`
	TimedOut         bool   `json:"timed_out"`
}
type Budget struct {
	LimitBytes int
	UsedBytes  int
	UsedTime   time.Duration
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (b *Budget) charge(payload []byte, elapsed time.Duration) error {
	if b == nil || b.LimitBytes < 0 || b.UsedBytes < 0 || len(payload) > b.LimitBytes-b.UsedBytes {
		return ErrAssertion
	}
	b.UsedBytes += len(payload)
	b.UsedTime += elapsed
	return nil
}
func Assert(ctx context.Context, conn *pgx.Conn, e Expectation, placement string, budget *Budget) (Receipt, error) {
	started := time.Now()
	if ctx == nil || ctx.Err() != nil || conn == nil || conn.IsClosed() || e.Role == "" || e.SessionUser == "" || e.BackendPID <= 0 || placement == "" {
		return Receipt{}, ErrAssertion
	}
	params := []any{e.Role, e.SessionUser, e.BackendPID}
	wire, err := json.Marshal(params)
	if err != nil {
		return Receipt{}, ErrAssertion
	}
	rows, err := conn.Query(ctx, AssertionSQL, params...)
	if err != nil {
		return Receipt{}, ErrAssertion
	}
	for rows.Next() {
		rows.Close()
		return Receipt{}, ErrAssertion
	}
	rows.Close()
	if rows.Err() != nil || ctx.Err() != nil || rows.CommandTag().String() != "SELECT 0" {
		return Receipt{}, ErrAssertion
	}
	receipt := Receipt{Kind: "server-role-session-assertion-v1", SQLSHA256: digest([]byte(AssertionSQL)), ParameterSHA256: digest(wire), AssertedRole: e.Role, BoundSessionUser: e.SessionUser, BoundBackendPID: e.BackendPID, Placement: placement, SQLState: "00000", RowCount: 0, CommandTag: "SELECT 0", TimedOut: false}
	body, err := json.Marshal(receipt)
	if err != nil || budget.charge(body, time.Since(started)) != nil {
		return Receipt{}, ErrAssertion
	}
	return receipt, nil
}
