package apiserver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type orderedPolicyTraceKey struct{}
type orderedPolicyTracePhase struct {
	name  string
	began time.Time
}
type orderedPolicyQueryTrace struct {
	t        *testing.T
	next     pgx.QueryTracer
	messages map[string]bool
}

func orderedPolicyDiagnosticTracer(t *testing.T, prior pgx.QueryTracer) pgx.QueryTracer {
	if os.Getenv("ZASP_ORDERED_POLICY_TRACE") != "1" {
		return prior
	}
	// Only exact, bounded static migration error literals may become labels.
	// Dynamic messages, arguments, SQL text and server WHERE context never log.
	files, err := filepath.Glob("../migrations/sql/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatal("diagnostic static message sources unavailable", err)
	}
	literal := regexp.MustCompile(`MESSAGE\s*=\s*'((?:[^']|'')*)'`)
	safe := regexp.MustCompile(`^[A-Za-z0-9 _-]{1,120}$`)
	messages := make(map[string]bool)
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal("diagnostic static message source unavailable", err)
		}
		for _, match := range literal.FindAllSubmatch(data, -1) {
			value := strings.ReplaceAll(string(match[1]), "''", "'")
			if safe.MatchString(value) {
				messages[value] = true
			}
		}
	}
	return &orderedPolicyQueryTrace{t: t, next: prior, messages: messages}
}

func (x *orderedPolicyQueryTrace) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if x.next != nil {
		ctx = x.next.TraceQueryStart(ctx, conn, data)
	}
	phase := ""
	switch data.SQL {
	case `SELECT zasp_authorization80_worker.prepare_ordered68_effect($1::jsonb)`:
		phase = "prepare-effect"
	case `SELECT zasp_authorization80_worker.prepare_ordered68_policy($1,$2::jsonb)`:
		phase = "prepare-policy"
	case `SELECT zasp_authorization80_worker.ordered68_operation_source($1,$2::jsonb)`:
		phase = "ordinary-source"
	case `SELECT zasp_authorization80_worker.ordered68_effect_source($1,$2::jsonb)`:
		phase = "effect-source"
	case `SELECT zasp_authorization80_worker.ordered68_policy_source($1,$2::jsonb)`:
		phase = "policy-source"
	case `SELECT zasp_authorization80_worker.ordered68_policy_begin($1,$2::jsonb,$3)`:
		phase = "signing-begin"
	case `SELECT zasp_authorization80_worker.ordered68_policy_store($1,$2::jsonb,$3,$4::bytea,$5::bytea,$6)`:
		phase = "signing-store"
	case `SELECT zasp_temporal68.effect($1::jsonb)`:
		phase = "native-effect"
	case `SELECT zasp_temporal68.application($1::jsonb)`:
		phase = "native-application"
	case `SELECT zasp_temporal68.delivery($1::jsonb)`:
		phase = "native-delivery"
	case `SELECT zasp_temporal68.cleanup($1::jsonb)`:
		phase = "native-cleanup"
	}
	if phase == "" {
		return ctx
	}
	return context.WithValue(ctx, orderedPolicyTraceKey{}, orderedPolicyTracePhase{phase, time.Now()})
}

func (x *orderedPolicyQueryTrace) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	if x.next != nil {
		x.next.TraceQueryEnd(ctx, conn, data)
	}
	phase, ok := ctx.Value(orderedPolicyTraceKey{}).(orderedPolicyTracePhase)
	if !ok {
		return
	}
	class, label := ordered62TraceClass(data.Err), "none"
	var native *pgconn.PgError
	if errors.As(data.Err, &native) {
		label = "unlisted-static-message"
		if x.messages[native.Message] {
			label = native.Message
		}
	}
	x.t.Log("ordered policy native", phase.name, "elapsed_ms", time.Since(phase.began).Milliseconds(), "class", class, "label", label)
}

// Diagnose the exact retained provider predicate without changing either the
// captured plan or provider row. Both observations are read-only and rolled back.
func orderedPolicyProviderDiagnostic(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, run string) {
	if os.Getenv("ZASP_ORDERED_POLICY_TRACE") != "1" {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := owner.BeginTx(bounded, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Log("ordered provider diagnostic begin", ordered62TraceClass(err))
		return
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("ordered provider diagnostic rollback", ordered62TraceClass(err))
		}
	}()
	for _, phase := range []string{"original-session", "utc-session"} {
		if phase == "utc-session" {
			if _, err := tx.Exec(bounded, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
				t.Log("ordered provider diagnostic timezone", ordered62TraceClass(err))
				return
			}
		}
		var present, settled, digestEqual, outstanding, utc bool
		err := tx.QueryRow(bounded, `SELECT
 EXISTS(SELECT 1 FROM zasp_temporal68.provider_reservations u WHERE (u.organization_id,u.workspace_id,u.environment_id,u.run_id,u.attempt)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.attempt)),
 COALESCE(u.settled_at IS NOT NULL,false),
 COALESCE(p.plan->>'provider_usage_digest'='sha256:'||encode(digest(convert_to(to_jsonb(u)::text,'UTF8'),'sha256'),'hex'),false),
 EXISTS(SELECT 1 FROM zasp_temporal68.provider_reservations x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id) AND x.settled_at IS NULL),
 current_setting('TimeZone') IN('UTC','Etc/UTC')
 FROM zasp_temporal68.admissions a
 JOIN public.zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id)
 LEFT JOIN zasp_temporal68.provider_reservations u ON(u.organization_id,u.workspace_id,u.environment_id,u.run_id,u.attempt)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.attempt)
 WHERE(a.organization_id,a.workspace_id,a.environment_id,a.run_id)=($1,$2,$3,$4)`, o, w, e, run).Scan(&present, &settled, &digestEqual, &outstanding, &utc)
		if err != nil {
			t.Log("ordered provider diagnostic query", phase, ordered62TraceClass(err))
			return
		}
		t.Log("ordered provider predicate", phase, "row_present", present, "settled", settled, "digest_equal", digestEqual, "outstanding", outstanding, "timezone_is_utc", utc)
	}
}
